"""Narrow, authenticated, read-only event projection for the single-camera pilot."""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import os
from pathlib import Path
import re
import socket
from socketserver import ThreadingMixIn
import threading
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
try:
    from reolink_protect_events.http_deadline import get_bytes, _DeadlineSocket
except ModuleNotFoundError:
    from http_deadline import get_bytes, _DeadlineSocket

CAMERA = "vor_dem_haus"
CAMERAS = frozenset(("neubau_eingang", "garage_hinten", "hintertuer", "garten_neubau", "eingang", "vor_dem_haus"))
BACKEND = "http://172.31.216.3:5000"
TOKEN = None
ALLOWED = {"192.168.1.1", "192.168.1.175", "172.31.216.1", "127.0.0.1", "192.168.1.196"}
STATUS_ONLY = {"192.168.1.196"}
STATUS_DIR = Path('/run/camera-resilience')
BACKEND_SECONDS = 8
REQUEST_SECONDS = 12
WORKERS = 4
LOOP_STALE_SECONDS = 30
FIELDS = ("id", "camera", "label", "start_time", "end_time", "top_score", "false_positive")


def backend(path, deadline=None):
    try:
        remaining = BACKEND_SECONDS if deadline is None else min(BACKEND_SECONDS, deadline-time.monotonic())
        if remaining <= 0:
            raise TimeoutError('request_total_deadline')
        status, body = get_bytes(BACKEND + path, timeout=remaining,
                                 limit=2 * 1024 * 1024)
        if status != 200:
            raise HTTPError(BACKEND + path, status, 'backend_status', None, None)
        return json.loads(body)
    except ValueError:
        raise RuntimeError('backend_invalid_response') from None


def status_view(now_ms=None):
    """Only fixed public status files and allowlisted scalar fields leave here."""
    now_ms=int(time.time()*1000)if now_ms is None else now_ms
    result={'schemaVersion':1,'atMs':now_ms,'actionRequired':False,'alerts':[]}
    for name,ttl in [('monitor',420000),('events',120000)]:
        try:
            with (STATUS_DIR/(name+'.json')).open('rb')as f:raw=f.read(65537)
            if len(raw)>65536:raise ValueError('oversized_status')
            value=json.loads(raw)
            if not isinstance(value,dict):raise ValueError('status_shape')
            if value.get('schemaVersion')!=1:raise ValueError('status_schema')
            completed=value.get('completedAtMs',value.get('atMs'))
            if type(completed)is not int or not -5000<=now_ms-completed<=ttl:
                raise ValueError('stale_status')
            if type(value.get('actionRequired'))is not bool or not isinstance(value.get('alerts'),list):
                raise ValueError('status_shape')
            if value.get('state')not in ['healthy','starting','verifying','maintenance','attention','degraded']:
                raise ValueError('status_state')
            alerts=[]
            for row in value['alerts'][:32]:
                if not isinstance(row,dict)or not re.fullmatch('[a-z][a-z0-9_]{0,79}',row.get('code','')):
                    raise ValueError('status_code')
                if type(row.get('actionRequired'))is not bool:raise ValueError('status_action')
                alert={'code':row['code'],'actionRequired':row['actionRequired'],'component':name}
                if row.get('cameraId')is not None:
                    if not re.fullmatch('[a-f0-9]{24}',row['cameraId']):raise ValueError('status_camera')
                    alert['cameraId']=row['cameraId']
                alerts.append(alert)
            view={'state':value['state'],'completedAtMs':completed,
                  'actionRequired':value['actionRequired']or any(a['actionRequired']for a in alerts),'alerts':alerts}
        except (OSError,ValueError,TypeError):
            alert={'code':name+'_status_unavailable','component':name,'actionRequired':True}
            view={'state':'attention','completedAtMs':None,'actionRequired':True,'alerts':[alert]}
        result[name]=view
        result['alerts'].extend(view['alerts'])
        result['actionRequired']=result['actionRequired']or view['actionRequired']
    return result


class RequestSocket(_DeadlineSocket):
    """The same absolute limit includes headers, parsing and response writes."""
    def __getattr__(self, name):
        return getattr(self.sock, name)


class BoundedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, *args, exit_process=os._exit, **kwargs):
        self._slots = threading.BoundedSemaphore(WORKERS)
        self._loop_last = time.monotonic()
        self._watch_stop = threading.Event()
        self._exit_process = exit_process
        self._watch_thread = None
        super().__init__(*args, **kwargs)

    def get_request(self):
        sock, address = super().get_request()
        return RequestSocket(sock, time.monotonic() + REQUEST_SECONDS), address

    def process_request(self, request, client_address):
        # A brief bounded queue lets normal simultaneous camera polls finish;
        # saturation never creates unbounded threads or stalls the accept loop.
        if not self._slots.acquire(timeout=.1):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, *args):
        try:
            super().process_request_thread(*args)
        finally:
            self._slots.release()

    def service_actions(self):
        self._loop_last = time.monotonic()

    def handle_error(self, request, client_address):
        # Closed peers and deadline failures need no raw request diagnostics.
        pass

    def _watch_loop(self):
        while not self._watch_stop.wait(1):
            if time.monotonic() - self._loop_last > LOOP_STALE_SECONDS:
                # Observe actual accept-loop progress. No independent fake
                # heartbeat can keep a wedged loop looking healthy.
                self._exit_process(70)
                return

    def serve_forever(self, poll_interval=.5):
        self._loop_last = time.monotonic()
        self._watch_thread = threading.Thread(target=self._watch_loop,
                                              name='api-loop-watch', daemon=True)
        self._watch_thread.start()
        try:
            return super().serve_forever(poll_interval)
        finally:
            self._watch_stop.set()

    def server_close(self):
        self._watch_stop.set()
        super().server_close()


def event_view(value):
    if not isinstance(value, dict) or value.get("camera") not in CAMERAS:
        raise ValueError("camera_mismatch")
    result = {key: value.get(key) for key in FIELDS}
    data = value.get("data") or {}
    result["type"] = data.get("type")
    result["data"] = {key: data[key] for key in ("type", "score", "top_score", "stationary", "position_changes", "max_severity") if key in data}
    return result


def query_params(query):
    parsed = parse_qs(query, keep_blank_values=True, strict_parsing=True) if query else {}
    if set(parsed) - {"camera", "after", "before", "limit", "in_progress", "include_thumbnails"} or any(len(v) != 1 for v in parsed.values()):
        raise ValueError("query")
    if parsed.get("include_thumbnails", ["0"])[0] != "0":
        raise ValueError("thumbnails")
    camera = parsed.get("camera", [CAMERA])[0]
    if camera not in CAMERAS:
        raise ValueError("camera")
    params = {"camera": camera, "include_thumbnails": 0, "limit": 200}
    for key in ("after", "before"):
        if key in parsed:
            value = float(parsed[key][0])
            if not math.isfinite(value) or value < 0:
                raise ValueError("time")
            params[key] = value
    if "limit" in parsed:
        limit = int(parsed["limit"][0])
        if not 1 <= limit <= 200:
            raise ValueError("limit")
        params["limit"] = limit
    if "in_progress" in parsed:
        value = parsed["in_progress"][0]
        if value not in ("0", "1"):
            raise ValueError("in_progress")
        params["in_progress"] = value
    return params


def health_view(stats, camera=None):
    """Project one camera independently; global output retains the original pilot view."""
    if camera is not None and camera not in CAMERAS:
        raise ValueError("camera")
    detector = stats.get("detectors", {}).get("coral", {})
    version = stats.get("service", {}).get("version")

    def positive(value):
        try:
            number = float(value or 0)
            return math.isfinite(number) and number > 0
        except (ValueError, TypeError):
            return False

    def one(name):
        cam = stats.get("cameras", {}).get(name, {})
        healthy = (str(version).startswith("0.18.1")
                   and positive(cam.get("camera_fps"))
                   and positive(cam.get("process_fps"))
                   and positive(detector.get("pid"))
                   and positive(detector.get("inference_speed")))
        return {
            "healthy": healthy, "camera": name, "version": version,
            "detector_type": "edgetpu", "camera_fps": cam.get("camera_fps"),
            "process_fps": cam.get("process_fps"), "detection_fps": cam.get("detection_fps"),
            "skipped_fps": cam.get("skipped_fps"),
            "coral_inference_ms": detector.get("inference_speed"),
            "coral_pid": detector.get("pid"), "uptime": stats.get("service", {}).get("uptime"),
        }

    if camera is not None:
        return one(camera)
    result = one(CAMERA)
    # The configured scope is authoritative. A disappeared backend entry must
    # appear as unhealthy, not silently shrink the population being checked.
    result["cameras"] = {name: one(name) for name in sorted(CAMERAS)}
    result["overall_healthy"] = all(value["healthy"] for value in result["cameras"].values())
    return result


def health_camera(query):
    if not query:
        return None
    parsed = parse_qs(query, keep_blank_values=True, strict_parsing=True)
    if set(parsed) != {"camera"} or len(parsed["camera"]) != 1 or parsed["camera"][0] not in CAMERAS:
        raise ValueError("camera")
    return parsed["camera"][0]


class Handler(BaseHTTPRequestHandler):
    server_version = "FrigatePilotProjection/1"

    def log_message(self, *_args):
        # No request paths, Authorization headers or backend data are logged.
        pass

    def backend(self, path):
        return backend(path, self.connection.deadline)

    def send_json(self, status, data):
        body = json.dumps(data, allow_nan=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.client_address[0] not in ALLOWED:
            return self.send_json(403, {"error": "source_denied"})
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            return self.send_json(401, {"error": "authentication_required"})
        try:
            url = urlsplit(self.path)
            if self.client_address[0]in STATUS_ONLY and url.path not in ['/resilience','/livez']:
                return self.send_json(403, {'error':'source_scope_denied'})
            if url.path == '/livez' and not url.query:
                return self.send_json(200, {'alive': True})
            if url.path == '/resilience' and not url.query:
                return self.send_json(200,status_view())
            if url.path == "/api/events":
                result = self.backend("/api/events?" + urlencode(query_params(url.query)))
                if not isinstance(result, list):
                    raise RuntimeError("event_list")
                return self.send_json(200, [event_view(event) for event in result])
            if re.fullmatch(r"/api/events/[A-Za-z0-9_.-]{1,100}", url.path) and not url.query:
                result = self.backend(url.path)
                if result.get("camera") not in CAMERAS:
                    return self.send_json(404, {"error": "not_found"})
                return self.send_json(200, event_view(result))
            if url.path == "/health":
                stats = self.backend("/api/stats")
                return self.send_json(200, health_view(stats, health_camera(url.query)))
            return self.send_json(404, {"error": "not_found"})
        except ValueError:
            return self.send_json(400, {"error": "invalid_request"})
        except HTTPError as error:
            return self.send_json(404 if error.code == 404 else 502, {"error": "backend_not_found" if error.code == 404 else "backend_unavailable"})
        except Exception:
            return self.send_json(502, {"error": "backend_unavailable"})

    def do_POST(self):
        self.send_json(405, {"error": "read_only"})

    do_PUT = do_PATCH = do_DELETE = do_POST


if __name__ == "__main__":
    TOKEN = Path("/run/secrets/frigate-pilot-api-token").read_text().strip()
    if len(TOKEN) < 48:
        raise RuntimeError("invalid_api_token")
    socket.setdefaulttimeout(10)
    BoundedHTTPServer(("192.168.1.175", 18799), Handler).serve_forever()
