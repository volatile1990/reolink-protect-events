"""Private Unix-socket proxy. Camera secrets stay in the root-owned host config."""
import argparse
import base64
import http.server
import http.client
import contextlib
import json
import os
from pathlib import Path
import re
import socketserver
import socket
import stat
import threading
import time
import urllib.error
import urllib.request
import urllib.parse

CONFIG = Path('/etc/reolink-protect-controls/config.json')
SOCKET = Path('/run/reolink-protect-controls/controls.sock')
HOSTS = {'192.168.30.' + str(i) for i in range(210, 216)}
CONTROL_SECONDS = 70
REQUEST_SECONDS = 10
RESPONSE_SECONDS = 5
AUDIO_PROGRESS_SECONDS = 20
MAX_HANDLERS = 8
MAX_RESPONSE = 262144


class ControlError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def load_config(path=None):
    path = CONFIG if path is None else Path(path)
    info = path.stat()
    if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise ControlError('private_config_required', 503)
    value = json.loads(path.read_text())
    bridges = value.get('bridges')
    if not isinstance(bridges, list) or len(bridges) != 6 or {b.get('host') for b in bridges} != HOSTS:
        raise ControlError('unexpected_camera_scope', 503)
    if len({b.get('cameraId') for b in bridges}) != 6:
        raise ControlError('unexpected_camera_scope', 503)
    for bridge in bridges:
        if not re.fullmatch('[a-f0-9]{24}', bridge.get('cameraId', '')) or not all(isinstance(bridge.get(k), str) and bridge[k] for k in ('username','password')) or ':' in bridge['username']:
            raise ControlError('invalid_private_config', 503)
    return {b['cameraId']: b for b in bridges}


def validate_job(job, bridges):
    if not isinstance(job, dict) or set(job) != {'cameraId','host','method','resource','body','queryType'}:
        raise ControlError('invalid_control_request')
    bridge = bridges.get(job['cameraId'])
    if not bridge or bridge['host'] != job['host']:
        raise ControlError('camera_identity_mismatch', 403)
    method, resource, body = job['method'], job['resource'], job['body']
    if method not in ('GET','POST') or not isinstance(resource,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',resource):
        raise ControlError('invalid_control_request')
    selector=job['queryType']
    if selector is not None and (method!='GET' or not isinstance(selector,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,31}',selector)):
        raise ControlError('invalid_control_selector')
    if method == 'GET':
        if body is not None: raise ControlError('invalid_control_request')
    elif resource in ('capabilities','state') or not isinstance(body,dict) or set(body) != {'values'} or not isinstance(body['values'],dict):
        raise ControlError('invalid_control_request')
    if len(json.dumps(body).encode()) > 70000: raise ControlError('control_request_too_large')
    return bridge


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class SocketDeadline:
    """A total deadline, including a peer which keeps dribbling header bytes."""
    def __init__(self, connection, seconds):
        self.connection = connection
        self.expired = threading.Event()
        self.timer = threading.Timer(seconds, self.abort)
        self.timer.daemon = True
        self.timer.start()

    def abort(self):
        self.expired.set()
        try:self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.connection.close()

    def close(self):
        self.timer.cancel()


@contextlib.contextmanager
def backend_reply(request, seconds, opener=None, *, continuous=False,
                  rejected_code='camera_control_rejected',rejected_statuses=(400,403,404,409,422,503)):
    """No redirects/proxies or retries; abort the owned socket at the deadline.

    In particular an uncertain POST is never dispatched a second time. The
    optional opener exists for the established offline contract fixtures.
    """
    deadline=time.monotonic()+seconds
    if opener is not None:
        with opener.open(request,timeout=seconds)as response:
            yield response,deadline
        return
    parsed=urllib.parse.urlsplit(request.full_url)
    if parsed.scheme!='http' or parsed.username is not None or parsed.password is not None:
        raise ControlError('invalid_control_endpoint',503)
    connection=http.client.HTTPConnection(parsed.hostname,parsed.port or 80,timeout=seconds)
    guard=None;response=None
    try:
        connection.connect()
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ControlError('camera_control_timeout',504)
        guard=SocketDeadline(connection.sock,remaining)
        connection.sock.settimeout(remaining)
        target=parsed.path+('?' + parsed.query if parsed.query else '')
        connection.request(request.get_method(),target,body=request.data,headers=dict(request.header_items()))
        response=connection.getresponse()
        if guard.expired.is_set()or time.monotonic()>=deadline:raise ControlError('camera_control_timeout',504)
        if response.status>=300:
            raise ControlError(rejected_code,response.status if response.status in rejected_statuses else 502)
        response._control_socket=guard.connection
        if continuous:guard.close()
        yield response,deadline
        if not continuous and guard.expired.is_set():raise ControlError('camera_control_timeout',504)
    finally:
        if guard is not None:guard.close()
        if response is not None:response.close()
        connection.close()


def read_body(response,deadline,limit=MAX_RESPONSE):
    output=bytearray()
    read=getattr(response,'read1',response.read)
    while True:
        if time.monotonic()>=deadline:raise ControlError('camera_control_timeout',504)
        # HTTPResponse closes its file (and a Connection: close socket) once
        # Content-Length has been consumed. Do not touch that retired socket
        # just to discover EOF on the following iteration.
        if getattr(response,'isclosed',lambda:False)():
            if getattr(response,'length',None) not in(None,0):
                raise ControlError('camera_control_truncated_response',502)
            return bytes(output)
        if getattr(response,'_control_socket',None)is not None:
            response._control_socket.settimeout(max(.001,deadline-time.monotonic()))
        part=read(min(65536,limit+1-len(output)))
        if not part:
            if getattr(response,'length',None) not in(None,0):
                raise ControlError('camera_control_truncated_response',502)
            return bytes(output)
        output.extend(part)
        if len(output)>limit:raise ControlError('camera_control_response_too_large',502)


class AdtsProgress:
    """Count only complete AAC frames, not an arbitrary trickle of bytes."""
    def __init__(self):self.buffer=bytearray()
    def feed(self,data):
        self.buffer.extend(data);frames=0
        while len(self.buffer)>=7:
            b=self.buffer
            if b[0]!=255 or b[1]&0xf6!=0xf0:raise ControlError('invalid_camera_audio_response',502)
            size=((b[3]&3)<<11)|(b[4]<<3)|(b[5]>>5)
            if size<(7 if b[1]&1 else 9)or size>8191:raise ControlError('invalid_camera_audio_response',502)
            if len(b)<size:break
            del b[:size];frames+=1
        if len(self.buffer)>8191:raise ControlError('invalid_camera_audio_response',502)
        return frames


def dispatch(job, bridges, opener=None):
    bridge = validate_job(job, bridges)
    headers = {'Authorization':'Basic ' + base64.b64encode((bridge['username']+':'+bridge['password']).encode()).decode(),
               'Content-Type':'application/json', 'X-Reolink-Control-Intent':'user'}
    data = None if job['method'] == 'GET' else json.dumps(job['body']).encode()
    query='' if job['queryType'] is None else '?type='+urllib.parse.quote(job['queryType'],safe='')
    req = urllib.request.Request('http://'+bridge['host']+':8080/control/'+job['resource']+query,data=data,headers=headers,method=job['method'])
    try:
        with backend_reply(req,CONTROL_SECONDS,opener) as (response,deadline):
            raw = read_body(response,deadline)
            result=json.loads(raw)
            if not isinstance(result,dict): raise ControlError('invalid_camera_control_response',502)
            # Bridge endpoint is a projected, dedicated control contract, never a raw camera API.
            if job['method']=='GET' and job['resource'] in ('state','capabilities') and result.get('schemaVersion')!=1: raise ControlError('control_schema_mismatch',502)
            return result
    except urllib.error.HTTPError as exc:
        raise ControlError('camera_control_rejected',exc.code if exc.code in (400,403,404,409,422,503) else 502) from None
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        raise ControlError('camera_control_unavailable',503) from None


def stream_listen(job, bridges, handler):
    bridge=validate_job(job,bridges)
    if job['method']!='GET' or job['resource']!='listen' or job['queryType'] is not None:
        raise ControlError('invalid_audio_request')
    headers={'Authorization':'Basic '+base64.b64encode((bridge['username']+':'+bridge['password']).encode()).decode()}
    req=urllib.request.Request('http://'+bridge['host']+':8080/control/listen',headers=headers)
    try:
        with backend_reply(req,AUDIO_PROGRESS_SECONDS,continuous=True,
                           rejected_code='camera_audio_unavailable',rejected_statuses=(401,404,429,503))as(response,_):
            if response.headers.get('Content-Type','').split(';')[0]!='audio/aac':
                raise ControlError('invalid_camera_audio_response',502)
            handler.send_response(200);handler.send_header('Content-Type','audio/aac');handler.send_header('Cache-Control','no-store')
            handler.send_header('Connection','close');handler.end_headers();handler.audio_started=True
            handler.close_connection=True
            handler.server.replace_deadline(handler.connection,None)
            handler.connection.settimeout(RESPONSE_SECONDS)
            progress=AdtsProgress();deadline=time.monotonic()+AUDIO_PROGRESS_SECONDS
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ControlError('camera_audio_timeout',504)
                response._control_socket.settimeout(remaining)
                data=response.read1(8192)
                if not data:break
                if progress.feed(data):deadline=time.monotonic()+AUDIO_PROGRESS_SECONDS
                handler.wfile.write(data);handler.wfile.flush()
    except urllib.error.HTTPError as exc:
        raise ControlError('camera_audio_unavailable',exc.code if exc.code in (401,404,429,503)else 502)from None
    except ControlError:
        if not getattr(handler,'audio_started',False):raise
    except (OSError,urllib.error.URLError,http.client.HTTPException):
        if not getattr(handler,'audio_started',False):raise ControlError('camera_audio_unavailable',503)from None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass

    def do_POST(self):
        status=200
        try:
            if self.path != '/control' or self.headers.get('Transfer-Encoding'): raise ControlError('invalid_control_request')
            size=int(self.headers.get('Content-Length','0'))
            if not 1<=size<=80000: raise ControlError('invalid_control_request')
            job=json.loads(self.rfile.read(size))
            self.server.replace_deadline(self.connection,CONTROL_SECONDS+RESPONSE_SECONDS)
            self.connection.settimeout(RESPONSE_SECONDS)
            if isinstance(job,dict)and job.get('resource')=='listen':
                stream_listen(job,self.server.bridges,self);return
            value=dispatch(job,self.server.bridges)
        except ControlError as exc: status=exc.status;value={'ok':False,'error':exc.code}
        except Exception: status=503;value={'ok':False,'error':'camera_control_unavailable'}
        data=json.dumps(value,ensure_ascii=False).encode()
        self.close_connection=True
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data)


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads=True
    max_handlers=MAX_HANDLERS
    request_seconds=REQUEST_SECONDS

    def __init__(self,*args,**kwargs):
        self.handler_slots=threading.BoundedSemaphore(self.max_handlers)
        self.deadlines={}
        self.deadline_lock=threading.Lock()
        self.watchdog_last=0.0
        super().__init__(*args,**kwargs)

    def replace_deadline(self,connection,seconds):
        with self.deadline_lock:
            old=self.deadlines.pop(connection,None)
            if old is not None:old.close()
            self.deadlines[connection]=SocketDeadline(connection,seconds)if seconds is not None else None

    def process_request(self,request,address):
        if not self.handler_slots.acquire(blocking=False):
            try:
                request.settimeout(.1)
                request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            except OSError:pass
            self.shutdown_request(request)
            return
        try:
            request.settimeout(self.request_seconds)
            self.replace_deadline(request,self.request_seconds)
            super().process_request(request,address)
        except BaseException:
            self.replace_deadline(request,None)
            with self.deadline_lock:self.deadlines.pop(request,None)
            self.handler_slots.release()
            raise

    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:
            self.replace_deadline(request,None)
            with self.deadline_lock:self.deadlines.pop(request,None)
            self.handler_slots.release()

    def service_actions(self):
        # This notification is driven by serve_forever's acceptor event loop,
        # never by an independent thread which could conceal a stuck loop.
        super().service_actions()
        notify=os.environ.get('NOTIFY_SOCKET');usec=os.environ.get('WATCHDOG_USEC','')
        pid=os.environ.get('WATCHDOG_PID','')
        if not notify or not usec.isdigit() or int(usec)<=0 or pid and pid!=str(os.getpid()):return
        now=time.monotonic();interval=max(.1,int(usec)/2e6)
        if now-self.watchdog_last<interval:return
        endpoint='\0'+notify[1:]if notify.startswith('@')else notify
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as target:
                target.settimeout(.1);target.sendto(b'WATCHDOG=1',endpoint)
            self.watchdog_last=now
        except OSError:pass


class Server(BoundedThreadingMixIn, getattr(socketserver, 'UnixStreamServer', socketserver.TCPServer)):
    def get_request(self):
        connection,address=super().get_request()
        connection.settimeout(75)
        return connection,address


def numeric_identity(value):
    if not re.fullmatch(r'[0-9]+', str(value)) or not 0 <= int(value) < 4294967295:
        raise argparse.ArgumentTypeError('numeric Unix uid/gid required')
    return int(value)


def private_mode(value):
    if not re.fullmatch(r'(?:0o)?[0-7]{3,4}', str(value)):
        raise argparse.ArgumentTypeError('octal permission mode required')
    result = int(value, 8)
    if result > 0o777 or result & 0o007:
        raise argparse.ArgumentTypeError('mode must deny access to other users')
    return result


def arguments(argv=None, environ=None):
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=env.get('REOLINK_CONTROLS_CONFIG', str(CONFIG)))
    parser.add_argument('--socket', type=Path, default=env.get('REOLINK_CONTROLS_SOCKET', str(SOCKET)))
    parser.add_argument('--socket-uid', type=numeric_identity,
                        default=env.get('REOLINK_CONTROLS_SOCKET_UID', str(getattr(os, 'geteuid', lambda: 0)())))
    parser.add_argument('--socket-gid', type=numeric_identity,
                        default=env.get('REOLINK_CONTROLS_SOCKET_GID', str(getattr(os, 'getegid', lambda: 0)())))
    parser.add_argument('--socket-dir-mode', type=private_mode, default=env.get('REOLINK_CONTROLS_SOCKET_DIR_MODE', '0750'))
    parser.add_argument('--socket-mode', type=private_mode, default=env.get('REOLINK_CONTROLS_SOCKET_MODE', '0660'))
    return parser.parse_args(argv)


def serve(options, server_factory=Server):
    os.umask(0o077)
    bridges=load_config(options.config)
    endpoint=options.socket
    if not endpoint.is_absolute() or not options.config.is_absolute():
        raise RuntimeError('absolute_runtime_paths_required')
    endpoint.parent.mkdir(mode=options.socket_dir_mode,exist_ok=True)
    if endpoint.parent.is_symlink() or not endpoint.parent.is_dir():
        raise RuntimeError('unexpected_socket_directory')
    os.chown(endpoint.parent,options.socket_uid,options.socket_gid)
    os.chmod(endpoint.parent,options.socket_dir_mode)
    if endpoint.exists() or endpoint.is_symlink():
        if endpoint.is_symlink() or not stat.S_ISSOCK(endpoint.lstat().st_mode):
            raise RuntimeError('unexpected_socket_path')
        endpoint.unlink()
    with server_factory(str(endpoint),Handler) as server:
        server.bridges=bridges
        os.chown(endpoint,options.socket_uid,options.socket_gid)
        os.chmod(endpoint,options.socket_mode)
        server.serve_forever()


def main(argv=None):
    serve(arguments(argv))


if __name__=='__main__': main()
