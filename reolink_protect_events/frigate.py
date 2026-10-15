"""Bounded, authenticated Frigate history polling; no video or model inference.

Frigate history has no sequence number or retention-floor proof. We therefore
keep an overlap, refresh in-progress events independently, and reject saturated
time windows instead of advancing a cursor over an unproven result limit.
"""
import ipaddress
import json
import math
import re
import time
import urllib.parse

from .http_deadline import get_bytes


LABELS = {"person": "person", "car": "vehicle", "bus": "vehicle", "truck": "vehicle",
          "motorcycle": "vehicle", "bicycle": "vehicle", "dog": "animal", "cat": "animal",
          "bird": "animal", "horse": "animal", "sheep": "animal", "cow": "animal",
          "elephant": "animal", "bear": "animal", "zebra": "animal", "giraffe": "animal"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def settings(config):
    value = config.get("frigate")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("invalid_frigate_config")
    parsed = urllib.parse.urlsplit(value.get("url", ""))
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("invalid_frigate_url")
    try:
        ipaddress.ip_address(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("invalid_frigate_url") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid_frigate_port")
    token = value.get("bearerToken")
    if not isinstance(token, str) or not 24 <= len(token) <= 512 or any(c.isspace() or ord(c) < 33 for c in token):
        raise ValueError("invalid_frigate_token")
    mapping = value.get("cameraMap")
    cameras = {item["cameraId"] for item in config["bridges"]}
    if not isinstance(mapping, dict) or not mapping or len(mapping) > 6 or any(
            not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or camera not in cameras
            for name, camera in mapping.items()) or len(set(mapping.values())) != len(mapping):
        raise ValueError("invalid_frigate_camera_map")
    result = dict(value, url=value["url"].rstrip("/"))
    for name, default, low, high in (("pollSeconds", 2, 1, 30), ("historySeconds", 300, 30, 86400),
                                    ("overlapSeconds", 30, 5, 300), ("staleSeconds", 120, 10, 600),
                                    ("finalizeSeconds", 4, 1, 30)):
        number = value.get(name, default)
        if type(number) is not int or not low <= number <= high:
            raise ValueError("invalid_frigate_" + name)
        result[name] = number
    return result


def event(value, camera, now_ms):
    """Keep only real object-event fields; arbitrary upstream data never persists."""
    if not isinstance(value, dict) or value.get("camera") != camera or not isinstance(value.get("id"), str) or not IDENTIFIER.fullmatch(value["id"]):
        raise ValueError("invalid_frigate_event_identity")
    label = value.get("label")
    if not isinstance(label, str) or len(label) > 64:
        raise ValueError("invalid_frigate_label")
    def millis(number, optional=False):
        if number is None and optional:
            return None
        if type(number) not in (int, float) or not math.isfinite(number) or not 0 < number < 0xffffffff or number * 1000 > now_ms + 300000:
            raise ValueError("invalid_frigate_event_time")
        return int(number * 1000)
    start, end = millis(value.get("start_time")), millis(value.get("end_time"), True)
    if end is not None and end < start:
        raise ValueError("invalid_frigate_event_end")
    if type(value.get("false_positive")) is not bool:
        raise ValueError("invalid_frigate_false_positive")
    data = value.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("invalid_frigate_event_data")
    object_type = data.get("type")
    if object_type is not None and (not isinstance(object_type, str) or len(object_type) > 32):
        raise ValueError("invalid_frigate_event_type")
    score = value.get("top_score")
    if score is None:
        score = data.get("top_score")
    if score is not None and (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1):
        raise ValueError("invalid_frigate_score")
    return {"id": value["id"], "camera": camera, "label": label, "start": start, "end": end,
            "type": object_type,
            "class": LABELS.get(label) if value["false_positive"] is False and object_type == "object" else None,
            "falsePositive": value["false_positive"], "topScore": score}


def poll(options, camera, cursor, active_ids, now_ms=None):
    """Return a fully checked batch; the caller commits events and cursor together."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    first = cursor is None
    watermark = now_ms - options["historySeconds"] * 1000 if first else cursor
    # Catch up in bounded chunks without discarding an old persisted watermark.
    through = min(now_ms, watermark + 60000)
    after = max(1, watermark - options["overlapSeconds"] * 1000)
    deadline, requests = time.monotonic() + 12, [0]
    found = {}
    def get(path, query=None, missing=False):
        requests[0] += 1
        remaining = deadline - time.monotonic()
        if requests[0] > 32 or remaining <= 0:
            raise TimeoutError("frigate_poll_budget")
        status, content = get_bytes(options["url"] + path + ("?" + urllib.parse.urlencode(query) if query else ""),
                                    {"Authorization": "Bearer " + options["bearerToken"]},
                                    timeout=min(4, remaining), limit=2 * 1024 * 1024)
        if status == 404 and missing:
            return None
        if status != 200:
            raise ValueError("frigate_http_status")
        return json.loads(content)
    def collect(values):
        if not isinstance(values, list) or len(values) > 200:
            raise ValueError("invalid_frigate_event_list")
        for item in values:
            parsed = event(item, camera, now_ms)
            found[parsed["id"]] = parsed
    def window(low, high, depth=0):
        # Upstream after/before are strict comparisons. One-millisecond overlap
        # on BOTH boundaries preserves events exactly on a bisection boundary.
        values = get("/api/events", {"camera": camera, "after": (low - 1) / 1000,
                     "before": (high + 1) / 1000, "limit": 200, "include_thumbnails": 0})
        if not isinstance(values, list) or len(values) > 200:
            raise ValueError("invalid_frigate_event_list")
        if len(values) == 200:
            if high - low <= 2 or depth >= 24:
                raise ValueError("frigate_history_saturated")
            middle = (low + high) // 2
            window(low, middle, depth + 1)
            window(middle, high, depth + 1)
        else:
            collect(values)
    health = get("/health")
    if not isinstance(health, dict) or health.get("healthy") is not True:
        raise ValueError("frigate_detector_unhealthy")
    window(after, through)
    # The start of a long-lived track can precede the history cursor by hours.
    # Query live tracks separately, and refresh saved live IDs to see their end.
    active = get("/api/events", {"camera": camera, "in_progress": 1, "limit": 200, "include_thumbnails": 0})
    if not isinstance(active, list) or len(active) >= 200:
        raise ValueError("frigate_active_saturated")
    collect(active)
    missing_ids = []
    for identifier in active_ids:
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError("invalid_saved_frigate_id")
        if identifier in found:
            continue
        # Always refresh: the history copy may be older than the live query.
        value = get("/api/events/" + urllib.parse.quote(identifier, safe=""), missing=True)
        if value is None:
            missing_ids.append(identifier)
        else:
            collect([value])
    return {"events": sorted(found.values(), key=lambda item: (item["start"], item["id"])),
            "cursor": through, "atMs": now_ms, "requests": requests[0], "initial": first,
            "backlogMs": max(0, now_ms - through), "missingIds": missing_ids}
