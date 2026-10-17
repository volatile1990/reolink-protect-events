"""Pure success criteria for the read-only native API/graph audit."""

VERSION = "7.3.70"
OWNER = "reolink-protect-events"
CLASSES = {"person", "vehicle", "animal"}


def _group_class_times(event, classes):
    """Fail closed on incomplete or impossible grouped classification evidence."""
    def millis(value):
        return type(value) is int and 0 < value < 2**53
    start, end = event.get("start"), event.get("end")
    identity, activation, span = event.get("groupIdentityStart"), event.get("activationMs"), event.get("groupMaxSpanMs")
    if (type(event.get("visualGroupVersion")) is not int or event["visualGroupVersion"] != 1 or
            type(event.get("sourceUnionVersion")) is not int or event["sourceUnionVersion"] != 1 or
            not all(millis(value) for value in (start, identity, activation, event.get("identityStart"))) or
            event.get("identityStart") != identity or not activation <= start <= identity or
            type(span) is not int or not 30000 <= span <= 300000 or identity >= start + span or
            (end is not None and (not millis(end) or not start < end <= start + span))):
        return None
    intervals = event.get("classIntervals")
    if (event.get("classIntervalsComplete") is not True or not classes or not set(classes) <= CLASSES or
            not isinstance(intervals, dict) or set(intervals) != set(classes)):
        return None
    times = {}
    for kind, values in intervals.items():
        if not isinstance(values, list) or not 1 <= len(values) <= 256:
            return None
        previous = start
        for item in values:
            if not isinstance(item, dict) or set(item) != {"start", "end"}:
                return None
            left, right = item["start"], item["end"]
            if (not millis(left) or previous is None or left < previous or left < start or left >= start + span or
                    (right is None and end is not None) or
                    (right is not None and (not millis(right) or not left < right <= start + span or
                                           (end is not None and right > end)))):
                return None
            previous = right
        times[kind] = values[0]["start"]
    return times


def verify_checks(report, event_id, expected_classes, camera_ids):
    """Do not mistake diagnostic fields or empty collections for passed checks."""
    event = report.get("event", {})
    camera = event.get("camera")
    graph = report.get("graph", {})
    objects = graph.get("objects", [])
    tracks = report.get("tracksApi", {})
    searches = report.get("searchFilters", [])
    cameras = report.get("cameras", [])
    selected = set(camera_ids or [camera])
    expected = sorted(set(expected_classes))
    source_types = event.get("sourceTypes")
    union = event.get("sourceUnionVersion") == 1 and isinstance(source_types, list) and bool(source_types) and set(source_types) <= {"reolink", "frigate"}
    union_origin = "mixed" if union and len(set(source_types)) > 1 else "external-model" if union and source_types == ["frigate"] else "camera"
    union_source = "reolink-and-frigate" if union_origin == "mixed" else "frigate-object-detection" if union_origin == "external-model" else "reolink-camera-ai"
    grouped = event.get("visualGroupVersion") is not None
    group_times = _group_class_times(event, expected) if grouped else None
    group_valid = not grouped or group_times is not None
    ownership = event.get("classificationOrigin") == "camera" and event.get("sourceUnionVersion") is None if not union else (
        event.get("classificationOrigin") == union_origin and event.get("source") == union_source and
        event.get("mergePolicy") == ("camera_visual_positive_overlap" if grouped else "camera_class_time_union") and event.get("objectIdentityMatched") is False)
    checks = {
        "version": report.get("protectVersion") == VERSION,
        "bootstrap": report.get("bootstrapApiStatus") == 200,
        "eventApi": report.get("eventApiStatus") == 200 and event.get("id") == event_id,
        "eventCameraScope": camera in selected and set(c.get("id") for c in cameras) == selected and len(cameras) == len(selected),
        "sourceOwnership": event.get("owner") == OWNER and event.get("schemaVersion") == 1 and ownership and group_valid and (not grouped or union),
        "truthfulSource": event.get("score") is None and event.get("confidenceAvailable") is False and event.get("spatialTrackAvailable") is False and event.get("adapterVirtualZone") is True,
        "eventClasses": bool(expected) and set(expected) <= CLASSES and event.get("type") == "smartDetectZone" and sorted(event.get("smartDetectTypes", [])) == expected and group_valid,
        "eventFilter": report.get("eventFilteredApi", {}).get("status") == 200 and report.get("eventFilteredApi", {}).get("found") is True,
        "graph": group_valid and graph.get("readOnly") == "on" and graph.get("eventRows") == 1 and graph.get("deleted") is False and
                 sorted(o.get("type", "") for o in objects) == expected and all(
                     o.get("eventId") == event_id and o.get("cameraId") == camera and o.get("detectedAt") == (group_times.get(o.get("type")) if grouped else event.get("start")) and
                     o.get("confidenceKeyPresent") is False and o.get("spatialCoordPresent") is False and o.get("adapterVirtualZone") is True for o in objects) and graph.get("spatialAreaRows") == 0,
        "tracks": tracks.get("status") == 200 and tracks.get("samples") == 0 and tracks.get("event") == event_id and tracks.get("camera") == camera and
                  len(graph.get("tracks", [])) == 1 and graph["tracks"][0].get("samples") == 0,
        "searchFilters": len(searches) == 6 and {(s.get("class"), s.get("minConfidence")) for s in searches} == {(kind, confidence) for kind in CLASSES for confidence in (30, 95)} and
                         all(s.get("status") == 200 and s.get("found") == (s.get("class") in expected) and s.get("inventedConfidencePresent") is False for s in searches),
        "cameraFeatures": bool(cameras) and all(c.get("isThirdPartyCamera") is True and c.get("hasSmartDetect") is True and
                            c.get("isPairedWithAiPort") is False and sorted(c.get("smartDetectTypes") or []) == sorted(CLASSES) and c.get("zoneIds") == [1] for c in cameras),
    }
    checks["thumbnailPaths"] = all(
        report.get(key, {}).get("status") == 200 and report[key].get("isJpeg") is True and report[key].get("bytes", 0) > 0 and
        (report[key].get("dimensions") or {}).get("width", 0) > 0 and (report[key].get("dimensions") or {}).get("height", 0) > 0
        for key in ("thumbnailApi", "timelineThumbnailApi", "timelineThumbnailExplicitApi"))
    thumbnails = graph.get("thumbnails", [])
    checks["thumbnailGraph"] = all(any((t.get("isFullfov") is full or full is None and t.get("isFullfov") is False) and t.get("bytes", 0) > 0 and
        t.get("width", 0) > 0 and t.get("height", 0) > 0 and
        (event.get("start", 0) <= t.get("timestamp", -1) <= (event.get("end") or event.get("start", 0) + (event.get("groupMaxSpanMs", 0) if grouped and group_valid else 6000))
         if union else t.get("timestamp") == event.get("start"))
        for t in thumbnails) for full in (None, True))
    return checks
