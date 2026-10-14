"""Pure success criteria for the read-only native API/graph audit."""

VERSION = "7.3.70"
OWNER = "reolink-protect-events"
CLASSES = {"person", "vehicle", "animal"}


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
    checks = {
        "version": report.get("protectVersion") == VERSION,
        "bootstrap": report.get("bootstrapApiStatus") == 200,
        "eventApi": report.get("eventApiStatus") == 200 and event.get("id") == event_id,
        "eventCameraScope": camera in selected and set(c.get("id") for c in cameras) == selected and len(cameras) == len(selected),
        "sourceOwnership": event.get("owner") == OWNER and event.get("schemaVersion") == 1 and event.get("classificationOrigin") == "camera",
        "truthfulSource": event.get("score") is None and event.get("confidenceAvailable") is False and event.get("spatialTrackAvailable") is False and event.get("adapterVirtualZone") is True,
        "eventClasses": bool(expected) and set(expected) <= CLASSES and event.get("type") == "smartDetectZone" and sorted(event.get("smartDetectTypes", [])) == expected,
        "eventFilter": report.get("eventFilteredApi", {}).get("status") == 200 and report.get("eventFilteredApi", {}).get("found") is True,
        "graph": graph.get("readOnly") == "on" and graph.get("eventRows") == 1 and graph.get("deleted") is False and
                 sorted(o.get("type", "") for o in objects) == expected and all(
                     o.get("eventId") == event_id and o.get("cameraId") == camera and o.get("detectedAt") == event.get("start") and
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
        t.get("width", 0) > 0 and t.get("height", 0) > 0 and t.get("timestamp") == event.get("start")
        for t in thumbnails) for full in (None, True))
    return checks
