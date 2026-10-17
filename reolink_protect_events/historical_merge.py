"""Exact-snapshot, single-transaction merge of one explicitly selected pair.

This is an operator migration, not an extension of the normal native writer's
class permissions. The caller must guard the live schema and coordinate the
durable journal/manual-group receipt. No recording or video table is touched.
"""
import re

from .native import OWNER, _sql_json, native_id, sql_text


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{24}", value):
        raise ValueError("Historical merge requires exact native IDs")
    return value


def _integer(value):
    if type(value) is not int or value <= 0:
        raise ValueError("Historical merge requires positive integer measurements")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError("Historical merge requires an exact MD5 snapshot")
    return value


def _literal(value):
    if value is None:
        return "NULL"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    return sql_text(value)


def build_pair_merge_sql(adapter, group_interval, before_graph):
    """Build one guarded transaction retaining the existing vehicle event ID.

    The two original events must be closed, unlocked, unfavorited and have
    exactly one native class each. Every supplied graph row is checked again
    under locks. The returned SQL intentionally is not blindly repeatable:
    the external durable operation receipt owns retry/recovery decisions.
    """
    native_sql, desired = adapter.build_interval_sql(group_interval)
    provenance = desired["metadata"]["reolinkProtectEvents"]["provenance"]
    primary = _id(desired["id"])
    camera = _id(desired["camera"])
    if (desired["smartDetectTypes"] != ["person", "vehicle"] or desired["end"] is None or
            provenance.get("visualGroupVersion") != 1 or
            provenance.get("mergePolicy") != "camera_visual_positive_overlap"):
        raise ValueError("Historical merge requires a closed two-class visual group")
    if before_graph.get("readOnly") != "on" or type(before_graph.get("favoriteCount")) is not int or before_graph["favoriteCount"] != 0:
        raise ValueError("Historical merge requires an unfavorited read-only snapshot")
    events = before_graph.get("events")
    if not isinstance(events, list) or len(events) != 2:
        raise ValueError("Historical merge requires exactly two source events")
    mapped = {}
    for event in events:
        identifier = _id(event.get("id"))
        if (identifier in mapped or event.get("camera") != camera or event.get("locked") is not False or
                event.get("deleted") is not False or event.get("types") not in (["person"], ["vehicle"])):
            raise ValueError("Historical source event scope or state is incompatible")
        if _integer(event.get("end")) <= _integer(event.get("start")):
            raise ValueError("Historical source events must have genuine closed bounds")
        _id(event.get("thumbnailId")); _id(event.get("thumbnailFullfovId"))
        if event["thumbnailId"] == event["thumbnailFullfovId"]:
            raise ValueError("Historical source events require separate preview and full-frame variants")
        _digest(event.get("metadataMd5"))
        mapped[identifier] = event
    if primary not in mapped or mapped[primary]["types"] != ["vehicle"]:
        raise ValueError("Historical merge must retain the existing vehicle identity")
    secondary, = (identifier for identifier in mapped if identifier != primary)
    if mapped[secondary]["types"] != ["person"]:
        raise ValueError("Historical merge requires one actual person event")
    left, right = min(e["start"] for e in events), max(e["end"] for e in events)
    if max(e["start"] for e in events) >= min(e["end"] for e in events):
        raise ValueError("Historical source events must overlap positively")
    if (desired["start"], desired["end"]) != (left, right):
        raise ValueError("Historical group must cover the exact source union")
    if provenance.get("groupIdentityStart") != mapped[primary]["start"]:
        raise ValueError("Historical merge cannot change the retained graph identity")
    expected_ranges = {e["types"][0]: [{"start": e["start"], "end": e["end"]}] for e in events}
    if provenance.get("classIntervals") != expected_ranges:
        raise ValueError("Historical class intervals must match both exact source events")
    thumbnails = before_graph.get("thumbnails", [])
    objects = before_graph.get("objects", [])
    tracks = before_graph.get("tracks", [])
    if not (all(isinstance(rows, list) for rows in (thumbnails, objects, tracks)) and
            len(thumbnails) == 4 and len(objects) == 2 and len(tracks) == 2):
        raise ValueError("Historical merge requires complete two-event graph snapshots")
    seen = set()
    for thumb in thumbnails:
        identifier, event_id = _id(thumb.get("id")), _id(thumb.get("eventId"))
        if identifier in seen or event_id not in mapped or thumb.get("locked") is not False:
            raise ValueError("Historical thumbnail scope or lock changed")
        seen.add(identifier)
        event = mapped[event_id]
        if identifier not in (event["thumbnailId"], event["thumbnailFullfovId"]):
            raise ValueError("Historical thumbnail is outside the selected variants")
        if ((identifier == event["thumbnailFullfovId"] and thumb.get("fullfov") is not True) or
                (identifier == event["thumbnailId"] and thumb.get("fullfov") is not None and thumb.get("fullfov") is not False)):
            raise ValueError("Historical thumbnail variant is incompatible")
        _integer(thumb.get("timestamp")); _integer(thumb.get("bytes")); _digest(thumb.get("md5"))
    for rows, table in ((objects, "object"), (tracks, "track")):
        seen = set()
        for row in rows:
            identifier, event_id = _id(row.get("id")), _id(row.get("eventId"))
            if event_id not in mapped or event_id in seen:
                raise ValueError("Historical graph snapshot contains duplicate or foreign rows")
            seen.add(event_id)
            event = mapped[event_id]
            if table == "object":
                if (row.get("type") != event["types"][0] or row.get("detectedAt") != event["start"] or
                        row.get("thumbnailId") != event["thumbnailFullfovId"]):
                    raise ValueError("Historical object evidence differs from the selected events")
            elif type(row.get("samples")) is not int or row["samples"] != 0:
                raise ValueError("Historical merge cannot erase measured track samples")
            if event_id == primary and identifier != native_id(table, event["start"], primary + (":vehicle" if table == "object" else "")):
                raise ValueError("Retained native graph IDs must stay stable")
    identifiers = ",".join(sql_text(identifier) for identifier in sorted(mapped))
    failures = []
    def require(expression):
        failures.append("IF NOT (%s) THEN RAISE EXCEPTION 'Historical merge snapshot changed'; END IF;" % expression)
    require("current_database()='unifi-protect'")
    require("(SELECT count(*) FROM events WHERE id IN (%s))=2" % identifiers)
    require('(SELECT count(*) FROM "favoriteEvents" WHERE "eventId" IN (%s))=0' % identifiers)
    for event in events:
        conditions = ["id=" + sql_text(event["id"]), 'type=\'smartDetectZone\'',
            '"cameraId"=' + sql_text(camera), "start=" + str(event["start"]), '"end"=' + str(event["end"]),
            '"smartDetectTypes"::jsonb=' + _sql_json(event["types"], "jsonb"),
            "locked IS FALSE", '"deletedAt" IS NULL',
            '"thumbnailId"=' + sql_text(event["thumbnailId"]), '"thumbnailFullfovId"=' + sql_text(event["thumbnailFullfovId"]),
            "md5(metadata::text)=" + sql_text(event["metadataMd5"]),
            "metadata::jsonb->'reolinkProtectEvents'->>'owner'=" + sql_text(OWNER)]
        require("EXISTS (SELECT 1 FROM events WHERE " + " AND ".join(conditions) + ")")
    require('(SELECT count(*) FROM thumbnails WHERE "eventId" IN (%s))=4' % identifiers)
    for thumb in thumbnails:
        require('EXISTS (SELECT 1 FROM thumbnails WHERE id=%s AND "eventId"=%s AND "cameraId"=%s '
            'AND timestamp=%d AND "isFullfov" IS NOT DISTINCT FROM %s AND locked IS FALSE '
            'AND octet_length(content)=%d AND md5(content)=%s)' %
            (sql_text(thumb["id"]), sql_text(thumb["eventId"]), sql_text(camera), thumb["timestamp"],
             _literal(thumb.get("fullfov")), thumb["bytes"], sql_text(thumb["md5"])))
    require('(SELECT count(*) FROM "smartDetectObjects" WHERE "eventId" IN (%s))=2' % identifiers)
    for obj in objects:
        require('EXISTS (SELECT 1 FROM "smartDetectObjects" WHERE id=%s AND "eventId"=%s AND "cameraId"=%s '
                'AND type=%s AND "detectedAt"=%d AND "thumbnailId"=%s '
                'AND metadata->\'reolinkProtectEvents\'->>\'owner\'=%s)' %
                (sql_text(obj["id"]), sql_text(obj["eventId"]), sql_text(camera), sql_text(obj["type"]),
                 obj["detectedAt"], sql_text(obj["thumbnailId"]), sql_text(OWNER)))
    require('(SELECT count(*) FROM "smartDetectTracks" WHERE "eventId" IN (%s))=2' % identifiers)
    for track in tracks:
        require('EXISTS (SELECT 1 FROM "smartDetectTracks" WHERE id=%s AND "eventId"=%s '
                'AND "cameraId"=%s AND json_array_length(payload)=0)' %
                (sql_text(track["id"]), sql_text(track["eventId"]), sql_text(camera)))
    advisory_sql = '\n'.join("PERFORM pg_advisory_xact_lock(hashtextextended(%s,0));" % sql_text(OWNER + ":" + identifier)
                             for identifier in sorted(mapped))
    lock_sql = '\n'.join('PERFORM id FROM %s WHERE %s IN (%s) ORDER BY id FOR UPDATE;' %
        (table, field, identifiers) for table, field in (("events", "id"), ("thumbnails", '"eventId"'),
        ('"smartDetectObjects"', '"eventId"'), ('"smartDetectTracks"', '"eventId"')))
    if not native_sql.startswith("BEGIN;\n") or not native_sql.endswith("COMMIT;\n"):
        raise ValueError("Native transaction format changed")
    native_body = native_sql[len("BEGIN;\n"):-len("COMMIT;\n")]
    car_object = native_id("object", provenance["groupIdentityStart"], primary + ":vehicle")
    car_track = native_id("track", provenance["groupIdentityStart"], primary)
    person_object = native_id("object", provenance["groupIdentityStart"], primary + ":person")
    return ("BEGIN;\nSET LOCAL statement_timeout='10s';\nSET LOCAL lock_timeout='2s';\n"
        "DO $historical_merge$ BEGIN\n" + advisory_sql + "\n" + lock_sql + "\n" + "\n".join(failures) + "\nEND $historical_merge$;\n"
        'UPDATE events SET "smartDetectTypes"=%s,metadata=jsonb_set(metadata::jsonb,\'{reolinkProtectEvents,provenance}\',%s,true)::json WHERE id=%s;\n' %
        (_sql_json(desired["smartDetectTypes"]), _sql_json(provenance, "jsonb"), sql_text(primary)) + native_body +
        "DO $historical_merge$ BEGIN\nIF (SELECT count(*) FROM \"smartDetectObjects\" WHERE \"eventId\"=%s)<>2 OR "
        "NOT EXISTS (SELECT 1 FROM \"smartDetectObjects\" WHERE id=%s AND \"eventId\"=%s AND type='vehicle') OR "
        "NOT EXISTS (SELECT 1 FROM \"smartDetectObjects\" WHERE id=%s AND \"eventId\"=%s AND type='person') OR "
        "NOT EXISTS (SELECT 1 FROM \"smartDetectTracks\" WHERE id=%s AND \"eventId\"=%s) "
        "THEN RAISE EXCEPTION 'Historical merge graph verification failed'; END IF;\nEND $historical_merge$;\n" %
        (sql_text(primary), sql_text(car_object), sql_text(primary), sql_text(person_object), sql_text(primary), sql_text(car_track), sql_text(primary)) +
        'DELETE FROM thumbnails WHERE "eventId"=%s;\nDELETE FROM events WHERE id=%s;\n' % (sql_text(secondary), sql_text(secondary)) +
        "SELECT json_build_object('id',id,'removed',%s,'classes',\"smartDetectTypes\",'start',start,'end',\"end\","
        "'thumbnailId',\"thumbnailId\",'thumbnailFullfovId',\"thumbnailFullfovId\") FROM events WHERE id=%s;\nCOMMIT;\n" %
        (sql_text(secondary), sql_text(primary)))
