"""Real PostgreSQL transactions. Skipped unless an isolated executor is supplied.

The runner creates a disposable database with a required marker. Even an
accidental production psql command cannot load this fixture without that marker.
"""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events.native import NativeAdapter, NativeError, RetiredEventError, SchemaError, Thumbnail, native_id
from reolink_protect_events.features import CameraFeatures, INTEGRATION_ZONE
from reolink_protect_events.historical_merge import build_pair_merge_sql

EXECUTOR = None  # Set only by tools/test_postgres.py, or use explicit JSON argv.
MARKER = "reolink-protect-events isolated integration fixture"
START = 1791586947512
CAMERA = "111111111111111111111111"
JPEG = bytes.fromhex("ffd8ffc00011080018002003011100021100031100ffda0008010100003f0000ffd9")


def execute(sql):
    if EXECUTOR is not None:
        return EXECUTOR(sql)
    command = json.loads(os.environ["REOLINK_TEST_PSQL_COMMAND"])
    if not isinstance(command, list) or not command or any(not isinstance(v, str) for v in command):
        raise ValueError("Explicit psql argv required")
    result = subprocess.run(command, input=sql, encoding="utf-8", capture_output=True, timeout=20, shell=False)
    if result.returncode:
        if "reolink-protect-events:retired" in result.stderr:
            raise RetiredEventError("Synthetic event was retired")
        raise NativeError("Isolated PostgreSQL command failed")
    return result.stdout


def value(sql):
    for line in reversed(execute(sql).splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    raise AssertionError("PostgreSQL returned no JSON")


def interval(index=1, **changes):
    result = {"eventId": "6ac9700311450300%08x" % index, "cameraId": CAMERA,
              "start": START + index * 1000, "end": None, "classes": ["person"],
              "provenance": {"adapter": "reolink-protect-events", "seq": index, "rawAiTypes": ["people"]}}
    result.update(changes)
    return result


def visual_group(classes=("vehicle",), end=None):
    row = interval(classes=list(classes), end=end)
    first = row["start"]
    row["provenance"] = {"sourceUnionVersion": 1, "identityStart": first,
        "sourceTypes": ["reolink"], "visualGroupVersion": 1, "groupIdentityStart": first,
        "activationMs": first - 1000, "groupMaxSpanMs": 120000,
        "classIntervalsComplete": True,
        "classIntervals": {kind: [{"start": first + (2000 if kind == "person" else 0), "end": end}]
                           for kind in classes}}
    return row


def adapter():
    return NativeAdapter(execute=execute, version_reader=lambda: "7.3.70")


@unittest.skipUnless(EXECUTOR is not None or "REOLINK_TEST_PSQL_COMMAND" in os.environ,
                     "Use tools/test_postgres.py to create an isolated PostgreSQL fixture")
class PostgreSqlIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        marker = value("SELECT to_json(shobj_description(oid,'pg_database')) FROM pg_database WHERE datname=current_database();")
        if marker != MARKER:
            raise RuntimeError("Refusing PostgreSQL tests outside their marked isolated database")

    def setUp(self):
        execute((Path(__file__).parent / "fixtures" / "protect_schema.sql").read_text(encoding="utf-8"))
        self.db = adapter()

    def counts(self):
        return value('SELECT json_build_object(\'events\',(SELECT count(*) FROM events),\'objects\',(SELECT count(*) FROM "smartDetectObjects"),'
                     '\'tracks\',(SELECT count(*) FROM "smartDetectTracks"),\'detectionLabels\',(SELECT count(*) FROM "detectionLabels"),'
                     '\'thumbnails\',(SELECT count(*) FROM thumbnails),\'labels\',(SELECT count(*) FROM labels));')

    def historical_pair_fixture(self):
        execute('CREATE TABLE "favoriteEvents" ("eventId" varchar REFERENCES events(id) ON DELETE CASCADE);')
        car = interval(1, classes=["vehicle"], end=START + 20000)
        person = interval(2, classes=["person"], end=START + 16000)
        self.db.upsert_interval(car, Thumbnail(JPEG, car["start"]))
        self.db.upsert_interval(person, Thumbnail(JPEG, person["start"]))
        graph = value('BEGIN READ ONLY; SELECT json_build_object(\'readOnly\',current_setting(\'transaction_read_only\'),'
            '\'favoriteCount\',(SELECT count(*) FROM "favoriteEvents"),'
            '\'events\',(SELECT json_agg(json_build_object(\'id\',id,\'camera\',"cameraId",\'start\',start,\'end\',"end",'
            '\'types\',"smartDetectTypes",\'locked\',locked,\'deleted\',"deletedAt" IS NOT NULL,\'thumbnailId\',"thumbnailId",'
            '\'thumbnailFullfovId\',"thumbnailFullfovId",\'metadataMd5\',md5(metadata::text))) FROM events),'
            '\'thumbnails\',(SELECT json_agg(json_build_object(\'id\',id,\'eventId\',"eventId",\'timestamp\',timestamp,'
            '\'fullfov\',"isFullfov",\'locked\',locked,\'bytes\',octet_length(content),\'md5\',md5(content))) FROM thumbnails),'
            '\'objects\',(SELECT json_agg(json_build_object(\'id\',id,\'eventId\',"eventId",\'type\',type,'
            '\'detectedAt\',"detectedAt",\'thumbnailId\',"thumbnailId")) FROM "smartDetectObjects"),'
            '\'tracks\',(SELECT json_agg(json_build_object(\'id\',id,\'eventId\',"eventId",\'samples\',json_array_length(payload))) '
            'FROM "smartDetectTracks")); ROLLBACK;')
        group = copy.deepcopy(car)
        group.update(classes=["person", "vehicle"], deliveredRevision=1)
        group["provenance"] = {"sourceUnionVersion": 1, "identityStart": car["start"],
            "sourceTypes": ["reolink"], "visualGroupVersion": 1, "groupIdentityStart": car["start"],
            "activationMs": car["start"], "groupMaxSpanMs": 120000, "classIntervalsComplete": True,
            "mergePolicy": "camera_visual_positive_overlap", "objectIdentityMatched": False,
            "classIntervals": {kind: [{"start": row["start"], "end": row["end"]}]
                               for kind, row in (("vehicle", car), ("person", person))}}
        return car, person, group, graph

    def test_historical_pair_merge_is_atomic_and_retains_original_car_graph_and_pixels(self):
        car, person, group, graph = self.historical_pair_fixture()
        result = value(build_pair_merge_sql(self.db, group, graph))
        self.assertEqual(result["id"], car["eventId"])
        self.assertEqual(result["removed"], person["eventId"])
        self.assertEqual(result["classes"], ["person", "vehicle"])
        self.assertEqual(self.counts()["events"], 1)
        self.assertEqual(self.counts()["objects"], 2)
        self.assertEqual(self.counts()["tracks"], 1)
        self.assertEqual(self.counts()["thumbnails"], 2)
        after = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id) FROM "smartDetectObjects"),'
            '\'tracks\',(SELECT json_agg(id) FROM "smartDetectTracks"),'
            '\'images\',(SELECT json_agg(json_build_object(\'id\',id,\'md5\',md5(content),\'locked\',locked)) FROM thumbnails),'
            '\'personTime\',(SELECT "detectedAt" FROM "smartDetectObjects" WHERE type=\'person\'));')
        self.assertIn(next(o["id"] for o in graph["objects"] if o["eventId"] == car["eventId"]), after["objects"])
        self.assertEqual(after["tracks"], [next(t["id"] for t in graph["tracks"] if t["eventId"] == car["eventId"])])
        self.assertEqual({t["id"]: (t["md5"], t["locked"]) for t in after["images"]},
            {t["id"]: (t["md5"], t["locked"]) for t in graph["thumbnails"] if t["eventId"] == car["eventId"]})
        self.assertEqual(after["personTime"], person["start"])
        native = self.db.upsert_interval(group)
        self.assertEqual(native["smartDetectTypes"], ["person", "vehicle"])
        self.assertEqual([t["type"] for t in native["metadata"]["detectedThumbnails"]], ["vehicle"])

    def test_historical_pair_merge_refuses_new_favorite_without_modifying_anything(self):
        car, person, group, graph = self.historical_pair_fixture()
        sql = build_pair_merge_sql(self.db, group, graph)
        execute('INSERT INTO "favoriteEvents" ("eventId") VALUES (\'' + person["eventId"] + '\');')
        before = value('SELECT json_build_object(\'events\',(SELECT json_agg(row_to_json(e) ORDER BY id) FROM events e),'
            '\'thumbnails\',(SELECT json_agg(row_to_json(t) ORDER BY id) FROM thumbnails t));')
        with self.assertRaises(NativeError):
            execute(sql)
        after = value('SELECT json_build_object(\'events\',(SELECT json_agg(row_to_json(e) ORDER BY id) FROM events e),'
            '\'thumbnails\',(SELECT json_agg(row_to_json(t) ORDER BY id) FROM thumbnails t));')
        self.assertEqual(after, before)
        self.assertEqual(value('SELECT to_json(count(*)) FROM "favoriteEvents";'), 1)

    def test_historical_pair_merge_refuses_changed_pixel_snapshot_and_rolls_back(self):
        car, person, group, graph = self.historical_pair_fixture()
        sql = build_pair_merge_sql(self.db, group, graph)
        execute('UPDATE thumbnails SET content=content || decode(\'00\',\'hex\') WHERE "eventId"=\'' + car["eventId"] + '\';')
        before = value('SELECT json_build_object(\'events\',(SELECT json_agg(row_to_json(e) ORDER BY id) FROM events e),'
            '\'thumbnails\',(SELECT json_agg(row_to_json(t) ORDER BY id) FROM thumbnails t));')
        with self.assertRaises(NativeError):
            execute(sql)
        after = value('SELECT json_build_object(\'events\',(SELECT json_agg(row_to_json(e) ORDER BY id) FROM events e),'
            '\'thumbnails\',(SELECT json_agg(row_to_json(t) ORDER BY id) FROM thumbnails t));')
        self.assertEqual(after, before)

    def test_real_schema_graph_and_duplicate_retry(self):
        self.assertTrue(self.db.guard_schema()["schemaVerified"])
        row = interval(classes=["vehicle", "person", "animal"])
        first = self.db.upsert_interval(row)
        self.assertEqual(first, self.db.upsert_interval(copy.deepcopy(row)))
        self.assertEqual(self.counts(), {"events": 1, "objects": 3, "tracks": 1, "detectionLabels": 4, "thumbnails": 0, "labels": 6})
        truths = value('SELECT json_build_object(\'scores\',(SELECT count(*) FROM events WHERE score IS NOT NULL),'
                       '\'objectTypes\',(SELECT json_agg(type ORDER BY type) FROM "smartDetectObjects"),'
                       '\'payload\',(SELECT payload FROM "smartDetectTracks"),'
                       '\'invented\',(SELECT count(*) FROM "smartDetectObjects" WHERE metadata::text LIKE \'%"confidence":%\' OR attributes::text LIKE \'%"coord":%\'));')
        self.assertEqual(truths, {"scores": 0, "objectTypes": ["animal", "person", "vehicle"], "payload": [], "invented": 0})

    def test_visual_group_live_expansion_preserves_pixels_favorite_and_both_searches(self):
        row = visual_group()
        first = row["start"]
        original = self.db.upsert_interval(row, Thumbnail(JPEG, first + 100))
        execute("UPDATE events SET locked=true; UPDATE thumbnails SET locked=true;")
        before = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id) FROM "smartDetectObjects"),'
                       '\'tracks\',(SELECT json_agg(id) FROM "smartDetectTracks"),'
                       '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails),'
                       '\'preview\',(SELECT "thumbnailId" FROM events));')
        expanded = visual_group(("vehicle", "person"))
        expanded["deliveredRevision"] = 1
        event = self.db.upsert_interval(expanded)
        self.assertEqual(event["smartDetectTypes"], ["person", "vehicle"])
        self.assertEqual(event, self.db.upsert_interval(copy.deepcopy(expanded)))
        self.assertEqual(self.counts()["events"], 1)
        self.assertEqual(self.counts()["objects"], 2)
        self.assertEqual(self.counts()["thumbnails"], 2)
        actual = value('SELECT json_build_object(\'times\',(SELECT json_object_agg(type,"detectedAt") FROM "smartDetectObjects"),'
                       '\'tracks\',(SELECT json_agg(id) FROM "smartDetectTracks"),'
                       '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails),'
                       '\'preview\',(SELECT "thumbnailId" FROM events),\'locked\',(SELECT locked FROM events),'
                       '\'pixelTimes\',(SELECT json_agg(timestamp ORDER BY id) FROM thumbnails),'
                       '\'bothClasses\',(SELECT "smartDetectTypes"::jsonb ? \'person\' AND "smartDetectTypes"::jsonb ? \'vehicle\' FROM events));')
        self.assertEqual(actual["times"], {"vehicle": first, "person": first + 2000})
        self.assertEqual(actual["tracks"], before["tracks"])
        self.assertEqual(actual["thumbnails"], before["thumbnails"])
        self.assertEqual(actual["preview"], before["preview"])
        self.assertEqual(actual["pixelTimes"], [first + 100, first + 100])
        self.assertTrue(actual["locked"])
        self.assertTrue(actual["bothClasses"])
        thumbs = {thumb["type"]: thumb for thumb in event["metadata"]["detectedThumbnails"]}
        self.assertEqual(set(thumbs), {"vehicle"})
        self.assertEqual({thumb["clockBestWall"] for thumb in thumbs.values()}, {first + 100})
        self.assertEqual(thumbs["vehicle"], original["metadata"]["detectedThumbnails"][0])
        self.assertIsNone(value('SELECT json_build_object(\'thumbnail\',"thumbnailId") FROM "smartDetectObjects" WHERE type=\'person\';')["thumbnail"])
        labels = value('SELECT json_object_agg(COALESCE(o.type,\'event\'),x.names) FROM "detectionLabels" dl '
            'LEFT JOIN "smartDetectObjects" o ON o.id=dl."objectId" CROSS JOIN LATERAL '
            '(SELECT json_agg(l.name ORDER BY l.name) names FROM labels l WHERE l.lid=ANY(dl.labels)) x;')
        for kind in ("person", "vehicle"):
            self.assertIn("smartDetectType:" + kind, labels["event"])
            self.assertIn("smartDetectType:" + kind, labels[kind])
        self.assertNotIn("smartDetectType:vehicle", labels["person"])
        self.assertNotIn("smartDetectType:person", labels["vehicle"])
        self.assertEqual(event["metadata"]["reolinkProtectEvents"]["provenance"]["classIntervals"],
                         expanded["provenance"]["classIntervals"])
        closed = visual_group(("vehicle", "person"), end=first + 5000)
        closed["deliveredRevision"] = 1
        self.assertEqual(self.db.upsert_interval(closed)["end"], first + 5000)
        self.assertTrue(value('SELECT to_json(bool_and(locked)) FROM thumbnails;'))

    def test_visual_group_protocol_cannot_promote_downgrade_remove_or_change_identity(self):
        group = visual_group(("vehicle", "person"))
        self.db.upsert_interval(group, Thumbnail(JPEG, group["start"]))
        before = self.counts()
        removal = visual_group()
        downgrade = copy.deepcopy(group)
        downgrade["provenance"] = {"sourceUnionVersion": 1, "identityStart": group["start"], "sourceTypes": ["reolink"]}
        candidates = [removal, downgrade, dict(group, cameraId="222222222222222222222222")]
        for field, amount in (("identityStart", 1), ("activationMs", -1), ("groupMaxSpanMs", 1000)):
            changed = copy.deepcopy(group)
            changed["provenance"][field] += amount
            if field == "identityStart":
                changed["provenance"]["groupIdentityStart"] += amount
            candidates.append(changed)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(NativeError):
                self.db.upsert_interval(candidate, Thumbnail(JPEG, group["start"]))
            self.assertEqual(self.counts(), before)
        ordinary = interval(2, classes=["vehicle"])
        self.db.upsert_interval(ordinary)
        with self.assertRaises(NativeError):
            self.db.upsert_interval(dict(ordinary, classes=["vehicle", "person"]))
        promoted = visual_group()
        promoted.update(eventId=ordinary["eventId"], start=ordinary["start"])
        for field in ("identityStart", "groupIdentityStart"):
            promoted["provenance"][field] = ordinary["start"]
        promoted["provenance"]["classIntervals"]["vehicle"][0]["start"] = ordinary["start"]
        before = self.counts()
        with self.assertRaises(NativeError):
            self.db.upsert_interval(promoted)
        self.assertEqual(self.counts(), before)

    def test_visual_group_late_clear_removes_only_invalid_class_image_association(self):
        row = visual_group(("person", "vehicle"))
        first = row["start"]
        initial = self.db.upsert_interval(row, Thumbnail(JPEG, first + 5000))
        self.assertEqual({thumb["type"] for thumb in initial["metadata"]["detectedThumbnails"]}, {"person", "vehicle"})
        execute("UPDATE events SET locked=true; UPDATE thumbnails SET locked=true;")
        picture_sql = ('SELECT json_build_object(\'event\',(SELECT json_build_object(\'preview\',"thumbnailId",'
            '\'full\',"thumbnailFullfovId",\'locked\',locked) FROM events),'
            '\'images\',(SELECT json_agg(json_build_object(\'id\',id,\'bytes\',encode(content,\'hex\'),'
            '\'time\',timestamp,\'locked\',locked) ORDER BY id) FROM thumbnails));')
        before = value(picture_sql)
        counts = self.counts()
        cleared = visual_group(("person", "vehicle"), end=first + 8000)
        cleared["deliveredRevision"] = 1
        cleared["provenance"]["classIntervals"]["person"][0]["end"] = first + 4000
        event = self.db.upsert_interval(cleared)
        self.assertEqual(event["smartDetectTypes"], ["person", "vehicle"])
        self.assertEqual([thumb["type"] for thumb in event["metadata"]["detectedThumbnails"]], ["vehicle"])
        objects = value('SELECT json_object_agg(type,json_build_object(\'time\',"detectedAt",\'image\',"thumbnailId")) '
                        'FROM "smartDetectObjects";')
        self.assertEqual(objects["person"]["time"], first + 2000)
        self.assertIsNone(objects["person"]["image"])
        self.assertIsNotNone(objects["vehicle"]["image"])
        self.assertEqual(value(picture_sql), before)
        self.assertEqual(self.counts(), counts)
        for kind in ("person", "vehicle"):
            matches = value('SELECT to_json(count(*)) FROM "detectionLabels" dl JOIN labels l '
                'ON l.lid=ANY(dl.labels) WHERE l.name=\'smartDetectType:' + kind + '\';')
            self.assertEqual(matches, 2)  # Event search and the genuine class object.
        self.assertEqual(event, self.db.upsert_interval(cleared))

    def test_visual_group_retired_expansion_and_later_thumbnail_do_not_resurrect(self):
        row = visual_group()
        self.db.upsert_interval(row)
        expanded = visual_group(("vehicle", "person"))
        expanded["deliveredRevision"] = 1
        before_image = self.db.upsert_interval(expanded)
        self.assertEqual(before_image["metadata"]["detectedThumbnails"], [])
        with_image = self.db.upsert_interval(expanded, Thumbnail(JPEG, row["start"] + 2500))
        self.assertEqual(len(with_image["metadata"]["detectedThumbnails"]), 2)
        self.assertEqual(value('SELECT to_json(count(*)) FROM "smartDetectObjects" WHERE "thumbnailId" IS NOT NULL;'), 2)
        execute('UPDATE events SET "deletedAt"=CURRENT_TIMESTAMP;')
        before = self.counts()
        with self.assertRaises(RetiredEventError):
            self.db.upsert_interval(expanded)
        self.assertEqual(self.counts(), before)
        execute('DELETE FROM events;')
        before = self.counts()
        with self.assertRaises(RetiredEventError):
            self.db.upsert_interval(expanded, Thumbnail(JPEG, row["start"]))
        self.assertEqual(self.counts(), before)

    def test_audio_event_search_graph_retry_and_retirement(self):
        row = interval(classes=["babyCry"])
        row["provenance"].update(sourceUnionVersion=1, identityStart=row["start"],
            sourceTypes=["frigate", "reolink"], mergePolicy="camera_class_time_union", objectIdentityMatched=False)
        event = self.db.upsert_interval(row, Thumbnail(JPEG, row["start"]))
        self.assertEqual(event["type"], "smartAudioDetect")
        self.assertEqual(event["smartDetectTypes"], ["alrmBabyCry"])
        self.assertFalse(event["metadata"]["reolinkProtectEvents"]["adapterVirtualZone"])
        self.assertEqual(event["metadata"]["zonesStatus"], {})
        self.assertEqual(self.counts(), {"events": 1, "objects": 0, "tracks": 0,
                                      "detectionLabels": 1, "thumbnails": 2, "labels": 3})
        labels = value('SELECT json_agg(l.name ORDER BY l.name) FROM "detectionLabels" dl JOIN labels l ON l.lid=ANY(dl.labels);')
        self.assertEqual(labels, ["camera:" + CAMERA, "eventType:smartAudioDetect", "smartDetectType:alrmBabyCry"])
        self.assertTrue(value('SELECT to_json("smartDetectTypes"::jsonb ? \'alrmBabyCry\') FROM events;'))
        execute("UPDATE events SET locked=true;")
        closed = dict(row, end=row["start"] + 4000, deliveredRevision=1)
        again = self.db.upsert_interval(closed)
        self.assertEqual(again["end"], closed["end"])
        self.assertEqual(again["metadata"]["detectedThumbnails"], event["metadata"]["detectedThumbnails"])
        self.assertTrue(value("SELECT to_json(locked) FROM events;"))
        self.assertEqual(self.counts()["objects"], 0)
        execute("DELETE FROM events;")
        with self.assertRaises(RetiredEventError):
            self.db.upsert_interval(closed)

    def test_late_details_enrich_stable_objects_and_correct_search_labels(self):
        row = interval(classes=["vehicle", "animal"])
        self.db.upsert_interval(row, Thumbnail(JPEG, row["start"]))
        before = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectObjects"),'
                       '\'tracks\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectTracks"),'
                       '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails));')
        first_thumb = value("SELECT to_json(metadata::jsonb->'detectedThumbnails'->0->>'croppedId') FROM events;")
        updated = copy.deepcopy(row)
        updated["deliveredRevision"] = 1
        updated["provenance"]["classificationDetails"] = {"vehicleType": ["bike"], "animalType": ["cat"]}
        result = self.db.upsert_interval(updated)
        attrs = value('SELECT json_object_agg(type,attributes) FROM "smartDetectObjects";')
        self.assertEqual(attrs["vehicle"]["vehicleType"], {"val": "bike"})
        self.assertEqual(attrs["animal"]["species"], {"val": "cat"})
        thumbs = {thumb["type"]: thumb for thumb in result["metadata"]["detectedThumbnails"]}
        self.assertEqual(thumbs["vehicle"]["attributes"]["vehicleType"], {"val": "bike"})
        self.assertEqual(thumbs["animal"]["attributes"]["species"], {"val": "cat"})
        self.assertEqual(first_thumb, result["metadata"]["detectedThumbnails"][0]["croppedId"])
        labels = value('SELECT json_object_agg(COALESCE(o.type,\'event\'),x.names) FROM "detectionLabels" dl '
            'LEFT JOIN "smartDetectObjects" o ON o.id=dl."objectId" CROSS JOIN LATERAL '
            '(SELECT json_agg(l.name ORDER BY l.name) names FROM labels l WHERE l.lid=ANY(dl.labels)) x;')
        self.assertIn("vehicleType:bike", labels["event"])
        self.assertIn("species:cat", labels["event"])
        self.assertIn("vehicleType:bike", labels["vehicle"])
        self.assertNotIn("species:cat", labels["vehicle"])
        self.assertIn("species:cat", labels["animal"])
        self.assertNotIn("vehicleType:bike", labels["animal"])
        updated["provenance"]["classificationDetails"] = {"vehicleType": ["bike", "bus"], "animalType": ["cat", "dog"]}
        result = self.db.upsert_interval(updated)
        attrs = value('SELECT json_object_agg(type,attributes) FROM "smartDetectObjects";')
        self.assertNotIn("vehicleType", attrs["vehicle"])
        self.assertNotIn("species", attrs["animal"])
        for thumb in result["metadata"]["detectedThumbnails"]:
            self.assertNotIn("vehicleType", thumb["attributes"])
            self.assertNotIn("species", thumb["attributes"])
        after = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectObjects"),'
                      '\'tracks\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectTracks"),'
                      '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails));')
        self.assertEqual(before, after)
        self.assertEqual(self.counts()["objects"], 2)

    def test_thumbnail_variants_and_favorites_are_preserved(self):
        row = interval(); thumbnail = Thumbnail(JPEG, row["start"])
        self.db.upsert_interval(row, thumbnail)
        execute("UPDATE events SET locked=true; UPDATE thumbnails SET locked=true;")
        closed = dict(row, end=row["start"] + 5000, deliveredRevision=1)
        self.db.upsert_interval(closed, thumbnail)
        replay = self.db.upsert_interval(row, thumbnail)
        self.assertEqual(replay["end"], closed["end"])
        self.assertEqual(replay["metadata"]["zonesStatus"], {"1": {"status": "leave"}})
        picture = value('SELECT json_build_object(\'count\',count(*),\'full\',count(*) FILTER (WHERE "isFullfov" IS TRUE),'
                        '\'preview\',count(*) FILTER (WHERE "isFullfov" IS NULL OR "isFullfov" IS FALSE),'
                        '\'favorites\',bool_and(locked),\'sameBytes\',bool_and(content=decode(\'' + JPEG.hex() + "','hex'))) FROM thumbnails;")
        self.assertEqual(picture, {"count": 2, "full": 1, "preview": 1, "favorites": True, "sameBytes": True})
        self.assertTrue(value("SELECT to_json(locked) FROM events;"))

    def test_union_late_start_end_correction_retains_all_graph_ids_and_favorite(self):
        row = interval()
        identity = row["start"]
        row["provenance"] = {"sourceUnionVersion": 1, "identityStart": identity,
                             "sourceTypes": ["reolink"], "mergePolicy": "camera_class_time_union",
                             "objectIdentityMatched": False}
        self.db.upsert_interval(row, Thumbnail(JPEG, identity))
        execute("UPDATE events SET locked=true;")
        before_ids = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectObjects"),'
                           '\'tracks\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectTracks"),'
                           '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails));')
        changed = copy.deepcopy(row)
        changed.update(start=identity - 2000, end=identity + 5000, deliveredRevision=1)
        changed["provenance"]["sourceTypes"] = ["frigate", "reolink"]
        result = self.db.upsert_interval(changed, Thumbnail(JPEG, identity))
        self.assertEqual((result["start"], result["end"]), (identity - 2000, identity + 5000))
        self.assertEqual(result["metadata"]["source"], "reolink-and-frigate")
        self.assertEqual(result["metadata"]["reolinkProtectEvents"]["classificationOrigin"], "mixed")
        after_ids = value('SELECT json_build_object(\'objects\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectObjects"),'
                          '\'tracks\',(SELECT json_agg(id ORDER BY id) FROM "smartDetectTracks"),'
                          '\'thumbnails\',(SELECT json_agg(id ORDER BY id) FROM thumbnails));')
        self.assertEqual(before_ids, after_ids)
        self.assertEqual(self.counts()["objects"], 1)
        self.assertTrue(value("SELECT to_json(locked) FROM events;"))
        self.assertEqual(value('SELECT to_json("detectedAt") FROM "smartDetectObjects";'), changed["start"])
        reopened = self.db.upsert_interval(dict(changed, end=None))
        self.assertIsNone(reopened["end"])
        self.assertEqual(reopened["metadata"]["zonesStatus"]["1"]["status"], "enter")
        incompatible = copy.deepcopy(changed)
        incompatible["provenance"]["identityStart"] += 1000
        with self.assertRaises(NativeError):
            self.db.upsert_interval(incompatible)
        execute("DELETE FROM events WHERE id='" + row["eventId"] + "';")
        with self.assertRaises(RetiredEventError):
            self.db.upsert_interval(changed)

    def test_legacy_activation_union_keeps_existing_object_identity(self):
        row = interval()
        self.db.upsert_interval(row)
        before = value('SELECT to_json(id) FROM "smartDetectObjects";')
        migrated = copy.deepcopy(row)
        migrated.update(start=row["start"] - 1000, end=row["start"] + 2000, deliveredRevision=1)
        migrated["provenance"].update(sourceUnionVersion=1, identityStart=row["start"],
                                      sourceTypes=["frigate", "reolink"], mergePolicy="camera_class_time_union",
                                      objectIdentityMatched=False)
        self.db.upsert_interval(migrated)
        self.assertEqual(self.counts()["objects"], 1)
        self.assertEqual(value('SELECT to_json(id) FROM "smartDetectObjects";'), before)

    def test_preview_repair_changes_only_missing_preview(self):
        row = interval(); self.db.upsert_interval(row, Thumbnail(JPEG, row["start"]))
        full_id = native_id("thumbnail", row["start"], row["eventId"])
        preview_id = native_id("preview-thumbnail", row["start"], row["eventId"])
        execute("UPDATE events SET locked=true,\"thumbnailId\"='" + full_id + "'; DELETE FROM thumbnails WHERE id='" + preview_id + "';")
        before = value("SELECT row_to_json(events) FROM events;")
        candidates = self.db.preview_repair_candidates()
        self.assertEqual(len(candidates), 1)
        self.assertIsNotNone(self.db.repair_preview_thumbnail(candidates[0]))
        after = value("SELECT row_to_json(events) FROM events;")
        for field in ("thumbnailId", "updatedAt"):
            before.pop(field); after.pop(field)
        self.assertEqual(before, after)
        self.assertEqual(self.counts()["thumbnails"], 2)
        self.assertTrue(value("SELECT to_json(locked) FROM thumbnails WHERE id='" + preview_id + "';"))

    def test_retired_soft_and_hard_deleted_rows_do_not_resurrect(self):
        for soft in (False, True):
            row = interval(1 if soft else 2); self.db.upsert_interval(row)
            if soft:
                execute("UPDATE events SET \"deletedAt\"=CURRENT_TIMESTAMP WHERE id='" + row["eventId"] + "';")
            else:
                execute("DELETE FROM events WHERE id='" + row["eventId"] + "';")
            before = self.counts()
            with self.assertRaises(RetiredEventError):
                self.db.upsert_interval(dict(row, deliveredRevision=1), Thumbnail(JPEG, row["start"]))
            self.assertEqual(self.counts(), before)

    def test_identity_collision_rolls_back_every_graph_write(self):
        row = interval(); self.db.upsert_interval(row)
        before = self.counts()
        with self.assertRaises(NativeError):
            self.db.upsert_interval(dict(row, cameraId="222222222222222222222222"), Thumbnail(JPEG, row["start"]))
        self.assertEqual(self.counts(), before)
        # Force a SQL error after INSERT statements: the transaction must undo
        # the event, thumbnails, labels, objects and track together.
        next_row = interval(2); sql, _ = self.db.build_interval_sql(next_row, Thumbnail(JPEG, next_row["start"]))
        with self.assertRaises(NativeError):
            execute(sql.replace("COMMIT;", "SELECT 1/0; COMMIT;"))
        self.assertEqual(self.counts(), before)

    def test_concurrent_upserts_and_retention_lock(self):
        row = interval()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: adapter().upsert_interval(row, Thumbnail(JPEG, row["start"])), range(4)))
        self.assertTrue(all(event["id"] == row["eventId"] for event in results))
        self.assertEqual(self.counts()["objects"], 1)
        self.assertEqual(self.counts()["thumbnails"], 2)
        # A vendor-like DELETE holds the row lock briefly. The delivered retry
        # waits, rechecks after commit, then reports retirement without inserts.
        locked = "BEGIN; DELETE FROM events WHERE id='" + row["eventId"] + "'; SELECT pg_sleep(0.5); COMMIT;"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            deleted = pool.submit(execute, locked)
            import time
            time.sleep(0.15)
            retried = pool.submit(adapter().upsert_interval, dict(row, deliveredRevision=1))
            deleted.result()
            with self.assertRaises(RetiredEventError):
                retried.result()
        self.assertEqual(self.counts()["events"], 0)

    def test_delete_is_owned_and_cascades_only_selected_graph(self):
        self.db.upsert_interval(interval(1), Thumbnail(JPEG, START + 1000))
        self.db.upsert_interval(interval(2), Thumbnail(JPEG, START + 2000))
        execute("UPDATE events SET metadata='{}'::json WHERE id='" + interval(2)["eventId"] + "';")
        self.assertEqual(self.db.delete_owned_event(interval(2)["eventId"]), {"deleted": 0})
        self.assertEqual(self.db.delete_owned_event(interval(1)["eventId"]), {"deleted": 1})
        counts = self.counts()
        self.assertEqual((counts["events"], counts["objects"], counts["tracks"], counts["detectionLabels"], counts["thumbnails"]), (1, 1, 1, 2, 2))
        self.assertEqual(value("SELECT to_json(count(*)) FROM cameras;"), 2)

    def test_schema_drift_fails_before_write(self):
        execute('ALTER TABLE events ALTER COLUMN score TYPE integer;')
        with self.assertRaises(SchemaError):
            self.db.upsert_interval(interval())
        self.assertEqual(self.counts()["events"], 0)

    def test_camera_feature_apply_rollback_preserves_intervening_native_settings(self):
        cameras = [CAMERA, "222222222222222222222222"]
        features = CameraFeatures(self.db)
        with tempfile.TemporaryDirectory(prefix="rpe-pg-feature-fixture-") as backup:
            result = features.apply(cameras, backup, audio_types_by_camera={CAMERA: ["alrmBabyCry", "alrmBark"]})
            configured = value('SELECT json_agg(row_to_json(cameras) ORDER BY id) FROM cameras;')
            for row in configured:
                self.assertTrue(row["featureFlags"]["hasSmartDetect"])
                self.assertTrue(row["featureFlags"]["syntheticUnchangedFlag"])
                if row["id"] == CAMERA:
                    self.assertEqual(row["featureFlags"]["smartDetectAudioTypes"], ["alrmBabyCry", "alrmBark"])
                else:
                    self.assertNotIn("smartDetectAudioTypes", row["featureFlags"])
                self.assertEqual(row["smartDetectZones"], [INTEGRATION_ZONE])
                self.assertEqual(row["smartDetectSettings"], {"objectTypes": []})
            # This represents a user's later native recognition change. Rollback
            # owns featureFlags/zones only and must retain the new native setting.
            execute('UPDATE cameras SET "smartDetectSettings"=\'{"objectTypes":["face"],"syntheticOperatorChoice":true}\'::json;')
            rolled = features.rollback(result["manifest"])
            self.assertEqual(rolled["state"], "rolled_back")
            restored = value('SELECT json_agg(row_to_json(cameras) ORDER BY id) FROM cameras;')
            for row in restored:
                self.assertEqual(row["featureFlags"], {"hasSmartDetect": False, "syntheticUnchangedFlag": True})
                self.assertEqual(row["smartDetectZones"], [])
                self.assertEqual(row["smartDetectSettings"], {"objectTypes": ["face"], "syntheticOperatorChoice": True})
                self.assertTrue(row["isThirdPartyCamera"])
                self.assertFalse(row["isPairedWithAiPort"])

    def test_camera_feature_second_camera_cas_failure_rolls_back_first(self):
        features = CameraFeatures(self.db)
        cameras = [CAMERA, "222222222222222222222222"]
        plan = features.plan(cameras)
        # Capture the real PostgreSQL plan, then change the second row before
        # apply. The first UPDATE executes; the second CAS must abort both.
        execute('UPDATE cameras SET "featureFlags"=("featureFlags"::jsonb || \'{"syntheticOperatorChoice":true}\'::jsonb)::json '
                'WHERE id=\'222222222222222222222222\';')
        before = value('SELECT json_agg(row_to_json(cameras) ORDER BY id) FROM cameras;')
        with tempfile.TemporaryDirectory(prefix="rpe-pg-cas-fixture-") as backup:
            with patch.object(features, "plan", return_value=plan), self.assertRaises(NativeError):
                features.apply(cameras, backup)
            manifests = list(Path(backup).glob("cameras-*.json"))
            self.assertEqual(len(manifests), 1)
            self.assertEqual(json.loads(manifests[0].read_text(encoding="utf-8"))["state"], "prepared")
        after = value('SELECT json_agg(row_to_json(cameras) ORDER BY id) FROM cameras;')
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
