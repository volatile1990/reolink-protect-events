import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from reolink_protect_events.native import (
    AUDIO_TYPES, CLASSES, NativeAdapter, NativeError, RetiredEventError, SchemaError, Thumbnail,
    _REQUIRED_COLUMNS, native_id, sql_text,
)


START = 1791586947512
INTERVAL = {"eventId": "6ac970031145030000000001", "cameraId": "111111111111111111111111",
            "start": START, "end": None, "classes": ["person"],
            "provenance": {"adapter": "reolink-protect-events", "seq": 3,
                "classificationInferred": False, "rawAiTypes": ["people"],
                "timestampUtc": "2026-10-09T23:02:27.5128436Z"}}


def schema_fixture():
    return {"database": "unifi-protect", "columns": [
        {"table": table, "column": column, "type": kind}
        for table, columns in _REQUIRED_COLUMNS.items() for column, kind in columns.items()],
        "indexes": [
            {"table": "labels", "name": "labels_name_key", "definition":
             'CREATE UNIQUE INDEX "labels_name_key" ON public.labels USING btree (name)'},
            {"table": "detectionLabels", "name": "detectionLabels_eventId_index_unique", "definition":
             'CREATE UNIQUE INDEX "detectionLabels_eventId_index_unique" ON public."detectionLabels" USING btree ("eventId") WHERE ("objectId" IS NULL)'},
            {"table": "detectionLabels", "name": "detectionLabels_eventId_objectId_index_unique", "definition":
             'CREATE UNIQUE INDEX "detectionLabels_eventId_objectId_index_unique" ON public."detectionLabels" USING btree ("eventId", "objectId") WHERE ("objectId" IS NOT NULL)'}]}


def adapter(execute=None, version="7.3.70"):
    return NativeAdapter(execute=execute or (lambda sql: json.dumps(schema_fixture())),
                         version_reader=lambda: version)


# A minimal SOF header is enough to exercise dimensions without storing a camera
# image fixture. The adapter only validates JPEG structure; it does not decode.
JPEG = bytes.fromhex("ffd8ffc00011080018002003011100021100031100ffda0008010100003f0000ffd9")


def visual_group(classes=("vehicle",), end=None):
    row = copy.deepcopy(INTERVAL)
    row.update(classes=list(classes), end=end)
    row["provenance"] = {"sourceUnionVersion": 1, "identityStart": START,
        "sourceTypes": ["reolink"], "visualGroupVersion": 1, "groupIdentityStart": START,
        "activationMs": START - 1000, "groupMaxSpanMs": 120000,
        "classIntervalsComplete": True,
        "classIntervals": {kind: [{"start": START + (500 if kind == "person" else 0), "end": end}]
                           for kind in classes}}
    return row


class NativeContractTests(unittest.TestCase):
    @staticmethod
    def decoded_json(sql):
        import re
        result = []
        for encoded in re.findall(r"convert_from\(decode\('([0-9a-f]*)','hex'\),'UTF8'\)", sql):
            try:
                result.append(json.loads(bytes.fromhex(encoded).decode("utf-8")))
            except ValueError:
                pass
        return result

    def test_audio_uses_native_audio_event_enum_and_event_only_graph(self):
        for source_class, native_class in AUDIO_TYPES.items():
            with self.subTest(source_class=source_class):
                sql, event = adapter().build_interval_sql(dict(INTERVAL, classes=[source_class]), Thumbnail(JPEG, START))
                self.assertEqual(event["type"], "smartAudioDetect")
                self.assertEqual(event["smartDetectTypes"], [native_class])
                self.assertEqual(event["metadata"]["zonesStatus"], {})
                self.assertFalse(event["metadata"]["reolinkProtectEvents"]["adapterVirtualZone"])
                self.assertEqual(event["metadata"]["detectedThumbnails"], [
                    {"clockBestWall": START, "type": native_class,
                     "croppedId": native_id("thumbnail", START, INTERVAL["eventId"])}])
                self.assertNotIn('INSERT INTO "smartDetectObjects"', sql)
                self.assertNotIn('INSERT INTO "smartDetectTracks"', sql)
                self.assertEqual(sql.count('INSERT INTO "detectionLabels"'), 1)
                self.assertIn(sql_text("eventType:smartAudioDetect"), sql)
                self.assertIn(sql_text("smartDetectType:" + native_class), sql)
                self.assertNotIn(sql_text("zone:" + INTERVAL["cameraId"] + ":1"), sql)
                self.assertNotIn('"smartDetectAudioTypes"', sql)

    def test_audio_and_visual_are_separate_and_unknown_details_fail_closed(self):
        for changes in ({"classes": ["person", "babyCry"]},
                        {"classes": ["alrmBabyCry"]},
                        {"classes": ["bark"], "details": {"animalType": ["dog"]}},
                        {"classes": ["vehicle"], "details": {"vehicleType": ["sedan"]}},
                        {"classes": ["vehicle"], "details": {"vehicleType": ["car"]}},
                        {"classes": ["animal"], "details": {"animalType": ["dog_cat"]}},
                        {"classes": ["person"], "details": {"vehicleType": ["bike"]}},
                        {"classes": ["vehicle"], "details": {"vehicleType": "bike"}}):
            row = copy.deepcopy(INTERVAL)
            row["classes"] = changes["classes"]
            if "details" in changes:
                row["provenance"]["classificationDetails"] = changes["details"]
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                adapter().build_interval_sql(row)

    def test_details_add_searchable_labels_without_fabricated_confidence(self):
        row = copy.deepcopy(INTERVAL)
        row["classes"] = ["vehicle", "animal"]
        row["provenance"]["classificationDetails"] = {"vehicleType": ["bike"], "animalType": ["cat"]}
        sql, event = adapter().build_interval_sql(row, Thumbnail(JPEG, START))
        thumbs = {thumb["type"]: thumb for thumb in event["metadata"]["detectedThumbnails"]}
        self.assertEqual(thumbs["vehicle"]["attributes"]["vehicleType"], {"val": "bike"})
        self.assertEqual(thumbs["animal"]["attributes"]["species"], {"val": "cat"})
        for label in ("vehicleType:bike", "species:cat"):
            self.assertIn(sql_text(label), sql)
        self.assertIn("attributes=EXCLUDED.attributes", sql)
        self.assertIn("WITH ORDINALITY", sql)
        self.assertNotIn('"confidence":', json.dumps(self.decoded_json(sql)))

    def test_multiple_details_are_labels_without_choosing_one_object_subtype(self):
        row = copy.deepcopy(INTERVAL)
        row["classes"] = ["vehicle", "animal"]
        row["provenance"]["classificationDetails"] = {
            "vehicleType": ["bus", "bike", "bus"], "animalType": ["cat", "dog"]}
        sql, event = adapter().build_interval_sql(row, Thumbnail(JPEG, START))
        for thumb in event["metadata"]["detectedThumbnails"]:
            self.assertNotIn("vehicleType", thumb["attributes"])
            self.assertNotIn("species", thumb["attributes"])
        for label in ("vehicleType:bus", "vehicleType:bike", "species:cat", "species:dog"):
            self.assertIn(sql_text(label), sql)

    def test_schema_guard_accepts_live_schema_fixture(self):
        seen = []
        db = adapter(lambda sql: seen.append(sql) or json.dumps(schema_fixture()))
        self.assertTrue(db.guard_schema()["schemaVerified"])
        self.assertIn("BEGIN READ ONLY", seen[0])
        self.assertIn("ROLLBACK", seen[0])
        self.assertNotIn("INSERT ", seen[0])

    def test_version_or_schema_drift_prevents_write(self):
        for version in ("7.3.71", "8.0.0", "7.3.70-unknown"):
            seen = []
            db = adapter(lambda sql: seen.append(sql) or "{}", version=version)
            with self.assertRaises(SchemaError):
                db.upsert_interval(INTERVAL)
            self.assertFalse(seen)
        for mutation in ("missing-column", "changed-type", "missing-index", "changed-index-semantics", "wrong-database"):
            schema = schema_fixture()
            if mutation == "missing-column":
                schema["columns"].pop(0)
            elif mutation == "changed-type":
                schema["columns"][0]["type"] = "uuid"
            elif mutation == "missing-index":
                schema["indexes"].pop()
            elif mutation == "changed-index-semantics":
                schema["indexes"][1]["definition"] = schema["indexes"][1]["definition"].replace("IS NULL", "IS NOT NULL")
            else:
                schema["database"] = "postgres"
            seen = []
            db = adapter(lambda sql: seen.append(sql) or json.dumps(schema))
            with self.assertRaises(SchemaError):
                db.upsert_interval(INTERVAL)
            self.assertEqual(len(seen), 1)
            self.assertNotIn("INSERT ", seen[0])

    def test_schema_guard_accepts_actual_unquoted_label_index(self):
        schema = schema_fixture()
        schema["indexes"][0]["definition"] = schema["indexes"][0]["definition"].replace('"labels_name_key"', 'labels_name_key')
        self.assertTrue(adapter(lambda sql: json.dumps(schema)).guard_schema()["schemaVerified"])

    def test_interval_uses_real_classes_and_explicit_unknown_spatial_data(self):
        sql, event = adapter().build_interval_sql(INTERVAL)
        self.assertEqual(event["smartDetectTypes"], ["person"])
        self.assertIsNone(event["score"])
        self.assertEqual(event["metadata"]["zonesStatus"], {"1": {"status": "enter"}})
        self.assertTrue(event["metadata"]["reolinkProtectEvents"]["adapterVirtualZone"])
        self.assertFalse(event["metadata"]["reolinkProtectEvents"]["confidenceAvailable"])
        self.assertEqual(event["metadata"]["reolinkProtectEvents"]["sourceZoneIds"], [])
        self.assertIn("'[]'::json", sql)
        self.assertNotIn('"smartDetectObjectAreas"', sql)
        self.assertNotIn('"smartDetectRaws"', sql)
        # None of the JSON payloads contains inferred camera measurements.
        decoded = []
        import re
        for item in re.findall(r"convert_from\(decode\('([0-9a-f]*)','hex'\),'UTF8'\)", sql):
            text = bytes.fromhex(item).decode("utf-8")
            try:
                decoded.append(json.loads(text))
            except ValueError:
                pass
        all_json = json.dumps(decoded)
        for key in ('"confidence":', '"coord":', '"trackerId":', '"faceEmbed":', '"boundingX1":'):
            self.assertNotIn(key, all_json)

    def test_duplicate_interval_builds_identical_graph_and_no_reopen(self):
        first, _ = adapter().build_interval_sql(INTERVAL)
        second, _ = adapter().build_interval_sql(copy.deepcopy(INTERVAL))
        self.assertEqual(first, second)
        self.assertIn('WHEN EXCLUDED."end" IS NULL THEN events."end"', first)
        self.assertIn('GREATEST(events."end",EXCLUDED."end")', first)
        self.assertIn('ON CONFLICT ("eventId") WHERE "objectId" IS NULL', first)
        self.assertIn('ON CONFLICT ("eventId","objectId") WHERE "objectId" IS NOT NULL', first)
        self.assertIn("Integration event identity collision", first)
        self.assertIn('"deletedAt" IS NOT NULL', first)
        # Protect owns retention/favoriting; updates cannot unlock/revive rows.
        event_update = first.split("ON CONFLICT (id) DO UPDATE SET", 1)[1].split("INSERT INTO labels", 1)[0]
        self.assertNotIn("locked=", event_update)
        self.assertNotIn('"deletedAt"=', event_update)

    def test_multiclass_labels_are_separate_and_classes_sorted(self):
        interval = dict(INTERVAL, classes=["vehicle", "person", "vehicle", "animal"])
        sql, event = adapter().build_interval_sql(interval)
        self.assertEqual(event["smartDetectTypes"], sorted(CLASSES))
        self.assertEqual(sql.count('INSERT INTO "smartDetectObjects"'), 3)
        self.assertEqual(sql.count('INSERT INTO "detectionLabels"'), 4)
        self.assertEqual(sql.count('INSERT INTO "smartDetectTracks"'), 1)

    def test_visual_group_expansion_is_scoped_and_uses_real_class_times(self):
        row = visual_group(("vehicle", "person"))
        sql, event = adapter().build_interval_sql(row)
        self.assertEqual(event["smartDetectTypes"], ["person", "vehicle"])
        self.assertIn('"smartDetectTypes"=EXCLUDED."smartDetectTypes"', sql)
        self.assertIn('"smartDetectTypes"::jsonb <@', sql)
        for key in ("visualGroupVersion", "groupIdentityStart", "activationMs", "groupMaxSpanMs"):
            self.assertIn(sql_text(key), sql)
        self.assertIn(",%d,(SELECT \"thumbnailFullfovId\"" % (START + 500), sql)
        self.assertIn(",%d,(SELECT \"thumbnailFullfovId\"" % START, sql)
        self.assertIn("'clockBestWall',t.timestamp", sql)
        self.assertIn("pixel.timestamp=(item->>'clockBestWall')::bigint", sql)
        self.assertIn('"thumbnailId"=EXCLUDED."thumbnailId"', sql)
        self.assertNotIn("'clockBestWall',%d" % (START + 500), sql)
        self.assertEqual(event["metadata"]["detectedThumbnails"], [])
        ordinary_sql, _ = adapter().build_interval_sql(INTERVAL)
        self.assertIn('"smartDetectTypes"::jsonb IS DISTINCT FROM', ordinary_sql)
        self.assertNotIn('"smartDetectTypes"=EXCLUDED."smartDetectTypes"', ordinary_sql)

    def test_visual_group_rejects_incomplete_unclipped_or_unsupported_protocol(self):
        changes = [{"visualGroupVersion": True}, {"visualGroupVersion": 2},
                   {"sourceUnionVersion": 0}, {"classIntervalsComplete": False},
                   {"classIntervals": {}}, {"groupIdentityStart": START + 1},
                   {"activationMs": START + 1}, {"groupMaxSpanMs": 300001},
                   {"classIntervals": {"vehicle": [{"start": START - 1, "end": None}]}},
                   {"classIntervals": {"vehicle": [{"start": START, "end": START}]}},
                   {"classIntervals": {"vehicle": [{"start": START, "end": START + 120001}]}},
                   {"classIntervals": {"vehicle": [{"start": START, "end": START + 2000},
                                                     {"start": START + 1000, "end": None}]}}]
        for change in changes:
            row = visual_group()
            row["provenance"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                adapter().build_interval_sql(row)
        for row in (visual_group(end=START + 120001),
                    dict(visual_group(), end=START + 1000),
                    visual_group(("babyCry",))):
            with self.subTest(row=row), self.assertRaises(ValueError):
                adapter().build_interval_sql(row)

    def test_visual_group_thumbnail_keeps_pixel_time_distinct_from_detection_time(self):
        row = visual_group(("person", "vehicle"), end=START + 3000)
        _, event = adapter().build_interval_sql(row, Thumbnail(JPEG, START + 250))
        self.assertEqual([thumb["type"] for thumb in event["metadata"]["detectedThumbnails"]], ["vehicle"])
        self.assertEqual({thumb["clockBestWall"] for thumb in event["metadata"]["detectedThumbnails"]},
                         {START + 250})
        self.assertEqual(event["metadata"]["reolinkProtectEvents"]["provenance"]["classIntervals"]["person"][0]["start"],
                         START + 500)
        _, event = adapter().build_interval_sql(row, Thumbnail(JPEG, START + 750))
        self.assertEqual({thumb["type"] for thumb in event["metadata"]["detectedThumbnails"]}, {"person", "vehicle"})

    def test_closed_interval_and_source_time_retained(self):
        interval = dict(INTERVAL, end=START + 12000)
        _, event = adapter().build_interval_sql(interval)
        self.assertEqual(event["start"], START)
        self.assertEqual(event["end"], START + 12000)
        self.assertEqual(event["metadata"]["zonesStatus"]["1"]["status"], "leave")
        self.assertEqual(event["metadata"]["reolinkProtectEvents"]["provenance"], INTERVAL["provenance"])

    def test_delivered_retry_cannot_resurrect_vendor_purged_event(self):
        retry_sql, _ = adapter().build_interval_sql(dict(INTERVAL, deliveredRevision=1))
        first_sql, _ = adapter().build_interval_sql(INTERVAL)
        self.assertIn("IF true AND NOT EXISTS (SELECT 1 FROM events", retry_sql)
        self.assertIn("IF false AND NOT EXISTS (SELECT 1 FROM events", first_sql)
        self.assertIn('PERFORM id FROM events WHERE id=', retry_sql)
        self.assertIn('FOR UPDATE;', retry_sql)
        self.assertLess(retry_sql.index("reolink-protect-events:retired"),
                        retry_sql.index("INSERT INTO events"))
        media_sql, _ = adapter().build_interval_sql(dict(INTERVAL, requireExisting=True), Thumbnail(JPEG, START))
        self.assertLess(media_sql.index("reolink-protect-events:retired"),
                        media_sql.index("INSERT INTO thumbnails"))

    def test_invalid_or_unclassified_input_fails_before_io(self):
        bad = [dict(INTERVAL, classes=[]), dict(INTERVAL, classes=["motion"]),
               dict(INTERVAL, classes=["human"]), dict(INTERVAL, start=True),
               dict(INTERVAL, end=START - 1), dict(INTERVAL, provenance={}),
               dict(INTERVAL, eventId="x'; DROP TABLE events; --"),
               dict(INTERVAL, cameraId="../../camera")]
        for interval in bad:
            seen = []
            with self.assertRaises(ValueError):
                adapter(lambda sql: seen.append(sql) or "{}").upsert_interval(interval)
            self.assertFalse(seen)

    def test_secret_keys_nonfinite_values_and_large_provenance_rejected(self):
        for provenance in ({"SUPERVISOR_TOKEN": "hidden"}, {"nested": {"password": "hidden"}},
                           {"seq": float("nan")}, {"text": "x" * 9000}):
            with self.assertRaises(ValueError):
                adapter().build_interval_sql(dict(INTERVAL, provenance=provenance))

    def test_sql_literal_handles_quotes_unicode_backslash_and_do_delimiter(self):
        malicious = "ä'\\ $rpe$; DROP TABLE events; --\n"
        expression = sql_text(malicious)
        self.assertNotIn("DROP", expression)
        self.assertNotIn("$rpe$", expression)
        encoded = expression.split("decode('", 1)[1].split("'", 1)[0]
        self.assertEqual(bytes.fromhex(encoded).decode("utf-8"), malicious)
        interval = dict(INTERVAL, provenance={"actualSourceText": malicious})
        sql, _ = adapter().build_interval_sql(interval)
        self.assertNotIn(malicious, sql)
        self.assertEqual(sql.count("$rpe$"), 2)

    def test_ids_are_stable_timestamp_ordered_and_separated(self):
        a = native_id("object", START, "event:person")
        self.assertEqual(a, native_id("object", START, "event:person"))
        self.assertNotEqual(a, native_id("object", START, "event:vehicle"))
        self.assertNotEqual(a, native_id("thumbnail", START, "event:person"))
        self.assertEqual(int(a[:8], 16), START // 1000)
        self.assertEqual(len(a), 24)

    def test_real_jpeg_full_frame_content_optional_and_preserved_on_retry(self):
        sql, event = adapter().build_interval_sql(INTERVAL, Thumbnail(JPEG, START + 500))
        self.assertIn(JPEG.hex(), sql)
        self.assertIn(",32,24,", sql)
        thumbs = event["metadata"]["detectedThumbnails"]
        self.assertEqual(thumbs[0]["clockBestWall"], START + 500)
        self.assertEqual(thumbs[0]["type"], "person")
        self.assertNotIn("coord", thumbs[0])
        self.assertIn("jsonb_array_length", sql)
        self.assertIn('COALESCE(events."thumbnailFullfovId",EXCLUDED."thumbnailFullfovId")', sql)
        # The timeline's false/NULL selector and full-FoV's true selector must
        # resolve independently; one full-FoV row cannot serve both routes.
        self.assertEqual(sql.count("INSERT INTO thumbnails"), 2)
        self.assertEqual(sql.count(JPEG.hex()), 2)
        self.assertIn(sql_text(native_id("preview-thumbnail", START, INTERVAL["eventId"])), sql)
        self.assertNotEqual(native_id("preview-thumbnail", START, INTERVAL["eventId"]),
                            thumbs[0]["croppedId"])
        self.assertEqual(event["thumbnailFullfov"], thumbs[0]["croppedId"])
        for thumbnail in (Thumbnail(b"not a JPEG", START), Thumbnail(JPEG, START, width=999),
                          Thumbnail(JPEG[:-2], START), Thumbnail(JPEG, True)):
            with self.assertRaises(ValueError):
                adapter().build_interval_sql(INTERVAL, thumbnail)

    def test_preview_repair_plan_is_readonly_and_bounded(self):
        candidate = {"eventId": INTERVAL["eventId"], "cameraId": INTERVAL["cameraId"],
                     "start": START, "fullfovId": native_id("thumbnail", START, INTERVAL["eventId"])}
        seen = []
        def execute(sql):
            seen.append(sql)
            return json.dumps(schema_fixture() if "information_schema" in sql else [candidate])
        db = adapter(execute)
        self.assertEqual(db.preview_repair_candidates(64), [candidate])
        self.assertIn("BEGIN READ ONLY", seen[-1])
        self.assertIn("ROLLBACK", seen[-1])
        self.assertNotIn("INSERT ", seen[-1])
        for limit in (0, 257, True, "128"):
            with self.assertRaises(ValueError):
                db.preview_repair_candidates(limit)

    def test_preview_repair_copies_existing_bytes_and_preserves_detection(self):
        candidate = {"eventId": INTERVAL["eventId"], "cameraId": INTERVAL["cameraId"],
                     "start": START, "fullfovId": native_id("thumbnail", START, INTERVAL["eventId"])}
        sql = adapter().build_preview_repair_sql(candidate)
        self.assertIn("FOR UPDATE OF e", sql)
        self.assertIn("reolinkProtectEvents", sql)
        self.assertIn('e."deletedAt" IS NULL', sql)
        self.assertIn("f.timestamp,f.content,NULL", sql)
        self.assertIn("(e.locked OR f.locked)", sql)
        self.assertNotIn("INSERT INTO events", sql)
        self.assertNotIn("DELETE ", sql)
        self.assertNotIn('INSERT INTO "smartDetectObjects"', sql)
        update = sql.split("UPDATE events e SET", 1)[1].split("SELECT json_build_object", 1)[0]
        for field in ("start=", '"end"=', "metadata=", "locked=", '"smartDetectTypes"=', '"thumbnailFullfovId"='):
            self.assertNotIn(field, update)
        with self.assertRaises(ValueError):
            adapter().build_preview_repair_sql(dict(candidate, fullfovId="x'; DELETE FROM events;"))

    def test_preview_repair_does_not_resurrect_concurrently_retired_event(self):
        candidate = {"eventId": INTERVAL["eventId"], "cameraId": INTERVAL["cameraId"],
                     "start": START, "fullfovId": native_id("thumbnail", START, INTERVAL["eventId"])}
        seen = []
        def execute(sql):
            seen.append(sql)
            return json.dumps(schema_fixture()) if "information_schema" in sql else "\n"
        self.assertIsNone(adapter(execute).repair_preview_thumbnail(candidate))
        self.assertNotIn("INSERT INTO events", seen[-1])
        for bad in (dict(candidate, eventId="../event"), dict(candidate, start=True)):
            with self.assertRaises(ValueError):
                adapter().repair_preview_thumbnail(bad)

    def test_actual_db_result_drives_ds_representation(self):
        db_result = {"id": INTERVAL["eventId"], "end": START + 1000,
                     "metadata": {"detectedThumbnails": [{"croppedId": "existing"}]}}
        seen = []
        def execute(sql):
            seen.append(sql)
            return json.dumps(schema_fixture() if "BEGIN READ ONLY" in sql else db_result)
        result = adapter(execute).upsert_interval(INTERVAL)
        self.assertEqual(result, db_result)
        self.assertEqual(len(seen), 2)
        self.assertIn("COMMIT", seen[1])

    def test_executor_sends_sql_on_stdin_and_never_leaks_database_error(self):
        db = adapter()
        db.execute = db._execute
        sql = "SELECT 'private provenance';"
        with patch("reolink_protect_events.native.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(db.psql_command, 0, "{}", "")
            self.assertEqual(db._execute(sql), "{}")
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs["input"], sql)
            self.assertFalse(kwargs["shell"])
            self.assertNotIn(sql, run.call_args.args[0])
            run.return_value = subprocess.CompletedProcess(db.psql_command, 1, "", "private SQL error")
            with self.assertRaises(NativeError) as exc:
                db._execute(sql)
            self.assertNotIn("private", str(exc.exception))
            run.return_value = subprocess.CompletedProcess(db.psql_command, 1, "", "ERROR: reolink-protect-events:retired\nprivate SQL context")
            with self.assertRaises(RetiredEventError) as retired:
                db._execute(sql)
            self.assertNotIn("private", str(retired.exception))

    def test_canary_delete_is_scoped_to_owned_graph_without_video(self):
        seen = []
        def execute(sql):
            seen.append(sql)
            return json.dumps(schema_fixture() if "BEGIN READ ONLY" in sql else {"deleted": 1})
        self.assertEqual(adapter(execute).delete_owned_event(INTERVAL["eventId"]), {"deleted": 1})
        self.assertIn("reolinkProtectEvents", seen[1])
        self.assertIn("DELETE FROM thumbnails", seen[1])
        self.assertIn("DELETE FROM events", seen[1])
        self.assertNotIn("DELETE FROM cameras", seen[1])
        self.assertNotIn("recording", seen[1])


if __name__ == "__main__":
    unittest.main()
