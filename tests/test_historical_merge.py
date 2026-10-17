import copy
import unittest

from reolink_protect_events.historical_merge import build_pair_merge_sql
from reolink_protect_events.native import NativeAdapter, native_id, sql_text


START = 1792168300000
CAMERA = "1" * 24
CAR = "a" * 24
PERSON = "b" * 24


def fixture():
    group = {"eventId": CAR, "cameraId": CAMERA, "classes": ["person", "vehicle"],
        "start": START, "end": START + 20000, "deliveredRevision": 1,
        "provenance": {"sourceUnionVersion": 1, "identityStart": START,
            "sourceTypes": ["frigate", "reolink"], "visualGroupVersion": 1,
            "groupIdentityStart": START, "activationMs": START, "groupMaxSpanMs": 120000,
            "classIntervalsComplete": True, "mergePolicy": "camera_visual_positive_overlap",
            "classIntervals": {"vehicle": [{"start": START, "end": START + 20000}],
                               "person": [{"start": START + 2000, "end": START + 16000}]}}}
    graph = {"readOnly": "on", "favoriteCount": 0, "events": [], "thumbnails": [], "objects": [], "tracks": []}
    for identifier, kind, start, end in ((CAR, "vehicle", START, START + 20000),
                                        (PERSON, "person", START + 2000, START + 16000)):
        full = native_id("thumbnail", start, identifier)
        preview = native_id("preview-thumbnail", start, identifier)
        graph["events"].append({"id": identifier, "camera": CAMERA, "start": start, "end": end,
            "types": [kind], "locked": False, "deleted": False,
            "thumbnailId": preview, "thumbnailFullfovId": full, "metadataMd5": "0" * 32})
        for image_id, fullfov in ((full, True), (preview, None)):
            graph["thumbnails"].append({"id": image_id, "eventId": identifier, "timestamp": start,
                "fullfov": fullfov, "locked": False, "bytes": 100, "md5": "1" * 32})
        graph["objects"].append({"id": native_id("object", start, identifier + ":" + kind),
            "eventId": identifier, "type": kind, "detectedAt": start, "thumbnailId": full})
        graph["tracks"].append({"id": native_id("track", start, identifier), "eventId": identifier, "samples": 0})
    return group, graph


class HistoricalMergeTests(unittest.TestCase):
    def test_exact_pair_builds_one_atomic_guarded_transaction_and_preserves_native_guard(self):
        group, graph = fixture()
        sql = build_pair_merge_sql(NativeAdapter(), group, graph)
        self.assertEqual(sql.count("BEGIN;\n"), 1)
        self.assertEqual(sql.count("COMMIT;\n"), 1)
        self.assertIn('ORDER BY id FOR UPDATE', sql)
        self.assertIn('FROM "favoriteEvents"', sql)
        self.assertIn('md5(metadata::text)', sql)
        self.assertIn('md5(content)', sql)
        self.assertIn("Historical merge snapshot changed", sql)
        self.assertIn("Historical merge graph verification failed", sql)
        self.assertIn("Integration event identity collision", sql)
        self.assertIn('DELETE FROM events WHERE id=' + sql_text(PERSON), sql)
        self.assertNotIn('DELETE FROM events WHERE id=' + sql_text(CAR), sql)
        self.assertNotIn('DELETE FROM labels', sql)
        self.assertNotIn('recordingFiles', sql)
        self.assertNotIn('smartDetectRaws', sql)
        self.assertLess(sql.index('md5(metadata::text)'), sql.index('UPDATE events SET'))
        self.assertLess(sql.index('Historical merge graph verification failed'), sql.index('DELETE FROM thumbnails'))
        self.assertEqual((group, graph), fixture())

    def test_missing_drifted_locked_favorite_or_foreign_input_is_rejected(self):
        for mutate in (
                lambda g, b: b.update(favoriteCount=1),
                lambda g, b: b.update(readOnly='off'),
                lambda g, b: b['events'][0].update(locked=True),
                lambda g, b: b['events'][1].update(deleted=True),
                lambda g, b: b['events'][1].update(camera='2' * 24),
                lambda g, b: b['events'][1].update(metadataMd5="bad"),
                lambda g, b: b['thumbnails'][0].update(locked=True),
                lambda g, b: b['thumbnails'][0].update(md5="bad"),
                lambda g, b: b['objects'][0].update(id='2' * 24),
                lambda g, b: b['tracks'][0].update(id='2' * 24),
                lambda g, b: b['tracks'][1].update(samples=1),
                lambda g, b: b.update(objects=[]),
                lambda g, b: b.update(tracks=[]),
                lambda g, b: g.update(eventId=PERSON),
                lambda g, b: g.update(end=START + 21000),
                lambda g, b: g['provenance']['classIntervals']['person'][0].update(end=START + 15000),
                lambda g, b: g['provenance'].update(mergePolicy='camera_class_time_union')):
            group, graph = fixture()
            mutate(group, graph)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                build_pair_merge_sql(NativeAdapter(), group, graph)

    def test_actual_source_union_must_overlap_instead_of_being_adjacent(self):
        group, graph = fixture()
        graph['events'][1].update(start=START + 20000, end=START + 25000)
        with self.assertRaises(ValueError):
            build_pair_merge_sql(NativeAdapter(), group, graph)


if __name__ == '__main__':
    unittest.main()
