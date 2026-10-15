"""Optional local contract against the actual pilot projection, no live API."""
import importlib.util
import json
from pathlib import Path
import unittest
import urllib.parse
from unittest.mock import patch

from reolink_protect_events.frigate import event, poll
from test_frigate import options, START


PROJECTION = Path(__file__).resolve().parents[2] / "frigate-pilot" / "api_proxy.py"
EXPANSION_PROJECTION = Path(__file__).resolve().parents[2] / "frigate-expansion-20261015" / "api_proxy.py"


@unittest.skipUnless(PROJECTION.is_file(), "Local pilot projection is an independently deployed component")
class ProjectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("pilot_projection_contract", PROJECTION)
        cls.proxy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.proxy)  # Import must not load private tokens.

    def test_real_projection_and_object_consumer_share_actual_018_shape(self):
        source = {"id": "1791586947.512843-abcdef", "camera": self.proxy.CAMERA, "label": "car",
                  "start_time": 1791586947.512843, "end_time": 1791586955.6,
                  "top_score": None, "false_positive": None,
                  "data": {"type": "object", "top_score": 0.91, "score": 0.85,
                           "stationary": False, "box": [0.1, 0.1, 0.3, 0.3]}}
        projected = self.proxy.event_view(source)
        parsed = event(projected, self.proxy.CAMERA, 1791587000000)
        self.assertEqual(parsed["class"], "vehicle")
        self.assertEqual(parsed["topScore"], 0.91)
        self.assertIsNone(parsed["falsePositive"])
        self.assertEqual(parsed["acceptanceBasis"], "object_data_with_nullable_legacy_flag")
        self.assertNotIn("box", projected["data"])
        source["false_positive"] = False
        source["data"]["type"] = "manual"
        self.assertIsNone(event(self.proxy.event_view(source), self.proxy.CAMERA, 1791587000000)["class"])

    def test_actual_history_and_active_queries_are_accepted_and_thumbnail_bounded(self):
        for query in ({"camera": self.proxy.CAMERA, "after": 1791586947.1, "before": 1791587000.2,
                       "limit": 200, "include_thumbnails": 0},
                      {"camera": self.proxy.CAMERA, "in_progress": 1, "limit": 200, "include_thumbnails": 0}):
            parsed = self.proxy.query_params(urllib.parse.urlencode(query))
            self.assertEqual(parsed["camera"], self.proxy.CAMERA)
            self.assertEqual(parsed["include_thumbnails"], 0)
        with self.assertRaises(ValueError):
            self.proxy.query_params("include_thumbnails=1")


@unittest.skipUnless(EXPANSION_PROJECTION.is_file(), "Local six-camera projection is an independently deployed component")
class ExpansionProjectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("expansion_projection_contract", EXPANSION_PROJECTION)
        cls.proxy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.proxy)

    def stats(self):
        return {"service": {"version": "0.18.1-cf67f08", "uptime": 1000},
                "detectors": {"coral": {"pid": 525, "inference_speed": 9.29}},
                "cameras": {name: {"camera_fps": 5, "process_fps": 5,
                                     "detection_fps": 2, "skipped_fps": 0} for name in self.proxy.CAMERAS}}

    def test_actual_all_six_health_and_object_queries_isolate_one_bad_camera(self):
        stats = self.stats()
        bad = "hintertuer"
        stats["cameras"][bad]["process_fps"] = 0
        def get(url, _headers, **_kwargs):
            parsed = urllib.parse.urlsplit(url)
            if parsed.path == "/health":
                name = self.proxy.health_camera(parsed.query)
                value = self.proxy.health_view(stats, name)
            else:
                query = self.proxy.query_params(parsed.query)
                name = query["camera"]
                source = {"id": "fixture-" + name, "camera": name, "label": "person",
                          "start_time": (START + 10000) / 1000, "end_time": (START + 20000) / 1000,
                          "top_score": None, "false_positive": None,
                          "data": {"type": "object", "top_score": 0.84375}}
                value = [] if "in_progress" in query else [self.proxy.event_view(source)]
            return 200, json.dumps(value).encode()
        with patch("reolink_protect_events.frigate.get_bytes", side_effect=get):
            for name in self.proxy.CAMERAS:
                with self.subTest(camera=name):
                    if name == bad:
                        with self.assertRaisesRegex(ValueError, "frigate_detector_unhealthy"):
                            poll(options(), name, START, [], START + 60000)
                    else:
                        result = poll(options(), name, START, [], START + 60000)
                        self.assertEqual(result["cursor"], START + 60000)
                        self.assertEqual(result["events"][0]["camera"], name)
                        self.assertEqual(result["events"][0]["class"], "person")
        legacy = self.proxy.health_view(stats)
        self.assertEqual(legacy["camera"], "vor_dem_haus")
        self.assertTrue(legacy["healthy"])
        self.assertFalse(legacy["overall_healthy"])

    def test_actual_allowlist_and_consumer_reject_cross_camera_or_unknown_sources(self):
        self.assertEqual(set(self.proxy.CAMERAS), {"neubau_eingang", "garage_hinten", "hintertuer",
                                                  "garten_neubau", "eingang", "vor_dem_haus"})
        for query in ("camera=outside", "camera=eingang&camera=vor_dem_haus", "camera=eingang&config=1"):
            with self.assertRaises(ValueError):
                self.proxy.health_camera(query)
        source = {"id": "fixture-cross-camera", "camera": "eingang", "label": "car",
                  "start_time": START / 1000, "end_time": None, "false_positive": None,
                  "data": {"type": "object", "top_score": 0.9}}
        projected = self.proxy.event_view(source)
        with self.assertRaisesRegex(ValueError, "invalid_frigate_event_identity"):
            event(projected, "vor_dem_haus", START + 60000)


if __name__ == "__main__":
    unittest.main()
