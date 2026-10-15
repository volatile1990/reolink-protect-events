"""Optional local contract against the actual pilot projection, no live API."""
import importlib.util
from pathlib import Path
import unittest
import urllib.parse

from reolink_protect_events.frigate import event


PROJECTION = Path(__file__).resolve().parents[2] / "frigate-pilot" / "api_proxy.py"


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
                  "top_score": None, "false_positive": False,
                  "data": {"type": "object", "top_score": 0.91, "score": 0.85,
                           "stationary": False, "box": [0.1, 0.1, 0.3, 0.3]}}
        projected = self.proxy.event_view(source)
        parsed = event(projected, self.proxy.CAMERA, 1791587000000)
        self.assertEqual(parsed["class"], "vehicle")
        self.assertEqual(parsed["topScore"], 0.91)
        self.assertNotIn("box", projected["data"])
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


if __name__ == "__main__":
    unittest.main()
