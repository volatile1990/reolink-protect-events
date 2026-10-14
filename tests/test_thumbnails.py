"""Real JPEG signal selection and isolated native outbox boundary tests."""
import copy
import datetime
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reolink_protect_events.native import RetiredEventError, Thumbnail
from reolink_protect_events.runtime import Runtime, recording_thumbnail, validate_config
from reolink_protect_events.thumbnails import (
    HEIGHT, WIDTH, QualityDecoderUnavailable, SelectedThumbnail,
    ThumbnailDeferred, ThumbnailExpired, candidate_times, decode_gray,
    select_recorded, settings, signal_score)

try:
    from PIL import Image, ImageFilter
except ImportError:
    Image = None

START = 1791586947512
CAMERA = "1" * 24
JPEG = bytes.fromhex("ffd8ffc00011080018002003011100021100031100ffda0008010100003f0000ffd9")


def interval(end=START + 6000):
    return {"eventId": "2" * 24, "cameraId": CAMERA, "classes": ["person"],
            "start": START, "end": end,
            "provenance": {"classificationOrigin": "camera", "sourceSeq": 1,
                           "sourceUtc": "2026-10-10T01:42:27.512Z"}}


def config():
    return {"protectUserId": "fixture-owner", "protectVersion": "7.3.70",
            "bridges": [{"cameraId": CAMERA, "host": "192.168.30.214",
                         "username": "fixture-user", "password": "fixture-password",
                         "mac": "001122334455"}],
            "thumbnailSelection": {"mode": "automatic"}}


def source(sequence, offset=0, classes=("person",)):
    return {"seq": sequence, "timestampUtc": datetime.datetime.fromtimestamp(
        (START + offset) / 1000, datetime.timezone.utc).isoformat(),
        "classes": list(classes), "rawAiTypes": [], "motion": False,
        "source": {"connectionEpoch": 0}, "zones": []}


def response(events):
    return {"instanceId": "a" * 32, "oldestSeq": 1,
            "currentSeq": max(item["seq"] for item in events), "events": events}


def jpeg_image(kind, night=False):
    """A sharp moving patch, blur, and clipping; no object semantics in fixture."""
    image = Image.new("L", (WIDTH, HEIGHT), 2 if night else 96)
    if kind in ("sharp", "blurred"):
        for y in range(9, 28):
            for x in range(16, 49):
                image.putpixel((x, y), (35 if night else 50) if (x + y) % 2 else (100 if night else 200))
        if kind == "blurred":
            image = image.filter(ImageFilter.GaussianBlur(1.5))
    if kind == "clipped":
        image.paste(255, (0, 0, WIDTH, HEIGHT))
    image = image.resize((320, 180), Image.Resampling.NEAREST)
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=95)
    return output.getvalue()


class ThumbnailSelectionTests(unittest.TestCase):
    def setUp(self):
        self.options = settings(config())
        self.item = interval()

    def test_config_limits_and_legacy_default(self):
        self.assertEqual(settings({})["mode"], "start")
        self.assertEqual(validate_config(config())["thumbnailSelection"]["mode"], "automatic")
        for value in ({"mode": "ai"}, {"maxCandidates": 100}, {"maxCandidates": True},
                      {"windowSeconds": 0}, {"settleSeconds": 7}, {"historyDays": 31},
                      {"budgetSeconds": float("nan")}, {"budgetSeconds": True},
                      {"inventedConfidence": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                settings({"thumbnailSelection": value})

    def test_candidates_are_bounded_by_actual_end_and_recorded_past(self):
        self.assertEqual(candidate_times(self.item, self.options, START + 10000),
                         [START, START + 2000, START + 4000, START + 6000])
        early = candidate_times(interval(None), self.options, START + 5000)
        self.assertEqual(len(early), 4)
        self.assertLessEqual(max(early), START + 3500)
        short = interval(START + 900)
        self.assertEqual(max(candidate_times(short, self.options, START + 10000)), START + 900)

    def test_future_window_and_expired_history_never_fetch(self):
        with self.assertRaises(ThumbnailDeferred) as pending:
            candidate_times(interval(None), self.options, START + 2000)
        self.assertEqual(pending.exception.ready_at, START + 4500)
        with self.assertRaises(ThumbnailExpired), patch("builtins.print"):
            select_recorded(self.item, self.options,
                            lambda *_: self.fail("expired history fetched"),
                            now_ms=START + 31 * 86400000)

    def test_global_brightness_shift_is_not_foreground_change(self):
        reference = bytes([96]) * (WIDTH * HEIGHT)
        score = signal_score(bytes([126]) * len(reference), reference)
        self.assertEqual(score["foregroundChange"], 0)
        self.assertEqual(score["sharpness"], 0)
        self.assertEqual(score["exposure"], 1)

    def test_decoder_unavailable_reports_real_recorded_fallback(self):
        requests = []
        def fetch(timestamp, timeout):
            requests.append(timestamp)
            return Thumbnail(JPEG, timestamp)
        def unavailable(_):
            raise QualityDecoderUnavailable()
        result = select_recorded(self.item, self.options, fetch,
                                 now_ms=START + 10000, decoder=unavailable)
        self.assertEqual(requests, [START])
        self.assertEqual(result.content, JPEG)
        self.assertFalse(result.selection["automaticSelected"])
        self.assertEqual(result.selection["fallbackReason"], "quality_decoder_unavailable")

    def test_dependency_integrity_failure_is_a_categorical_decoder_failure(self):
        with patch("reolink_protect_events.vendor_support.ensure_pillow",
                   side_effect=RuntimeError("private decoder detail")):
            with self.assertRaisesRegex(QualityDecoderUnavailable,
                                        "^thumbnail_quality_decoder_unavailable$"):
                decode_gray(JPEG)

    def test_invalid_jpeg_never_becomes_a_thumbnail(self):
        with self.assertRaisesRegex(ValueError, "recorded_thumbnail_unavailable"):
            select_recorded(self.item, self.options, lambda timestamp, _: Thumbnail(b"bad", timestamp),
                            now_ms=START + 10000)

    def test_budget_stops_new_fetches_and_does_not_claim_ranking(self):
        elapsed, requests = [0.0], []
        def fetch(timestamp, timeout):
            requests.append((timestamp, timeout))
            elapsed[0] += 8
            return Thumbnail(JPEG, timestamp)
        result = select_recorded(self.item, self.options, fetch, now_ms=START + 10000,
                                 decoder=lambda _: self.fail("decoded after deadline"),
                                 clock=lambda: elapsed[0])
        self.assertEqual(requests, [(START, 2)])
        self.assertFalse(result.selection["automaticSelected"])
        self.assertEqual(result.selection["fallbackReason"], "selection_budget_exhausted")

    def test_retry_fetches_only_pinned_sample_time_without_reselection(self):
        self.item["provenance"]["thumbnailSelection"] = {
            "timestamp": START + 4000, "automaticSelected": True, "mode": "automatic"}
        requests = []
        result = select_recorded(self.item, self.options,
                                 lambda ts, _: requests.append(ts) or Thumbnail(JPEG, ts),
                                 now_ms=START + 10000,
                                 decoder=lambda _: self.fail("retry rescored"))
        self.assertEqual(requests, [START + 4000])
        self.assertEqual(result.timestamp, START + 4000)

    @unittest.skipUnless(Image, "Pillow is required for the real JPEG decoder checks")
    def test_real_jpeg_selects_sharp_changed_frame_and_preserves_event_truth(self):
        original = copy.deepcopy(self.item)
        contents = [jpeg_image(kind) for kind in ("baseline", "blurred", "sharp", "clipped")]
        requests = []
        def fetch(timestamp, timeout):
            requests.append((timestamp, timeout))
            return Thumbnail(contents[(timestamp - START) // 2000], timestamp)
        result = select_recorded(self.item, self.options, fetch, now_ms=START + 10000)
        self.assertEqual(result.timestamp, START + 4000)
        self.assertEqual(result.content, contents[2])
        self.assertEqual(result.dimensions(), (320, 180))
        self.assertTrue(result.selection["automaticSelected"])
        self.assertEqual(result.selection["decodedCandidates"], 4)
        self.assertFalse(result.selection["semanticObjectDetection"])
        self.assertFalse(result.selection["captureTimestampRecovered"])
        self.assertEqual(self.item, original)
        self.assertEqual([ts for ts, _ in requests], [START, START + 2000, START + 4000, START + 6000])
        self.assertTrue(all(timeout <= 2 for _, timeout in requests))

    @unittest.skipUnless(Image, "Pillow is required for the real JPEG decoder checks")
    def test_night_jpeg_selects_detail_without_treating_black_background_as_object(self):
        contents = [jpeg_image(kind, night=True) for kind in ("baseline", "blurred", "sharp", "clipped")]
        result = select_recorded(self.item, self.options,
                                 lambda ts, _: Thumbnail(contents[(ts - START) // 2000], ts),
                                 now_ms=START + 10000)
        self.assertEqual(result.timestamp, START + 4000)
        self.assertTrue(result.selection["automaticSelected"])
        self.assertEqual(result.selection["candidates"][0]["foregroundChange"], 0)
        self.assertEqual(result.selection["candidates"][-1]["exposure"], 0)

    @unittest.skipUnless(Image, "Pillow is required for the real JPEG decoder checks")
    def test_actual_recording_api_requests_selected_timestamp_not_live(self):
        contents = [jpeg_image(kind) for kind in ("baseline", "blurred", "sharp", "clipped")]
        requests = []
        def get(url, headers, timeout, limit):
            self.assertIn("snapshot?ts=", url)
            self.assertEqual(headers["X-UserId"], "fixture-owner")
            requests.append(int(url.split("ts=")[1]))
            return 200, contents[(requests[-1] - START) // 2000]
        with patch("reolink_protect_events.runtime.get_bytes", side_effect=get), \
             patch("reolink_protect_events.thumbnails.time.time", return_value=(START + 10000) / 1000):
            result = recording_thumbnail(config(), self.item)
        self.assertEqual(requests, [START, START + 2000, START + 4000, START + 6000])
        self.assertEqual(result.timestamp, START + 4000)

    @unittest.skipUnless(Image, "Pillow is required for the real JPEG decoder checks")
    def test_source_pixel_budget_rejects_large_jpeg_before_decode(self):
        data = bytearray(JPEG)
        data[7:11] = bytes.fromhex("13881388")  # 5000 x 5000 source dimensions.
        with self.assertRaisesRegex(ValueError, "recorded_thumbnail_unavailable"):
            select_recorded(self.item, self.options, lambda ts, _: Thumbnail(bytes(data), ts),
                            now_ms=START + 10000, decoder=lambda _: self.fail("oversized decode"))
        pixels = decode_gray(jpeg_image("sharp"))
        self.assertEqual(len(pixels), WIDTH * HEIGHT)


class FakeNative:
    def __init__(self):
        self.calls = []
        self.retired = False
    def upsert_interval(self, item, thumbnail=None):
        self.calls.append((copy.deepcopy(item), thumbnail, threading.get_ident()))
        if self.retired:
            raise RetiredEventError("fixture retired")
        return {"id": item["eventId"], "start": item["start"], "end": item["end"],
                "smartDetectTypes": item["classes"],
                "metadata": {"zonesStatus": {"1": {"status": "enter"}}}}


class FakeClient:
    def __init__(self):
        self.sent = []
        self.fail = False
    def send_event(self, action, event):
        if self.fail:
            raise ConnectionError("private fixture details")
        self.sent.append((action, event))
    def close(self):
        pass


class AutomaticRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.runtime = Runtime(config(), Path(self.folder.name), background_native=False)
        self.native, self.client = FakeNative(), FakeClient()
        self.runtime.native, self.runtime.clients, self.runtime.native_ready = self.native, {CAMERA: self.client}, True
        self.clock = patch("reolink_protect_events.runtime.time.time", return_value=(START + 10000) / 1000)
        self.clock.start()
        self.runtime.journal.ingest(self.runtime.config["bridges"][0], response([source(1)]))
        self.event_id = self.runtime.journal.pending()[0]["eventId"]
        self.runtime.deliver()
        self.frame = SelectedThumbnail(JPEG, START + 4000, selection={
            "mode": "automatic", "automaticSelected": True, "timestamp": START + 4000})

    def tearDown(self):
        self.runtime.close()
        self.clock.stop()
        self.folder.cleanup()

    def complete(self, now=START + 10000):
        self.runtime._media_future.result(timeout=2)
        self.runtime.deliver_media(now)

    def media(self):
        return self.runtime.journal.db.execute(
            "SELECT attempts,done,selection FROM media WHERE event_id=?", (self.event_id,)).fetchone()

    def test_media_runs_off_native_thread_and_commits_selected_time_source_unchanged(self):
        owner = threading.get_ident()
        threads = []
        original = self.runtime.journal.media_interval(self.event_id)
        def thumbnail(*_):
            threads.append(threading.get_ident())
            return self.frame
        with patch("reolink_protect_events.runtime.recording_thumbnail", side_effect=thumbnail):
            self.runtime.deliver_media(START + 10000)
            self.complete()
        self.assertNotEqual(threads, [owner])
        self.assertTrue(all(call[2] == owner for call in self.native.calls))
        written, thumbnail, _ = self.native.calls[-1]
        self.assertEqual((written["start"], written["classes"], written["deliveredRevision"]), (START, ["person"], 1))
        self.assertEqual(thumbnail.timestamp, START + 4000)
        for key, value in original["provenance"].items():
            self.assertEqual(written["provenance"][key], value)
        self.assertEqual(self.media()[:2], (1, 1))
        self.assertEqual(json.loads(self.media()[2])["timestamp"], START + 4000)

    def test_slow_image_worker_does_not_delay_new_native_event_delivery(self):
        waiting, release = threading.Event(), threading.Event()
        def thumbnail(*_):
            waiting.set()
            release.wait(2)
            return self.frame
        with patch("reolink_protect_events.runtime.recording_thumbnail", side_effect=thumbnail):
            try:
                self.runtime.deliver_media(START + 10000)
                self.assertTrue(waiting.wait(1))
                self.runtime.journal.ingest(self.runtime.config["bridges"][0], response([source(2, classes=("person", "vehicle"))]))
                self.runtime.deliver()
                self.assertEqual(self.runtime.journal.health()["pending"], 0)
                self.runtime.deliver_media(START + 10000)
                self.assertEqual(len([call for call in self.native.calls if call[1] is not None]), 0)
            finally:
                release.set()
                self.complete()

    def test_deletion_while_loading_is_terminal_and_cannot_recreate_event(self):
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=self.frame):
            self.runtime.deliver_media(START + 10000)
            self.native.retired = True
            self.complete()
            self.runtime.deliver_media(START + 30000)
        self.assertEqual(self.media()[:2], (1, 1))
        self.assertEqual(self.runtime.journal.health()["counters"]["retiredMedia"], 1)
        self.assertEqual([action for action, _ in self.client.sent], ["add"])

    def test_clear_shortening_window_discards_outside_frame_then_resamples(self):
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=self.frame):
            self.runtime.deliver_media(START + 10000)
            self.runtime.journal.ingest(self.runtime.config["bridges"][0], response([source(2, 2000, classes=())]))
            self.runtime.deliver()
            self.complete()
        self.assertEqual(self.media()[:2], (0, 0))
        self.assertEqual(self.runtime.journal.health()["counters"]["thumbnailWindowChanged"], 1)
        self.assertEqual(len([call for call in self.native.calls if call[1] is not None]), 0)

    def test_settle_and_expired_backlog_do_not_consume_retry_or_network_budget(self):
        with patch("reolink_protect_events.runtime.recording_thumbnail") as thumbnail:
            self.runtime.deliver_media(START + 2000)
            thumbnail.assert_not_called()
            self.assertEqual(self.media()[:2], (0, 0))
            self.runtime.deliver_media(START + 31 * 86400000)
            thumbnail.assert_not_called()
        self.assertEqual(self.media()[:2], (1, 1))
        self.assertEqual(self.runtime.journal.health()["counters"]["expiredThumbnailWindows"], 1)

    def test_notification_failure_keeps_first_choice_pinned_for_retry(self):
        self.client.fail = True
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=self.frame):
            self.runtime.deliver_media(START + 10000)
            self.complete()
        self.assertEqual(self.media()[:2], (1, 0))
        current = self.runtime.journal.media_interval(self.event_id)
        self.assertEqual(current["provenance"]["thumbnailSelection"]["timestamp"], START + 4000)
        self.client.fail = False
        with patch("reolink_protect_events.runtime.recording_thumbnail", return_value=self.frame) as snapshot:
            self.runtime.deliver_media(START + 30001)
            self.complete(START + 30001)
        self.assertEqual(snapshot.call_args.args[1]["provenance"]["thumbnailSelection"]["timestamp"], START + 4000)
        self.assertEqual(self.media()[:2], (2, 1))
        self.assertEqual([action for action, _ in self.client.sent], ["add", "update"])


if __name__ == "__main__":
    unittest.main()
