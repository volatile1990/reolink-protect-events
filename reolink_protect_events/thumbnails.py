"""Bounded recorded-frame selection using image signal quality, never camera AI.

All class labels and event times remain the camera's. A selected timestamp is
the Protect recorded-snapshot request time, not a recovered sensor capture PTS.
Only 64x36 grayscale pixels are compared; no crop, recognition or confidence is
invented. Pillow is an explicit release-local dependency supplied by the loader.
"""
from dataclasses import dataclass, field
import io
import math
import statistics
import time

from .native import Thumbnail

WIDTH, HEIGHT = 64, 36
MAX_JPEG_BYTES = 2 * 1024 * 1024
MAX_SOURCE_PIXELS = 16 * 1024 * 1024
DEFAULTS = {"mode": "start", "maxCandidates": 4, "windowSeconds": 6,
            "settleSeconds": 3, "recordingLagMs": 1500, "historyDays": 30,
            "budgetSeconds": 8}


class ThumbnailDeferred(Exception):
    """The short candidate window is not yet recorded; native events still ship."""
    def __init__(self, ready_at):
        self.ready_at = ready_at
        super().__init__("thumbnail_window_pending")


class ThumbnailExpired(Exception):
    """Outside the explicitly bounded history budget; never fetch live instead."""


class QualityDecoderUnavailable(Exception):
    pass


@dataclass(frozen=True)
class SelectedThumbnail(Thumbnail):
    selection: dict = field(default_factory=dict)


def settings(config):
    value = config.get("thumbnailSelection", {})
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError("invalid_thumbnail_selection")
    result = dict(DEFAULTS, **value)
    if result["mode"] not in ("start", "automatic"):
        raise ValueError("invalid_thumbnail_mode")
    for key, minimum, maximum in (("maxCandidates", 2, 5), ("windowSeconds", 1, 12),
            ("settleSeconds", 0, 12), ("recordingLagMs", 0, 10000), ("historyDays", 1, 30)):
        if type(result[key]) is not int or not minimum <= result[key] <= maximum:
            raise ValueError("invalid_thumbnail_" + key)
    if result["settleSeconds"] > result["windowSeconds"]:
        raise ValueError("thumbnail_settle_exceeds_window")
    budget = result["budgetSeconds"]
    if type(budget) not in (int, float) or not math.isfinite(budget) or not 1 <= budget <= 12:
        raise ValueError("invalid_thumbnail_budget")
    return result


def candidate_times(interval, options, now_ms):
    start, end = interval["start"], interval.get("end")
    if type(start) is not int or start <= 0 or (end is not None and (type(end) is not int or end < start)):
        raise ValueError("invalid_thumbnail_interval")
    if now_ms - start > options["historyDays"] * 86400000:
        raise ThumbnailExpired("thumbnail_history_expired")
    recorded = now_ms - options["recordingLagMs"]
    ready = start + options["settleSeconds"] * 1000
    if end is not None:
        ready = min(ready, end)
    if recorded < max(start, ready):
        raise ThumbnailDeferred(max(start, ready) + options["recordingLagMs"])
    stop = min(start + options["windowSeconds"] * 1000, recorded)
    if end is not None:
        stop = min(stop, end)
    count = options["maxCandidates"]
    return sorted({start + (stop - start) * index // (count - 1) for index in range(count)})


def decode_gray(content):
    """JPEG draft decode keeps the full-frame scoring buffer small and bounded."""
    try:
        # The production hook verifies the pinned wheel and installs its private
        # import path. A normal Pillow installation suffices for isolated tests.
        try:
            from .vendor_support import ensure_pillow
        except ImportError:
            ensure_pillow = None
        if ensure_pillow is not None:
            ensure_pillow()
        from PIL import Image
    except Exception:
        raise QualityDecoderUnavailable("thumbnail_quality_decoder_unavailable") from None
    with Image.open(io.BytesIO(content)) as image:
        if image.format != "JPEG" or image.width * image.height > MAX_SOURCE_PIXELS:
            raise ValueError("thumbnail_decode_pixel_budget")
        image.draft("L", (WIDTH, HEIGHT))
        if image.width * image.height > 1024 * 1024:
            raise ValueError("thumbnail_draft_pixel_budget")
        small = image.convert("L").resize((WIDTH, HEIGHT), Image.Resampling.BOX)
        pixels = small.tobytes()
    if len(pixels) != WIDTH * HEIGHT:
        raise ValueError("thumbnail_gray_size")
    return pixels


def signal_score(pixels, reference):
    if not isinstance(pixels, bytes) or len(pixels) != WIDTH * HEIGHT or len(reference) != len(pixels):
        raise ValueError("thumbnail_gray_size")
    signed = [value - baseline for value, baseline in zip(pixels, reference)]
    brightness_shift = statistics.median(signed)
    changes = [abs(delta - brightness_shift) for delta in signed]
    noise = statistics.median(changes)
    threshold = max(12, noise * 3)
    changed = [delta > threshold for delta in changes]
    count = sum(changed)
    foreground = min(1.0, count / (len(pixels) * .2))
    # Laplacian contrast within changed areas emphasizes visible detail over an
    # equally positioned motion-blurred patch. With no change use all interiors.
    contrasts = []
    for y in range(1, HEIGHT - 1):
        for x in range(1, WIDTH - 1):
            i = y * WIDTH + x
            if not count or changed[i]:
                contrasts.append(abs(4 * pixels[i] - pixels[i-1] - pixels[i+1]
                                     - pixels[i-WIDTH] - pixels[i+WIDTH]))
    sharpness = min(1.0, (sum(contrasts) / max(1, len(contrasts))) / 128)
    clipped = sum(value <= 3 or value >= 252 for value in pixels) / len(pixels)
    exposure = 1 - clipped
    score = (.5 * foreground + .35 * sharpness + .15 * exposure) * exposure
    return {"score": round(score, 6), "foregroundChange": round(foreground, 6),
            "sharpness": round(sharpness, 6), "exposure": round(exposure, 6)}


def select_recorded(interval, options, fetch, *, now_ms=None, decoder=decode_gray, clock=time.monotonic):
    """Fetch at most five past recorded JPEGs; keep only the best full JPEG."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    times = candidate_times(interval, options, now_ms)
    prior = interval.get("provenance", {}).get("thumbnailSelection")
    if isinstance(prior, dict) and type(prior.get("timestamp")) is int:
        pinned = prior["timestamp"]
        if not interval["start"] <= pinned <= min(interval.get("end") or now_ms, now_ms):
            raise ValueError("thumbnail_previous_timestamp_outside_event")
        image = fetch(pinned, min(5, options["budgetSeconds"]))
        width, height = image.dimensions()
        if len(image.content) > MAX_JPEG_BYTES or width * height > MAX_SOURCE_PIXELS:
            raise ValueError("thumbnail_image_budget")
        return SelectedThumbnail(image.content, pinned, selection=dict(prior))
    deadline = clock() + options["budgetSeconds"]
    first = best = None
    reference = None
    best_score = -1
    observations = []
    failures = 0
    fallback = "insufficient_candidates"
    for timestamp in times:
        remaining = deadline - clock()
        if remaining <= 0:
            fallback = "selection_budget_exhausted"
            break
        try:
            image = fetch(timestamp, min(2, remaining))
            width, height = image.dimensions()
            if len(image.content) > MAX_JPEG_BYTES or width * height > MAX_SOURCE_PIXELS:
                raise ValueError("thumbnail_image_budget")
        except Exception:
            failures += 1
            fallback = "recorded_candidate_unavailable"
            continue
        if first is None:
            first = image
        if clock() >= deadline:
            fallback = "selection_budget_exhausted"
            break
        try:
            pixels = decoder(image.content)
            if reference is None:
                reference = pixels
            metrics = signal_score(pixels, reference)
        except QualityDecoderUnavailable:
            fallback = "quality_decoder_unavailable"
            break
        except Exception:
            failures += 1
            fallback = "quality_decode_failed"
            continue
        observations.append(dict(timestamp=timestamp, **metrics))
        if metrics["score"] > best_score:
            best, best_score = image, metrics["score"]
    if first is None:
        raise ValueError("recorded_thumbnail_unavailable")
    ranked = len(observations) >= 2
    chosen = best if ranked else first
    selection = {"mode": "automatic" if ranked else "recorded_fallback",
        "automaticSelected": ranked, "timestamp": chosen.timestamp,
        "timeBasis": "Protect-recorded-snapshot-requested-UTC",
        "captureTimestampRecovered": False, "semanticObjectDetection": False,
        "scoreBasis": "foreground-change-sharpness-exposure-64x36-gray",
        "plannedCandidates": len(times), "decodedCandidates": len(observations),
        "candidateFailures": failures, "candidates": observations,
        "fallbackReason": None if ranked else fallback}
    return SelectedThumbnail(chosen.content, chosen.timestamp, selection=selection)
