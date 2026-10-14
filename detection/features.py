"""Feature extraction and request-rate tracking for the ML engine.

The same ``extract_features`` function is used for live traffic and for the
offline training script, so training and inference can never drift apart.

Feature list (order is fixed by ``FEATURE_NAMES``):
    path_len, query_len, body_len, param_count, header_count,
    non_alnum_ratio, digit_ratio, suspicious_char_ratio, pct_encoded_count,
    path_depth, requests_last_window, seconds_since_last_request,
    user_agent_len, has_json_content_type
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Mapping

FEATURE_NAMES: tuple[str, ...] = (
    "path_len",
    "query_len",
    "body_len",
    "param_count",
    "header_count",
    "non_alnum_ratio",
    "digit_ratio",
    "suspicious_char_ratio",
    "pct_encoded_count",
    "path_depth",
    "requests_last_window",
    "seconds_since_last_request",
    "user_agent_len",
    "has_json_content_type",
)

SUSPICIOUS_CHARS = set("'\"<>;|&`$(){}[]\\%")
_ALNUM = re.compile(r"[A-Za-z0-9]")
_PCT_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")
DEFAULT_RATE_WINDOW = 60.0
DEFAULT_FIRST_SEEN_GAP = DEFAULT_RATE_WINDOW


class RateTracker:
    """Sliding-window counter per client key (used for features + rate limits)."""

    def __init__(self, window_seconds: float = DEFAULT_RATE_WINDOW) -> None:
        self.window_seconds = float(window_seconds)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_seen: dict[str, float] = {}

    def prune(self, key: str, now: float) -> None:
        hits = self._hits.get(key)
        if not hits:
            return
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def observe(self, key: str, now: float | None = None) -> tuple[int, float]:
        """Record a hit and return (count in window, seconds since previous hit)."""
        now = time.time() if now is None else now
        self.prune(key, now)
        previous = self._last_seen.get(key)
        gap = (now - previous) if previous is not None else DEFAULT_FIRST_SEEN_GAP
        self._hits[key].append(now)
        self._last_seen[key] = now
        return len(self._hits[key]), max(gap, 0.0)

    def count(self, key: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        self.prune(key, now)
        return len(self._hits.get(key, ()))

    def over_limit(self, key: str, limit: int, now: float | None = None) -> bool:
        return self.count(key, now) >= limit

    def reset(self) -> None:
        self._hits.clear()
        self._last_seen.clear()


def _ratio(count: int, total: int) -> float:
    return round(count / total, 4) if total else 0.0


def extract_features(
    *,
    path: str,
    query: str,
    headers: Mapping[str, str],
    body: str,
    requests_last_window: int,
    seconds_since_last_request: float,
) -> dict[str, float]:
    """Return an ordered feature dict for one request snapshot."""
    target = f"{path}?{query}" if query else path
    combined = f"{path}\n{query}\n{body}"

    total_chars = len(combined)
    alnum = len(_ALNUM.findall(combined))
    non_alnum = total_chars - alnum
    digits = sum(ch.isdigit() for ch in combined)
    suspicious = sum(ch in SUSPICIOUS_CHARS for ch in combined)

    params = [pair for pair in query.split("&") if pair] if query else []
    if body and "x-www-form-urlencoded" in headers.get("content-type", ""):
        params.extend(pair for pair in body.split("&") if pair)

    lower_headers = {key.lower(): value for key, value in headers.items()}
    path_depth = len([segment for segment in path.split("/") if segment])

    return {
        "path_len": float(len(path)),
        "query_len": float(len(query)),
        "body_len": float(len(body)),
        "param_count": float(len(params)),
        "header_count": float(len(headers)),
        "non_alnum_ratio": _ratio(non_alnum, total_chars),
        "digit_ratio": _ratio(digits, total_chars),
        "suspicious_char_ratio": _ratio(suspicious, total_chars),
        "pct_encoded_count": float(len(_PCT_ENCODED.findall(target))),
        "path_depth": float(path_depth),
        "requests_last_window": float(requests_last_window),
        "seconds_since_last_request": round(float(seconds_since_last_request), 3),
        "user_agent_len": float(len(lower_headers.get("user-agent", ""))),
        "has_json_content_type": 1.0 if "application/json" in lower_headers.get("content-type", "") else 0.0,
    }


def to_vector(features: Mapping[str, float]) -> list[float]:
    """Project a feature dict onto the fixed training order."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
