"""Tests for feature extraction and the request-rate tracker."""

from __future__ import annotations

from detection.features import (
    FEATURE_NAMES,
    RateTracker,
    extract_features,
    to_vector,
)


def test_features_cover_documented_schema():
    features = extract_features(
        path="/api/products/42/reviews",
        query="page=2&sort=desc",
        headers={"user-agent": "Mozilla/5.0", "content-type": "application/json"},
        body="",
        requests_last_window=3,
        seconds_since_last_request=5.0,
    )
    assert set(features) == set(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in features.values())
    assert features["param_count"] == 2.0
    assert features["path_depth"] == 4.0
    assert features["has_json_content_type"] == 1.0
    assert features["requests_last_window"] == 3.0


def test_vector_matches_training_order():
    features = extract_features(
        path="/x",
        query="a=1",
        headers={},
        body="",
        requests_last_window=1,
        seconds_since_last_request=60.0,
    )
    vector = to_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("path_len")] == float(len("/x"))  # 2.0


def test_suspicious_and_encoding_ratios():
    features = extract_features(
        path="/search",
        query="q=%3Cscript%3E",
        headers={},
        body="",
        requests_last_window=1,
        seconds_since_last_request=60.0,
    )
    assert features["pct_encoded_count"] >= 1.0
    assert features["suspicious_char_ratio"] > 0.0


def test_empty_request_does_not_divide_by_zero():
    features = extract_features(
        path="/",
        query="",
        headers={},
        body="",
        requests_last_window=1,
        seconds_since_last_request=60.0,
    )
    # "/" contains no alphanumerics, so the non-alnum ratio is 1.0
    assert features["non_alnum_ratio"] == 1.0
    assert features["digit_ratio"] == 0.0
    assert 0.0 <= features["suspicious_char_ratio"] <= 1.0


def test_rate_tracker_counts_within_window():
    tracker = RateTracker(window_seconds=60)
    tracker.observe("10.0.0.1", now=1000.0)
    tracker.observe("10.0.0.1", now=1001.0)
    count, gap = tracker.observe("10.0.0.1", now=1002.0)

    assert count == 3
    assert gap == 1.0
    assert tracker.count("10.0.0.1", now=1002.0) == 3

    # after the window the old hits expire
    assert tracker.count("10.0.0.1", now=1060.0) == 2  # 1001 and 1002 remain
    assert tracker.count("10.0.0.1", now=1100.0) == 0  # all older than 60s


def test_rate_tracker_is_per_client():
    tracker = RateTracker(window_seconds=60)
    tracker.observe("a", now=1000.0)
    tracker.observe("a", now=1001.0)
    tracker.observe("b", now=1002.0)
    assert tracker.count("a", now=1003.0) == 2
    assert tracker.count("b", now=1003.0) == 1


def test_over_limit():
    tracker = RateTracker(window_seconds=60)
    for i in range(5):
        tracker.observe("ip", now=1000.0 + i)
    assert tracker.over_limit("ip", 5, now=1010.0) is True
    assert tracker.over_limit("ip", 6, now=1010.0) is False
    assert tracker.over_limit("ip", 1, now=2000.0) is False
