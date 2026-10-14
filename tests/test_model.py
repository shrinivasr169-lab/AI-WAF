"""Tests for the ML model: fallback, training, thresholds and metrics."""

from __future__ import annotations

import json
from pathlib import Path

from detection.features import FEATURE_NAMES, extract_features
from detection.model import load_model, train_baseline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DATA = PROJECT_ROOT / "data" / "sample_requests.json"


def test_missing_artifact_falls_back_safely(tmp_path):
    model = load_model(tmp_path / "missing.joblib")
    assert model.available is False
    assert model.reason  # explains why it is unavailable
    assert model.score({"path_len": 1.0}) is None
    assert model.classify(None) == "none"


def test_corrupt_artifact_falls_back_safely(tmp_path):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a joblib file")
    model = load_model(bad)
    assert model.available is False
    assert model.score({"path_len": 1.0}) is None


def test_training_produces_artifact_and_report(tmp_path):
    samples = json.loads(SAMPLE_DATA.read_text(encoding="utf-8"))["requests"]
    out = tmp_path / "model.joblib"
    report_path = tmp_path / "report.json"

    report = train_baseline(samples, out, report_path=report_path)

    assert out.is_file()
    assert report_path.is_file()
    assert report.n_train + report.n_test == len(samples)
    assert report.alert_threshold < report.block_threshold

    # metrics are in range and reported (success criteria)
    for value in (report.ml_precision, report.ml_recall, report.ml_accuracy):
        assert 0.0 <= value <= 1.0
    assert report.ml_recall >= 0.5
    assert set(report.ml_confusion) == {"tp", "fp", "tn", "fn"}

    # the rule engine is measured on the same samples for comparison
    assert report.rule_recall >= 0.9

    stored = json.loads(report_path.read_text(encoding="utf-8"))
    assert stored["n_samples"] == len(samples)


def test_trained_model_scores_and_classifies(tmp_path):
    samples = json.loads(SAMPLE_DATA.read_text(encoding="utf-8"))["requests"]
    out = tmp_path / "model.joblib"
    report = train_baseline(samples, out)

    model = load_model(out)
    assert model.available is True
    assert model.alert_threshold == report.alert_threshold
    assert model.block_threshold == report.block_threshold

    benign = extract_features(
        path="/products",
        query="category=shoes",
        headers={"user-agent": "Mozilla/5.0"},
        body="",
        requests_last_window=1,
        seconds_since_last_request=60.0,
    )
    attack = extract_features(
        path="/search",
        query="q=1+UNION+SELECT+password+FROM+users+--",
        headers={"user-agent": "sqlmap/1.7.2"},
        body="<script>alert(1)</script>",
        requests_last_window=25,
        seconds_since_last_request=0.1,
    )

    benign_score = model.score(benign)
    attack_score = model.score(attack)
    assert benign_score is not None and attack_score is not None
    assert 0.0 <= benign_score <= 1.0
    assert 0.0 <= attack_score <= 1.0
    assert attack_score >= benign_score

    # classify() is a pure threshold comparison
    assert model.classify(None) == "none"
    assert model.classify(0.0) == "none"
    assert model.classify(model.alert_threshold) == "alert"
    assert model.classify(model.block_threshold) == "block"


def test_scores_separate_attacks_from_benign_on_sample_data(tmp_path):
    """Measured behaviour on the labelled dataset (as required by section 6)."""
    from detection.model import _offline_features

    samples = json.loads(SAMPLE_DATA.read_text(encoding="utf-8"))["requests"]
    out = tmp_path / "model.joblib"
    train_baseline(samples, out)
    model = load_model(out)

    features = _offline_features(samples, 60.0)
    benign_scores = sorted(
        model.score(f) for f, s in zip(features, samples) if s["label"] == 0
    )
    attack_scores = sorted(
        model.score(f) for f, s in zip(features, samples) if s["label"] == 1
    )

    threshold = model.alert_threshold
    benign_fp = sum(1 for s in benign_scores if s >= threshold) / len(benign_scores)
    attack_detect = sum(1 for s in attack_scores if s >= threshold) / len(attack_scores)

    assert benign_scores[len(benign_scores) // 2] < attack_scores[len(attack_scores) // 2]
    assert benign_fp <= 0.10  # measured false-positive budget
    assert attack_detect >= 0.60  # majority of attacks flagged by the ML layer


def test_feature_order_is_stable():
    # Artifact compatibility depends on this exact order.
    assert FEATURE_NAMES[0] == "path_len"
    assert "requests_last_window" in FEATURE_NAMES
    assert len(FEATURE_NAMES) == 14
