"""Isolation Forest anomaly model with calibrated thresholds and safe fallback.

Design notes
------------
* ``load_model`` never raises: if the artifact is missing or scikit-learn is
  unavailable the gateway falls back to rule-only inspection (requirement:
  "if the ML model is unavailable, known-rule checks should still work").
* Raw IsolationForest scores are mapped to a stable 0..1 range using the
  median/standard deviation of *benign* training scores, so thresholds stay
  meaningful across retrained artifacts.
* Alert/block thresholds are *measured* on benign training scores (95th/99th
  percentile = ~5% / ~1% false-positive budget) instead of being guessed,
  which keeps the default policy conservative.
* The estimator is fitted on benign traffic only, so attacks are scored
  against a model of normal behaviour (labels are used only for evaluation).

CLI: ``python -m detection.model`` trains, evaluates on a held-out split and
prints precision / recall / false-positive rate / confusion matrix.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from detection.features import (
    DEFAULT_RATE_WINDOW,
    FEATURE_NAMES,
    extract_features,
    to_vector,
)

ALERT_THRESHOLD_DEFAULT = 0.65
BLOCK_THRESHOLD_DEFAULT = 0.90
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class EvalReport:
    """Metrics produced by a training run (also stored in the artifact)."""

    n_samples: int = 0
    n_train: int = 0
    n_test: int = 0
    alert_threshold: float = 0.0
    block_threshold: float = 0.0
    ml_precision: float = 0.0
    ml_recall: float = 0.0
    ml_false_positive_rate: float = 0.0
    ml_accuracy: float = 0.0
    ml_confusion: dict[str, int] = field(default_factory=dict)
    rule_precision: float = 0.0
    rule_recall: float = 0.0
    rule_false_positive_rate: float = 0.0
    rule_confusion: dict[str, int] = field(default_factory=dict)
    trained_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def _safe_div(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth and pred:
            tp += 1
        elif pred:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, float]:
    c = _confusion(y_true, y_pred)
    return {
        "precision": _safe_div(c["tp"], c["tp"] + c["fp"]),
        "recall": _safe_div(c["tp"], c["tp"] + c["fn"]),
        "false_positive_rate": _safe_div(c["fp"], c["fp"] + c["tn"]),
        "accuracy": _safe_div(c["tp"] + c["tn"], len(y_true)),
    }


class AnomalyModel:
    """Scoring wrapper that is safe to use even when no model is loaded."""

    def __init__(
        self,
        estimator: Any | None = None,
        center: float = 0.0,
        scale: float = 1.0,
        alert_threshold: float = ALERT_THRESHOLD_DEFAULT,
        block_threshold: float = BLOCK_THRESHOLD_DEFAULT,
        reason: str = "",
        trained_at: str = "",
    ) -> None:
        self._estimator = estimator
        self.center = center
        self.scale = scale if scale > 1e-9 else 1.0
        self.alert_threshold = alert_threshold
        self.block_threshold = max(block_threshold, alert_threshold)
        self.reason = reason
        self.trained_at = trained_at

    @property
    def available(self) -> bool:
        return self._estimator is not None

    def score(self, features: Mapping[str, float]) -> float | None:
        """Return an anomaly score in 0..1, or None when unavailable."""
        if not self.available:
            return None
        import numpy as np

        vector = np.array([to_vector(features)], dtype=float)
        raw = -float(self._estimator.decision_function(vector)[0])
        return float(min(max(_sigmoid((raw - self.center) / self.scale), 0.0), 1.0))

    def classify(self, score: float | None) -> str:
        """Map a score to 'none' | 'alert' | 'block'."""
        if score is None:
            return "none"
        if score >= self.block_threshold:
            return "block"
        if score >= self.alert_threshold:
            return "alert"
        return "none"


def load_model(path: Path) -> AnomalyModel:
    """Load the saved artifact; never raises (fallback = rule-only mode)."""
    if not path.is_file():
        return AnomalyModel(reason=f"model artifact not found: {path}")
    try:
        import joblib  # noqa: F401

        payload = joblib.load(path)
        estimator = payload["estimator"]
        feature_names = tuple(payload.get("feature_names", FEATURE_NAMES))
        if feature_names != FEATURE_NAMES:
            return AnomalyModel(
                reason="feature mismatch between artifact and code; retrain the model"
            )
        return AnomalyModel(
            estimator=estimator,
            center=float(payload.get("center", 0.0)),
            scale=float(payload.get("scale", 1.0)),
            alert_threshold=float(payload.get("alert_threshold", ALERT_THRESHOLD_DEFAULT)),
            block_threshold=float(payload.get("block_threshold", BLOCK_THRESHOLD_DEFAULT)),
            trained_at=str(payload.get("trained_at", "")),
        )
    except Exception as exc:  # pragma: no cover - defensive by design
        return AnomalyModel(reason=f"failed to load model: {exc}")


# ---------------------------------------------------------------------------
# Training / evaluation
# ---------------------------------------------------------------------------
def _offline_features(samples: Sequence[Mapping[str, Any]], window: float) -> list[dict[str, float]]:
    """Compute features (incl. request-rate) for labelled sample requests."""
    ordered = sorted(
        enumerate(samples),
        key=lambda pair: (str(pair[1].get("client", "")), float(pair[1].get("timestamp", 0))),
    )
    by_index: dict[int, dict[str, float]] = {}
    per_client: dict[str, list[float]] = {}
    last_seen: dict[str, float] = {}

    for index, sample in ordered:
        client = str(sample.get("client", "unknown"))
        now = float(sample.get("timestamp", 0))
        history = per_client.setdefault(client, [])
        history.append(now)
        cutoff = now - window
        count = sum(1 for ts in history if ts > cutoff)
        gap = (now - last_seen[client]) if client in last_seen else window
        last_seen[client] = now

        features = extract_features(
            path=str(sample.get("path", "/")),
            query=str(sample.get("query", "")),
            headers={str(k).lower(): str(v) for k, v in dict(sample.get("headers", {})).items()},
            body=str(sample.get("body", "")),
            requests_last_window=count,
            seconds_since_last_request=max(gap, 0.0),
        )
        by_index[index] = features
    return [by_index[i] for i in range(len(samples))]


def _rule_predictions(samples: Sequence[Mapping[str, Any]]) -> list[int]:
    from detection.rules import inspect_request

    predictions: list[int] = []
    for sample in samples:
        path = str(sample.get("path", "/"))
        query = str(sample.get("query", ""))
        raw_target = f"{path}?{query}" if query else path
        headers = {str(k).lower(): str(v) for k, v in dict(sample.get("headers", {})).items()}
        findings = inspect_request(
            method=str(sample.get("method", "GET")),
            raw_target=raw_target,
            path=path,
            query=query,
            headers=headers,
            body=str(sample.get("body", "")),
        )
        predictions.append(1 if findings else 0)
    return predictions


def train_baseline(
    samples: Sequence[Mapping[str, Any]],
    out_path: Path,
    *,
    report_path: Path | None = None,
    test_size: float = 0.3,
    random_state: int = 42,
    window: float = DEFAULT_RATE_WINDOW,
) -> EvalReport:
    """Train IsolationForest, measure it on held-out data and save artifact."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.model_selection import train_test_split

    if len(samples) < 20:
        raise ValueError("need at least 20 sample requests to train")

    features = _offline_features(samples, window)
    x = np.array([to_vector(f) for f in features], dtype=float)
    y = np.array([int(s.get("label", 0)) for s in samples], dtype=int)

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Classic anomaly-detection setup: fit on *benign* training traffic only,
    # so attacks are judged against a model of normal behaviour.
    benign_train = x_train[y_train == 0]
    fit_x = benign_train if len(benign_train) >= 10 else x_train

    estimator = IsolationForest(
        n_estimators=200,
        contamination="auto",
        max_samples="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    estimator.fit(fit_x)

    raw_fit = -estimator.decision_function(fit_x)
    center = float(np.median(raw_fit))
    scale = float(np.std(raw_fit)) or 1e-6

    # Thresholds carry a measured false-positive budget on benign traffic:
    # alert at the 95th percentile (~5% FPR), block at the 99th (~1% FPR).
    normalized_benign = [min(max(_sigmoid((v - center) / scale), 0.0), 1.0) for v in raw_fit]
    alert_threshold = round(float(np.quantile(normalized_benign, 0.95)), 4)
    block_threshold = round(float(np.quantile(normalized_benign, 0.99)), 4)
    if block_threshold < alert_threshold + 0.03:
        block_threshold = round(min(alert_threshold + 0.1, 0.99), 4)

    def predict(vectors: np.ndarray, threshold: float) -> list[int]:
        raw = -estimator.decision_function(vectors)
        return [1 if _sigmoid((v - center) / scale) >= threshold else 0 for v in raw]

    ml_pred = predict(x_test, alert_threshold)
    ml_metrics = _metrics(y_test.tolist(), ml_pred)

    # Rule engine measured on the same samples for comparison.
    rule_pred = _rule_predictions(samples)
    y_list = y.tolist()
    rule_metrics = _metrics(y_list, rule_pred)

    report = EvalReport(
        n_samples=len(samples),
        n_train=len(x_train),
        n_test=len(x_test),
        alert_threshold=alert_threshold,
        block_threshold=block_threshold,
        ml_precision=ml_metrics["precision"],
        ml_recall=ml_metrics["recall"],
        ml_false_positive_rate=ml_metrics["false_positive_rate"],
        ml_accuracy=ml_metrics["accuracy"],
        ml_confusion=_confusion(y_test.tolist(), ml_pred),
        rule_precision=rule_metrics["precision"],
        rule_recall=rule_metrics["recall"],
        rule_false_positive_rate=rule_metrics["false_positive_rate"],
        rule_confusion=_confusion(y_list, rule_pred),
        trained_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(
        {
            "estimator": estimator,
            "center": center,
            "scale": scale,
            "alert_threshold": alert_threshold,
            "block_threshold": block_threshold,
            "feature_names": FEATURE_NAMES,
            "trained_at": report.trained_at,
            "metrics": report.as_dict(),
        },
        out_path,
    )

    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")

    return report


def _load_samples(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return list(payload.get("requests", []))
    return list(payload)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the AI-WAF anomaly model")
    parser.add_argument("--data", default="data/sample_requests.json")
    parser.add_argument("--out", default="models/model.joblib")
    parser.add_argument("--report", default="data/evaluation_report.json")
    args = parser.parse_args(argv)

    samples = _load_samples(Path(args.data))
    report = train_baseline(samples, Path(args.out), report_path=Path(args.report))

    print(f"Trained on {report.n_train} / evaluated on {report.n_test} held-out samples")
    print(f"alert threshold = {report.alert_threshold}  block threshold = {report.block_threshold}")
    print("ML  precision={p} recall={r} fpr={f} accuracy={a} confusion={c}".format(
        p=report.ml_precision, r=report.ml_recall, f=report.ml_false_positive_rate,
        a=report.ml_accuracy, c=report.ml_confusion))
    print("Rules precision={p} recall={r} fpr={f} confusion={c}".format(
        p=report.rule_precision, r=report.rule_recall,
        f=report.rule_false_positive_rate, c=report.rule_confusion))
    print(f"Saved artifact -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
