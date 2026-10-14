"""Central configuration for the AI-WAF gateway.

All runtime settings come from environment variables, optionally loaded from a
``.env`` file in the project root, so thresholds, target URLs and secrets never
live in source code. See ``.env.example`` for the documented list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"

VALID_MODES = ("monitor", "enforce")


def _load_dotenv(path: Path = DEFAULT_ENV_FILE) -> None:
    """Minimal ``KEY=VALUE`` reader that never overrides real env vars."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


def _get_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _get_opt_str(key: str) -> str | None:
    value = os.environ.get(key, "")
    value = value.strip()
    return value or None


def _get_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (TypeError, ValueError):
        return default


def _get_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, str(default)))
    except (TypeError, ValueError):
        return default


def _get_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


@dataclass(frozen=True)
class Settings:
    # --- server -----------------------------------------------------------
    host: str
    port: int
    # --- upstream target --------------------------------------------------
    upstream_url: str | None
    # --- decision policy --------------------------------------------------
    mode: str  # "monitor" (alert only) or "enforce" (allow/block)
    # --- inspection limits ------------------------------------------------
    max_body_bytes: int
    request_timeout_seconds: float
    rule_scan_limit: int
    # --- rate limiting ----------------------------------------------------
    rate_limit_requests: int
    rate_limit_window_seconds: int
    trusted_proxy_header: str | None
    # --- ML ---------------------------------------------------------------
    ml_enabled: bool
    ml_model_path: Path
    ml_alert_threshold: float | None  # None -> use model calibrated value
    ml_block_threshold: float | None  # None -> use model calibrated value
    ml_blocking_enabled: bool
    # --- audit log --------------------------------------------------------
    db_path: Path
    log_retention_days: int

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build (and cache) settings from the environment."""
    _load_dotenv()

    mode = _get_str("WAF_MODE", "monitor").strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(f"WAF_MODE must be one of {VALID_MODES}, got {mode!r}")

    alert_threshold = _get_opt_str("ML_ALERT_THRESHOLD")
    block_threshold = _get_opt_str("ML_BLOCK_THRESHOLD")

    return Settings(
        host=_get_str("WAF_HOST", "127.0.0.1"),
        port=_get_int("WAF_PORT", 8000),
        upstream_url=_get_opt_str("UPSTREAM_URL"),
        mode=mode,
        max_body_bytes=_get_int("MAX_BODY_BYTES", 1_048_576),
        request_timeout_seconds=_get_float("REQUEST_TIMEOUT_SECONDS", 10.0),
        rule_scan_limit=_get_int("RULE_SCAN_LIMIT", 10_000),
        rate_limit_requests=_get_int("RATE_LIMIT_REQUESTS", 120),
        rate_limit_window_seconds=_get_int("RATE_LIMIT_WINDOW_SECONDS", 60),
        trusted_proxy_header=_get_opt_str("TRUSTED_PROXY_HEADER"),
        ml_enabled=_get_bool("ML_ENABLED", True),
        ml_model_path=_resolve(_get_str("ML_MODEL_PATH", "models/model.joblib")),
        ml_alert_threshold=float(alert_threshold) if alert_threshold else None,
        ml_block_threshold=float(block_threshold) if block_threshold else None,
        ml_blocking_enabled=_get_bool("ML_BLOCKING_ENABLED", False),
        db_path=_resolve(_get_str("DB_PATH", "data/events.db")),
        log_retention_days=_get_int("LOG_RETENTION_DAYS", 30),
    )
