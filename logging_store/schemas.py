"""Event schema and redaction helpers for the audit log.

Everything that reaches SQLite goes through ``sanitize`` first:
* sensitive values (passwords, tokens, cookies, personal data) are masked,
* control characters and newlines are stripped so a payload cannot forge
  extra log lines (log injection),
* values are truncated to a bounded length.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

MAX_FIELD_LEN = 400

# key names whose values must never be stored
SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|authorization|auth|"
    r"cookie|session|ssid|ssn|cvv|card|credential|private[_-]?key)",
    re.IGNORECASE,
)

# value patterns masked anywhere in free text
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b\d{3}@\d{4}\b"), "***"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "***@***"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"), r"\1 ***"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b"), "***"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "***"),
)

_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_KV = re.compile(r"(?i)\b([A-Za-z_][\w-]*)\s*=\s*([^&;\s\"']+)")


class Decision:
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"  # allowed but flagged (monitor mode / ML alert)


class BlockedBy:
    RULE = "rule"
    ML = "ml"
    RATE_LIMIT = "rate_limit"
    BODY_SIZE = "body_size"


def sanitize(value: Any, limit: int = MAX_FIELD_LEN) -> str:
    """Strip control characters (log-injection guard) and truncate."""
    text = "" if value is None else str(value)
    text = _CONTROL.sub(" ", text)
    text = " ".join(text.split())
    return text[:limit]


def redact_text(value: Any, limit: int = MAX_FIELD_LEN) -> str:
    """Mask credentials / personal data, then sanitise and truncate."""
    text = "" if value is None else str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = _KV.sub(_mask_kv, text)
    return sanitize(text, limit)


def _mask_kv(match: re.Match[str]) -> str:
    key, value = match.group(1), match.group(2)
    if SENSITIVE_KEY.search(key):
        return f"{key}=***"
    return match.group(0)


def redact_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Copy headers, masking anything that looks sensitive."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        name = sanitize(key, 64)
        if SENSITIVE_KEY.search(name):
            out[name] = "***"
        else:
            out[name] = redact_text(value, 160)
    return out


def redact_path(path: str) -> str:
    """Path with sensitive values in embedded key=value pairs masked."""
    return redact_text(path, 300)


def redact_query(query: str) -> str:
    if not query:
        return ""
    return redact_text(query, 400)


@dataclass
class EventRecord:
    """One audit-log row. Values are pre-redacted by the caller helpers."""

    timestamp: str
    request_id: str
    client_ip: str
    method: str
    path: str
    query: str
    decision: str
    blocked_by: str | None
    status_code: int
    rule_ids: str  # comma separated
    categories: str  # comma separated
    ml_score: float | None
    ml_flag: bool
    latency_ms: float
    upstream: str
    user_agent: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_event(
    *,
    timestamp: str,
    request_id: str,
    client_ip: str,
    method: str,
    path: str,
    query: str,
    decision: str,
    blocked_by: str | None,
    status_code: int,
    rule_ids: list[str] | tuple[str, ...],
    categories: list[str] | tuple[str, ...],
    ml_score: float | None,
    ml_flag: bool,
    latency_ms: float,
    upstream: str,
    user_agent: str,
) -> EventRecord:
    return EventRecord(
        timestamp=timestamp,
        request_id=sanitize(request_id, 64),
        client_ip=sanitize(client_ip, 64),
        method=sanitize(method, 16),
        path=redact_path(path),
        query=redact_query(query),
        decision=decision,
        blocked_by=sanitize(blocked_by, 32) if blocked_by else None,
        status_code=int(status_code),
        rule_ids=",".join(sanitize(r, 32) for r in rule_ids),
        categories=",".join(sanitize(c, 48) for c in categories),
        ml_score=None if ml_score is None else round(float(ml_score), 4),
        ml_flag=bool(ml_flag),
        latency_ms=round(float(latency_ms), 3),
        upstream=sanitize(upstream, 16),
        user_agent=sanitize(user_agent, 160),
    )


def row_to_event(row: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a DB row into a JSON-friendly dict for the dashboard/API."""
    data = dict(row)
    data.pop("_raw", None)
    if data.get("ml_score") is not None:
        data["ml_score"] = float(data["ml_score"])
    data["rule_id_list"] = [r for r in str(data.get("rule_ids") or "").split(",") if r]
    data["category_list"] = [c for c in str(data.get("categories") or "").split(",") if c]
    data["ml_flag"] = bool(data.get("ml_flag"))
    return data
