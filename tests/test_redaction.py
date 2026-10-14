"""Tests for redaction and log-injection protection."""

from __future__ import annotations

from logging_store.schemas import build_event, redact_headers, redact_text, sanitize


def test_password_and_token_values_masked():
    text = "login password=hunter2&token=abcdef123456&user=bob"
    cleaned = redact_text(text)
    assert "hunter2" not in cleaned
    assert "abcdef123456" not in cleaned
    assert "password=***" in cleaned
    assert "token=***" in cleaned
    assert "user=bob" in cleaned  # non-sensitive values are kept


def test_email_and_card_masked():
    text = "contact alice@example.com with card 4111 1111 1111 1111"
    cleaned = redact_text(text)
    assert "alice@example.com" not in cleaned
    assert "4111" not in cleaned
    assert "***" in cleaned


def test_bearer_token_masked():
    cleaned = redact_text("Authorization: Bearer eyJhbGciOi.payload.signature")
    assert "eyJ" not in cleaned.replace("***", "")


def test_control_characters_and_newlines_stripped():
    dirty = "name=ok\r\nFAKE LOG LINE\r\n\x00\x1b[31m"
    cleaned = sanitize(dirty)
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\x00" not in cleaned
    assert "\x1b" not in cleaned


def test_sanitize_truncates():
    assert len(sanitize("x" * 5000)) == 400


def test_headers_masked():
    headers = {
        "user-agent": "Mozilla/5.0",
        "authorization": "Bearer abcdef123456",
        "cookie": "session=deadbeef",
        "x-api-key": "sk-secret-value",
    }
    cleaned = redact_headers(headers)
    assert cleaned["user-agent"] == "Mozilla/5.0"
    assert cleaned["authorization"] == "***"
    assert cleaned["cookie"] == "***"
    assert cleaned["x-api-key"] == "***"


def test_build_event_redacts_query_and_path():
    event = build_event(
        timestamp="2026-01-01T00:00:00Z",
        request_id="req-1",
        client_ip="10.0.0.1",
        method="POST",
        path="/api/login",
        query="password=supersecret&user=bob",
        decision="allow",
        blocked_by=None,
        status_code=200,
        rule_ids=[],
        categories=[],
        ml_score=None,
        ml_flag=False,
        latency_ms=12.3456,
        upstream="local",
        user_agent="Mozilla/5.0\r\nInjected: header",
    )
    assert "supersecret" not in event.query
    assert "password=***" in event.query
    assert "\n" not in event.user_agent and "\r" not in event.user_agent
    assert "Injected" in event.user_agent  # content kept, single line only
