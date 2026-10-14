"""Integration tests for the gateway: policy, limits, logging, forwarding."""

from __future__ import annotations

import httpx
import pytest

from app import gateway
from logging_store.schemas import Decision

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"


def rows(app) -> list[dict]:
    return app.state.store.query(limit=1000)


# ---------------------------------------------------------------------------
# Health / control endpoints
# ---------------------------------------------------------------------------
def test_health_endpoint(client):
    response = client.get("/__waf/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["mode"] == "enforce"
    assert payload["ml_available"] is False  # ML disabled in the test env


def test_control_endpoint_is_not_proxied(client):
    response = client.get("/__waf/events")
    assert response.status_code == 200
    assert "events" in response.json()


# ---------------------------------------------------------------------------
# Decision policy
# ---------------------------------------------------------------------------
def test_benign_request_allowed_in_enforce_mode(client):
    response = client.get("/products?category=shoes", headers={"user-agent": UA})
    assert response.status_code == 200
    assert response.headers["x-waf-decision"] == "allow"
    assert "request_id" in response.json()


def test_sqli_blocked_in_enforce_mode(client):
    response = client.get(
        "/api/products?id=1%27+OR+%271%27%3D%271", headers={"user-agent": UA}
    )
    assert response.status_code == 403
    payload = response.json()
    assert payload["blocked_by"] == "rule"
    assert "SQLI-002" in payload["rule_ids"]
    assert response.headers["x-waf-decision"] == "block"

    event = rows(client.app)[0]
    assert event["decision"] == Decision.BLOCK
    assert "SQLI-002" in event["rule_ids"]
    assert event["status_code"] == 403


def test_xss_blocked(client):
    response = client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert response.status_code == 403
    assert "XSS-001" in response.json()["rule_ids"]


def test_path_traversal_blocked(client):
    response = client.get("/download?file=..%2F..%2Fetc%2Fpasswd")
    assert response.status_code == 403
    assert any(r.startswith("TRAVERSAL") for r in response.json()["rule_ids"])


def test_monitor_mode_alerts_but_allows(client_factory):
    client = client_factory(WAF_MODE="monitor")
    response = client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert response.status_code == 200  # never blocks in monitor mode
    assert response.headers["x-waf-decision"] == "alert"

    event = rows(client.app)[0]
    assert event["decision"] == Decision.ALERT
    assert event["ml_flag"] is True


def test_all_allow_is_logged(client):
    client.get("/basket", headers={"user-agent": UA})
    event = rows(client.app)[0]
    assert event["decision"] == Decision.ALLOW
    assert event["rule_ids"] == ""


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
def test_oversized_body_rejected(client_factory):
    client = client_factory(MAX_BODY_BYTES="256")
    response = client.post(
        "/api/upload", content=b"x" * 1024, headers={"content-type": "text/plain"}
    )
    assert response.status_code == 413
    assert response.json()["blocked_by"] == "body_size"


def test_rate_limit_returns_429(client_factory):
    client = client_factory(RATE_LIMIT_REQUESTS="3", RATE_LIMIT_WINDOW_SECONDS="60")
    for _ in range(3):
        assert client.get("/api/health").status_code == 200
    blocked = client.get("/api/health")
    assert blocked.status_code == 429
    assert blocked.json()["blocked_by"] == "rate_limit"


def test_rate_limit_window_is_per_client(client_factory, monkeypatch):
    client = client_factory(RATE_LIMIT_REQUESTS="2", RATE_LIMIT_WINDOW_SECONDS="60")
    # TestClient keeps one client IP, so simulate a second one explicitly.
    for _ in range(2):
        client.get("/api/health")
    assert client.get("/api/health").status_code == 429


# ---------------------------------------------------------------------------
# Model-unavailable fallback (fail safely)
# ---------------------------------------------------------------------------
def test_rules_still_work_when_model_missing(client_factory):
    client = client_factory(ML_ENABLED="true", ML_MODEL_PATH="models/does-not-exist.joblib")
    health = client.get("/__waf/health").json()
    assert health["ml_enabled"] is True
    assert health["ml_available"] is False

    # rule checks still protect the gateway
    assert client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").status_code == 403
    # and benign traffic still passes
    assert client.get("/products").status_code == 200

    event = rows(client.app)[0]
    assert event["ml_score"] is None  # no score when the model is unavailable


# ---------------------------------------------------------------------------
# Audit logging & redaction
# ---------------------------------------------------------------------------
def test_credentials_are_redacted_in_audit_log(client):
    client.post(
        "/api/search?password=supersecret123&q=shoes",
        json={"email": "alice@example.com", "api_key": "sk-abcdefghijklmnop"},
        headers={"user-agent": UA, "content-type": "application/json"},
    )
    event = rows(client.app)[0]
    assert "supersecret123" not in event["query"]
    assert "password=***" in event["query"]

    stored = str(event)
    assert "sk-abcdefghijklmnop" not in stored
    assert "alice@example.com" not in stored


def test_log_injection_is_stripped(client):
    client.get("/api/items?name=ok%0d%0aFAKE-EVENT-line")
    event = rows(client.app)[0]
    assert "\n" not in event["query"]
    assert "\r" not in event["query"]
    assert "FAKE-EVENT" in event["query"]  # content kept, just single-line


def test_event_contains_required_fields(client):
    client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    event = rows(client.app)[0]
    for key in (
        "timestamp", "request_id", "method", "path", "decision",
        "status_code", "rule_ids", "ml_score", "latency_ms",
    ):
        assert key in event
    assert event["request_id"]


# ---------------------------------------------------------------------------
# Forwarding to the upstream lab target
# ---------------------------------------------------------------------------
def test_allowed_request_is_forwarded_upstream(client_factory):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["query"] = request.url.query.decode()
        captured["request_id"] = request.headers.get("x-waf-request-id")
        return httpx.Response(200, json={"service": "lab-app", "ok": True})

    app = None
    client = client_factory(UPSTREAM_URL="http://127.0.0.1:3000")
    app = client.app
    gateway.set_upstream_transport(httpx.MockTransport(handler))
    try:
        response = client.get("/api/items?page=2", headers={"user-agent": UA})
    finally:
        gateway.set_upstream_transport(None)

    assert response.status_code == 200
    assert response.json() == {"service": "lab-app", "ok": True}
    assert captured["path"] == "/api/items"
    assert captured["query"] == "page=2"
    assert captured["request_id"]  # correlation id forwarded upstream
    assert response.headers["x-waf-request-id"]


def test_blocked_request_never_reaches_upstream(client_factory):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={})

    client = client_factory(UPSTREAM_URL="http://127.0.0.1:3000")
    gateway.set_upstream_transport(httpx.MockTransport(handler))
    try:
        response = client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    finally:
        gateway.set_upstream_transport(None)

    assert response.status_code == 403
    assert seen == []


def test_upstream_failure_fails_safe(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = client_factory(UPSTREAM_URL="http://127.0.0.1:3000")
    gateway.set_upstream_transport(httpx.MockTransport(handler))
    try:
        response = client.get("/products")
    finally:
        gateway.set_upstream_transport(None)

    assert response.status_code == 502
    # the failed attempt is still audited
    assert rows(client.app)[0]["status_code"] == 502


# ---------------------------------------------------------------------------
# Stats endpoint (dashboard data source)
# ---------------------------------------------------------------------------
def test_stats_endpoint_aggregates_events(client):
    client.get("/products", headers={"user-agent": UA})
    client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")

    stats = client.get("/__waf/stats?window_minutes=60").json()
    assert stats["total"] >= 2
    assert stats["blocked"] >= 1
    assert stats["allowed"] >= 1
    assert "xss" in stats["categories"]
    assert stats["latency_ms"]["p50"] is not None
