"""Dashboard tests (requirements section 6: "dashboard refresh").

Runs the Streamlit app with ``streamlit.testing.v1.AppTest`` against the same
SQLite audit database a gateway instance just wrote to, and asserts the
rendered metrics reflect those events.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit.testing.v1", reason="streamlit AppTest unavailable")

from streamlit.testing.v1 import AppTest  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = PROJECT_ROOT / "dashboard" / "app.py"

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"


def _metrics(at: AppTest) -> dict[str, str]:
    return {m.label: m.value for m in at.metric}


def _selectbox(at: AppTest, label: str):
    """Find a selectbox by its label (element order is not UI order)."""
    for box in at.selectbox:
        if box.label == label:
            return box
    raise AssertionError(f"selectbox {label!r} not found")


def test_dashboard_reflects_gateway_events(client):
    """Events written by the gateway must show up in the rendered dashboard."""
    # benign traffic + one blocked XSS attempt (enforce mode from conftest)
    assert client.get("/products", headers={"user-agent": UA}).status_code == 200
    assert client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").status_code == 403

    at = AppTest.from_file(str(DASHBOARD), default_timeout=30)
    at.run()

    assert not at.exception, f"dashboard raised: {at.exception}"

    metrics = _metrics(at)
    assert metrics["Requests"] == "2"
    assert metrics["Allowed"] == "1"
    assert metrics["Blocked"] == "1"

    # Recent events table lists both requests with their decisions.
    events_json = str(at)
    assert "/products" in events_json
    assert "/search" in events_json


def test_dashboard_shows_empty_state_without_events(make_app):
    """A fresh database renders without errors (empty-state paths)."""
    make_app()  # creates the app + empty DB under the test env

    at = AppTest.from_file(str(DASHBOARD), default_timeout=30)
    at.run()

    assert not at.exception, f"dashboard raised: {at.exception}"
    assert _metrics(at)["Requests"] == "0"


def test_dashboard_filters_update_query(client):
    """Sidebar filters must drive the event query (filter/search controls)."""
    client.get("/products", headers={"user-agent": UA})
    client.get("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")

    at = AppTest.from_file(str(DASHBOARD), default_timeout=30)
    at.run()
    assert not at.exception

    # select the "block" decision filter and rerun
    _selectbox(at, "Decision").select("block").run()
    assert not at.exception

    rows = str(at)
    assert "/search" in rows
    assert "/products" not in rows
