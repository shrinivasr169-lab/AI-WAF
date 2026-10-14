"""Shared pytest fixtures.

Environment is configured *before* ``app.main`` is imported so the gateway
always starts from a known, safe configuration. ``make_app`` rebuilds the
FastAPI app with per-test overrides.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Base environment for every test run (overridden per test via make_app).
os.environ["WAF_MODE"] = "enforce"
os.environ["ML_ENABLED"] = "false"
os.environ["UPSTREAM_URL"] = ""
os.environ["RATE_LIMIT_REQUESTS"] = "0"  # disabled unless a test enables it
os.environ["DB_PATH"] = "data/test_events.db"


@pytest.fixture
def make_app(monkeypatch, tmp_path):
    """Factory: build a fresh gateway app with the given env overrides."""
    from app.config import get_settings

    def _make(**env: str):
        monkeypatch.setenv("DB_PATH", str(tmp_path / "events.db"))
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))
        get_settings.cache_clear()
        from app import main as main_module

        return main_module.create_app()

    yield _make
    get_settings.cache_clear()


@pytest.fixture
def client_factory(make_app):
    """Factory: app -> context-managed TestClient (runs lifespan)."""
    from fastapi.testclient import TestClient

    clients: list[TestClient] = []

    def _client(**env: str) -> TestClient:
        app = make_app(**env)
        client = TestClient(app)
        client.__enter__()  # run lifespan (db init / purge)
        clients.append(client)
        return client

    yield _client
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(client_factory):
    """Default test client (enforce mode, rules only, echo upstream)."""
    return client_factory()


@pytest.fixture
def events(client_factory):
    """Helper to read audit events back out of the app's store."""
    from logging_store.schemas import row_to_event

    def _events(app) -> list[dict]:
        return app.state.store.query(limit=1000)

    return _events
