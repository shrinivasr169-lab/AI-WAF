"""FastAPI application: WAF control endpoints + catch-all inspection proxy.

Route order matters: the ``/__waf/*`` operational endpoints are registered
before the catch-all proxy route so they are never inspected as traffic.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request
from starlette.responses import JSONResponse

from app import gateway
from app.config import get_settings
from detection.features import RateTracker
from detection.model import AnomalyModel, load_model
from logging_store.db import EventStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("aiwaf")

PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store: EventStore = app.state.store
        purged = store.purge_old()
        if purged:
            log.info("purged %s events beyond %s day retention", purged, settings.log_retention_days)
        yield
        store.close()

    app = FastAPI(
        title="AI-Powered WAF",
        version="0.1.0",
        description="Local HTTP/API gateway combining signature rules with ML anomaly detection.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = EventStore(settings.db_path, retention_days=settings.log_retention_days)
    app.state.rate_tracker = RateTracker(window_seconds=settings.rate_limit_window_seconds)
    if settings.ml_enabled:
        app.state.model = load_model(settings.ml_model_path)
    else:
        app.state.model = AnomalyModel(reason="ML disabled by configuration (ML_ENABLED=false)")
    if not app.state.model.available:
        log.warning("ML model unavailable, running rule-only: %s", app.state.model.reason)
    else:
        log.info(
            "ML model loaded (alert>=%.2f, block>=%.2f)",
            app.state.model.alert_threshold,
            app.state.model.block_threshold,
        )

    # ------------------------------------------------------------------
    # Operational endpoints (never proxied, never inspected)
    # ------------------------------------------------------------------
    @app.get("/__waf/health")
    async def health() -> dict:
        model = app.state.model
        return {
            "status": "ok",
            "mode": settings.mode,
            "ml_enabled": settings.ml_enabled,
            "ml_available": model.available,
            "ml_reason": model.reason,
            "ml_alert_threshold": model.alert_threshold,
            "ml_block_threshold": model.block_threshold,
            "ml_blocking_enabled": settings.ml_blocking_enabled,
            "upstream_url": settings.upstream_url,
            "max_body_bytes": settings.max_body_bytes,
            "rate_limit": {
                "requests": settings.rate_limit_requests,
                "window_seconds": settings.rate_limit_window_seconds,
            },
            "db_path": str(settings.db_path),
        }

    @app.get("/__waf/stats")
    async def stats(window_minutes: int = Query(60, ge=1, le=10080)) -> dict:
        return app.state.store.stats(since_minutes=window_minutes)

    @app.get("/__waf/events")
    async def events(
        decision: str | None = None,
        category: str | None = None,
        search: str | None = None,
        since_minutes: int | None = Query(None, ge=1, le=10080),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> dict:
        items = app.state.store.query(
            decision=decision,
            category=category,
            search=search,
            since_minutes=since_minutes,
            limit=limit,
            offset=offset,
        )
        return {"count": len(items), "events": items}

    # ------------------------------------------------------------------
    # Catch-all: inspect -> decide -> forward
    # ------------------------------------------------------------------
    @app.api_route("/{path:path}", methods=PROXY_METHODS, include_in_schema=False)
    async def waf_proxy(request: Request) -> JSONResponse:
        return await gateway.handle(request)  # type: ignore[return-value]

    return app


app = create_app()
