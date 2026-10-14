"""Gateway pipeline: read -> rate-limit -> inspect -> detect -> decide -> forward.

Order of operations (documented so failures are explainable):

1. Resolve the client identity (with an explicit trusted-proxy opt-in).
2. Rate limit per client (cheap, runs before any body is read).
3. Read the body with a hard size cap (oversized -> 413).
4. Deterministic rule engine (works even if the ML model is unavailable).
5. Feature extraction + ML anomaly score (optional, fails safe).
6. Decision policy: monitor mode never blocks; enforce mode blocks on rule
   matches, and only on ML scores when ML blocking is explicitly enabled.
7. Forward permitted traffic upstream (or answer locally when no target is
   configured) and write the redacted audit event.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import Settings
from detection.features import RateTracker, extract_features
from detection.model import AnomalyModel
from detection.rules import RuleMatch, inspect_request
from logging_store.db import EventStore, now_iso
from logging_store.schemas import BlockedBy, Decision, build_event

log = logging.getLogger("aiwaf.gateway")

HOP_BY_HOP_REQUEST = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
HOP_BY_HOP_RESPONSE = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

# Test seam: tests inject an httpx.MockTransport to capture forwarded traffic.
_upstream_transport: httpx.BaseTransport | None = None


def set_upstream_transport(transport: httpx.BaseTransport | None) -> None:
    global _upstream_transport
    _upstream_transport = transport


@dataclass
class Inspection:
    request_id: str
    method: str
    raw_target: str
    path: str
    query: str
    headers: dict[str, str]
    content_type: str
    body: bytes
    body_text: str
    client_ip: str
    user_agent: str
    oversize_body: bool = False


@dataclass
class Verdict:
    decision: str
    blocked_by: str | None
    status_code: int
    matches: list[RuleMatch] = field(default_factory=list)
    ml_score: float | None = None
    ml_action: str = "none"
    reason: str = ""
    rate_count: int = 0

    @property
    def allowed(self) -> bool:
        return self.decision != Decision.BLOCK

    @property
    def rule_ids(self) -> list[str]:
        return [m.rule_id for m in self.matches]

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for match in self.matches:
            if match.category not in seen:
                seen.append(match.category)
        return seen


def resolve_client_ip(request: Request, settings: Settings) -> str:
    """Client identity for rate limiting.

    The proxy header is only trusted when explicitly configured; trusting it
    blindly would let any client spoof its identity.
    """
    if settings.trusted_proxy_header:
        value = request.headers.get(settings.trusted_proxy_header, "")
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def read_body(request: Request, max_bytes: int) -> tuple[bytes, bool]:
    """Stream the body up to ``max_bytes``; returns (body, oversize_flag)."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            return b"", True
        chunks.append(chunk)
    return b"".join(chunks), False


def build_inspection(
    request: Request,
    body: bytes,
    oversize: bool,
    settings: Settings,
    client_ip: str,
) -> Inspection:
    url = request.url
    query = url.query or ""
    raw_target = url.path + (f"?{query}" if query else "")
    headers = {key.lower(): value for key, value in request.headers.items()}
    try:
        body_text = body.decode("utf-8", errors="replace") if body else ""
    except Exception:  # pragma: no cover - decode with replace never raises
        body_text = ""
    return Inspection(
        request_id=str(uuid.uuid4()),
        method=request.method.upper(),
        raw_target=raw_target,
        path=url.path or "/",
        query=query,
        headers=headers,
        content_type=headers.get("content-type", ""),
        body=body,
        body_text=body_text,
        client_ip=client_ip,
        user_agent=headers.get("user-agent", ""),
        oversize_body=oversize,
    )


def evaluate(
    inspection: Inspection,
    *,
    settings: Settings,
    rate_tracker: RateTracker,
    model: AnomalyModel,
) -> Verdict:
    """Apply rate limiting, rules and ML, then decide allow/block/alert."""
    # 1. rate limiting (the hit is recorded even when later stages block)
    count, _gap = rate_tracker.observe(inspection.client_ip)
    if settings.rate_limit_requests > 0 and count > settings.rate_limit_requests:
        return Verdict(
            decision=Decision.BLOCK,
            blocked_by=BlockedBy.RATE_LIMIT,
            status_code=429,
            reason="Rate limit exceeded for this client",
            rate_count=count,
        )

    # 2. body size limit
    if inspection.oversize_body:
        return Verdict(
            decision=Decision.BLOCK,
            blocked_by=BlockedBy.BODY_SIZE,
            status_code=413,
            reason=f"Request body exceeds {settings.max_body_bytes} bytes",
            rate_count=count,
        )

    # 3. deterministic rules (always run, independent of the model)
    matches = inspect_request(
        method=inspection.method,
        raw_target=inspection.raw_target,
        path=inspection.path,
        query=inspection.query,
        headers=inspection.headers,
        body=inspection.body_text,
        scan_limit=settings.rule_scan_limit,
    )

    # 4. ML anomaly score (fails safe when unavailable/disabled)
    ml_score: float | None = None
    ml_action = "none"
    if settings.ml_enabled:
        features = extract_features(
            path=inspection.path,
            query=inspection.query,
            headers=inspection.headers,
            body=inspection.body_text,
            requests_last_window=count,
            seconds_since_last_request=_gap,
        )
        ml_score = model.score(features)
        ml_action = model.classify(ml_score)

    ml_blocks = (
        settings.enforce
        and settings.ml_blocking_enabled
        and ml_action == "block"
    )
    flagged = bool(matches) or ml_action in ("alert", "block")

    # 5. decision policy
    if settings.enforce and matches:
        return Verdict(
            decision=Decision.BLOCK,
            blocked_by=BlockedBy.RULE,
            status_code=403,
            matches=matches,
            ml_score=ml_score,
            ml_action=ml_action,
            reason=f"Blocked by security rules: {', '.join(v.rule_id for v in matches)}",
            rate_count=count,
        )
    if ml_blocks:
        return Verdict(
            decision=Decision.BLOCK,
            blocked_by=BlockedBy.ML,
            status_code=403,
            matches=matches,
            ml_score=ml_score,
            ml_action=ml_action,
            reason="Blocked by anomaly model score above the block threshold",
            rate_count=count,
        )
    if flagged:
        return Verdict(
            decision=Decision.ALERT,
            blocked_by=None,
            status_code=0,  # filled from the upstream response
            matches=matches,
            ml_score=ml_score,
            ml_action=ml_action,
            reason="Flagged for review (monitor mode)" if settings.mode == "monitor" else "Flagged for review",
            rate_count=count,
        )
    return Verdict(
        decision=Decision.ALLOW,
        blocked_by=None,
        status_code=0,
        matches=[],
        ml_score=ml_score,
        ml_action=ml_action,
        reason="Allowed",
        rate_count=count,
    )


def _block_response(verdict: Verdict, request_id: str) -> Response:
    return JSONResponse(
        status_code=verdict.status_code,
        content={
            "detail": verdict.reason,
            "request_id": request_id,
            "blocked_by": verdict.blocked_by,
            "rule_ids": verdict.rule_ids,
            "categories": verdict.categories,
        },
        headers={
            "X-WAF-Decision": "block",
            "X-WAF-Request-ID": request_id,
            "Cache-Control": "no-store",
        },
    )


async def forward(inspection: Inspection, settings: Settings, verdict: Verdict) -> Response:
    """Send an allowed request upstream (or answer locally without a target)."""
    headers = {
        key: value
        for key, value in inspection.headers.items()
        if key not in HOP_BY_HOP_REQUEST
    }
    headers["X-WAF-Request-ID"] = inspection.request_id
    headers["X-WAF-Decision"] = verdict.decision

    if not settings.upstream_url:
        # Local echo mode: lets the demo/tests run without a lab target.
        return JSONResponse(
            status_code=200,
            content={
                "service": "ai-waf echo responder",
                "request_id": inspection.request_id,
                "decision": verdict.decision,
                "method": inspection.method,
                "path": inspection.path,
                "note": "No UPSTREAM_URL configured; set it to proxy a local test app.",
            },
            headers={"X-WAF-Decision": verdict.decision, "X-WAF-Request-ID": inspection.request_id},
        )

    url = settings.upstream_url.rstrip("/") + inspection.raw_target
    try:
        async with httpx.AsyncClient(
            transport=_upstream_transport,
            timeout=settings.request_timeout_seconds,
            follow_redirects=False,
        ) as client:
            upstream = await client.request(
                inspection.method,
                url,
                headers=headers,
                content=inspection.body if inspection.body else None,
            )
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={"detail": "Upstream target timed out", "request_id": inspection.request_id},
            headers={"X-WAF-Decision": verdict.decision, "X-WAF-Request-ID": inspection.request_id},
        )
    except httpx.HTTPError as exc:
        log.warning("upstream error for %s: %s", inspection.request_id, type(exc).__name__)
        return JSONResponse(
            status_code=502,
            content={"detail": "Upstream target unavailable", "request_id": inspection.request_id},
            headers={"X-WAF-Decision": verdict.decision, "X-WAF-Request-ID": inspection.request_id},
        )

    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in HOP_BY_HOP_RESPONSE
    }
    response_headers["X-WAF-Decision"] = verdict.decision
    response_headers["X-WAF-Request-ID"] = inspection.request_id
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


def record_event(
    *,
    inspection: Inspection,
    verdict: Verdict,
    settings: Settings,
    store: EventStore,
    latency_ms: float,
    status_code: int,
) -> None:
    """Persist one redacted audit event; logging must never break the request."""
    try:
        event = build_event(
            timestamp=now_iso(),
            request_id=inspection.request_id,
            client_ip=inspection.client_ip,
            method=inspection.method,
            path=inspection.path,
            query=inspection.query,
            decision=verdict.decision,
            blocked_by=verdict.blocked_by,
            status_code=status_code,
            rule_ids=verdict.rule_ids,
            categories=verdict.categories,
            ml_score=verdict.ml_score,
            ml_flag=verdict.decision == Decision.ALERT,
            latency_ms=latency_ms,
            upstream="local" if not settings.upstream_url else "upstream",
            user_agent=inspection.user_agent,
        )
        store.insert(event)
    except Exception:  # pragma: no cover - fail-safe by design
        log.exception("failed to persist audit event")


async def handle(request: Request) -> Response:
    """Full gateway pipeline for one inbound request."""
    started = time.perf_counter()
    app = request.app
    settings: Settings = app.state.settings
    store: EventStore = app.state.store
    rate_tracker: RateTracker = app.state.rate_tracker
    model: AnomalyModel = app.state.model

    client_ip = resolve_client_ip(request, settings)
    body, oversize = await read_body(request, settings.max_body_bytes)
    inspection = build_inspection(request, body, oversize, settings, client_ip)

    # CPU-bound inspection (rules + ML scoring) runs in a worker thread so
    # one slow score never stalls the event loop for every other request.
    verdict = await anyio.to_thread.run_sync(
        lambda: evaluate(
            inspection, settings=settings, rate_tracker=rate_tracker, model=model
        )
    )

    if verdict.allowed:
        response = await forward(inspection, settings, verdict)
        status_code = response.status_code
    else:
        response = _block_response(verdict, inspection.request_id)
        status_code = verdict.status_code

    latency_ms = (time.perf_counter() - started) * 1000
    if "X-WAF-Request-ID" not in response.headers:
        response.headers["X-WAF-Request-ID"] = inspection.request_id
    await anyio.to_thread.run_sync(
        lambda: record_event(
            inspection=inspection,
            verdict=verdict,
            settings=settings,
            store=store,
            latency_ms=latency_ms,
            status_code=status_code,
        )
    )
    log.info(
        "%s %s -> %s (%s) score=%s latency=%.1fms id=%s",
        inspection.method,
        inspection.path,
        status_code,
        verdict.decision,
        "n/a" if verdict.ml_score is None else f"{verdict.ml_score:.3f}",
        latency_ms,
        inspection.request_id,
    )
    return response
