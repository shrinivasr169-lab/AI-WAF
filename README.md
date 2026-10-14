# AI-Powered Web Application Firewall (AI-WAF)

A local HTTP/API gateway that inspects every request with two independent layers — a
deterministic **signature rule engine** and a machine-learning **anomaly detector** — makes an
explainable **allow / block / alert** decision, records a **redacted** audit event in SQLite, and
surfaces the traffic in a **Streamlit dashboard**.

> **Educational prototype.** This is a learning / portfolio project, not a drop-in replacement
> for a professionally configured WAF. Run it only against targets you are authorised to test
> (for example, OWASP Juice Shop on localhost). See [Limitations](#9-limitations).

**At a glance**

| | |
| --- | --- |
| **Stack** | Python 3.11+ · FastAPI + Uvicorn · scikit-learn · SQLite · Streamlit |
| **Detection** | 15 signature rules + Isolation Forest anomaly model |
| **Modes** | `monitor` (alert only) · `enforce` (allow / block) |
| **Tests** | 76 pytest tests — all passing |
| **Docs** | [`README.md`](README.md) · [`.env.example`](.env.example) |

---

## Contents

1. [Architecture](#1-architecture)
2. [Quick start](#2-quick-start)
3. [Configuration](#3-configuration)
4. [Detection](#4-detection)
5. [API](#5-api)
6. [Audit logging & redaction](#6-audit-logging--redaction)
7. [Dashboard](#7-dashboard)
8. [Testing & results](#8-testing--results)
9. [Limitations](#9-limitations)
10. [Threat model](#10-threat-model)
11. [Project layout](#11-project-layout)

---

## 1. Architecture

```text
Client
 └─▶ FastAPI + Uvicorn ................ app/main.py
       │  operational endpoints:  /__waf/health · /__waf/stats · /__waf/events
       │  catch-all proxy:        /{path}
       └─▶ Gateway pipeline ............ app/gateway.py
             │  identity → rate limit → read body → rules → ML score → decide → forward
             ├─▶ Upstream target (httpx)  ·  or local echo responder when UPSTREAM_URL is empty
             └─▶ Redacted audit event ──▶ SQLite (WAL) ──▶ Streamlit dashboard ... dashboard/app.py
```

### Module map

| Path | Responsibility |
| --- | --- |
| `app/main.py` | FastAPI app, operational endpoints, catch-all proxy route, startup / shutdown |
| `app/gateway.py` | Inspection pipeline: identity → rate limit → body → rules → ML → decide → forward → audit |
| `app/config.py` | Environment-driven settings (`.env` aware); single source of truth |
| `detection/rules.py` | Deterministic signature rules (SQLi, XSS, traversal, malformed, command injection) |
| `detection/features.py` | Feature extraction + `RateTracker` (shared by live traffic *and* training) |
| `detection/model.py` | Isolation Forest wrapper, calibrated thresholds, training / evaluation CLI |
| `logging_store/schemas.py` | Event schema + redaction helpers (credentials, PII, log-injection guard) |
| `logging_store/db.py` | Thread-safe SQLite audit store (WAL, retention purge, stats aggregation) |
| `dashboard/app.py` | Streamlit security dashboard (KPIs, charts, filters, recent events) |
| `scripts/benchmark.py` | Reproducible latency / throughput benchmark against the real app |
| `tests/` | pytest suite (76 tests across 6 files) |

### Request pipeline

The order is deliberate, so every decision is explainable:

| # | Stage | Notes |
| --- | --- | --- |
| 1 | Resolve client identity | Proxy header is trusted **only** when `TRUSTED_PROXY_HEADER` is set, otherwise any client could spoof its IP |
| 2 | Rate limit per client | Cheap; runs before any body is read. Over limit → `429` |
| 3 | Read body with a hard byte cap | Oversized → `413`; the body is never fully buffered |
| 4 | Rule engine | Always runs, independent of the ML model |
| 5 | ML anomaly score | Optional; fails safe when unavailable |
| 6 | Decision policy | `monitor` never blocks; `enforce` blocks on rule matches, and on ML scores only when `ML_BLOCKING_ENABLED=true` |
| 7 | Forward + audit | Permitted traffic is proxied upstream (or echoed locally); every request writes one redacted event |

---

## 2. Quick start

```bash
# 1. Enter the project
cd ai-waf

# 2. Create a virtual environment and install pinned dependencies (Python 3.11+)
python -m venv .venv
source .venv/Scripts/activate        # Windows (Git Bash) — use .venv/bin/activate on Linux/macOS
pip install -r requirements.txt

# 3. Create your config (defaults to the safe "monitor" mode)
cp .env.example .env

# 4. Train the baseline model
#    writes models/model.joblib + data/evaluation_report.json
python -m detection.model
```

Then run the gateway and dashboard in **two terminals**:

```bash
# Terminal 1 — gateway (echo mode: no upstream target required)
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — dashboard (bind to localhost explicitly; see the note below)
streamlit run dashboard/app.py --server.address 127.0.0.1
```

Open <http://127.0.0.1:8501> for the dashboard, or send traffic directly:

```bash
curl "http://127.0.0.1:8000/products?category=shoes"                     # → 200 allow
curl "http://127.0.0.1:8000/search?q=%3Cscript%3Ealert(1)%3C/script%3E"  # → alert (monitor) / 403 block (enforce)
curl "http://127.0.0.1:8000/__waf/health"                                # → status + thresholds
```

### Pointing at a lab target

Set `UPSTREAM_URL` in `.env` (leave it empty for echo mode), then start your target — for example
OWASP Juice Shop on `http://127.0.0.1:3000`:

```ini
# .env
UPSTREAM_URL=http://127.0.0.1:3000
WAF_MODE=monitor                     # start in monitor mode, review the dashboard, then switch to enforce
```

---

## 3. Configuration

All settings come from environment variables (optionally via `.env`), so thresholds, target URLs
and secrets never live in source. The documented template is [`.env.example`](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_HOST` / `WAF_PORT` | `127.0.0.1` / `8000` | Bind address for the gateway |
| `UPSTREAM_URL` | *(empty)* | Lab target to proxy; empty = built-in echo responder |
| `WAF_MODE` | `monitor` | `monitor` = log / alert only · `enforce` = allow / block |
| `MAX_BODY_BYTES` | `1048576` | Hard request-body cap (`413` above it) |
| `REQUEST_TIMEOUT_SECONDS` | `10` | Upstream timeout (`504` on expiry) |
| `RULE_SCAN_LIMIT` | `10000` | Characters scanned per request location |
| `RATE_LIMIT_REQUESTS` | `120` | Per-client requests per window (`0` disables) |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `TRUSTED_PROXY_HEADER` | *(empty)* | Header trusted for the client IP — set only behind a trusted proxy |
| `ML_ENABLED` | `true` | Enable the anomaly layer |
| `ML_MODEL_PATH` | `models/model.joblib` | Model artifact |
| `ML_ALERT_THRESHOLD` / `ML_BLOCK_THRESHOLD` | *(empty)* | Override calibrated thresholds (empty = use trained values) |
| `ML_BLOCKING_ENABLED` | `false` | Let the model block on its own — keep `false` until measured |
| `DB_PATH` | `data/events.db` | SQLite audit database |
| `LOG_RETENTION_DAYS` | `30` | Events older than this are purged at startup |

### Decision policy

| Situation | `monitor` | `enforce` |
| --- | --- | --- |
| Rule match | `alert` (200, flagged) | `block` (403) |
| ML score ≥ block threshold **and** `ML_BLOCKING_ENABLED=true` | `alert` | `block` (403) |
| ML score ≥ alert threshold | `alert` | `alert` |
| Rate limit exceeded | `block` (429) | `block` (429) |
| Body over `MAX_BODY_BYTES` | `block` (413) | `block` (413) |
| Otherwise | `allow` | `allow` |

---

## 4. Detection

### Rule engine — `detection/rules.py`

15 signature rules, each a compiled regex matched against a decoded view of the request
(percent-encoding is decoded twice, so `%3Cscript%3E` becomes `<script>`). Matched evidence is
sanitised — control characters stripped, length truncated — before it can reach a log.

| Category | Rules |
| --- | --- |
| **SQL injection** | `SQLI-001` UNION SELECT · `SQLI-002` boolean tautology · `SQLI-003` SQL statements · `SQLI-004` quote + comment · `SQLI-005` SELECT…FROM + metacharacters |
| **Cross-site scripting** | `XSS-001` script tag · `XSS-002` event handler · `XSS-003` script URL scheme · `XSS-004` dangerous tag / DOM sink |
| **Path traversal** | `TRAVERSAL-001` dot-dot slash · `TRAVERSAL-002` sensitive system file |
| **Malformed** | `MALFORMED-001` NUL byte · `MALFORMED-002` control characters · `MALFORMED-003` invalid percent-encoding |
| **Command injection** | `CMDI-001` shell metacharacter chain |

`SQLI-005` carries a context condition (a SQL metacharacter must also be present), so ordinary
English such as *"select shoes from the store"* is not flagged.

### ML engine — `detection/model.py`

- **Model** — scikit-learn `IsolationForest`, fitted on **benign traffic only**, so attacks are
  scored against a model of normal behaviour; labels are used only for evaluation.
- **Features (14, fixed order)** — `path_len`, `query_len`, `body_len`, `param_count`,
  `header_count`, `non_alnum_ratio`, `digit_ratio`, `suspicious_char_ratio`, `pct_encoded_count`,
  `path_depth`, `requests_last_window`, `seconds_since_last_request`, `user_agent_len`,
  `has_json_content_type`. Live traffic and training share the same `extract_features`, so
  inference can never drift from training.
- **Score** — raw isolation scores are mapped to a stable `0..1` range using the median and
  standard deviation of benign training scores.
- **Thresholds are measured, not guessed** — alert = 95th percentile of benign scores (~5%
  false-positive budget), block = 99th (~1%). A model score is *never* treated as proof of an
  attack, which is why ML blocking is off by default.

Train and evaluate:

```bash
python -m detection.model                 # uses data/sample_requests.json
# alert threshold = ...   block threshold = ...
# ML     precision=... recall=... fpr=... accuracy=... confusion={...}
# Rules  precision=... recall=... fpr=... confusion={...}
```

### Fail-safe behaviour

If the model artifact is missing, unreadable, corrupt, or was trained with a different feature
order, the gateway logs a warning and runs **rule-only**: known-rule checks still protect
traffic, and `/__waf/health` reports `ml_available: false` with the reason. Audit logging is
equally safe — a persistence failure is logged and the response is still returned.

---

## 5. API

| Endpoint | Description |
| --- | --- |
| `GET /__waf/health` | Status, mode, ML availability and thresholds, configured limits |
| `GET /__waf/stats?window_minutes=60` | Aggregated KPIs: totals, block rate, latency percentiles, categories, top rules, timeline |
| `GET /__waf/events` | Recent audit events; filters: `decision`, `category`, `search`, `since_minutes`, `limit`, `offset` |
| `ANY /{path}` | Catch-all inspection proxy (also serves `/docs` and `/openapi.json`) |

A blocked request returns the reason and correlation id:

```json
{
  "detail": "Blocked by security rules: XSS-001",
  "request_id": "…",
  "blocked_by": "rule",
  "rule_ids": ["XSS-001"],
  "categories": ["xss"]
}
```

Every response carries `X-WAF-Decision` and `X-WAF-Request-ID`; allowed requests are forwarded
upstream with the correlation id, so a request can be traced end to end.

---

## 6. Audit logging & redaction

Each request produces one redacted row in SQLite:

```text
timestamp · request_id · client_ip · method · path · query · decision · blocked_by
status_code · rule_ids · categories · ml_score · ml_flag · latency_ms · upstream · user_agent
```

Redaction happens **before** storage — `logging_store/schemas.py`:

- **Masked keys** — password, secret, token, api_key, authorization, cookie, session, SSN, CVV,
  card, credential, private_key (in headers and `key=value` pairs).
- **Masked values** — emails, `Bearer` / `Basic` credentials, JWT-shaped strings, long digit runs
  (card- or phone-like).
- **Log-injection guard** — control characters and newlines are stripped, so a payload cannot
  forge extra log lines; all values are truncated to a bounded length.

Retention follows `LOG_RETENTION_DAYS` (purged at startup). SQLite runs in WAL mode so the
dashboard can read the same file from a second process.

---

## 7. Dashboard

```bash
streamlit run dashboard/app.py --server.address 127.0.0.1
```

Shows total / allowed / blocked / flagged counts, p95 latency and req/s, a traffic timeline,
attack-category and blocked-reason charts, top matched rules, and a filterable recent-events
table (decision, category, path / request-id / IP search) with a redacted payload detail view.

> **Bind to localhost.** Streamlit listens on `0.0.0.0` (every interface) by default, which would
> expose request paths, client IPs and event metadata to your whole network — inconsistent with
> the local-only stance of this project. Pass `--server.address 127.0.0.1`.

---

## 8. Testing & results

```bash
python -m pytest                                      # 76 tests
python scripts/benchmark.py --requests 500 --concurrency 10
```

The suite covers: every rule (including benign-lookalike traffic), the decision policy in both
modes, rate limiting, oversized bodies, malformed encodings, redaction and log injection, the
model-unavailable fallback, upstream forwarding / blocking / failure, the stats API, dashboard
rendering against real events (via `streamlit.testing.v1.AppTest`), and ML training quality on
held-out data.

**Current result: 76 passed** (Python 3.13.5).

### ML evaluation — `data/evaluation_report.json`, 91 labelled samples

| Layer | Precision | Recall | False-positive rate | Accuracy |
| --- | --- | --- | --- | --- |
| ML (Isolation Forest) | 1.00 | 0.833 | 0.00 | 0.929 |
| Rules | 1.00 | 1.00 | 0.00 | 1.00 |

ML confusion matrix on the held-out split: `tp=10, fp=0, tn=16, fn=2`. The ML layer complements
the rules on *unseen* patterns; the rules carry the known signatures.

### Performance — `scripts/benchmark.py`, echo mode, 500 requests @ concurrency 10

| Configuration | Throughput | p50 | p95 | p99 |
| --- | --- | --- | --- | --- |
| Rules only (`ML_ENABLED=false`) | ~224 req/s | 32 ms | 75 ms | 242 ms |
| Rules + ML | ~58 req/s | 113 ms | 503 ms | 780 ms |

Mean *processing* cost measured in isolation: rules ≈ 0.04 ms/request, SQLite audit write ≈
0.85 ms/request, ML single-row scoring ≈ 12.4 ms/request. The ML scoring call dominates total
latency — see [Limitations](#9-limitations). Numbers are machine-specific; re-run the benchmark
to reproduce them.

---

## 9. Limitations

- **Not production-ready.** An educational prototype, not a substitute for a professionally
  configured WAF. Layering ModSecurity + OWASP CRS is future work.
- **ML scoring is the latency bottleneck.** scikit-learn 1.9.1's `IsolationForest` scores a single
  sample by dispatching **one joblib task per tree** (200 trees), paying a Python-level
  `check_is_fitted` and warnings/config wrapper per tree — ≈12 ms per single-row request, versus
  ≈0.04 ms for the entire rule set. It scales with `n_estimators`, and the GIL serialises it, so
  throughput drops from ~224 to ~58 req/s with the ML layer on. Mitigations: run with
  `ML_ENABLED=false` for maximum throughput, lower `n_estimators` when retraining, or score in
  batches. The overhead does **not** change the scores.
- **Model quality is bounded by the sample set** (91 labelled requests). Retrain on traffic that
  represents your environment before trusting the anomaly layer — hence the default
  `ML_BLOCKING_ENABLED=false`.
- **Signature rules are a starter set** (15 regex rules), not a curated rule pack; they target
  common test patterns, not every real-world payload.
- **State is per-process and in memory.** The rate tracker resets on restart and is not shared
  across workers.
- **Redaction is heuristic.** Regex masking reduces leakage but is not a guarantee; treat the
  audit store as sensitive.
- **Benchmark numbers are single-machine** and include localhost client/server overhead, so they
  are comparative rather than absolute.
- **`pandas` is pinned but unused.** The requirements document suggested it as an initial package;
  no source module imports it.

---

## 10. Threat model

**In scope** — what the gateway defends against:

- Known attack signatures in the path, query, headers and body (SQLi, XSS, path traversal,
  command injection, malformed or over-encoded input).
- Oversized request bodies (bounded read → `413`).
- Per-client request floods (sliding-window rate limit → `429`).
- Malformed percent-encoding, NUL bytes and raw control characters.
- Accidental secret / PII leakage into logs (redaction) and log injection (single-line sanitising).
- Upstream unavailability or timeouts (fail safe with `502` / `504`, still audited).
- ML artifact tampering or unavailability (validated feature order, rule-only fallback).

**Out of scope** — explicitly not defended:

- **TLS.** The prototype speaks plain HTTP and is meant to bind to localhost. Put a TLS
  terminator in front before exposing it, and set `TRUSTED_PROXY_HEADER` only then. The gateway
  defaults to `127.0.0.1`; the dashboard needs `--server.address 127.0.0.1` because Streamlit
  otherwise listens on all interfaces.
- **Protocol-level attacks** — request smuggling, HTTP/2 attacks, slowloris beyond the body cap
  and timeout, header-count / header-size exhaustion.
- **Application logic abuse** — business-logic flaws, authentication and session weaknesses,
  broken access control (IDOR), CSRF tokens, file-upload content.
- **Response inspection.** Only inbound requests are inspected; response bodies and data
  exfiltration are not.
- **Denial of service at scale.** No distributed rate limiting; the in-memory `RateTracker` is
  per-process and resets on restart.
- **Adversarial ML evasion.** An attacker who shapes features to look benign can evade the
  anomaly detector — which is precisely why it does not block by default.

---

## 11. Project layout

```text
ai-waf/
├── app/              main.py · gateway.py · config.py
├── detection/        rules.py · features.py · model.py
├── logging_store/    db.py · schemas.py
├── dashboard/        app.py
├── scripts/          benchmark.py
├── tests/            test_rules · test_gateway · test_features
│                     test_model · test_redaction · test_dashboard
├── data/             sample_requests.json (91 labelled samples) · evaluation_report.json
├── models/           model.joblib (trained artifact)
├── requirements.txt  pinned dependencies
├── .env.example      documented configuration template
├── .gitignore
└── README.md
```

### Build phases (requirements checklist)

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | FastAPI gateway + deterministic rules + allow / block / alert | ✅ 15 signature rules |
| 2 | SQLite audit events + pytest tests + size and rate limits | ✅ redaction included |
| 3 | ML feature extraction + baseline model + measured thresholds | ✅ 14 features |
| 4 | Streamlit dashboard with charts and filters | ✅ KPIs + timeline |
| 5 | Lab validation and documentation | ✅ results / limitations documented · *future:* Juice Shop runs, ModSecurity/CRS, Docker |
