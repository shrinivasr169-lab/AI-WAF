"""Benchmark the AI-WAF gateway: latency percentiles + requests/second.

Starts the real FastAPI app with uvicorn on localhost (echo mode, ML enabled),
fires a mixed benign/attack load at it and prints the measured numbers, so
README performance claims can be reproduced on any machine:

    python scripts/benchmark.py --requests 500 --concurrency 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Configure logging *before* importing the app so its per-request INFO logs do
# not dominate the measurement (console I/O would otherwise be timed as
# gateway latency). app.main only calls basicConfig when the root logger is
# unconfigured, so this level wins.
logging.basicConfig(level=logging.WARNING)

# Benchmark configuration (fixed before app import).
os.environ.setdefault("WAF_MODE", "enforce")
os.environ.setdefault("ML_ENABLED", "true")
os.environ.setdefault("UPSTREAM_URL", "")
os.environ.setdefault("RATE_LIMIT_REQUESTS", "0")
os.environ.setdefault("DB_PATH", str(Path(tempfile.mkdtemp()) / "bench_events.db"))

import httpx  # noqa: E402
import uvicorn  # noqa: E402

BENIGN = [
    "GET /products?category=shoes&page=1",
    "GET /basket",
    "POST /api/checkout",
    "GET /search?q=running+shoes",
    "GET /api/products/42",
]
ATTACK = [
    "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "GET /api/products?id=1%27%20OR%20%271%27%3D%271",
    "GET /download?file=..%2F..%2Fetc%2Fpasswd",
]


def percentile(sorted_values: list[float], q: float) -> float:
    position = q * (len(sorted_values) - 1)
    low = int(position)
    high = min(low + 1, len(sorted_values) - 1)
    weight = position - low
    return sorted_values[low] * (1 - weight) + sorted_values[high] * weight


async def worker(client: httpx.AsyncClient, requests: list[str], latencies: list[float]) -> None:
    for spec in requests:
        method, _, target = spec.partition(" ")
        started = time.perf_counter()
        response = await client.request(method, target)
        latencies.append((time.perf_counter() - started) * 1000)
        response.read()


async def run_load(port: int, total: int, concurrency: int) -> dict:
    # 20% attack traffic mixed in, matching the label ratio in sample data.
    schedule = [
        ATTACK[i % len(ATTACK)] if i % 5 == 0 else BENIGN[i % len(BENIGN)]
        for i in range(total)
    ]
    chunks = [schedule[i::concurrency] for i in range(concurrency)]
    latencies: list[float] = []

    async with httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{port}", timeout=30.0
    ) as client:
        # warm-up (connection pools, JIT, page cache)
        await asyncio.gather(*(worker(client, BENIGN, []) for _ in range(1)))

        started = time.perf_counter()
        await asyncio.gather(*(worker(client, chunk, latencies) for chunk in chunks))
        elapsed = time.perf_counter() - started

    latencies.sort()
    return {
        "requests": total,
        "concurrency": concurrency,
        "elapsed_s": round(elapsed, 3),
        "rps": round(total / elapsed, 1),
        "latency_ms": {
            "avg": round(statistics.fmean(latencies), 3),
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(latencies[-1], 3),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the AI-WAF gateway")
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    from app.main import app  # import after env is configured

    config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning")
    server = uvicorn.Server(config)
    import threading

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            import httpx as _httpx

            if _httpx.get(f"http://127.0.0.1:{args.port}/__waf/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.2)
    else:
        print("server failed to start", file=sys.stderr)
        return 1

    result = asyncio.run(run_load(args.port, args.requests, args.concurrency))
    print(json.dumps(result, indent=2))

    server.should_exit = True
    thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
