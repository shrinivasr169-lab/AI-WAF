"""Streamlit security dashboard for the AI-WAF.

Reads the same SQLite audit database the gateway writes (WAL mode) and renders
a dark "security operations" console: a hero header with a derived threat
level, accent KPI cards, hand-built SVG charts (traffic timeline, decision
donut, category / block-reason bars, rule pills) and a filterable event log.

Everything visual is plain HTML/CSS/SVG injected through ``st.markdown`` — no
extra dependencies and no network round-trips for fonts or JS. Data comes from
:class:`logging_store.db.EventStore`, the same source the ``/__waf/stats`` API
serves.

Run with:  streamlit run dashboard/app.py
"""

from __future__ import annotations

import html
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import get_settings  # noqa: E402
from detection.rules import CATEGORIES  # noqa: E402
from logging_store.db import EventStore  # noqa: E402

st.set_page_config(
    page_title="AI-WAF · Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Palette (kept in one place so the CSS and the inline SVG agree)
# ---------------------------------------------------------------------------
CYAN = "#22d3ee"
VIOLET = "#8b5cf6"
GREEN = "#34d399"
AMBER = "#fbbf24"
RED = "#f87171"
SLATE = "#8f9dc0"

BLOCKED_BY_LABELS: dict[str, str] = {
    "rule": "Rule engine",
    "ml": "Anomaly model",
    "rate_limit": "Rate limit",
    "body_size": "Body size",
}

_CSS = """
<style>
:root{
  --bg:#070b16; --panel:rgba(255,255,255,.035); --border:rgba(255,255,255,.09);
  --text:#e8eefc; --muted:#8f9dc0;
  --cyan:#22d3ee; --violet:#8b5cf6; --green:#34d399; --amber:#fbbf24; --red:#f87171;
}

.stApp{
  background:
    radial-gradient(1100px 520px at 10% -8%, rgba(34,211,238,.10), transparent 58%),
    radial-gradient(900px 460px at 92% -4%, rgba(139,92,246,.13), transparent 55%),
    linear-gradient(180deg,#070b16,#05080f 70%);
  color:var(--text);
}
[data-testid="stHeader"]{background:transparent;}

/* -- sidebar ------------------------------------------------------------- */
[data-testid="stSidebar"]{
  background:linear-gradient(180deg,rgba(12,18,34,.97),rgba(6,10,18,.97));
  border-right:1px solid var(--border);
}
.brand{font-size:1.05rem;font-weight:800;letter-spacing:-.01em;}
.brand-sub{color:var(--muted);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;margin-bottom:6px;}

/* -- hero ---------------------------------------------------------------- */
.hero{
  display:flex;justify-content:space-between;align-items:center;gap:1.5rem;flex-wrap:wrap;
  padding:22px 26px;margin:4px 0 18px;border-radius:20px;
  background:linear-gradient(135deg,rgba(34,211,238,.10),rgba(139,92,246,.10) 55%,rgba(255,255,255,.02));
  border:1px solid var(--border);
  box-shadow:0 18px 50px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.05);
}
.hero-badge{
  display:inline-block;font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--cyan);border:1px solid rgba(34,211,238,.35);border-radius:999px;
  padding:3px 11px;margin-bottom:10px;background:rgba(34,211,238,.08);
}
.hero-title{
  margin:0;font-size:2rem;line-height:1.1;font-weight:800;letter-spacing:-.03em;
  background:linear-gradient(90deg,#eaf6ff,#7dd3fc 45%,#a78bfa);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.hero-sub{color:var(--muted);font-size:.84rem;margin-top:9px;line-height:1.7;}
.hero-sub code{background:rgba(255,255,255,.06);padding:1px 7px;border-radius:6px;color:#cfe3ff;}
.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-weight:700;color:var(--c);
  border:1px solid var(--c);background:rgba(255,255,255,.05);letter-spacing:.02em;}
.hero-right{text-align:right;}
.threat{
  display:inline-flex;flex-direction:column;align-items:flex-end;gap:3px;
  padding:11px 18px;border-radius:14px;border:1px solid var(--c);background:rgba(255,255,255,.03);
  box-shadow:0 0 26px -10px var(--c);
}
.threat-label{font-size:.64rem;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);}
.threat-value{font-size:1.15rem;font-weight:800;color:var(--c);letter-spacing:.06em;}
.hero-refresh{color:var(--muted);font-size:.71rem;margin-top:10px;}

/* -- section titles ------------------------------------------------------ */
.sec-title{
  display:flex;align-items:center;gap:9px;font-size:.75rem;font-weight:700;
  letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:2px 0 12px;
}
.sec-title::before{content:"";width:3px;height:14px;border-radius:2px;
  background:linear-gradient(180deg,var(--cyan),var(--violet));}

/* -- KPI cards ----------------------------------------------------------- */
.st-key-kpis [data-testid="stColumn"]{gap:0;}
.kpi-accent{height:4px;border-radius:4px 4px 0 0;
  background:linear-gradient(90deg,var(--accent),rgba(255,255,255,0));}
[data-testid="stMetric"]{
  background:var(--panel);border:1px solid var(--border);border-radius:14px;
  padding:14px 16px 16px;
  box-shadow:0 12px 34px -22px rgba(0,0,0,.95), inset 0 1px 0 rgba(255,255,255,.04);
}
.st-key-kpis [data-testid="stMetric"]{border-radius:0 0 14px 14px;border-top:none;}
[data-testid="stMetricLabel"] p{
  color:var(--muted)!important;text-transform:uppercase;letter-spacing:.09em;
  font-size:.7rem;font-weight:600;
}
[data-testid="stMetricValue"]{font-weight:800;color:var(--text);letter-spacing:-.01em;}

/* -- panels & charts ----------------------------------------------------- */
.panel{
  background:var(--panel);border:1px solid var(--border);border-radius:16px;
  padding:16px 18px;box-shadow:0 14px 40px -30px rgba(0,0,0,.95);
}
.donut-wrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap;}
.legend{display:flex;flex-direction:column;gap:9px;min-width:150px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:.82rem;color:#cbd7f2;width:100%;}
.dot{width:9px;height:9px;border-radius:50%;background:currentColor;
  box-shadow:0 0 10px -1px currentColor;flex:0 0 auto;}
.legend-count{margin-left:auto;font-weight:700;color:#e8eefc;font-variant-numeric:tabular-nums;}

.bar-row{display:grid;grid-template-columns:132px 1fr 46px;align-items:center;gap:10px;margin:8px 0;}
.bar-label{color:#c9d6f2;font-size:.8rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.bar-track{height:9px;border-radius:999px;background:rgba(255,255,255,.06);overflow:hidden;}
.bar-fill{height:100%;border-radius:999px;background:var(--c);min-width:3px;
  box-shadow:0 0 12px -2px var(--c);}
.bar-value{text-align:right;font-variant-numeric:tabular-nums;color:#e8eefc;font-size:.8rem;font-weight:600;}

.rule-pill{display:inline-flex;align-items:center;gap:7px;margin:4px 6px 0 0;padding:4px 11px;
  border-radius:999px;background:rgba(139,92,246,.12);border:1px solid rgba(139,92,246,.32);
  font-size:.76rem;color:#ddd6fe;}
.rule-pill b{color:#fff;font-weight:700;}
.empty{color:var(--muted);font-size:.83rem;padding:6px 2px;}

/* -- native widgets ------------------------------------------------------ */
[data-testid="stDataFrame"]{border:1px solid var(--border);border-radius:14px;overflow:hidden;}
.stButton>button{
  border-radius:10px;border:1px solid rgba(34,211,238,.35);
  background:linear-gradient(135deg,rgba(34,211,238,.18),rgba(139,92,246,.18));
  color:#eaf6ff;font-weight:600;transition:.15s ease;
}
.stButton>button:hover{border-color:var(--cyan);box-shadow:0 0 22px -6px var(--cyan);color:#fff;}
[data-testid="stSidebar"] [data-baseweb="select"]>div,
[data-testid="stSidebar"] [data-baseweb="input"]>div{
  background:rgba(255,255,255,.045);border-color:var(--border);border-radius:10px;
}
[data-testid="stSidebar"] [data-testid="stSliderTickBar"]{color:var(--muted);}
[data-testid="stExpander"] details{border:1px solid var(--border);border-radius:12px;
  background:rgba(255,255,255,.02);}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.14);border-radius:8px;}
::-webkit-scrollbar-track{background:transparent;}
</style>
"""


# ---------------------------------------------------------------------------
# Small rendering helpers
# ---------------------------------------------------------------------------
def _esc(value: Any) -> str:
    """HTML-escape any value (audit fields are user-controlled)."""
    return html.escape("" if value is None else str(value))


def _accent(color: str) -> None:
    st.markdown(f'<div class="kpi-accent" style="--accent:{color}"></div>', unsafe_allow_html=True)


def _panel(title: str, inner: str) -> None:
    st.markdown(
        f'<div class="panel"><div class="sec-title">{_esc(title)}</div>{inner}</div>',
        unsafe_allow_html=True,
    )


def _empty(text: str) -> str:
    return f'<div class="empty">{_esc(text)}</div>'


def _threat_level(stats: Mapping[str, Any]) -> tuple[str, str]:
    """Derive a coarse threat level from the block ratio in the window."""
    total = int(stats.get("total") or 0)
    if total == 0:
        return "IDLE", SLATE
    rate = float(stats.get("block_rate") or 0.0)
    if rate >= 0.25:
        return "CRITICAL", RED
    if rate >= 0.10:
        return "ELEVATED", AMBER
    if rate > 0:
        return "GUARDED", CYAN
    return "NORMAL", GREEN


def _bars_html(
    values: Mapping[str, Any],
    color: str,
    labels: Mapping[str, str] | None = None,
) -> str:
    """Horizontal bar list for the first 8 entries of a count mapping."""
    if not values:
        return ""
    peak = max(int(v) for v in values.values()) or 1
    rows: list[str] = []
    for key, value in list(values.items())[:8]:
        label = (labels or {}).get(key, key)
        width = int(value) / peak * 100
        rows.append(
            '<div class="bar-row">'
            f'<div class="bar-label" title="{_esc(label)}">{_esc(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;--c:{color}"></div></div>'
            f'<div class="bar-value">{_esc(value)}</div>'
            "</div>"
        )
    return "".join(rows)


def _rule_pills(values: Mapping[str, Any]) -> str:
    if not values:
        return ""
    return "".join(
        f'<span class="rule-pill"><b>{_esc(rule_id)}</b><span>{_esc(count)}</span></span>'
        for rule_id, count in list(values.items())[:10]
    )


def _donut_svg(segments: Sequence[tuple[str, int, str]]) -> str:
    """Decision-mix donut; ``segments`` is (label, value, colour)."""
    total = sum(value for _label, value, _color in segments)
    radius = 56.0
    circumference = 2 * math.pi * radius
    rings: list[str] = []
    offset = 0.0
    for _label, value, color in segments:
        if total <= 0 or value <= 0:
            continue
        dash = (value / total) * circumference
        rings.append(
            f'<circle cx="80" cy="80" r="{radius}" fill="none" stroke="{color}" stroke-width="16" '
            f'stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 80 80)"/>'
        )
        offset += dash
    if not rings:
        rings.append(
            f'<circle cx="80" cy="80" r="{radius}" fill="none" '
            'stroke="rgba(255,255,255,.08)" stroke-width="16"/>'
        )
    return (
        '<svg viewBox="0 0 160 160" style="width:152px;height:152px;display:block">'
        + "".join(rings)
        + f'<text x="80" y="76" text-anchor="middle" fill="#e8eefc" font-size="28" '
        f'font-weight="700">{total}</text>'
        + '<text x="80" y="96" text-anchor="middle" fill="#8f9dc0" font-size="10" '
        'letter-spacing="2">REQUESTS</text>'
        + "</svg>"
    )


def _legend_html(segments: Sequence[tuple[str, int, str]]) -> str:
    total = sum(value for _label, value, _color in segments) or 1
    items = "".join(
        '<div class="legend-item">'
        f'<span class="dot" style="color:{color}"></span>'
        f'<span>{_esc(label)}</span>'
        f'<span class="legend-count">{value} · {value / total * 100:.0f}%</span>'
        "</div>"
        for label, value, color in segments
    )
    return f'<div class="legend">{items}</div>'


def _timeline_svg(timeline: Sequence[Mapping[str, Any]]) -> str:
    """Area-with-overlay-lines chart of the per-minute traffic buckets."""
    width, height, pad = 760.0, 210.0, 18.0
    count = len(timeline)
    peak = max(
        [float(row.get("total", 0)) for row in timeline]
        + [float(row.get("block", 0)) for row in timeline]
        + [float(row.get("alert", 0)) for row in timeline]
        + [1.0]
    )

    def x(index: int) -> float:
        return pad + (width - 2 * pad) * (index / (count - 1) if count > 1 else 0.5)

    def y(value: float) -> float:
        return height - pad - (height - 2 * pad) * (value / peak)

    def polyline(key: str) -> str:
        return " ".join(
            f"{x(i):.1f},{y(float(row.get(key, 0))):.1f}" for i, row in enumerate(timeline)
        )

    total_line = polyline("total")
    area = f"{x(0):.1f},{height - pad:.1f} {total_line} {x(count - 1):.1f},{height - pad:.1f}"

    grid = "".join(
        f'<line x1="{pad}" y1="{y(peak * frac):.1f}" x2="{width - pad}" y2="{y(peak * frac):.1f}" '
        'stroke="rgba(255,255,255,.07)" stroke-width="1"/>'
        for frac in (0.25, 0.5, 0.75, 1.0)
    )

    labels = ""
    for index in sorted({0, count // 2, count - 1}):
        bucket = str(timeline[index].get("bucket", ""))
        anchor = "middle" if 0 < index < count - 1 else ("start" if index == 0 else "end")
        labels += (
            f'<text x="{x(index):.1f}" y="{height - 2:.1f}" fill="#7f8db0" font-size="11" '
            f'text-anchor="{anchor}">{_esc(bucket[11:16] or bucket)}</text>'
        )

    return (
        f'<svg viewBox="0 0 {width:.0f} {height:.0f}" style="width:100%;height:auto;display:block">'
        "<defs><linearGradient id=\"fill-total\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\">"
        '<stop offset="0%" stop-color="#22d3ee" stop-opacity="0.45"/>'
        '<stop offset="100%" stop-color="#22d3ee" stop-opacity="0.02"/>'
        "</linearGradient></defs>"
        f"{grid}"
        f'<polygon points="{area}" fill="url(#fill-total)"/>'
        f'<polyline points="{total_line}" fill="none" stroke="{CYAN}" stroke-width="2"/>'
        f'<polyline points="{polyline("alert")}" fill="none" stroke="{AMBER}" stroke-width="1.6"/>'
        f'<polyline points="{polyline("block")}" fill="none" stroke="{RED}" stroke-width="1.6"/>'
        f"{labels}"
        "</svg>"
    )


def _timeline_legend() -> str:
    items = "".join(
        f'<span class="rule-pill"><span class="dot" style="color:{color}"></span>{_esc(label)}</span>'
        for label, color in (("total", CYAN), ("alerts", AMBER), ("blocked", RED))
    )
    return f'<div style="margin-top:6px">{items}</div>'


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------
@st.cache_resource
def get_store(db_path: str) -> EventStore:
    return EventStore(db_path)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def _hero(settings: Any, stats: Mapping[str, Any]) -> None:
    level, level_color = _threat_level(stats)
    mode_color = AMBER if settings.mode == "monitor" else GREEN
    upstream = settings.upstream_url or "echo responder (local)"
    st.markdown(
        f"""
<div class="hero">
  <div class="hero-left">
    <div class="hero-badge">🛡️ AI-WAF</div>
    <h1 class="hero-title">Security Operations Console</h1>
    <div class="hero-sub">
      mode <span class="pill" style="--c:{mode_color}">{_esc(settings.mode)}</span>
      &nbsp;·&nbsp; upstream <code>{_esc(upstream)}</code>
      &nbsp;·&nbsp; audit db <code>{_esc(settings.db_path)}</code>
    </div>
  </div>
  <div class="hero-right">
    <div class="threat" style="--c:{level_color}">
      <span class="threat-label">Threat level</span>
      <span class="threat-value">{_esc(level)}</span>
    </div>
    <div class="hero-refresh">window {int(stats.get("window_minutes", 0))} min · updated {datetime.now():%H:%M:%S}</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def _kpis(stats: Mapping[str, Any]) -> None:
    latency = stats.get("latency_ms") or {}
    p95 = latency.get("p95")
    cards = [
        ("Requests", f"{stats['total']:,}", CYAN),
        ("Allowed", f"{stats['allowed']:,}", GREEN),
        ("Blocked", f"{stats['blocked']:,}", RED),
        ("Flagged (alerts)", f"{stats['flagged']:,}", AMBER),
        ("p95 latency (ms)", f"{p95:.1f}" if p95 is not None else "–", VIOLET),
        ("Req/s (avg)", f"{stats['requests_per_second']}", CYAN),
    ]
    with st.container(key="kpis"):
        for column, (label, value, color) in zip(st.columns(len(cards)), cards):
            with column:
                _accent(color)
                st.metric(label, value)


def _charts(stats: Mapping[str, Any]) -> None:
    timeline = stats.get("timeline") or []

    _panel(
        "Traffic over time",
        (_timeline_svg(timeline) + _timeline_legend())
        if timeline
        else _empty("No traffic recorded in the selected window."),
    )

    segments = [
        ("Allow", int(stats.get("allowed", 0)), GREEN),
        ("Alert", int(stats.get("flagged", 0)), AMBER),
        ("Block", int(stats.get("blocked", 0)), RED),
    ]

    left, right = st.columns([1, 1.15])
    with left:
        _panel(
            "Decision mix",
            '<div class="donut-wrap">'
            + _donut_svg(segments)
            + _legend_html(segments)
            + "</div>",
        )
    with right:
        categories = stats.get("categories") or {}
        _panel(
            "Attack categories",
            _bars_html(categories, VIOLET, CATEGORIES)
            if categories
            else _empty("No attack categories recorded in this window."),
        )

    lower_left, lower_right = st.columns(2)
    with lower_left:
        blocked_by = stats.get("blocked_by") or {}
        _panel(
            "Why requests were blocked",
            _bars_html(blocked_by, RED, BLOCKED_BY_LABELS)
            if blocked_by
            else _empty("No blocked requests in this window."),
        )
    with lower_right:
        top_rules = stats.get("top_rules") or {}
        _panel(
            "Top matched rules",
            _rule_pills(top_rules) if top_rules else _empty("No rules matched in this window."),
        )

    ml_avg = stats.get("ml_score_avg")
    if ml_avg is not None:
        st.caption(f"Average anomaly score in window: **{ml_avg}**")


def _events(
    store: EventStore,
    window_minutes: int,
    decision_filter: str,
    category_filter: str,
    search: str,
) -> None:
    st.markdown('<div class="sec-title" style="margin-top:22px">Recent events</div>', unsafe_allow_html=True)
    events = store.query(
        decision=None if decision_filter == "All" else decision_filter,
        category=None if category_filter == "All" else category_filter,
        search=search.strip() or None,
        since_minutes=window_minutes,
        limit=200,
    )
    if not events:
        st.markdown(_empty("No events match the current filters."), unsafe_allow_html=True)
        return

    rows: list[dict[str, Any]] = []
    for event in events:
        rows.append(
            {
                "time": event["timestamp"],
                "decision": event["decision"],
                "method": event["method"],
                "path": event["path"],
                "status": event["status_code"],
                "blocked_by": event.get("blocked_by") or "",
                "rules": ", ".join(event["rule_id_list"]),
                "categories": ", ".join(event["category_list"]),
                "ml_score": event.get("ml_score"),
                "client": event["client_ip"],
                "latency_ms": event["latency_ms"],
                "request_id": event["request_id"],
            }
        )

    st.dataframe(
        rows,
        width="stretch",
        hide_index=True,
        column_config={
            "time": st.column_config.TextColumn("Time", width="medium"),
            "decision": st.column_config.TextColumn("Decision", width="small"),
            "method": st.column_config.TextColumn("Method", width="small"),
            "path": st.column_config.TextColumn("Path", width="large"),
            "status": st.column_config.NumberColumn("Status", format="%d"),
            "blocked_by": st.column_config.TextColumn("Blocked by", width="small"),
            "rules": st.column_config.TextColumn("Rules", width="medium"),
            "categories": st.column_config.TextColumn("Categories", width="medium"),
            "ml_score": st.column_config.ProgressColumn(
                "ML score", min_value=0.0, max_value=1.0, format="%.3f"
            ),
            "client": st.column_config.TextColumn("Client", width="small"),
            "latency_ms": st.column_config.NumberColumn("Latency ms", format="%.1f"),
            "request_id": st.column_config.TextColumn("Request ID", width="medium"),
        },
    )

    with st.expander("Event detail (redacted payload)"):
        selected = st.selectbox(
            "Request",
            rows,
            format_func=lambda row: f"{row['time']} {row['method']} {row['path']} [{row['decision']}]",
        )
        st.json(selected)


def _sidebar() -> tuple[int, str, str, str, bool, int]:
    with st.sidebar:
        st.markdown('<div class="brand">🛡️ AI-WAF</div>', unsafe_allow_html=True)
        st.markdown('<div class="brand-sub">Operations console</div>', unsafe_allow_html=True)
        st.markdown('<div class="sec-title">Filters</div>', unsafe_allow_html=True)
        window_minutes = st.select_slider(
            "Time window (minutes)",
            options=[5, 15, 60, 240, 720, 1440],
            value=60,
        )
        decision_filter = st.selectbox("Decision", ["All", "allow", "block", "alert"], index=0)
        category_filter = st.selectbox("Attack category", ["All"] + sorted(CATEGORIES.values()), index=0)
        search = st.text_input("Search path / request id / IP", "")

        st.divider()
        auto_refresh = st.toggle(
            "Live auto-refresh",
            value=False,
            help="Re-query the audit database on an interval without pressing R.",
        )
        refresh_seconds = st.select_slider(
            "Refresh every (seconds)",
            options=[2, 5, 10, 30],
            value=5,
            disabled=not auto_refresh,
        )

        st.divider()
        st.button("🔄 Refresh now", width="stretch")
        st.caption("Tip: press **R** in the browser to rerun Streamlit and reload the data.")
    return window_minutes, decision_filter, category_filter, search, auto_refresh, int(refresh_seconds)


def _body(
    settings: Any,
    store: EventStore,
    window_minutes: int,
    decision_filter: str,
    category_filter: str,
    search: str,
) -> None:
    stats = store.stats(since_minutes=window_minutes)
    _hero(settings, stats)
    _kpis(stats)
    _charts(stats)
    _events(store, window_minutes, decision_filter, category_filter, search)


def main() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    settings = get_settings()
    store = get_store(str(settings.db_path))

    window_minutes, decision_filter, category_filter, search, auto_refresh, refresh_seconds = _sidebar()

    if auto_refresh:
        st.fragment(
            _body,
            run_every=f"{refresh_seconds}s",
            key="live-body",
        )(settings, store, window_minutes, decision_filter, category_filter, search)
    else:
        _body(settings, store, window_minutes, decision_filter, category_filter, search)


if __name__ == "__main__":
    main()
