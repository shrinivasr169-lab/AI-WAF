"""Unit tests for the signature rule engine (one test per required category)."""

from __future__ import annotations

import pytest

from detection.rules import inspect_request

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"


def run(*, path="/", query="", body="", headers=None, raw_target=None, method="GET"):
    headers = headers or {"user-agent": UA}
    target = raw_target if raw_target is not None else path + (f"?{query}" if query else "")
    return inspect_request(
        method=method,
        raw_target=target,
        path=path,
        query=query,
        headers=headers,
        body=body,
    )


ATTACK_CASES = [
    ("sqli", "SQLI-001", {"query": "q=1+UNION+SELECT+password+FROM+users"}),
    ("sqli", "SQLI-002", {"query": "id=1%27+OR+%271%27%3D%271"}),
    ("sqli", "SQLI-003", {"query": "category=books%3B+DROP+TABLE+users--"}),
    ("sqli", "SQLI-003", {"query": "id=1%27+AND+SLEEP(5)--"}),
    ("sqli", "SQLI-004", {"query": "name=admin%27--"}),
    ("xss", "XSS-001", {"query": "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"}),
    ("xss", "XSS-002", {"query": "text=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"}),
    ("xss", "XSS-003", {"query": "url=javascript%3Aalert(1)"}),
    ("xss", "XSS-004", {"query": "name=%3Csvg+onload%3Dalert(1)%3E"}),
    ("path_traversal", "TRAVERSAL-001", {"query": "file=..%2F..%2F..%2Fetc%2Fpasswd"}),
    ("path_traversal", "TRAVERSAL-001", {"path": "/static/../../etc/passwd"}),
    ("path_traversal", "TRAVERSAL-002", {"query": "file=/etc/shadow"}),
    ("malformed", "MALFORMED-001", {"path": "/page%00.html"}),
    ("malformed", "MALFORMED-002", {"query": "x=%01%02"}),
    ("malformed", "MALFORMED-003", {"raw_target": "/a%zz", "path": "/a%zz"}),
    ("cmdi", "CMDI-001", {"query": "host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd"}),
    ("cmdi", "CMDI-001", {"query": "cmd=%60id%60"}),
]


@pytest.mark.parametrize("category,rule_id,kwargs", ATTACK_CASES)
def test_attack_patterns_detected(category, rule_id, kwargs):
    findings = run(**kwargs)
    ids = [m.rule_id for m in findings]
    assert rule_id in ids, f"expected {rule_id}, got {ids}"
    assert category in [m.category for m in findings]


def test_body_attack_detected():
    findings = run(
        path="/api/comments",
        method="POST",
        headers={"user-agent": UA, "content-type": "application/json"},
        body='{"text":"<script>alert(document.cookie)</script>"}',
    )
    assert any(m.rule_id == "XSS-001" and m.location == "body" for m in findings)


def test_header_attack_detected():
    findings = run(
        path="/search",
        query="q=shoes",
        headers={"user-agent": UA, "x-forwarded": "<script>alert(1)</script>"},
    )
    assert any(m.location == "headers" for m in findings)


def test_double_encoded_traversal_detected():
    # %252f -> %2f -> / after two decode passes
    findings = run(path="/files", query="name=%252e%252e%252f%252e%252e%252fetc%252fpasswd")
    assert any(m.category == "path_traversal" for m in findings)


BENIGN_CASES = [
    {"path": "/", "query": ""},
    {"path": "/products", "query": "category=shoes&page=2"},
    {"path": "/search", "query": "q=running+shoes"},
    {"path": "/search", "query": "q=men%27s+trail+shoes"},  # apostrophe in a word
    {"path": "/search", "query": "q=select+size+guide"},  # "select" alone
    {"path": "/api/search", "query": "q=how+to+select+shoes+from+the+store"},
    {"path": "/api/products/42/reviews", "query": "page=1&order=desc"},
    {"path": "/basket", "query": "coupon=SPRING10"},
    {"path": "/help/returns", "query": "section=size"},
    {"path": "/search", "query": "q=%3C3+valentines+special"},  # "<3" is not XSS
    {"path": "/static/css/app.css", "query": ""},
    {"path": "/api/orders", "query": "sort=price-asc", "method": "POST",
     "body": '{"item":42,"qty":1}', "headers": {"user-agent": UA, "content-type": "application/json"}},
]


@pytest.mark.parametrize("case", BENIGN_CASES)
def test_benign_requests_not_flagged(case):
    case = dict(case)
    method = case.pop("method", "GET")
    findings = run(method=method, **case)
    assert findings == [], f"false positive on {case}: {findings}"


def test_evidence_is_sanitised():
    findings = run(path="/x%01%02%03")
    for match in findings:
        assert "\x01" not in match.evidence
        assert "\n" not in match.evidence
        assert len(match.evidence) <= 80


def test_scan_limit_bounds_work(monkeypatch):
    # A huge body must not be scanned beyond the configured limit.
    long_body = "a" * 50_000 + "<script>alert(1)</script>"
    findings = inspect_request(
        method="POST",
        raw_target="/upload",
        path="/upload",
        query="",
        headers={"user-agent": UA},
        body=long_body,
        scan_limit=1_000,
    )
    assert findings == []
