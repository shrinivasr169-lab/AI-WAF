"""Deterministic signature rules for the AI-WAF (build Phase 1).

The rule engine is deliberately independent from the ML engine: known
malicious patterns must still be caught when the model is unavailable.
Every rule is a compiled regular expression applied to a normalised view of
one request location (path, query, headers, body).

Matching strategy
-----------------
1. Percent-encoding is decoded twice so single/double encoded payloads are
   compared in plain text (``%3Cscript%3E`` -> ``<script>``).
2. Scanned text is capped at ``RULE_SCAN_LIMIT`` characters to bound work.
3. Evidence is sanitised (control characters removed, truncated) before it
   can reach a log, which protects against log injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import unquote, unquote_plus

DEFAULT_SCAN_LIMIT = 10_000
EVIDENCE_LIMIT = 80

CATEGORIES: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "malformed": "Malformed Request",
    "cmdi": "Command Injection",
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str  # "high" | "medium" | "low"
    pattern: re.Pattern[str]
    targets: tuple[str, ...] = ("path", "query", "headers", "body")
    description: str = ""
    # Optional extra condition: the rule only fires when this pattern also
    # appears in the same location. Used to suppress false positives on
    # ordinary English such as "select shoes from the store".
    context: re.Pattern[str] | None = None


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str
    category: str
    severity: str
    location: str  # path | query | headers | body
    evidence: str

    @property
    def category_label(self) -> str:
        return CATEGORIES.get(self.category, self.category)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# Rule set (starter rules; ModSecurity / OWASP CRS can be layered on later)
# ---------------------------------------------------------------------------
RULES: tuple[Rule, ...] = (
    # --- SQL injection -----------------------------------------------------
    Rule(
        id="SQLI-001",
        name="UNION SELECT",
        category="sqli",
        severity="high",
        pattern=_rx(r"\bunion\b[\s\S]{0,60}?\b(select|all)\b"),
        description="UNION-based SQL injection probe.",
    ),
    Rule(
        id="SQLI-002",
        name="Boolean tautology",
        category="sqli",
        severity="high",
        pattern=_rx(
            r"\b(?:or|and)\s+(?:'?\d+'?\s*=\s*'?\d+'?|'\s*[^'\s]{1,30}\s*'\s*=\s*'\s*[^'\s]{1,30}\s*')"
        ),
        description="Classic 'OR 1=1' authentication bypass pattern.",
    ),
    Rule(
        id="SQLI-003",
        name="SQL statement keywords",
        category="sqli",
        severity="high",
        pattern=_rx(
            r"(?:"
            r"\binsert\s+into\b"
            r"|\bdelete\s+from\b"
            r"|\bupdate\s+[\w`]+\s+set\b"
            r"|\bdrop\s+(?:table|database|schema)\b"
            r"|\binformation_schema\b"
            r"|\bload_file\s*\("
            r"|\bxp_cmdshell\b"
            r"|\bsleep\s*\(\s*\d"
            r"|\bbenchmark\s*\("
            r")"
        ),
        description="SQL statement fragments commonly used in injection probes.",
    ),
    Rule(
        id="SQLI-005",
        name="SELECT ... FROM in user input",
        category="sqli",
        severity="high",
        pattern=_rx(r"\bselect\b[\s\S]{0,60}?\bfrom\b"),
        # Only fire when SQL punctuation is present too, so ordinary English
        # ("select shoes from the store") does not raise an alert.
        context=_rx(r"['\"`;#]|--|/\*"),
        description="SELECT ... FROM combined with SQL metacharacters.",
    ),
    Rule(
        id="SQLI-004",
        name="Quote + SQL comment",
        category="sqli",
        severity="medium",
        pattern=_rx(r"(?:'|%27|\"|%22)\s*(?:--|#|/\*)"),
        description="Quoted value terminated by a SQL comment marker.",
    ),
    # --- Cross-site scripting ---------------------------------------------
    Rule(
        id="XSS-001",
        name="Script tag",
        category="xss",
        severity="high",
        pattern=_rx(r"<\s*/?\s*script\b"),
        description="Inline <script> injection attempt.",
    ),
    Rule(
        id="XSS-002",
        name="Inline event handler",
        category="xss",
        severity="high",
        pattern=_rx(r"\bon(?:error|load|click|mouseover|focus|submit|toggle|animationstart)\s*="),
        description="HTML event handler attribute injection.",
    ),
    Rule(
        id="XSS-003",
        name="Script URL scheme",
        category="xss",
        severity="medium",
        pattern=_rx(r"(?:javascript|vbscript|data:text/html)\s*:"),
        description="javascript:/vbscript: URL scheme in a link target.",
    ),
    Rule(
        id="XSS-004",
        name="DOM sink or injected widget tag",
        category="xss",
        severity="medium",
        pattern=_rx(
            r"(?:"
            r"<\s*/?\s*(?:iframe|svg|object|embed|body|style|math|details|form)\b"
            r"|\b(?:document\.cookie|window\.location|eval\s*\(|setTimeout\s*\(\s*['\"])"
            r")"
        ),
        description="Dangerous tag or JavaScript DOM sink.",
    ),
    # --- Path traversal ----------------------------------------------------
    Rule(
        id="TRAVERSAL-001",
        name="Dot-dot slash traversal",
        category="path_traversal",
        severity="high",
        pattern=_rx(r"(?:\.\.[/\\])+|(?<=/)\.\.(?:/|$)"),
        description="Relative traversal sequence such as ../../",
    ),
    Rule(
        id="TRAVERSAL-002",
        name="Sensitive system file",
        category="path_traversal",
        severity="high",
        pattern=_rx(
            r"(?:"
            r"/etc/(?:passwd|shadow|hosts)"
            r"|/proc/self/"
            r"|[a-z]:\\windows\\(?:win\.ini|system32)"
            r"|\bweb\.config\b"
            r"|\bboot\.ini\b"
            r")"
        ),
        description="Attempt to reach OS or server configuration files.",
    ),
    # --- Malformed requests ------------------------------------------------
    Rule(
        id="MALFORMED-001",
        name="Null byte",
        category="malformed",
        severity="high",
        pattern=re.compile("\x00"),
        targets=("path", "query", "headers", "body"),
        description="NUL byte used to truncate or bypass validation.",
    ),
    Rule(
        id="MALFORMED-002",
        name="Control characters",
        category="malformed",
        severity="medium",
        pattern=re.compile("[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]"),
        description="Raw control characters inside request text.",
    ),
    # --- Command injection (extra starter rule) ----------------------------
    Rule(
        id="CMDI-001",
        name="Shell metacharacter chain",
        category="cmdi",
        severity="high",
        pattern=_rx(
            r"(?:"
            r";\s*(?:ls|cat|whoami|id|curl|wget|nc|bash|sh|cmd|powershell)\b"
            r"|\|\s*(?:bash|sh|cmd|powershell)\b"
            r"&&\s*(?:ls|cat|whoami|curl|wget|id)\b"
            r"|\$\(\s*(?:ls|cat|whoami|id|curl|wget)\b"
            r"|`(?:ls|cat|whoami|id|curl|wget)\b"
            r"|(?:/bin/|/usr/bin/)(?:ba|z|k)?sh\b"
            r")"
        ),
        description="Shell command chaining via metacharacters.",
    ),
)

_BAD_PCT = re.compile(r"%(?![0-9a-fA-F]{2})")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_evidence(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    """Make a matched snippet safe to store in a log line."""
    text = _CONTROL.sub(" ", text)
    text = " ".join(text.split())
    return text[:limit]


def _decode_twice(text: str, plus: bool = False) -> str:
    """Undo percent-encoding up to twice.

    ``plus=True`` also turns ``+`` into a space, which is the convention in
    query strings and form bodies (but *not* in paths).
    """
    decoder = unquote_plus if plus else unquote
    text = decoder(text)
    return decoder(text)


def _prepare(text: str, limit: int, plus: bool = False) -> str:
    return _decode_twice(text, plus)[:limit]


def _match_location(rule: Rule, location: str, text: str, out: list[RuleMatch]) -> None:
    if location not in rule.targets:
        return
    if rule.context is not None and not rule.context.search(text):
        return
    for match in rule.pattern.finditer(text):
        out.append(
            RuleMatch(
                rule_id=rule.id,
                name=rule.name,
                category=rule.category,
                severity=rule.severity,
                location=location,
                evidence=sanitize_evidence(match.group(0)),
            )
        )
        break  # one evidence sample per rule/location is enough


def check_malformed_target(raw_target: str) -> list[RuleMatch]:
    """Checks that must run on the *raw* (still encoded) request target."""
    findings: list[RuleMatch] = []
    if _BAD_PCT.search(raw_target):
        findings.append(
            RuleMatch(
                rule_id="MALFORMED-003",
                name="Invalid percent-encoding",
                category="malformed",
                severity="medium",
                location="path",
                evidence=sanitize_evidence(raw_target),
            )
        )
    return findings


def inspect_request(
    *,
    method: str,
    raw_target: str,
    path: str,
    query: str,
    headers: Mapping[str, str],
    body: str,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
) -> list[RuleMatch]:
    """Run every rule against every request location.

    ``raw_target`` is the request line target as received (still percent
    encoded); the remaining arguments are already parsed components.
    """
    findings: list[RuleMatch] = []
    findings.extend(check_malformed_target(raw_target))

    header_blob = "\n".join(f"{key}: {value}" for key, value in headers.items())
    content_type = str(headers.get("content-type", "")).lower()
    form_body = "x-www-form-urlencoded" in content_type

    locations = {
        "path": _prepare(path, scan_limit),
        "query": _prepare(query, scan_limit, plus=True),
        "headers": _prepare(header_blob, scan_limit),
        "body": _prepare(body, scan_limit, plus=form_body),
    }

    for rule in RULES:
        for location, text in locations.items():
            _match_location(rule, location, text, findings)

    findings.sort(key=lambda m: (m.severity != "high", m.severity != "medium"))
    return findings


def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in RULES}
