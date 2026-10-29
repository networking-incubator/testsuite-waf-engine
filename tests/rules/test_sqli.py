"""CRS 942 — SQL Injection.

Tests that SQL injection payloads in query parameters are blocked by
OWASP CRS rules 942100-942999. These rules detect common SQLi patterns
including tautologies, UNION SELECT, and destructive statement injection.

Expected triggering rules:
  - 942100: SQL injection attack detected via libinjection
  - 942210: detects chained SQL injection attempts
  - 942300: detects MySQL comment / space / backtick obfuscation
  - 942440: SQL comment sequence detected
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet", {"params": {"name": "1' OR '1'='1"}},
        id="or-tautology",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "' UNION SELECT name FROM greetings-- "}},
        id="union-select",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "'; DROP TABLE greetings;-- "}},
        id="drop-table",
    ),
]


@pytest.mark.attack
@pytest.mark.sqli
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_sqli(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 942 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"SQLi attack should be blocked (expected 403, got {resp.status_code})"
    )
