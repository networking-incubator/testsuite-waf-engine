"""CRS 911 — Method Enforcement.

Tests that unusual or dangerous HTTP methods are blocked by OWASP CRS
rules 911100-911999. By default, CRS allows only GET, HEAD, POST, and
OPTIONS — other methods like TRACE, DELETE, PUT, and PATCH are blocked
unless explicitly whitelisted.

Expected triggering rules:
  - 911100: method is not allowed by policy
"""

import pytest


CASES = [
    pytest.param("TRACE", "/greet", id="trace-method"),
    pytest.param("DELETE", "/greet", id="delete-method"),
    pytest.param("PUT", "/greet", id="put-method"),
    pytest.param("PATCH", "/greet", id="patch-method"),
]


@pytest.mark.attack
@pytest.mark.method_enforcement
@pytest.mark.parametrize("method,path", CASES)
def test_method_enforcement(gateway_url, browser_session, method, path):
    """Disallowed HTTP methods should be blocked by CRS 911100."""
    resp = browser_session.request(method, f"{gateway_url}{path}", timeout=10)
    assert resp.status_code == 403, (
        f"{method} should be blocked (expected 403, got {resp.status_code})"
    )
