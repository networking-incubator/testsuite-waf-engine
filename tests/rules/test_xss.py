"""CRS 941 — Cross-Site Scripting (XSS).

Tests that XSS payloads injected via query parameters are blocked by
OWASP CRS rules 941100-941999. These rules detect script tags, event
handler attributes, and other HTML/JS injection vectors.

Expected triggering rules:
  - 941100: XSS attack detected via libinjection
  - 941110: XSS filter — category 1 (script tag vector)
  - 941130: XSS filter — category 3 (attribute vector)
  - 941160: NoScript XSS InjectionChecker — HTML injection
  - 941390: JavaScript method detected
"""

import pytest


CASES = [
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "<script>alert(1)</script>"}},
        id="script-tag",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": '<img src=x onerror="alert(1)">'}},
        id="img-onerror",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "<svg onload=alert(1)>"}},
        id="svg-onload",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "javascript:alert(1)"}},
        id="javascript-uri",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">'}},
        id="iframe-srcdoc",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}},
        id="data-uri-base64",
    ),
]


@pytest.mark.attack
@pytest.mark.xss
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_xss(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 941 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"XSS attack should be blocked (expected 403, got {resp.status_code})"
    )
