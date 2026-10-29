"""CRS 921 — HTTP Request Smuggling / Response Splitting.

Tests that HTTP header injection and response splitting payloads are
blocked by OWASP CRS rules 921100-921999. These rules detect CRLF
sequences and other control characters in request headers and parameters
that could be used to inject additional HTTP headers or split responses.

Expected triggering rules:
  - 921110: HTTP request smuggling attack (CR/LF in request line)
  - 921120: HTTP response splitting attack (CR/LF in headers)
  - 921130: HTTP response splitting attack (CR/LF in parameter)
  - 921200: LDAP injection attack
"""

import pytest


CASES = [
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "test\r\nContent-Length: 0"}},
        id="crlf-content-length-injection",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "test\r\n\r\n<html>injected</html>"}},
        id="crlf-response-splitting",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "test\nSet-Cookie: evil=1"}},
        id="lf-cookie-injection",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "*)(uid=*))(|(uid=*"}},
        id="ldap-filter-injection",
    ),
]


@pytest.mark.attack
@pytest.mark.request_smuggling
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_request_smuggling(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 921 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"Request smuggling attack should be blocked (expected 403, got {resp.status_code})"
    )
