"""CRS 913 — Scanner / Bot Detection.

Tests that known security scanner User-Agent strings are blocked by
OWASP CRS rules 913100-913999. These rules maintain a list of tool
signatures (sqlmap, nikto, nmap, etc.) and block matching requests.

Expected triggering rules:
  - 913100: found User-Agent associated with security scanner

913100 is the only scanner rule left. Upstream removed 913110 (scanner
HTTP headers) and 913120 (scanner URLs / filenames) as ineffective, along
with the scanners-urls.data list, so there is nothing else here to cover
— do not add tests for those IDs.
"""

import pytest


CASES = [
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "test"}, "headers": {"User-Agent": "sqlmap/1.0"}},
        id="sqlmap-ua",
    ),
    pytest.param(
        "GET",
        "/greet",
        {"params": {"name": "test"}, "headers": {"User-Agent": "nikto/2.1.6"}},
        id="nikto-ua",
    ),
]


@pytest.mark.attack
@pytest.mark.scanner
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_scanner_ua(gateway_url, browser_session, method, path, kwargs):
    """Known scanner UAs override the session's browser UA and should be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"Scanner UA should be blocked (expected 403, got {resp.status_code})"
    )
