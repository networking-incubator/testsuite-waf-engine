"""CRS 931 — Remote File Inclusion (RFI).

Tests that remote file inclusion payloads are blocked by OWASP CRS rules
931100-931999. These rules detect URLs and protocol wrappers in parameters
that could trick the application into loading remote resources — a classic
attack vector for injecting malicious code from attacker-controlled servers.

Expected triggering rules:
  - 931100: possible RFI attack — URL parameter using IP address
  - 931110: possible RFI attack — common RFI parameter name with URL payload
  - 931120: possible RFI attack — URL payload with trailing question mark
  - 931130: possible RFI attack — off-domain reference/link
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "http://evil.com/shell.txt?"}},
        id="http-url-trailing-question",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "https://attacker.com/backdoor.php?"}},
        id="https-url-trailing-question",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "http://192.168.1.1/shell.txt"}},
        id="http-url-with-ip-address",
    ),
]


@pytest.mark.attack
@pytest.mark.rfi
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_rfi(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 931 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"RFI attack should be blocked (expected 403, got {resp.status_code})"
    )
