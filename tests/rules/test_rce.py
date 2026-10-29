"""CRS 932 — Remote Code Execution (RCE) / Command Injection.

Tests that OS command injection payloads are blocked by OWASP CRS rules
932100-932999. These rules detect shell metacharacters (;, |, &&) and
common system commands used to probe or exfiltrate data.

Expected triggering rules:
  - 932100: remote command execution (direct Unix command)
  - 932105: remote command execution (common command patterns)
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet", {"params": {"name": "; cat /etc/passwd"}},
        id="command-injection",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "| ls -la /"}},
        id="pipe-injection",
    ),
]


@pytest.mark.attack
@pytest.mark.rce
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_rce(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 932 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"RCE attack should be blocked (expected 403, got {resp.status_code})"
    )
