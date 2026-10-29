"""CRS 932 — Remote Code Execution (RCE) / Command Injection.

Tests that OS command injection payloads are blocked by OWASP CRS rules
932100-932999. These rules detect shell metacharacters (;, |, &&) and
common system commands used to probe or exfiltrate data.

Expected triggering rules:
  - 932250/932260: remote command execution — direct Unix command execution
  - 932270: remote command execution — Unix shell expression found
  - 932370/932380: remote command execution — Windows command injection
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
    pytest.param(
        "GET", "/greet", {"params": {"name": "$(id)"}},
        id="subshell-expansion",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "x=`cat /etc/passwd`"}},
        id="backtick-substitution",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "/bin/bash -c id"}},
        id="explicit-shell-invocation",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "powershell -enc ZQBjAGgAbwA="}},
        id="powershell-encoded-command",
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
