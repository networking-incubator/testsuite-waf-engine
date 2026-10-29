"""CRS 934 — Generic Application Attacks.

Tests the 934 family, which covers attack classes that are not tied to one
language runtime: server-side template injection, SSRF, Node.js and Ruby
injection, JavaScript prototype pollution, and NoSQL/ORM lookup operator
injection. Log4Shell lives in test_log4shell.py (it is a 944 Java rule,
not 934).

Expected triggering rules:
  - 934100/934101: Node.js injection attack
  - 934110: SSRF — cloud provider metadata URL in parameter
  - 934120: SSRF — URL parameter using an IP address
  - 934130: JavaScript prototype pollution
  - 934150: Ruby injection attack
  - 934180/934200: server-side template injection
  - 934190: SSRF — scheme-less localhost or internal hostname
  - 934210/934220: ORM lookup operator injection

Some payloads overlap neighbouring families (a ${...} template expression
can also match 944 Java EL, an IP-address URL can also match 931 RFI).
These tests assert the request is blocked, not which rule fired.
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet", {"params": {"name": "{{7*7}}"}},
        id="ssti-expression",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "${7*7}"}},
        id="ssti-dollar-expression",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "http://169.254.169.254/latest/meta-data/"}},
        id="ssrf-cloud-metadata",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "http://localhost/admin"}},
        id="ssrf-internal-hostname",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "http://127.0.0.1:22/"}},
        id="ssrf-ip-address",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": 'require("child_process").exec("id")'}},
        id="nodejs-injection",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": "__proto__[x]=y"}},
        id="prototype-pollution",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": 'IO.popen("id")'}},
        id="ruby-injection",
    ),
    pytest.param(
        "GET", "/greet", {"params": {"name": '{"$ne": null}'}},
        id="orm-operator-injection",
    ),
]


@pytest.mark.attack
@pytest.mark.generic
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_generic_attack(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger a CRS 934 rule and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"Generic attack should be blocked (expected 403, got {resp.status_code})"
    )
