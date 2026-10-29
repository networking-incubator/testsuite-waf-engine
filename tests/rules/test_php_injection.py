"""CRS 933 — PHP Injection.

Tests that PHP injection payloads are blocked by OWASP CRS rules
933100-933999. Even though this demo runs a Python (Flask) backend,
CRS checks for PHP injection patterns regardless of the server
technology — an attacker doesn't know the backend stack, and a
defense-in-depth WAF blocks these universally.

Expected triggering rules:
  - 933100: PHP injection attack — opening/closing tag found
  - 933110: PHP injection attack — PHP script file upload found
  - 933120: PHP injection attack — configuration directive found
  - 933130: PHP injection attack — PHP variables found
  - 933150: PHP injection attack — high-risk PHP function name found
  - 933160: PHP injection attack — high-risk PHP function call found
  - 933200: PHP injection attack — wrapper scheme detected
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "<?php system('id'); ?>"}},
        id="php-system-call",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "<?php eval($_GET['cmd']); ?>"}},
        id="php-eval-injection",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "<?php passthru('cat /etc/passwd'); ?>"}},
        id="php-passthru",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "php://input"}},
        id="php-wrapper-scheme",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "php://filter/convert.base64-encode/resource=index.php"}},
        id="php-filter-source-disclosure",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "$_SERVER[DOCUMENT_ROOT]"}},
        id="php-superglobal-variable",
    ),
]


@pytest.mark.attack
@pytest.mark.php_injection
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_php_injection(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 933 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"PHP injection should be blocked (expected 403, got {resp.status_code})"
    )
