"""CRS 944 — Java / Spring Attack.

Tests that Java-specific attack payloads are blocked by OWASP CRS rules
944100-944999. These rules detect Java deserialization gadgets, Spring
expression language injection, and other JVM-specific exploit patterns.
Like PHP injection tests, these fire regardless of the actual backend —
CRS applies defense-in-depth across all technology stacks.

Expected triggering rules:
  - 944100: remote command execution — suspicious Java class detected
  - 944110: Java injection attack (Spring expression, OGNL)
  - 944120: possible Java serialization payload
  - 944130: suspicious Java class detected
"""

import pytest


CASES = [
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "${T(java.lang.Runtime).getRuntime().exec('id')}"}},
        id="spring-expression-rce",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "java.lang.ProcessBuilder"}},
        id="java-processbuilder-class",
    ),
    pytest.param(
        "GET", "/greet",
        {"params": {"name": "${runtime.exec('cat /etc/passwd')}"}},
        id="ognl-runtime-exec",
    ),
]


@pytest.mark.attack
@pytest.mark.java_attack
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_java_attack(gateway_url, browser_session, method, path, kwargs):
    """Each payload should trigger CRS 944 rules and be blocked."""
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 403, (
        f"Java attack should be blocked (expected 403, got {resp.status_code})"
    )
