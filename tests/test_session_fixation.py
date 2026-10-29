"""CRS 943 — Session Fixation.

Tests that session fixation attacks are blocked by OWASP CRS rules
943100-943999. These rules detect attempts to force a known session ID
onto a victim, typically via query parameters combined with off-domain
referrers that suggest an external attacker is setting the session.

Expected triggering rules:
  - 943100: session fixation attempt (session ID in URL + external Referer)
"""

import pytest


@pytest.mark.attack
@pytest.mark.session_fixation
def test_session_fixation(gateway_url, browser_session):
    """JSESSIONID as query parameter with off-domain Referer — triggers CRS 943100."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "test", "JSESSIONID": "abc123"},
        headers={"Referer": "http://evil.com/steal"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Session fixation should be blocked (expected 403, got {resp.status_code})"
    )
