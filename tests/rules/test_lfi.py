"""CRS 930 — Local File Inclusion (LFI) / Path Traversal.

Tests that path traversal payloads are blocked by OWASP CRS rules
930100-930999. These rules detect attempts to escape the web root
and access sensitive files like /etc/passwd.

Expected triggering rules:
  - 930100: path traversal attack (/../)
  - 930110: path traversal attack (../ in parameter)
"""

import pytest


@pytest.mark.attack
@pytest.mark.lfi
def test_path_traversal(gateway_url, browser_session):
    """Encoded double-dot traversal (....//....//etc/passwd) to read system files."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "....//....//etc/passwd"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"LFI attack should be blocked (expected 403, got {resp.status_code})"
    )
