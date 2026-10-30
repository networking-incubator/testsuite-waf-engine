"""CRS 930 — Local File Inclusion (LFI) / Path Traversal.

Tests that path traversal payloads are blocked by OWASP CRS rules
930100-930999. These rules detect attempts to escape the web root
and access sensitive files like /etc/passwd.

Expected triggering rules:
  - 930100: path traversal attack (/../)
  - 930110: path traversal attack (../ in parameter)
  - 930120: OS file access attempt (lfi-os-files.data)
  - 930130: restricted file access attempt (restricted-files.data)
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


OS_FILE_CASES = [
    pytest.param("/etc/passwd", id="etc-passwd"),
    pytest.param("/proc/self/environ", id="proc-self-environ"),
]


@pytest.mark.attack
@pytest.mark.lfi
@pytest.mark.parametrize("payload", OS_FILE_CASES)
def test_os_file_access(gateway_url, browser_session, payload):
    """A bare OS file path needs no traversal sequence — 930120 matches the name itself."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": payload},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"OS file access should be blocked (expected 403, got {resp.status_code})"
    )


RESTRICTED_FILE_CASES = [
    pytest.param(".git/config", id="git-config"),
    pytest.param("/.htaccess", id="htaccess"),
]


@pytest.mark.attack
@pytest.mark.lfi
@pytest.mark.parametrize("payload", RESTRICTED_FILE_CASES)
def test_restricted_file_access(gateway_url, browser_session, payload):
    """Application files that should never be served — 930130 blocks them by name."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": payload},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Restricted file access should be blocked (expected 403, got {resp.status_code})"
    )
