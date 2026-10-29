"""CRS 920 + anomaly scoring — Protocol Enforcement.

Tests that requests violating HTTP protocol expectations accumulate enough
anomaly score to be blocked, even without a traditional attack payload.

Expected triggering rules:
  - 920350: Host header is a numeric IP address (+3 warning)
  - 920280: request missing a Host header
  - 920340: request containing content but missing Content-Type header
  - 920420: request Content-Type is not allowed by policy
  - 920440: URL file extension is restricted by policy
  - 949111: inbound anomaly score exceeded (early blocking)

In this demo environment, non-browser User-Agents are blocked because:
  - Rule 920350 adds +3 (warning) for numeric IP Host
  - An orphaned CRS chain rule adds +2 (notice) when UA lacks "AppleWebKit"
  - Total = 5 = blocking threshold → 949111 fires
"""

import requests
import pytest


@pytest.mark.attack
@pytest.mark.protocol
def test_non_browser_ua_blocked(gateway_url, extra_headers):
    """Non-browser UA accumulates enough anomaly score to be blocked.

    Uses raw requests (no browser_session fixture) to send a custom UA
    that triggers both 920350 and the orphaned chain rule.
    """
    resp = requests.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={**extra_headers, "User-Agent": "custom-script/1.0"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Non-browser UA should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.protocol
def test_empty_user_agent(gateway_url, extra_headers):
    """Empty User-Agent string — triggers 920350 + orphaned chain (no AppleWebKit)."""
    resp = requests.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={**extra_headers, "User-Agent": ""},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Empty UA should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.protocol
def test_invalid_content_type(gateway_url, browser_session):
    """POST with a disallowed Content-Type — triggers CRS 920420."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data="name=test",
        headers={"Content-Type": "text/csv"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Invalid Content-Type should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.protocol
def test_content_body_without_content_type(gateway_url, browser_session):
    """POST with body but no Content-Type header — triggers CRS 920340."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data="name=test",
        headers={"Content-Type": None},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Missing Content-Type with body should be blocked (expected 403, got {resp.status_code})"
    )


RESTRICTED_URL_CASES = [
    pytest.param("/backup.bak", id="backup-extension"),
    pytest.param("/.git/config", id="vcs-metadata-path"),
]


@pytest.mark.attack
@pytest.mark.protocol
@pytest.mark.parametrize("path", RESTRICTED_URL_CASES)
def test_restricted_url(gateway_url, browser_session, path):
    """URLs for files that should never be served — triggers CRS 920440."""
    resp = browser_session.get(f"{gateway_url}{path}", timeout=10)
    assert resp.status_code == 403, (
        f"{path} should be blocked (expected 403, got {resp.status_code})"
    )
