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

An empty User-Agent is detected by 920330 but scores only 2 (notice), so it
is blocked only alongside another signal - 920350 adds +3, but only when
the gateway is addressed by a numeric IP. Addressed by name the request is
allowed, hence the xfail below.

A merely non-browser User-Agent matches nothing at PL1 by design; known
scanner agents are covered by 913100 in tests/rules/test_scanner.py.
"""

import pytest
import requests


# 920330 scores the empty UA at 2, and the +3 from 920350 only lands when
# the Host header is a numeric IP, leaving the request under the blocking
# threshold of 5.
UA_SCORE_BELOW_THRESHOLD = "empty UA alone scores 2, under the inbound anomaly threshold"


@pytest.mark.attack
@pytest.mark.protocol
@pytest.mark.xfail(reason=UA_SCORE_BELOW_THRESHOLD, strict=False)
def test_empty_user_agent(gateway_url, extra_headers):
    """Empty User-Agent string - triggers 920330, +3 more is needed to block."""
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
