"""Normal traffic — legitimate requests that should pass through the WAF.

These tests verify that the WAF does not block ordinary user interactions:
homepage access, greeting with simple names, and names containing spaces.
All requests use a browser User-Agent to avoid CRS protocol enforcement
rules that penalize non-browser clients (920350 + orphaned chain scoring).

Body framing variants of legitimate traffic (chunked, trailers, empty and
oversized bodies) live in tests/engine/test_body_framing.py — a failure
there is a connector bug, not a ruleset false positive.
"""

import pytest


CASES = [
    pytest.param("GET", "/", {}, id="homepage"),
    pytest.param("GET", "/greet", {"params": {"name": "World"}}, id="greet-world"),
    pytest.param("GET", "/greet", {"params": {"name": "Alice Bob"}}, id="greet-spaces"),
]


@pytest.mark.normal
@pytest.mark.parametrize("method,path,kwargs", CASES)
def test_normal_traffic(gateway_url, browser_session, method, path, kwargs):
    resp = browser_session.request(method, f"{gateway_url}{path}", **kwargs, timeout=10)
    assert resp.status_code == 200, f"Normal request should succeed: {resp.text[:200]}"


@pytest.mark.normal
def test_normal_traffic_after_blocked_request(gateway_url, browser_session):
    """A blocked request leaves no state that breaks the next legitimate request."""
    blocked = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "1' OR '1'='1"},
        timeout=10,
    )
    assert blocked.status_code == 403, (
        f"Setup attack should be blocked (got {blocked.status_code})"
    )
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "Alice"},
        timeout=10,
    )
    assert resp.status_code == 200, (
        f"Request after a block should succeed (got {resp.status_code})"
    )
