"""Normal traffic — legitimate requests that should pass through the WAF.

These tests verify that the WAF does not block ordinary user interactions:
homepage access, greeting with simple names, and names containing spaces.
All requests use a browser User-Agent to avoid CRS protocol enforcement
rules that penalize non-browser clients (920350 + orphaned chain scoring).

The request-lifecycle tests below cover body framing variants that the WAF
must forward untouched: empty bodies, chunked encoding, trailers, bodies
larger than the inspection limit, and the Expect: 100-continue handshake.
They assert only that the WAF did not block the request, because the
backend behind the gateway decides the final status code.
"""

import pytest


BLOCKED = (403, 413)
MALFORMED = 400


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
def test_benign_request_body(gateway_url, browser_session):
    """A benign form body passes request-body inspection unchanged."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "Alice"},
        timeout=10,
    )
    assert resp.status_code not in BLOCKED, (
        f"Benign form body should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_empty_request_body(gateway_url, browser_session):
    """A POST that reaches end-of-stream with no body is not blocked."""
    resp = browser_session.post(f"{gateway_url}/greet", data=b"", timeout=10)
    assert resp.status_code not in BLOCKED, (
        f"Empty request body should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_oversized_benign_request_body(gateway_url, browser_session):
    """A benign body past the inspection limit is truncated for inspection, not rejected."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "x" * 65536},
        timeout=30,
    )
    assert resp.status_code not in BLOCKED, (
        f"Oversized benign body should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_expect_100_continue(gateway_url, browser_session):
    """The Expect: 100-continue handshake survives the WAF filter chain."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "Alice"},
        headers={"Expect": "100-continue"},
        timeout=10,
    )
    assert resp.status_code not in BLOCKED, (
        f"Expect: 100-continue request should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_chunked_request_body(chunked_request):
    """A benign chunked request body is forwarded without being blocked."""
    resp = chunked_request("/greet", body=b"name=Alice")
    assert resp.status_code != MALFORMED, "Chunked framing was rejected as malformed"
    assert resp.status_code not in BLOCKED, (
        f"Chunked benign body should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_chunked_empty_body_with_trailer(chunked_request):
    """An empty chunked request terminated by a trailer is not blocked."""
    resp = chunked_request("/greet", body=b"", trailer="passed")
    assert resp.status_code != MALFORMED, "Trailer framing was rejected as malformed"
    assert resp.status_code not in BLOCKED, (
        f"Empty trailer-terminated request should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_chunked_body_with_trailer(chunked_request):
    """A benign chunked body plus a request trailer is not blocked."""
    resp = chunked_request("/greet", body=b"name=Alice", trailer="passed")
    assert resp.status_code != MALFORMED, "Trailer framing was rejected as malformed"
    assert resp.status_code not in BLOCKED, (
        f"Trailer-terminated request should not be blocked (got {resp.status_code})"
    )


@pytest.mark.normal
def test_head_request_without_body(gateway_url, browser_session):
    """A HEAD response ends at the headers, with no body for the WAF to buffer."""
    resp = browser_session.head(f"{gateway_url}/", timeout=10)
    assert resp.status_code == 200, (
        f"HEAD request should succeed (got {resp.status_code})"
    )
    assert not resp.content, "HEAD response should not carry a body"


@pytest.mark.normal
def test_normal_traffic_after_blocked_request(gateway_url, browser_session):
    """A blocked request leaves no state that breaks the next request on the connection."""
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
