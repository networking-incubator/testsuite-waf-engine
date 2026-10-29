"""Request body framing — benign traffic the connector must forward untouched.

Covers the body framing variants a WAF has to buffer and release correctly:
empty bodies, chunked transfer-encoding, chunked bodies terminated by a
trailer, and the Expect: 100-continue handshake. A failure here is a
connector or filter-chain bug, not a ruleset decision.

These assert only that the WAF did not block or mangle the request, because
the backend behind the gateway owns the final status code. Byte-exact
pass-through needs an echo endpoint the target app does not yet have.
"""

import pytest
from conftest import BLOCKED, MALFORMED


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
    assert resp.status_code == 200, f"HEAD request should succeed (got {resp.status_code})"
    assert not resp.content, "HEAD response should not carry a body"
