"""Raw HTTP protocol handling — requests no client library will emit.

These go out on a bare socket because requests and http.client both insist
on a well-formed request. They check that a malformed or legacy request is
rejected by the proxy or by CRS rather than being served, which is a
connector-level concern: the request has to be parsed before any rule can
run against it.

Expected triggering rules:
  - 920280: request missing a Host header
"""

import pytest
from conftest import BROWSER_UA


@pytest.mark.attack
@pytest.mark.protocol
def test_missing_host_header(socket_request):
    """HTTP/1.1 request with no Host header — rejected by the proxy or CRS 920280."""
    status = socket_request(
        b"GET /greet?name=test HTTP/1.1\r\n"
        b"User-Agent: " + BROWSER_UA.encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    assert status in (400, 403), f"Request without Host should be rejected (got {status})"


@pytest.mark.attack
@pytest.mark.protocol
def test_http10_request_without_host(socket_request):
    """HTTP/1.0 request with no Host header — rejected rather than served."""
    status = socket_request(
        b"GET /greet?name=test HTTP/1.0\r\nUser-Agent: " + BROWSER_UA.encode("ascii") + b"\r\n\r\n"
    )
    assert status != 200, f"HTTP/1.0 request without Host should not be served (got {status})"
