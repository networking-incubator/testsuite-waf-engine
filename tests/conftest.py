import http.client
import json
import socket
import subprocess
from urllib.parse import urlsplit

import pytest
import requests


def pytest_addoption(parser):
    parser.addoption(
        "--url",
        default=None,
        help="Base URL of the gateway (e.g. http://172.18.255.127). "
             "Auto-detected from kubectl if omitted.",
    )
    parser.addoption(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra header sent with every request (e.g. 'Host: waf.example.com'). "
             "Repeatable. Headers set explicitly by a test take precedence.",
    )


@pytest.fixture(scope="session")
def gateway_url(request):
    url = request.config.getoption("--url")
    if url:
        return url.rstrip("/")
    raise ValueError("URL of the gateway was not specified.")


BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Status codes that mean the WAF stopped the request, as opposed to the
# backend answering it. Used by tests that can only assert "not blocked",
# because the app behind the gateway owns the final status code.
BLOCKED = (403, 413)
# A malformed request the proxy refused to parse — a framing bug in the
# test helper, not a WAF decision.
MALFORMED = 400


def pytest_collection_modifyitems(items):
    """Mark every test with the directory it lives in: rules/ or engine/.

    A rules/ failure means the ruleset missed or over-matched a payload.
    An engine/ failure means the connector mishandled the request itself.
    """
    for item in items:
        parent = item.path.parent.name
        if parent in ("rules", "engine"):
            item.add_marker(getattr(pytest.mark, parent))


@pytest.fixture(scope="session")
def extra_headers(request):
    """Headers from --header, as a dict."""
    headers = {}
    for item in request.config.getoption("--header"):
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise pytest.UsageError(
                f"--header expects 'NAME: VALUE', got {item!r}"
            )
        headers[name.strip()] = value.strip()
    return headers


@pytest.fixture(scope="session")
def browser_session(extra_headers):
    """Requests session with a realistic browser User-Agent."""
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    s.headers.update(extra_headers)
    return s


class RawResponse:
    """Minimal response wrapper for the hand-built HTTP helpers."""

    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers  # lowercase header name -> value
        self.body = body

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


def _connect(url, timeout):
    parts = urlsplit(url)
    if parts.scheme == "https":
        return http.client.HTTPSConnection(parts.hostname, parts.port, timeout=timeout)
    return http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)


@pytest.fixture
def chunked_request(gateway_url, extra_headers):
    """Send a chunked (Transfer-Encoding) request, optionally with a trailer.

    The requests library always sets Content-Length for a bytes body, so
    chunked framing and trailers need a hand-built request.
    """

    def send(path, body=b"", headers=None, trailer=None, method="POST", timeout=10):
        request_headers = {
            "Host": urlsplit(gateway_url).netloc,
            "User-Agent": BROWSER_UA,
            "Content-Type": "application/x-www-form-urlencoded",
            **extra_headers,
            **(headers or {}),
        }
        connection = _connect(gateway_url, timeout)
        try:
            connection.putrequest(
                method, path, skip_host=True, skip_accept_encoding=True
            )
            for name, value in request_headers.items():
                connection.putheader(name, value)
            connection.putheader("Transfer-Encoding", "chunked")
            if trailer is not None:
                connection.putheader("Trailer", "x-client-trailer")
            connection.putheader("Connection", "close")
            connection.endheaders()
            if body:
                connection.send(f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n")
            if trailer is None:
                connection.send(b"0\r\n\r\n")
            else:
                connection.send(
                    b"0\r\nx-client-trailer: " + trailer.encode("ascii") + b"\r\n\r\n"
                )
            response = connection.getresponse()
            return RawResponse(
                response.status,
                {name.lower(): value for name, value in response.getheaders()},
                response.read(),
            )
        finally:
            connection.close()

    return send


@pytest.fixture
def socket_request(gateway_url):
    """Send raw request bytes on a bare socket and return the status line code.

    Needed for requests that no HTTP client library will emit, such as a
    request with no Host header at all.
    """

    def send(raw, timeout=10):
        parts = urlsplit(gateway_url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        connection = socket.create_connection((parts.hostname, port), timeout=timeout)
        try:
            connection.sendall(raw)
            chunks = []
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except TimeoutError:
            pass
        finally:
            connection.close()
        data = b"".join(chunks)
        if not data:
            return None
        status_line = data.split(b"\r\n", 1)[0].split(b" ")
        return int(status_line[1]) if len(status_line) > 1 else None

    return send


