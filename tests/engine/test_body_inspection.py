"""Request body inspection — attacks delivered in the body, not the query.

Tests that the WAF buffers and inspects request bodies regardless of how
they are framed. An attacker can move a payload out of the query string
into a form body, split it across chunked encoding, or hide it behind a
trailer; none of these framings should let the payload through.

Payloads placed past the buffered body size are covered in test_limits.py.

Expected triggering rules:
  - 941100: XSS attack detected via libinjection
  - 942100: SQL injection attack detected via libinjection
"""

import pytest


@pytest.mark.attack
@pytest.mark.body_inspection
@pytest.mark.sqli
def test_sqli_in_form_body(gateway_url, browser_session):
    """SQLi in a urlencoded POST body is blocked, not only in the query string."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "1' OR '1'='1"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in the form body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.body_inspection
@pytest.mark.xss
def test_xss_in_form_body(gateway_url, browser_session):
    """XSS in a urlencoded POST body is blocked."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "<script>alert(1)</script>"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"XSS in the form body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.body_inspection
@pytest.mark.sqli
def test_sqli_in_chunked_body(chunked_request):
    """Chunked transfer-encoding does not hide a body payload from inspection."""
    resp = chunked_request("/greet", body=b"name=1%27+OR+%271%27%3D%271")
    assert resp.status_code == 403, (
        f"SQLi in a chunked body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.body_inspection
@pytest.mark.sqli
def test_sqli_in_trailer_terminated_body(chunked_request):
    """A payload in a body terminated by a trailer is still inspected before EOS."""
    resp = chunked_request(
        "/greet",
        body=b"name=1%27+OR+%271%27%3D%271",
        trailer="denied",
    )
    assert resp.status_code == 403, (
        f"SQLi in a trailer-terminated body should be blocked "
        f"(expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.body_inspection
@pytest.mark.multipart
@pytest.mark.sqli
@pytest.mark.xfail(
    reason="multipart body panics the Wasm VM (temp_dir unsupported on WASI)",
    strict=False,
)
def test_multipart_body_is_inspected(gateway_url, browser_session):
    """A payload inside a multipart part is inspected like any other body.

    The same payload in a urlencoded body is blocked, so a multipart
    wrapper must not become a way around request body inspection.

    Carries the multipart marker, so it is excluded from a default run
    along with tests/rules/test_multipart.py — see that module for why.
    """
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data=b'--X\r\nContent-Disposition: form-data; name="name"\r\n'
        b"\r\n1' OR '1'='1\r\n--X--\r\n",
        headers={"Content-Type": "multipart/form-data; boundary=X"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in a multipart part should be blocked (expected 403, got {resp.status_code})"
    )
