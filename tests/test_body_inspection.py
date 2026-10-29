"""Request body inspection — attacks delivered in the body, not the query.

Tests that the WAF buffers and inspects request bodies regardless of how
they are framed. An attacker can move a payload out of the query string
into a form body, split it across chunked encoding, hide it behind a
trailer, or pad it so that only a prefix fits the inspection limit; none
of these should let the payload through.

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
@pytest.mark.sqli
def test_sqli_at_start_of_oversized_body(gateway_url, browser_session):
    """A payload inside the inspected prefix is caught even if the body is truncated."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "1' OR '1'='1", "padding": "x" * 65536},
        timeout=30,
    )
    assert resp.status_code == 403, (
        f"SQLi in the inspected body prefix should be blocked "
        f"(expected 403, got {resp.status_code})"
    )
