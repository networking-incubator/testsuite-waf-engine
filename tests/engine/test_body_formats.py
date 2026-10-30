"""Request body formats — the same payload in each body encoding.

A WAF has to turn a request body into inspectable arguments before any
rule can match it, and it needs a parser per content type to do that. A
payload the ruleset catches in a urlencoded body must not survive just
because it was wrapped in JSON or XML. Which parser is missing is an
engine question, not a ruleset one, so these live here.

tests/engine/test_payload_locations.py covers the same idea for payloads
placed outside the body.
"""

import pytest


SQLI = "1' OR '1'='1"
XSS = "<script>alert(1)</script>"


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_xml_body(gateway_url, browser_session):
    """SQLi in an XML body is inspected — CRS targets XML:/* directly."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data=f"<?xml version='1.0'?><r><name>{SQLI}</name></r>".encode(),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in an XML body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.xss
def test_xss_in_json_body(gateway_url, browser_session):
    """XSS in a JSON body is blocked.

    This one passes without a JSON parser, because the XSS rules match the
    raw body text. It is here to stop that incidental hit from being read
    as proof that JSON bodies are inspected — see the SQLi case below.
    """
    resp = browser_session.post(
        f"{gateway_url}/greet",
        json={"name": XSS},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"XSS in a JSON body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_json_body(gateway_url, browser_session):
    """SQLi in a JSON body is inspected like any other body encoding.

    The identical payload is blocked in a urlencoded body and in an XML
    body, so a JSON wrapper must not be a way around inspection. Any API
    behind the WAF is unprotected against body payloads while this fails.
    """
    resp = browser_session.post(
        f"{gateway_url}/greet",
        json={"name": SQLI},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in a JSON body should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_nested_json_body(gateway_url, browser_session):
    """A payload nested in JSON objects and arrays is still reached."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        json={"outer": {"inner": [SQLI]}},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi nested in JSON should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.normal
def test_benign_json_body(gateway_url, browser_session):
    """An ordinary JSON document is not blocked."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        json={"name": "Alice", "id": 42, "tags": ["a", "b"]},
        timeout=10,
    )
    assert resp.status_code != 403, (
        f"Benign JSON body should not be blocked (got {resp.status_code})"
    )
