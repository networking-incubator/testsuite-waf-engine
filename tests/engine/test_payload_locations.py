"""Payload locations — the same attack moved out of the query string.

CRS rules name their targets explicitly: 942100, for example, inspects
REQUEST_COOKIES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer,
ARGS_NAMES and ARGS. Every one of those collections has to be populated
by the connector before the rule can see it, so a payload that is caught
in the query string but missed in a cookie points at a missing
collection rather than a missing rule.

The URL path is deliberately not asserted here: most CRS rules target
ARGS rather than the path, so a payload in a path segment passing is not
by itself a defect.
"""

import pytest


SQLI = "1' OR '1'='1"

REFERER_NOT_INSPECTED = "engine does not inspect REQUEST_HEADERS:Referer"


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_query_string(gateway_url, browser_session):
    """Baseline: the payload is caught in the query string."""
    resp = browser_session.get(
        f"{gateway_url}/greet", params={"name": SQLI}, timeout=10
    )
    assert resp.status_code == 403, (
        f"SQLi in the query string should be blocked (got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_cookie(gateway_url, browser_session):
    """A payload in a cookie value is inspected (REQUEST_COOKIES)."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={"Cookie": f"sid={SQLI}"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in a cookie should be blocked (got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_in_user_agent(gateway_url, browser_session):
    """A payload in User-Agent is inspected (REQUEST_HEADERS:User-Agent)."""
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={"User-Agent": SQLI},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in User-Agent should be blocked (got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
@pytest.mark.xfail(reason=REFERER_NOT_INSPECTED, strict=False)
def test_sqli_in_referer(gateway_url, browser_session):
    """A payload in Referer is inspected (REQUEST_HEADERS:Referer).

    942100 lists Referer alongside User-Agent and the cookie collections,
    and the identical payload in either of those is blocked, so this one
    passing is a missing collection rather than a ruleset choice.
    """
    resp = browser_session.get(
        f"{gateway_url}/greet",
        params={"name": "test"},
        headers={"Referer": SQLI},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"SQLi in Referer should be blocked (got {resp.status_code})"
    )
