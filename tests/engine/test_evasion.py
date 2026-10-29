"""Evasion — obfuscated payloads must still be caught.

Each case is a payload the suite already covers in its plain form,
rewritten the way an attacker would to slip past a naive matcher:
re-encoded, case-shifted, entity-escaped, null-byte prefixed, or split
with inline comments.

These exercise the transformation pipeline the rules rely on
(t:urlDecodeUni, t:lowercase, t:htmlEntityDecode, t:removeNulls,
t:replaceComments). That pipeline is engine code, so a regression here
is an engine defect even though the match itself is a ruleset concern.

Pre-encoded payloads go into the URL verbatim rather than through
params=, which would percent-encode the % signs and silently change
what is being tested.
"""

import pytest


LITERAL_CASES = [
    pytest.param("<ScRiPt>alert(1)</ScRiPt>", id="xss-mixed-case"),
    pytest.param("&lt;script&gt;alert(1)&lt;/script&gt;", id="xss-html-entities"),
    pytest.param("1'/**/OR/**/'1'='1", id="sqli-inline-comment-split"),
    pytest.param("1' oR '1'='1", id="sqli-mixed-case-keyword"),
]


@pytest.mark.attack
@pytest.mark.parametrize("payload", LITERAL_CASES)
def test_obfuscated_payload(gateway_url, browser_session, payload):
    """Case-shifted, entity-escaped and comment-split payloads stay blocked."""
    resp = browser_session.get(
        f"{gateway_url}/greet", params={"name": payload}, timeout=10
    )
    assert resp.status_code == 403, (
        f"Obfuscated payload should be blocked (expected 403, got {resp.status_code})"
    )


ENCODED_CASES = [
    pytest.param("%3Cscript%3Ealert(1)%3C/script%3E", id="xss-url-encoded"),
    pytest.param(
        "%253Cscript%253Ealert(1)%253C/script%253E", id="xss-double-url-encoded"
    ),
    pytest.param("%00%3Cscript%3Ealert(1)%3C/script%3E", id="xss-null-byte-prefix"),
    pytest.param("1%27%20OR%20%271%27%3D%271", id="sqli-url-encoded"),
]


@pytest.mark.attack
@pytest.mark.parametrize("query", ENCODED_CASES)
def test_encoded_payload(gateway_url, browser_session, query):
    """Percent-encoded and double-encoded payloads stay blocked."""
    resp = browser_session.get(f"{gateway_url}/greet?name={query}", timeout=10)
    assert resp.status_code == 403, (
        f"Encoded payload should be blocked (expected 403, got {resp.status_code})"
    )
