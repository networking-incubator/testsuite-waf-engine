"""False positives — ordinary input that happens to look like an attack.

The rest of the suite proves the ruleset blocks attacks. A ruleset that
blocks everything would pass all of it. These cases are the other half:
real user input containing apostrophes, SQL words used as English,
paths, URLs and encoded blobs, none of which may be rejected.

Over-blocking is usually what breaks a deployment, and it is what a
paranoia-level bump or a new rule tends to introduce, so treat a failure
here as seriously as a missed attack.
"""

import pytest


CASES = [
    pytest.param("O'Brien", id="apostrophe-in-surname"),
    pytest.param("Noël Lefèvre", id="accented-characters"),
    pytest.param("please select a union representative", id="sql-words-as-prose"),
    pytest.param("Dropbox Table Mountain", id="sql-keywords-inside-words"),
    pytest.param("alice.smith+tag@example.com", id="email-with-plus-tag"),
    pytest.param("550e8400-e29b-41d4-a716-446655440000", id="uuid"),
    pytest.param("https://example.com/products?id=42", id="url-as-value"),
    pytest.param(r"C:\Users\alice\Documents", id="windows-path"),
    pytest.param('{"id": 42, "ok": true}', id="json-document-as-value"),
    pytest.param(
        "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==",
        id="base64-blob",
    ),
    pytest.param("price > 100 && qty < 5", id="comparison-operators"),
    pytest.param("## Heading -- with dashes", id="markdown-with-double-dash"),
]


@pytest.mark.normal
@pytest.mark.parametrize("payload", CASES)
def test_benign_input_is_not_blocked(gateway_url, browser_session, payload):
    """Each value is legitimate user input and must reach the backend."""
    resp = browser_session.get(f"{gateway_url}/greet", params={"name": payload}, timeout=10)
    assert resp.status_code != 403, (
        f"Legitimate input {payload!r} was blocked as an attack (got {resp.status_code})"
    )
