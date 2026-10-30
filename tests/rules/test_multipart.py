"""CRS 922 — Multipart Attack.

Tests the 922 family, which rejects multipart/form-data requests whose
part headers are malformed or carry constructs that parsers disagree
about. These are the structural rules: a request smuggled past a
permissive multipart parser can present one body to the WAF and another
to the application.

Expected triggering rules:
  - 922100/922160: multipart _charset_ definition is not allowed by policy
  - 922110: illegal MIME multipart header content-type charset parameter
  - 922120: Content-Transfer-Encoding part header (deprecated by RFC 7578)
  - 922130: multipart header contains characters outside the valid range

These used to panic the engine's Wasm VM on any multipart body, which is
why the module was once excluded from a default run. The engine parses
multipart now, so they run like everything else; what remains is a
detection gap in three of the structural cases, marked xfail below.

See test_multipart_body_is_inspected in tests/engine/test_body_inspection.py
for the engine-side counterpart, which now passes.
"""

import pytest


BOUNDARY = "X"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"

# The body reaches the ruleset now, but these three structural cases are
# not scored up to the blocking threshold: two are answered by the backend
# (200) and the byte-range case hits the body limit first (413).
MULTIPART_NOT_BLOCKED = "CRS 922 structural case is not blocked (gets 200 or 413)"


CASES = [
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="name"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nQQ==\r\n--X--\r\n",
        id="content-transfer-encoding-part-header",
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="_charset_"\r\n\r\nutf-8\r\n--X--\r\n',
        id="charset-part",
        marks=pytest.mark.xfail(reason=MULTIPART_NOT_BLOCKED, strict=False),
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
        b"Content-Type: text/plain; charset=bogus-charset\r\n\r\nA\r\n--X--\r\n",
        id="illegal-part-content-type-charset",
        marks=pytest.mark.xfail(reason=MULTIPART_NOT_BLOCKED, strict=False),
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="name"\r\n\xc0Evil: x\r\n\r\nA\r\n--X--\r\n',
        id="invalid-header-byte-range",
        marks=pytest.mark.xfail(reason=MULTIPART_NOT_BLOCKED, strict=False),
    ),
]


@pytest.mark.attack
@pytest.mark.multipart
@pytest.mark.parametrize("body", CASES)
def test_multipart_attack(gateway_url, browser_session, body):
    """Each malformed multipart body should trigger a CRS 922 rule and be blocked."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data=body,
        headers={"Content-Type": CONTENT_TYPE},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"Malformed multipart should be blocked (expected 403, got {resp.status_code})"
    )


@pytest.mark.normal
@pytest.mark.multipart
def test_benign_multipart_passes(gateway_url, browser_session):
    """A well-formed multipart upload is not caught by the 922 structural rules."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data=b'--X\r\nContent-Disposition: form-data; name="name"\r\n\r\nAlice\r\n--X--\r\n',
        headers={"Content-Type": CONTENT_TYPE},
        timeout=10,
    )
    assert resp.status_code not in (403, 503), (
        f"Benign multipart should reach the backend (got {resp.status_code})"
    )
