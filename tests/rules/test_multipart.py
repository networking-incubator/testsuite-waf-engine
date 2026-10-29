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

Every test here is xfail, and the whole module is deselected from a
default run: against the current engine, any multipart/form-data body
panics the Wasm VM in on_http_request_body with "not supported by WASI
yet" (std::env::temp_dir(), which Coraza's multipart processor calls to
spill uploaded parts to disk). With failure_policy FAIL_CLOSED the
request becomes a 503, and because each panic takes out a worker VM, a
handful of such requests degrades the gateway for unrelated traffic.

Running these therefore corrupts the results of every test that follows,
which is why pyproject.toml excludes the multipart marker by default.
Run them deliberately with `make test-multipart`. They flip to passing
once multipart parsing works; until then they double as a reproducer.

See test_multipart_body_is_inspected in tests/engine/test_body_inspection.py
for the matching engine-side gap.
"""

import pytest


BOUNDARY = "X"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"

# Any multipart body panics the Wasm VM before a rule can evaluate, so the
# gateway answers 503 (FAIL_CLOSED) instead of 403.
MULTIPART_PANICS_VM = "multipart body panics the Wasm VM (temp_dir unsupported on WASI)"


CASES = [
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="name"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nQQ==\r\n--X--\r\n",
        id="content-transfer-encoding-part-header",
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="_charset_"\r\n'
        b"\r\nutf-8\r\n--X--\r\n",
        id="charset-part",
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n'
        b"Content-Type: text/plain; charset=bogus-charset\r\n\r\nA\r\n--X--\r\n",
        id="illegal-part-content-type-charset",
    ),
    pytest.param(
        b'--X\r\nContent-Disposition: form-data; name="name"\r\n'
        b"\xc0Evil: x\r\n\r\nA\r\n--X--\r\n",
        id="invalid-header-byte-range",
    ),
]


@pytest.mark.attack
@pytest.mark.multipart
@pytest.mark.xfail(reason=MULTIPART_PANICS_VM, strict=False)
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
@pytest.mark.xfail(reason=MULTIPART_PANICS_VM, strict=False)
def test_benign_multipart_passes(gateway_url, browser_session):
    """A well-formed multipart upload is not caught by the 922 structural rules.

    This is the clearest statement of the panic: even a benign upload
    never reaches the backend.
    """
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data=b'--X\r\nContent-Disposition: form-data; name="name"\r\n\r\nAlice\r\n--X--\r\n',
        headers={"Content-Type": CONTENT_TYPE},
        timeout=10,
    )
    assert resp.status_code not in (403, 503), (
        f"Benign multipart should reach the backend (got {resp.status_code})"
    )
