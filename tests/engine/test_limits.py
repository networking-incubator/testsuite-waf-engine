"""Body inspection limits — behavior at and past the buffered body size.

A WAF can only inspect as much of a body as it buffers. These tests pin
down what happens at the edge: a benign body past the limit must be
truncated for inspection rather than rejected, and a payload that lands
inside the inspected prefix must still be caught.

What happens to a payload placed *after* the limit is a policy choice
(ProcessPartial lets it through, Reject returns 413), so it is not
asserted here — that distinction needs a known directives map.
"""

import pytest
from conftest import BLOCKED


OVERSIZED = "x" * 65536


@pytest.mark.normal
def test_oversized_benign_request_body(gateway_url, browser_session):
    """A benign body past the inspection limit is truncated, not rejected."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": OVERSIZED},
        timeout=30,
    )
    assert resp.status_code not in BLOCKED, (
        f"Oversized benign body should not be blocked (got {resp.status_code})"
    )


@pytest.mark.attack
@pytest.mark.sqli
def test_sqli_at_start_of_oversized_body(gateway_url, browser_session):
    """A payload inside the inspected prefix is caught even if the body is truncated."""
    resp = browser_session.post(
        f"{gateway_url}/greet",
        data={"name": "1' OR '1'='1", "padding": OVERSIZED},
        timeout=30,
    )
    assert resp.status_code == 403, (
        f"SQLi in the inspected body prefix should be blocked "
        f"(expected 403, got {resp.status_code})"
    )
