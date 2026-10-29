"""Chained SQL injection attack — realistic multi-step campaign.

Simulates a real attacker's workflow against the vulnerable Flask+MariaDB
app at /greet?name=..., which uses raw f-string interpolation in both
INSERT and SELECT queries (textbook SQLi).

The attack progresses through 4 phases:
  1. Reconnaissance — fingerprint the target with a scanner
  2. Vulnerability discovery — probe for SQL injection
  3. Schema enumeration — map the database structure via UNION SELECT
  4. Data exfiltration — extract data, credentials, and server files

The WAF should block every step. Each test documents what would happen
without the WAF to illustrate the real-world impact.

CRS rules involved: 913100 (scanner detection), 942100-942440 (SQLi).
"""

import pytest


@pytest.mark.attack
@pytest.mark.sqli
@pytest.mark.chain
class TestSQLiAttackChain:
    """Multi-step SQLi campaign — ordered from recon to exfiltration."""

    # ------------------------------------------------------------------
    # Phase 1: Reconnaissance
    # ------------------------------------------------------------------

    def test_phase1_scanner_probe(self, gateway_url, browser_session):
        """Attacker runs sqlmap to find injectable endpoints.

        CRS 913100 blocks the known scanner User-Agent.
        Without WAF: returns 200, confirming the app is live and revealing
        Flask server headers.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "test"},
            headers={"User-Agent": "sqlmap/1.7.2"},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 1: scanner probe should be blocked (got {resp.status_code})"
        )

    # ------------------------------------------------------------------
    # Phase 2: Vulnerability discovery
    # ------------------------------------------------------------------

    def test_phase2a_error_based_probe(self, gateway_url, browser_session):
        """Attacker probes for SQLi with a tautology that forces a true condition.

        A bare single quote would also work in practice, but CRS correctly
        ignores it (could be a legitimate apostrophe like "O'Brien").
        The OR-based tautology is the attacker's next move and is detected
        by CRS 942100 via libinjection.
        Without WAF: the app returns the greeting — confirming the injection
        point is live and the database evaluates attacker-controlled SQL.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "' OR 1=1--"},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 2a: error probe should be blocked (got {resp.status_code})"
        )

    def test_phase2b_boolean_true(self, gateway_url, browser_session):
        """Attacker confirms injection with a boolean tautology (true case).

        CRS 942100/942210 detect the AND-based SQLi pattern.
        Without WAF: returns 200 with greeting — confirms the injected
        condition is evaluated by the database.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "test' AND '1'='1"},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 2b: boolean true probe should be blocked (got {resp.status_code})"
        )

    def test_phase2c_boolean_false(self, gateway_url, browser_session):
        """Attacker sends the false case to compare against the true case.

        CRS 942100/942210 detect the AND-based SQLi pattern.
        Without WAF: returns 200 but with no matching rows — confirming
        the boolean condition controls query results (injectable).
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "test' AND '1'='2"},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 2c: boolean false probe should be blocked (got {resp.status_code})"
        )

    # ------------------------------------------------------------------
    # Phase 3: Schema enumeration
    # ------------------------------------------------------------------

    def test_phase3a_column_count(self, gateway_url, browser_session):
        """Attacker determines column count for UNION-based extraction.

        CRS 942100/942440 detect the UNION SELECT pattern.
        Without WAF: returns 200 — confirms the SELECT has 1 column,
        so UNION SELECT payloads need exactly one expression.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "' UNION SELECT NULL-- "},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 3a: column count should be blocked (got {resp.status_code})"
        )

    def test_phase3b_enumerate_tables(self, gateway_url, browser_session):
        """Attacker lists all tables in the current database.

        CRS 942100/942440 detect the UNION SELECT + information_schema.
        Without WAF: response contains 'greetings' — attacker now
        knows the table name and can target it directly.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={
                "name": "' UNION SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=database()-- "
            },
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 3b: table enumeration should be blocked (got {resp.status_code})"
        )

    def test_phase3c_enumerate_columns(self, gateway_url, browser_session):
        """Attacker maps the columns of the 'greetings' table.

        CRS 942100/942440 detect the UNION SELECT + information_schema.
        Without WAF: response reveals columns id, name, created_at —
        attacker now has the full schema to craft targeted queries.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={
                "name": "' UNION SELECT column_name FROM information_schema.columns "
                "WHERE table_name='greetings'-- "
            },
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 3c: column enumeration should be blocked (got {resp.status_code})"
        )

    # ------------------------------------------------------------------
    # Phase 4: Data exfiltration
    # ------------------------------------------------------------------

    def test_phase4a_dump_data(self, gateway_url, browser_session):
        """Attacker extracts all stored names from the greetings table.

        CRS 942100/942440 detect the UNION SELECT.
        Without WAF: response contains every name ever submitted —
        full data breach of application records.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "' UNION SELECT name FROM greetings-- "},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 4a: data dump should be blocked (got {resp.status_code})"
        )

    def test_phase4b_db_metadata(self, gateway_url, browser_session):
        """Attacker extracts the database user and privileges.

        CRS 942100 detects the UNION SELECT + user() function call.
        Without WAF: response reveals 'root@localhost' — confirming
        the app connects to MariaDB as root with full privileges.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "' UNION SELECT user()-- "},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 4b: DB metadata extraction should be blocked (got {resp.status_code})"
        )

    def test_phase4c_file_read(self, gateway_url, browser_session):
        """Attacker reads server files via MariaDB's LOAD_FILE().

        CRS 942100 detects the UNION SELECT + LOAD_FILE pattern.
        Without WAF: if the DB user has FILE privilege, /etc/passwd
        contents are returned in the HTTP response — server compromise.
        """
        resp = browser_session.get(
            f"{gateway_url}/greet",
            params={"name": "' UNION SELECT LOAD_FILE('/etc/passwd')-- "},
            timeout=10,
        )
        assert resp.status_code == 403, (
            f"Phase 4c: file read should be blocked (got {resp.status_code})"
        )
