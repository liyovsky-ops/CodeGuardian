#!/usr/bin/env python3
"""Query functions over the CodeGuardian threats.db knowledge base.

Intended for AI agents. Each function opens its own connection with a
sqlite3.Row factory, runs one query, and closes the connection. Every result
is returned as a plain list[dict] (or a nested dict for get_threat_full).

Stdlib only.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "threats.db"


def get_db_path() -> str:
    """Absolute path to threats.db (sibling of this script)."""
    return str(DB_PATH)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def _rows(sql: str, params: tuple = ()) -> list:
    conn = _connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Public query API
# --------------------------------------------------------------------------
def get_all_categories() -> list:
    """All categories with total + researched threat counts."""
    return _rows(
        """
        SELECT c.*,
               COUNT(t.id) AS total_threats,
               SUM(CASE WHEN t.status = 'researched' THEN 1 ELSE 0 END) AS researched_count
        FROM categories c
        LEFT JOIN threats t ON t.category_id = c.id
        GROUP BY c.id
        ORDER BY c.num
        """
    )


def get_threats_by_lang(lang: str) -> list:
    """Threats applicable to a given language, highest CVSS first."""
    return _rows(
        """
        SELECT t.*, c.name AS category_name
        FROM threats t
        JOIN threat_langs l ON t.id = l.threat_id
        JOIN categories c ON t.category_id = c.id
        WHERE l.lang = ?
        ORDER BY t.cvss IS NULL, t.cvss DESC
        """,
        (lang,),
    )


def get_threats_by_severity(severity: str) -> list:
    """Threats at a given severity, highest CVSS first."""
    return _rows(
        """
        SELECT t.*, c.name AS category_name
        FROM threats t
        JOIN categories c ON t.category_id = c.id
        WHERE t.severity = ?
        ORDER BY t.cvss IS NULL, t.cvss DESC
        """,
        (severity,),
    )


def get_threat_full(threat_id: str) -> dict:
    """Full nested view of a threat and all its deep-dive content."""
    conn = _connect()
    try:
        def fetch(sql, params=(threat_id,)):
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

        threat_row = conn.execute(
            """SELECT t.*, c.name AS category_name
               FROM threats t
               LEFT JOIN categories c ON t.category_id = c.id
               WHERE t.id = ?""",
            (threat_id,),
        ).fetchone()
        threat = dict(threat_row) if threat_row else None

        if threat is not None:
            threat["langs"] = [
                r["lang"] for r in conn.execute(
                    "SELECT lang FROM threat_langs WHERE threat_id = ? ORDER BY lang",
                    (threat_id,),
                ).fetchall()
            ]
            threat["cwes"] = [
                r["cwe"] for r in conn.execute(
                    "SELECT cwe FROM threat_cwes WHERE threat_id = ? ORDER BY cwe",
                    (threat_id,),
                ).fetchall()
            ]

        return {
            "threat": threat,
            "attacks": fetch(
                "SELECT * FROM attacks WHERE threat_id = ? ORDER BY id"),
            "incidents": fetch(
                "SELECT * FROM incidents WHERE threat_id = ? ORDER BY year DESC, id"),
            "defenses": fetch(
                "SELECT * FROM defenses WHERE threat_id = ? ORDER BY rank"),
            "tools": fetch(
                "SELECT * FROM tools WHERE threat_id = ? ORDER BY tool_type, id"),
            "cves": fetch(
                "SELECT * FROM cves WHERE threat_id = ? ORDER BY year DESC, cve_id"),
            "compliance": fetch(
                "SELECT * FROM compliance_mappings WHERE threat_id = ? ORDER BY id"),
            "sources": fetch(
                "SELECT * FROM sources WHERE threat_id = ? ORDER BY id"),
        }
    finally:
        conn.close()


def get_category_stats() -> list:
    """Per-category totals: threats, researched, incidents, CVEs."""
    return _rows(
        """
        SELECT c.id, c.num, c.name, c.icon, c.color, c.difficulty,
               COUNT(DISTINCT t.id) AS total_threats,
               COUNT(DISTINCT CASE WHEN t.status = 'researched' THEN t.id END) AS researched_count,
               COUNT(DISTINCT i.id) AS incident_count,
               COUNT(DISTINCT cv.id) AS cve_count
        FROM categories c
        LEFT JOIN threats t ON t.category_id = c.id
        LEFT JOIN incidents i ON i.threat_id = t.id
        LEFT JOIN cves cv ON cv.threat_id = t.id
        GROUP BY c.id
        ORDER BY c.num
        """
    )


def search_threats(query: str) -> list:
    """Substring search across threat name/description and attack descriptions.

    DISTINCT on threat id; returns matched threats with category name.
    """
    like = "%{}%".format(query)
    return _rows(
        """
        SELECT DISTINCT t.id, t.name, t.severity, t.cvss, t.status,
               t.description_en, c.name AS category_name
        FROM threats t
        JOIN categories c ON t.category_id = c.id
        LEFT JOIN attacks a ON a.threat_id = t.id
        WHERE t.name LIKE ?
           OR t.description_en LIKE ?
           OR a.description_en LIKE ?
        ORDER BY t.cvss IS NULL, t.cvss DESC, t.id
        """,
        (like, like, like),
    )


def get_incidents_count_by_category() -> list:
    """Incident counts grouped by category, descending."""
    return _rows(
        """
        SELECT c.name, COUNT(i.id) AS incident_count
        FROM categories c
        JOIN threats t ON t.category_id = c.id
        LEFT JOIN incidents i ON i.threat_id = t.id
        GROUP BY c.id
        ORDER BY incident_count DESC
        """
    )


def get_cves_by_year(year: int) -> list:
    """CVEs recorded for a given year, with their threat name/severity."""
    return _rows(
        """
        SELECT t.name, t.severity, cv.cve_id
        FROM threats t
        JOIN cves cv ON cv.threat_id = t.id
        WHERE cv.year = ?
        ORDER BY t.severity, cv.cve_id
        """,
        (year,),
    )


def get_lang_risk_summary() -> list:
    """Per-language threat counts with Critical/High breakdown."""
    return _rows(
        """
        SELECT l.lang,
               COUNT(DISTINCT t.id) AS threat_count,
               SUM(CASE WHEN t.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
               SUM(CASE WHEN t.severity = 'High' THEN 1 ELSE 0 END) AS high_count
        FROM threat_langs l
        JOIN threats t ON l.threat_id = t.id
        GROUP BY l.lang
        ORDER BY critical_count DESC, threat_count DESC
        """
    )


if __name__ == "__main__":
    import json
    print("DB:", get_db_path())
    print(json.dumps(get_category_stats(), indent=2, ensure_ascii=False))
