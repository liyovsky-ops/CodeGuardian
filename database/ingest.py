#!/usr/bin/env python3
"""Ingest CodeGuardian YAML content into a SQLite knowledge base (threats.db).

Stdlib only (pathlib, sqlite3, re) plus PyYAML, which ships with the project.
Idempotent: uses INSERT OR REPLACE and clears deep-dive tables before reload,
so it is safe to re-run.

Run from anywhere:  python3 database/ingest.py
"""

import re
import sqlite3
from pathlib import Path

import yaml

# --------------------------------------------------------------------------
# Paths (resolved relative to this script, so it runs from any cwd)
# --------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONTENT_DIR = PROJECT_ROOT / "src" / "content"
CATEGORIES_DIR = CONTENT_DIR / "categories"
DEEPDIVES_DIR = CONTENT_DIR / "deepdives"
SCHEMA_PATH = SCRIPT_DIR / "schema.sql"
DB_PATH = SCRIPT_DIR / "threats.db"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Map raw lang markers -> normalized canonical language. Anything not in this
# map (http, json, yaml, text, unknown, graphql, ...) is treated as non-code
# and skipped.
LANG_MAP = {
    "python": "python",
    "py": "python",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "nodejs": "javascript",
    "node": "javascript",
    "node.js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "php": "php",
    "dotnet": "dotnet",
    ".net": "dotnet",
    "csharp": "dotnet",
    "c#": "dotnet",
    "go": "go",
    "golang": "go",
    "ruby": "ruby",
    "rb": "ruby",
    "cpp": "cpp",
    "c++": "cpp",
    "c": "cpp",
    "rust": "rust",
    "rs": "rust",
    "swift": "swift",
    "kotlin": "kotlin",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def clean(value):
    """Strip surrounding curly/smart quotes and whitespace from a scalar.

    Category 01's meta.yaml wraps values in U+201C / U+201D smart quotes which
    PyYAML keeps inside the string. Normalize those away.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    s = value.strip()
    # strip matched smart quotes
    if len(s) >= 2 and s[0] in "“”‘’" and s[-1] in "“”‘’":
        s = s[1:-1].strip()
    return s


def en(value):
    """Pick the English string from a {en, pl} dict, a plain string, or None."""
    if value is None:
        return None
    if isinstance(value, dict):
        return clean(value.get("en") or value.get("pl"))
    return clean(value)


def normalize_lang(raw):
    """Map a raw lang marker / code label to a canonical language or None."""
    if not raw:
        return None
    key = str(raw).strip().lower()
    if key in LANG_MAP:
        return LANG_MAP[key]
    # Code-section labels like "Python (Flask)", "Java (Spring)", "Node.js".
    # Take the leading word(s) before a parenthesis / slash and re-test.
    head = re.split(r"[\(/]", key, 1)[0].strip()
    if head in LANG_MAP:
        return LANG_MAP[head]
    # Try first token (handles ".NET 6", "C++17", etc.)
    first = head.split()[0] if head.split() else ""
    return LANG_MAP.get(first)


def cve_year(cve_id):
    m = re.match(r"CVE-(\d{4})-", cve_id, re.IGNORECASE)
    return int(m.group(1)) if m else None


def extract_cves(*texts):
    """Return a sorted set of normalized CVE ids found across the given texts."""
    found = set()
    for t in texts:
        if not t:
            continue
        for m in CVE_RE.findall(str(t)):
            found.add(m.upper())
    return found


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------------
# Ingest stages
# --------------------------------------------------------------------------
def ingest_categories(conn):
    count = 0
    for cat_dir in sorted(CATEGORIES_DIR.iterdir()):
        meta_path = cat_dir / "meta.yaml"
        if not meta_path.is_file():
            continue
        m = load_yaml(meta_path) or {}
        cat_id = clean(m.get("id"))
        if not cat_id:
            continue
        conn.execute(
            """INSERT OR REPLACE INTO categories
               (id, num, name, slug, icon, color, difficulty, description_en, verdict_en)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cat_id,
                m.get("num"),
                clean(m.get("name")),
                cat_dir.name,  # slug = directory name (e.g. 01_injection)
                clean(m.get("icon")),
                clean(m.get("color")),
                clean(m.get("difficulty")),
                clean(m.get("desc_en")),
                clean(m.get("verdict_en")),
            ),
        )
        count += 1
    return count


def ingest_threats(conn):
    """Insert threats from each category's threats.yaml, in directory order so
    a threat's category_id matches the directory it lives in."""
    count = 0
    # Build a num -> category_id index from categories table for FK linking.
    num_to_cat = {
        row[0]: row[1]
        for row in conn.execute("SELECT num, id FROM categories").fetchall()
    }
    for cat_dir in sorted(CATEGORIES_DIR.iterdir()):
        threats_path = cat_dir / "threats.yaml"
        meta_path = cat_dir / "meta.yaml"
        if not threats_path.is_file():
            continue
        meta = load_yaml(meta_path) if meta_path.is_file() else {}
        category_id = clean((meta or {}).get("id"))
        # Fallback: derive from num if id missing
        if not category_id:
            category_id = num_to_cat.get((meta or {}).get("num"))

        data = load_yaml(threats_path) or {}
        for t in data.get("threats") or []:
            tid = clean(t.get("id"))
            if not tid:
                continue
            cwe_list = t.get("cwe") or []
            cwe_primary = clean(cwe_list[0]) if cwe_list else None
            conn.execute(
                """INSERT OR REPLACE INTO threats
                   (id, category_id, name, severity, difficulty, confidence,
                    cvss, cwe_primary, description_en, vuln_example, safe_example,
                    note_en, status, color, standard)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           COALESCE((SELECT status FROM threats WHERE id = ?), 'pending'),
                           (SELECT color FROM threats WHERE id = ?),
                           (SELECT standard FROM threats WHERE id = ?))""",
                (
                    tid,
                    category_id,
                    clean(t.get("name")),
                    clean(t.get("severity")),
                    clean(t.get("difficulty")),
                    clean(t.get("confidence")),
                    None,  # cvss populated from deepdive
                    cwe_primary,
                    clean(t.get("desc_en")),
                    clean(t.get("vuln")),
                    clean(t.get("safe")),
                    clean(t.get("note_en")),
                    tid, tid, tid,  # preserve status/color/standard on re-run
                ),
            )
            count += 1

            # threat_cwes
            for cwe in cwe_list:
                cwe = clean(cwe)
                if cwe:
                    conn.execute(
                        "INSERT OR IGNORE INTO threat_cwes (threat_id, cwe) VALUES (?, ?)",
                        (tid, cwe),
                    )

            # threat_langs from the threats.yaml `lang` field
            lang = normalize_lang(t.get("lang"))
            if lang:
                conn.execute(
                    "INSERT OR IGNORE INTO threat_langs (threat_id, lang) VALUES (?, ?)",
                    (tid, lang),
                )
    return count


def ingest_deepdives(conn):
    stats = {"researched": 0, "attacks": 0, "incidents": 0,
             "defenses": 0, "tools": 0, "cves": 0,
             "compliance": 0, "sources": 0}

    if not DEEPDIVES_DIR.is_dir():
        return stats

    for dd_path in sorted(DEEPDIVES_DIR.glob("*.yaml")):
        d = load_yaml(dd_path) or {}
        meta = d.get("meta") or {}
        threat_id = clean(meta.get("threatId"))
        if not threat_id:
            continue

        # Only attach to a threat that actually exists.
        exists = conn.execute(
            "SELECT 1 FROM threats WHERE id = ?", (threat_id,)
        ).fetchone()
        if not exists:
            continue

        # Update threat: mark researched + enrich cvss/color/standard.
        conn.execute(
            """UPDATE threats
               SET status = 'researched',
                   cvss = COALESCE(?, cvss),
                   color = COALESCE(?, color),
                   standard = COALESCE(?, standard),
                   cwe_primary = COALESCE(cwe_primary, ?)
               WHERE id = ?""",
            (
                meta.get("cvss"),
                clean(meta.get("color")),
                clean(meta.get("standard")),
                clean(meta.get("cwe")),
                threat_id,
            ),
        )
        stats["researched"] += 1

        sections = d.get("sections") or {}

        # Clear existing deep-dive rows for this threat (idempotent reload).
        for tbl in ("attacks", "incidents", "defenses", "tools",
                    "cves", "compliance_mappings", "sources"):
            conn.execute(f"DELETE FROM {tbl} WHERE threat_id = ?", (threat_id,))

        cve_texts = []

        # --- attacks ---
        for a in (sections.get("attacks") or {}).get("items") or []:
            desc = en(a.get("description"))
            cve_texts.append(desc)
            conn.execute(
                """INSERT INTO attacks (threat_id, name, severity, description_en, payload)
                   VALUES (?, ?, ?, ?, ?)""",
                (threat_id, clean(a.get("name")), clean(a.get("sev")),
                 desc, clean(a.get("payload"))),
            )
            stats["attacks"] += 1

        # --- incidents ---
        for i in (sections.get("incidents") or {}).get("items") or []:
            desc = en(i.get("description"))
            cve_texts.append(desc)
            cve_texts.append(en(i.get("impact")))
            conn.execute(
                """INSERT INTO incidents (threat_id, org, year, impact, cost, description_en)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (threat_id, clean(i.get("org")), i.get("year"),
                 en(i.get("impact")), en(i.get("cost")), desc),
            )
            stats["incidents"] += 1

        # --- defenses ---
        for df in (sections.get("defenses") or {}).get("items") or []:
            conn.execute(
                """INSERT INTO defenses (threat_id, rank, effectiveness, kind, label_en, note_en)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (threat_id, df.get("rank"), df.get("eff"),
                 clean(df.get("kind")), en(df.get("label")), en(df.get("note"))),
            )
            stats["defenses"] += 1

        # --- tools (sast / dast) ---
        tools_sec = sections.get("tools") or {}
        for tool_type in ("sast", "dast"):
            for entry in tools_sec.get(tool_type) or []:
                if isinstance(entry, (list, tuple)):
                    name = clean(entry[0]) if len(entry) > 0 else None
                    desc = clean(entry[1]) if len(entry) > 1 else None
                elif isinstance(entry, dict):
                    name = clean(entry.get("name") or entry.get("label"))
                    desc = en(entry.get("description") or entry.get("note"))
                else:
                    name, desc = clean(entry), None
                conn.execute(
                    """INSERT INTO tools (threat_id, tool_type, name, description)
                       VALUES (?, ?, ?, ?)""",
                    (threat_id, tool_type, name, desc),
                )
                stats["tools"] += 1

        # --- compliance ---
        for c in (sections.get("compliance") or {}).get("items") or []:
            reqs = c.get("items") or []
            req_text = "; ".join(clean(r) for r in reqs if clean(r))
            conn.execute(
                """INSERT INTO compliance_mappings (threat_id, standard, requirements)
                   VALUES (?, ?, ?)""",
                (threat_id, clean(c.get("std")), req_text),
            )
            stats["compliance"] += 1

        # --- sources: hero.sources + every section's inlineSources ---
        seen_urls = set()
        source_buckets = []
        source_buckets.extend((d.get("hero") or {}).get("sources") or [])
        for sec in sections.values():
            if isinstance(sec, dict):
                source_buckets.extend(sec.get("inlineSources") or [])
                source_buckets.extend(sec.get("sources") or [])
        for s in source_buckets:
            if not isinstance(s, dict):
                continue
            url = clean(s.get("url"))
            label = clean(s.get("label"))
            key = url or label
            if not key or key in seen_urls:
                continue
            seen_urls.add(key)
            conn.execute(
                "INSERT OR IGNORE INTO sources (threat_id, label, url) VALUES (?, ?, ?)",
                (threat_id, label, url),
            )
            stats["sources"] += 1

        # --- langs from deepdive code section labels ---
        for lang_block in (sections.get("code") or {}).get("languages") or []:
            lang = normalize_lang(lang_block.get("lang")) or normalize_lang(lang_block.get("label"))
            if lang:
                conn.execute(
                    "INSERT OR IGNORE INTO threat_langs (threat_id, lang) VALUES (?, ?)",
                    (threat_id, lang),
                )

        # --- CVEs extracted from attack + incident text ---
        for cve in extract_cves(*cve_texts):
            conn.execute(
                "INSERT OR IGNORE INTO cves (threat_id, cve_id, year) VALUES (?, ?, ?)",
                (threat_id, cve, cve_year(cve)),
            )
            stats["cves"] += 1

    return stats


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
            conn.executescript(fh.read())

        n_cat = ingest_categories(conn)
        n_threats = ingest_threats(conn)
        dd = ingest_deepdives(conn)
        conn.commit()

        print(
            "Ingested: {c} categories, {t} threats ({r} researched), "
            "{a} attacks, {i} incidents".format(
                c=n_cat, t=n_threats, r=dd["researched"],
                a=dd["attacks"], i=dd["incidents"],
            )
        )
        print(
            "  + {d} defenses, {to} tools, {cv} CVEs, {co} compliance maps, "
            "{s} sources".format(
                d=dd["defenses"], to=dd["tools"], cv=dd["cves"],
                co=dd["compliance"], s=dd["sources"],
            )
        )
        print("  DB: {}".format(DB_PATH))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
