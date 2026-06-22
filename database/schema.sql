-- CodeGuardian threat intelligence knowledge base schema
-- SQLite. Run via ingest.py (which executes this script).

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Core entities
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS categories (
    id             TEXT PRIMARY KEY,
    num            INTEGER,
    name           TEXT,
    slug           TEXT,
    icon           TEXT,
    color          TEXT,
    difficulty     TEXT,
    description_en TEXT,
    verdict_en     TEXT
);

CREATE TABLE IF NOT EXISTS threats (
    id             TEXT PRIMARY KEY,
    category_id    TEXT REFERENCES categories(id),
    name           TEXT,
    severity       TEXT CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    difficulty     TEXT,
    confidence     TEXT,
    cvss           REAL,
    cwe_primary    TEXT,
    description_en TEXT,
    vuln_example   TEXT,
    safe_example   TEXT,
    note_en        TEXT,
    status         TEXT DEFAULT 'pending',   -- 'researched' when a deepdive exists
    color          TEXT,
    standard       TEXT
);

CREATE TABLE IF NOT EXISTS threat_langs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT REFERENCES threats(id),
    lang      TEXT,
    UNIQUE (threat_id, lang)
);

CREATE TABLE IF NOT EXISTS threat_cwes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT REFERENCES threats(id),
    cwe       TEXT,
    UNIQUE (threat_id, cwe)
);

-- ---------------------------------------------------------------------------
-- Deep-dive content (only for researched threats)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS attacks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id      TEXT REFERENCES threats(id),
    name           TEXT,
    severity       TEXT,
    description_en TEXT,
    payload        TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id      TEXT REFERENCES threats(id),
    org            TEXT,
    year           INTEGER,
    impact         TEXT,
    cost           TEXT,
    description_en TEXT
);

CREATE TABLE IF NOT EXISTS defenses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id     TEXT REFERENCES threats(id),
    rank          INTEGER,
    effectiveness INTEGER,
    kind          TEXT,
    label_en      TEXT,
    note_en       TEXT
);

CREATE TABLE IF NOT EXISTS tools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id   TEXT REFERENCES threats(id),
    tool_type   TEXT CHECK (tool_type IN ('sast', 'dast')),
    name        TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT REFERENCES threats(id),
    cve_id    TEXT,
    year      INTEGER,
    UNIQUE (threat_id, cve_id)
);

CREATE TABLE IF NOT EXISTS compliance_mappings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id    TEXT REFERENCES threats(id),
    standard     TEXT,
    requirements TEXT
);

CREATE TABLE IF NOT EXISTS sources (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT REFERENCES threats(id),
    label     TEXT,
    url       TEXT,
    UNIQUE (threat_id, url)
);

-- ---------------------------------------------------------------------------
-- Indexes for common query paths
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_threats_category   ON threats(category_id);
CREATE INDEX IF NOT EXISTS idx_threats_severity   ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_status     ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threat_langs_lang  ON threat_langs(lang);
CREATE INDEX IF NOT EXISTS idx_threat_langs_tid   ON threat_langs(threat_id);
CREATE INDEX IF NOT EXISTS idx_threat_cwes_tid    ON threat_cwes(threat_id);
CREATE INDEX IF NOT EXISTS idx_attacks_tid        ON attacks(threat_id);
CREATE INDEX IF NOT EXISTS idx_incidents_tid      ON incidents(threat_id);
CREATE INDEX IF NOT EXISTS idx_defenses_tid       ON defenses(threat_id);
CREATE INDEX IF NOT EXISTS idx_tools_tid          ON tools(threat_id);
CREATE INDEX IF NOT EXISTS idx_cves_tid           ON cves(threat_id);
CREATE INDEX IF NOT EXISTS idx_cves_year          ON cves(year);
CREATE INDEX IF NOT EXISTS idx_compliance_tid     ON compliance_mappings(threat_id);
CREATE INDEX IF NOT EXISTS idx_sources_tid        ON sources(threat_id);
