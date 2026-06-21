/* =========================================================================
   Code Guardian — NoSQL Injection deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: ORANGE (#f97316) — NoSQL Injection is High severity, not Critical.
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
  tab: { en: 'NoSQLi', pl: 'NoSQLi' },
  open: { en: 'Open NoSQL Injection deep-dive', pl: 'Otwórz przewodnik NoSQL Injection' },
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
  { id: 'nosqli-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'nosqli-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'nosqli-cheatsheet', en: 'DB cheatsheet', pl: 'Ściąga DB' },
  { id: 'nosqli-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'nosqli-orm', en: 'ODM false safety', pl: 'Fałszywe bezpieczeństwo ODM' },
  { id: 'nosqli-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'nosqli-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'nosqli-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'nosqli-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'nosqli-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'nosqli-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'nosqli-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'Operator injection',
    sev: 'high',
    desc: { en: 'Injecting query operators ($gt, $ne, $regex) as JSON keys manipulates query logic. No string grammar to escape — valid JSON rewrites the filter.', pl: 'Wstrzyknięcie operatorów ($gt, $ne, $regex) jako kluczy JSON zmienia logikę zapytania. Brak gramatyki stringów do escapowania — poprawny JSON przepisuje filtr.' },
    payload: '{"age": {"$gt": 0}}   // matches every document',
  },
  {
    name: 'Authentication bypass',
    sev: 'critical',
    desc: { en: 'The primary NoSQL attack: replacing a password string with an operator object makes the login filter match all users regardless of the real password.', pl: 'Główny atak NoSQL: zamiana stringa hasła na obiekt operatora sprawia, że filtr logowania pasuje do wszystkich użytkowników niezależnie od prawdziwego hasła.' },
    payload: '{"username": "admin", "password": {"$ne": "x"}}',
  },
  {
    name: 'Server-side JS ($where)',
    sev: 'critical',
    desc: { en: 'MongoDB $where executes arbitrary server-side JavaScript — enabling time-based blind exfiltration, DoS via infinite loops, and in some configs RCE.', pl: 'MongoDB $where wykonuje dowolny JavaScript po stronie serwera — umożliwia ślepą eksfiltrację czasową, DoS przez nieskończone pętle, a w niektórych konfiguracjach RCE.' },
    payload: '{"$where": "sleep(5000) || true"}',
  },
  {
    name: 'Regex extraction',
    sev: 'high',
    desc: { en: 'A $regex operator turns an equality check into a pattern match, allowing one-character-at-a-time blind extraction of secrets like password hashes or tokens.', pl: 'Operator $regex zamienia porównanie na dopasowanie wzorca, pozwalając na ślepą ekstrakcję sekretów (hashy, tokenów) znak po znaku.' },
    payload: '{"password": {"$regex": "^a"}}',
  },
  {
    name: 'CRLF / RESP injection (Redis)',
    sev: 'high',
    desc: { en: 'Unsanitized input with CRLF sequences smuggles extra commands into the Redis RESP protocol — CONFIG SET + cron/SSH key write can lead to RCE.', pl: 'Niesanityzowane wejście z sekwencjami CRLF przemyca dodatkowe komendy do protokołu RESP Redis — CONFIG SET + zapis crona/klucza SSH może prowadzić do RCE.' },
    payload: 'key\\r\\nCONFIG SET dir /var/spool/cron\\r\\n',
  },
  {
    name: 'JSON field override (CouchDB)',
    sev: 'critical',
    desc: { en: 'CVE-2017-12635 — duplicate JSON keys parsed differently by validator and storage let an attacker override the roles array and self-create an admin.', pl: 'CVE-2017-12635 — zduplikowane klucze JSON inaczej parsowane przez walidator i magazyn pozwalają nadpisać tablicę ról i samodzielnie utworzyć admina.' },
    payload: '{"roles": [], "roles": ["_admin"], ...}',
  },
  {
    name: 'mapReduce injection',
    sev: 'high',
    desc: { en: 'Map/reduce functions accept JavaScript; unsanitized input concatenated into the map or reduce body executes attacker code in the DB context.', pl: 'Funkcje map/reduce przyjmują JavaScript; niesanityzowane wejście wklejone do map/reduce wykonuje kod atakującego w kontekście DB.' },
    payload: 'map: "function(){ emit(this._id, <inject>); }"',
  },
  {
    name: 'Misconfigured rules (Firebase)',
    sev: 'high',
    desc: { en: 'Not injection per se, but the NoSQL analogue: `.read: true` exposes the whole datastore to anonymous clients reading directly from the REST API.', pl: 'Nie wstrzyknięcie sensu stricto, lecz odpowiednik NoSQL: `.read: true` odsłania cały magazyn anonimowym klientom czytającym wprost z REST API.' },
    payload: '{"rules": {".read": true, ".write": true}}',
  },
];

const DBS = [
  {
    name: 'MongoDB',
    rows: [
      ['Bypass', '{"$ne": null} / {"$gt": ""}'],
      ['Blind', '{"$regex": "^a"}'],
      ['Sleep / JS', '{"$where": "sleep(5000)"}'],
      ['Enumerate', '{"$in": [...]} / {"$exists": true}'],
      ['RCE vector', 'mapReduce / $where (self-hosted)'],
      ['Harden', 'security.javascriptEnabled: false'],
    ],
  },
  {
    name: 'Redis',
    rows: [
      ['Vector', 'CRLF in RESP protocol'],
      ['Config', 'CONFIG SET dir / dbfilename'],
      ['RCE', 'write cron job / SSH key'],
      ['Module', 'MODULE LOAD evil.so'],
      ['Lua', 'EVAL arbitrary scripts'],
      ['Harden', 'rename-command, protected-mode'],
    ],
  },
  {
    name: 'CouchDB',
    rows: [
      ['Admin create', 'CVE-2017-12635 role override'],
      ['RCE', 'CVE-2017-12636 query_server'],
      ['MapReduce', 'OS command via design doc'],
      ['Enumerate', '_all_dbs / _all_docs'],
      ['Selector', 'Mango $regex / $or injection'],
      ['Harden', 'require_valid_user = true'],
    ],
  },
  {
    name: 'Firebase',
    rows: [
      ['Vector', 'Misconfigured security rules'],
      ['Read', '.read: true → REST dump'],
      ['Write', '.write: true → tampering'],
      ['Enumerate', '/.json REST endpoint'],
      ['Scope', 'No path-level allow-list'],
      ['Harden', 'auth != null + granular rules'],
    ],
  },
  {
    name: 'Cassandra',
    rows: [
      ['Vector', 'CQL injection (unparam.)'],
      ['Bypass', "' OR '1'='1 in raw CQL"],
      ['Enumerate', 'system.schema_* tables'],
      ['Allow filter', 'ALLOW FILTERING abuse'],
      ['Note', 'No subqueries → limited impact'],
      ['Harden', 'PreparedStatement bind vars'],
    ],
  },
];

const CODE = {
  JavaScript: {
    lang: 'javascript',
    vuln: `// VULNERABLE (Node.js / Mongoose) — entire body becomes the query
app.post('/login', async (req, res) => {
  // password can be {"$ne": null} → matches any user
  const user = await User.findOne(req.body);
});`,
    safe: `// SECURE — validate scalar types, destructure explicitly
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).send('invalid input');
  const user = await User.findOne({ username, password });
});`,
  },
  Python: {
    lang: 'python',
    vuln: `# VULNERABLE (pymongo) — raw JSON value flows into the filter
pwd = request.json.get("password")   # could be {"$ne": null}
db.users.find({"username": username, "password": pwd})`,
    safe: `# SECURE — reject non-scalar input before querying
pwd = request.json.get("password")
if not isinstance(pwd, str):
    abort(400)
db.users.find({"username": str(username), "password": pwd})`,
  },
  PHP: {
    lang: 'php',
    vuln: `<?php // VULNERABLE — PHP arrays from query string become operators
// ?username=admin&password[$ne]=x  →  ['$ne' => 'x']
$collection->findOne([
  'username' => $_GET['username'],
  'password' => $_GET['password'],
]);`,
    safe: `<?php // SECURE — cast to string so operators cannot be injected
$user = (string) $_GET['username'];
$pass = (string) $_GET['password'];
$collection->findOne(['username' => $user, 'password' => $pass]);`,
  },
};

const ORM = [
  { fw: 'Mongoose', api: 'Model.find(req.body)', note: { en: 'Schema validation applies to document saves, NOT query filters. find(req.body) is fully injectable.', pl: 'Walidacja schematu dotyczy zapisów dokumentów, NIE filtrów zapytań. find(req.body) jest w pełni podatne.' } },
  { fw: 'Mongoose-Express', api: 'findOne({...req.body})', note: { en: 'Spreading a JSON-parsed body into findOne lets password be {"$ne": null}. Destructure scalars instead.', pl: 'Rozpakowanie sparsowanego JSON-a do findOne pozwala, by password był {"$ne": null}. Zamiast tego destrukturyzuj skalary.' } },
  { fw: 'Mongoose strictQuery', api: 'strictQuery: true', note: { en: 'Strips unknown schema paths but does NOT block operator injection inside known fields. Not a complete fix.', pl: 'Usuwa nieznane ścieżki schematu, ale NIE blokuje wstrzyknięcia operatorów w znanych polach. To nie pełna naprawa.' } },
  { fw: 'PyMongo', api: 'find(request.json)', note: { en: 'No ODM schema layer at all — dict from request.json passes operator keys straight to the query.', pl: 'Brak warstwy schematu ODM — słownik z request.json przekazuje klucze operatorów wprost do zapytania.' } },
];

const METHOD = [
  { en: ['Detect', 'Send an operator object ({"$gt":""}) or array param where a string is expected; differing responses reveal injectability.'], pl: ['Wykrycie', 'Wyślij obiekt operatora ({"$gt":""}) lub parametr-tablicę tam, gdzie oczekiwany jest string; różnica w odpowiedzi ujawnia podatność.'] },
  { en: ['Fingerprint', 'Operator dialect, error text, and JSON-parsing quirks identify the engine — $where = MongoDB, RESP errors = Redis.'], pl: ['Identyfikacja', 'Dialekt operatorów, treść błędów i osobliwości parsowania JSON wskazują silnik — $where = MongoDB, błędy RESP = Redis.'] },
  { en: ['Bypass auth', 'Replace credentials with {"$ne": null} or {"$gt": ""} to match any account and skip password verification.'], pl: ['Obejście logowania', 'Zamień poświadczenia na {"$ne": null} lub {"$gt": ""}, by dopasować dowolne konto i pominąć weryfikację hasła.'] },
  { en: ['Extract', 'Use $regex anchored patterns or $where boolean/time inference to read secrets one character at a time.'], pl: ['Ekstrakcja', 'Użyj zakotwiczonych wzorców $regex lub wnioskowania boolean/czasowego $where, by czytać sekrety znak po znaku.'] },
  { en: ['Escalate', '$where / mapReduce JS → DoS or RCE (self-hosted Mongo); Redis CONFIG SET → cron/SSH key → shell; CouchDB query_server → OS command.'], pl: ['Eskalacja', '$where / mapReduce JS → DoS lub RCE (self-hosted Mongo); Redis CONFIG SET → cron/klucz SSH → shell; CouchDB query_server → polecenie OS.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Validate scalar types', pl: 'Walidacja typów skalarnych' }, kind: 'primary', note: { en: 'Reject non-string inputs for string fields (typeof x !== "string"). Stops operator objects at the door.', pl: 'Odrzucaj nie-stringi dla pól tekstowych (typeof x !== "string"). Zatrzymuje obiekty operatorów na wejściu.' } },
  { rank: 2, eff: 90, label: { en: 'HTTP-layer schema validation', pl: 'Walidacja schematu na warstwie HTTP' }, kind: 'strong', note: { en: 'Joi .string().required(), Zod .string(), or Pydantic str fields enforce shape before the DB layer.', pl: 'Joi .string().required(), Zod .string() lub pola str Pydantic wymuszają kształt przed warstwą DB.' } },
  { rank: 3, eff: 80, label: { en: 'Strip $ operators / allowlist', pl: 'Usuwanie operatorów $ / allowlista' }, kind: 'strong', note: { en: 'mongo-sanitize or manual key filtering; whitelist only the operators your app actually uses.', pl: 'mongo-sanitize lub ręczne filtrowanie kluczy; dopuszczaj tylko operatory, których aplikacja faktycznie używa.' } },
  { rank: 4, eff: 60, label: { en: 'Disable $where / server-side JS', pl: 'Wyłączenie $where / JS po stronie serwera' }, kind: 'mitigation', note: { en: 'security.javascriptEnabled: false in mongod.conf removes the most dangerous escalation path.', pl: 'security.javascriptEnabled: false w mongod.conf usuwa najgroźniejszą ścieżkę eskalacji.' } },
  { rank: 5, eff: 45, label: { en: 'Parameterization equivalents', pl: 'Odpowiedniki parametryzacji' }, kind: 'mitigation', note: { en: 'Prefer $expr with $$ variables over $where; use prepared CQL statements for Cassandra.', pl: 'Wybieraj $expr ze zmiennymi $$ zamiast $where; używaj przygotowanych zapytań CQL dla Cassandry.' } },
  { rank: 6, eff: 20, label: { en: 'WAF (compensating only)', pl: 'WAF (tylko kompensacyjny)' }, kind: 'weak', note: { en: 'JSON operator payloads are easily obfuscated. Never a primary control.', pl: 'Ładunki z operatorami JSON łatwo zaciemnić. Nigdy jako główna kontrola.' } },
];

const INCIDENTS = [
  { org: 'Snapchat', year: 2014, impact: '4.6M phone numbers', cost: 'MongoDB injection', en: 'Find Friends API abuse via MongoDB injection exposed usernames matched to phone numbers.', pl: 'Nadużycie API Find Friends przez wstrzyknięcie MongoDB ujawniło nazwy użytkowników powiązane z numerami telefonów.' },
  { org: 'Firebase apps (Appthority)', year: 2018, impact: '2.7M records', cost: '2,271 apps', en: 'Misconfigured `.read: true` rules left databases of 2,271 mobile apps open to anonymous reads.', pl: 'Błędne reguły `.read: true` pozostawiły bazy 2 271 aplikacji mobilnych otwarte na anonimowy odczyt.' },
  { org: 'Apache CouchDB', year: 2017, impact: 'CVE-2017-12635/636', cost: 'Admin + RCE', en: 'JSON role override created admins; query_server config enabled OS command execution.', pl: 'Nadpisanie roli JSON tworzyło adminów; konfiguracja query_server umożliwiała wykonanie poleceń OS.' },
  { org: 'Kibana (Elastic)', year: 2019, impact: 'CVE-2019-7609', cost: 'Prototype poll. RCE', en: 'Timelion prototype pollution led to server-side code execution on the Kibana host.', pl: 'Prototype pollution w Timelion prowadziło do wykonania kodu po stronie serwera na hoście Kibana.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'Taint rules: req.body → mongoose/pymongo queries'],
    ['CodeQL', 'Dataflow tracking of untrusted JSON into filters'],
    ['Manual grep', "find(req.body), find(request.json), .find({...req."],
    ['ESLint custom', 'Flag spread of request bodies into query args'],
  ],
  dast: [
    ['NoSQLMap', 'Primary automated exploitation (MongoDB/CouchDB)'],
    ['Burp Suite', 'Fuzz JSON POST bodies with operator payloads'],
    ['Nuclei', 'Templates for open MongoDB / CouchDB ports'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS', items: ['6.2.4 — injection prevention (cardholder scope)', '6.3.2 — review custom code', '11.3 — penetration testing'] },
  { std: 'GDPR', items: ['Art. 25 — security by design', 'Art. 32 — appropriate technical measures', 'Art. 33/34 — 72h breach notification'] },
  { std: 'SOC 2', items: ['CC6.1 — logical access controls', 'CC6.6 — boundary protection', 'CC7.1 — vulnerability detection'] },
];

const IR = {
  en: [
    'Isolate the affected service / database endpoint from the network',
    'Preserve MongoDB / application logs (do not wipe profiler data)',
    'Rotate database credentials, API keys, and session secrets',
    'Assess scope — which collections / documents were accessed',
    'Patch: validate scalar types, strip $ operators, redeploy',
    'Disable $where / server-side JS if not strictly required',
    'Notify regulators within 72h (GDPR) and affected users',
    'Post-incident: Semgrep/NoSQLMap sweep for sibling endpoints',
  ],
  pl: [
    'Odizoluj dotkniętą usługę / endpoint bazy od sieci',
    'Zabezpiecz logi MongoDB / aplikacji (nie usuwaj danych profilera)',
    'Zrotuj poświadczenia DB, klucze API i sekrety sesji',
    'Oceń zakres — które kolekcje / dokumenty zostały odczytane',
    'Załataj: waliduj typy skalarne, usuwaj operatory $, wdróż ponownie',
    'Wyłącz $where / JS po stronie serwera, jeśli nie jest niezbędny',
    'Powiadom regulatorów w 72h (GDPR) i dotkniętych użytkowników',
    'Po incydencie: przegląd Semgrep/NoSQLMap pod kątem bliźniaczych endpointów',
  ],
};

const SOURCES = [
  ['OWASP — Testing for NoSQL Injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
  ['CWE-943 (MITRE)', 'https://cwe.mitre.org/data/definitions/943.html'],
  ['OWASP A03:2021 Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
  ['NoSQLMap (GitHub)', 'https://github.com/codingo/NoSQLMap'],
  ['CVE-2017-12635 (CouchDB)', 'https://nvd.nist.gov/vuln/detail/CVE-2017-12635'],
  ['CVE-2017-12636 (CouchDB)', 'https://nvd.nist.gov/vuln/detail/CVE-2017-12636'],
  ['CVE-2019-7609 (Kibana)', 'https://nvd.nist.gov/vuln/detail/CVE-2019-7609'],
  ['CVE-2021-22909 (UniFi)', 'https://nvd.nist.gov/vuln/detail/CVE-2021-22909'],
  ['PortSwigger — NoSQL injection', 'https://portswigger.net/web-security/nosql-injection'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="nosqli-code-area">
    <button class="nosqli-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="nosqli-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? 'NoSQL Injection attacks the JSON structure of a database query rather than its string grammar. There is no quote to escape — the attacker simply injects query operators ($gt, $ne, $regex, $where) as JSON keys, rewriting the filter logic from the inside. A single login endpoint that passes a request body straight into a query can be bypassed entirely, and on self-hosted MongoDB the $where operator can escalate to server-side JavaScript execution.'
    : 'NoSQL Injection atakuje strukturę JSON zapytania do bazy, a nie jego gramatykę stringów. Nie ma cudzysłowu do escapowania — atakujący po prostu wstrzykuje operatory ($gt, $ne, $regex, $where) jako klucze JSON, przepisując logikę filtra od środka. Pojedynczy endpoint logowania przekazujący ciało żądania wprost do zapytania można całkowicie obejść, a na self-hosted MongoDB operator $where eskaluje do wykonania JavaScriptu po stronie serwera.';

  return `<section id="nosqli-overview" class="nosqli-section">
    <div class="nosqli-hero">
      <span class="nosqli-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>No<span class="grad">SQL</span> Injection</h1>
      <span class="nosqli-sev-badge">${lang === 'en' ? 'High severity' : 'Wysoka waga'}</span>
      <p class="nosqli-lead">${lead}</p>
      <div class="nosqli-metrics">
        <div class="nosqli-metric high"><div class="nosqli-metric-k">CWE-943</div><div class="nosqli-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="nosqli-metric high"><div class="nosqli-metric-k">8.8</div><div class="nosqli-metric-v">CVSS · High</div></div>
        <div class="nosqli-metric"><div class="nosqli-metric-k">A03:2021</div><div class="nosqli-metric-v">OWASP Top 10</div></div>
        <div class="nosqli-metric"><div class="nosqli-metric-k">8</div><div class="nosqli-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="nosqli-sources">
        <span class="nosqli-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="nosqli-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/943.html" target="_blank" rel="noopener" class="nosqli-source-link">CWE-943 (MITRE)</a>
        <a href="https://portswigger.net/web-security/nosql-injection" target="_blank" rel="noopener" class="nosqli-source-link">PortSwigger Academy</a>
        <a href="https://github.com/codingo/NoSQLMap" target="_blank" rel="noopener" class="nosqli-source-link">NoSQLMap</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="nosqli-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="nosqli-payload"><span class="nosqli-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('nosqli-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from a one-key auth bypass to full server-side JavaScript execution.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od obejścia logowania jednym kluczem po pełne wykonanie JavaScriptu po stronie serwera.',
    `<div class="nosqli-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="nosqli-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="nosqli-db-row"><span class="nosqli-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('nosqli-cheatsheet', lang === 'en' ? 'DB-specific cheatsheet' : 'Ściąga per baza',
    lang === 'en' ? 'Each datastore has its own injection primitives. Confirmed across MongoDB, Redis, CouchDB, Firebase, and Cassandra.' : 'Każdy magazyn ma własne prymitywy wstrzyknięcia. Potwierdzone dla MongoDB, Redis, CouchDB, Firebase i Cassandry.',
    `<div class="nosqli-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="nosqli-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="nosqli-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="nosqli-vs">
        <div class="nosqli-vs-col vuln"><div class="nosqli-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="nosqli-vs-col safe"><div class="nosqli-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('nosqli-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix in three languages: never pass a raw request body into a query — validate scalar types first.' : 'Ta sama naprawa w trzech językach: nigdy nie przekazuj surowego ciała żądania do zapytania — najpierw waliduj typy skalarne.',
    `<div class="nosqli-lang-tabs">${tabs}</div><div class="nosqli-lang-panels">${panels}</div>`);
}

function buildOrm() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="nosqli-orm-row">
      <div class="nosqli-orm-fw">${esc(o.fw)}</div>
      <code class="nosqli-orm-api">${esc(o.api)}</code>
      <div class="nosqli-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('nosqli-orm', lang === 'en' ? 'ODM false safety' : 'Fałszywe bezpieczeństwo ODM',
    lang === 'en' ? 'Mongoose schema validation guards document saves — it does NOT guard query filters. Passing a request body into a query is injectable despite the schema.' : 'Walidacja schematu Mongoose chroni zapisy dokumentów — NIE chroni filtrów zapytań. Przekazanie ciała żądania do zapytania jest podatne mimo schematu.',
    `<div class="nosqli-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="nosqli-step">
      <div class="nosqli-step-num">${i + 1}</div>
      <div class="nosqli-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('nosqli-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a probe to full compromise.' : 'Jak atakujący przechodzi od sondy do pełnej kompromitacji.',
    `<div class="nosqli-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="nosqli-def-row ${d.kind}">
      <div class="nosqli-def-rank">#${d.rank}</div>
      <div class="nosqli-def-main">
        <div class="nosqli-def-label">${d.label[lang]}</div>
        <div class="nosqli-def-note">${d.note[lang]}</div>
      </div>
      <div class="nosqli-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('nosqli-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Scalar type validation is the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Walidacja typów skalarnych to naprawa; reszta ogranicza skutki.',
    `<div class="nosqli-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="nosqli-incident">
      <div class="nosqli-incident-top"><h4>${esc(i.org)}</h4><span class="nosqli-incident-year">${i.year}</span></div>
      <div class="nosqli-incident-nums"><span class="nosqli-incident-impact">${esc(i.impact)}</span><span class="nosqli-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="nosqli-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2017-12635" target="_blank" rel="noopener">CouchDB CVE-2017-12635</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2017-12636" target="_blank" rel="noopener">CouchDB CVE-2017-12636</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-7609" target="_blank" rel="noopener">Kibana CVE-2019-7609</a>
    <a href="https://www.appthority.com/" target="_blank" rel="noopener">Appthority (Firebase study)</a>
  </div>`;
  return secWrap('nosqli-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'NoSQL injection is not theoretical — these breaches exposed millions of records and produced CVEs with admin-creation and RCE impact.' : 'NoSQL injection nie jest teoretyczne — te wycieki odsłoniły miliony rekordów i dały CVE z tworzeniem admina i RCE.',
    `<div class="nosqli-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="nosqli-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="nosqli-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for <code>find(req.body)</code>, <code>find(request.json)</code>, and <code>.find({...req.</code> — these spread-the-body patterns are the single most common NoSQL injection root cause.'
    : '<strong>Kluczowy sygnał:</strong> szukaj <code>find(req.body)</code>, <code>find(request.json)</code> i <code>.find({...req.</code> — te wzorce rozpakowania ciała żądania to najczęstsza pojedyncza przyczyna NoSQL injection.';
  return secWrap('nosqli-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis catches request bodies flowing into queries; dynamic tools confirm exploitability. Use both.' : 'Analiza statyczna łapie ciała żądań trafiające do zapytań; narzędzia dynamiczne potwierdzają eksploatowalność. Używaj obu.',
    `<div class="nosqli-tools-grid">
      <div class="nosqli-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="nosqli-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="nosqli-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="nosqli-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="nosqli-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://gdpr-info.eu/art-32-gdpr/" target="_blank" rel="noopener">GDPR Art. 32</a>
    <a href="https://gdpr-info.eu/art-33-gdpr/" target="_blank" rel="noopener">GDPR Art. 33</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
  </div>`;
  return secWrap('nosqli-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where NoSQL injection prevention maps onto the controls auditors check.' : 'Gdzie zapobieganie NoSQL injection mapuje się na kontrole sprawdzane przez audytorów.',
    `<div class="nosqli-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="nosqli-ir-item"><span class="nosqli-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('nosqli-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active NoSQL injection breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku NoSQL injection przejdź tę listę od góry.',
    `<ol class="nosqli-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="nosqli-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('nosqli-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="nosqli-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="nosqli-section">
    <h2 class="nosqli-h2">${title}</h2>
    <p class="nosqli-section-lead">${lead}</p>
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
    buildSourcesSection(),
    `<footer class="nosqli-footer">Code Guardian — NoSQL Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.nosqli-copy', panel).forEach((btn) => {
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
  $$('.nosqli-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.nosqli-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.nosqli-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.nosqli-body', panel);
  const links = $$('.nosqli-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.nosqli-section', panel);
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
    <div class="nosqli-topbar">
      <span class="nosqli-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="nosqli-topbar-title">NoSQL Injection</span>
      <span style="flex:1"></span>
      <button class="nosqli-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="nosqli-shell">
      <nav class="nosqli-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="nosqli-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.nosqli-close', panel).addEventListener('click', close);
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
  document.body.classList.add('nosqli-lock');
  highlightOnce(_panel);
  const body = $('.nosqli-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('nosqli-lock');
}

export function openNosqliPage() { open(); }

export function initNosqliPage() {
  _panel = $('#nosqli-page');
  if (!_panel) return;

  // Re-render on language change so content tracks the global toggle.
  const langBtn = $('#lang-toggle');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      setTimeout(() => {
        if (_rendered) { const wasOpen = _panel.classList.contains('open'); render(_panel); if (wasOpen) { _panel.classList.add('open'); highlighted = false; highlightOnce(_panel); } }
      }, 0);
    });
  }

  const openBtn = $('#nosqli-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
