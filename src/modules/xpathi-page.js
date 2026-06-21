/* =========================================================================
   Code Guardian — XPath Injection deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: ORANGE (#f97316) — XPath Injection is High severity, not Critical.
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
  tab: { en: 'XPathi', pl: 'XPathi' },
  open: { en: 'Open XPath Injection deep-dive', pl: 'Otwórz przewodnik XPath Injection' },
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
  { id: 'xpathi-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'xpathi-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'xpathi-cheatsheet', en: 'Detection cheatsheet', pl: 'Ściąga detekcji' },
  { id: 'xpathi-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'xpathi-orm', en: 'Language cheatsheet', pl: 'Ściąga języków' },
  { id: 'xpathi-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'xpathi-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'xpathi-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'xpathi-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'xpathi-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'xpathi-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'xpathi-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'Auth Bypass (Always-True)',
    sev: 'critical',
    desc: { en: "Injecting ' or '1'='1 into //user[name=INPUT and password=INPUT] forms an always-true predicate that matches every user node — full authentication bypass.", pl: "Wstrzyknięcie ' or '1'='1 do //user[name=INPUT and password=INPUT] tworzy zawsze prawdziwy predykat pasujący do każdego węzła user — pełne obejście logowania." },
    payload: "' or '1'='1   →   //user[name='' or '1'='1']",
  },
  {
    name: 'Full Document Extraction',
    sev: 'high',
    desc: { en: 'A wildcard like /*|//* or //text()[position()=N] dumps the entire XML tree node by node, exfiltrating every element and text value the document holds.', pl: 'Wildcard /*|//* lub //text()[position()=N] zrzuca całe drzewo XML węzeł po węźle, eksfiltrując każdy element i wartość tekstową dokumentu.' },
    payload: '/*|//*   or   //text()[position()=N]',
  },
  {
    name: 'Blind Boolean Enumeration',
    sev: 'high',
    desc: { en: "substring(//user[1]/password,1,1)='a' yields a differential response that reveals stored values one character at a time without any data returned directly.", pl: "substring(//user[1]/password,1,1)='a' daje różnicową odpowiedź ujawniającą wartości znak po znaku, bez bezpośredniego zwracania danych." },
    payload: "substring(//user[1]/password,1,1)='a'",
  },
  {
    name: 'Error-Based Extraction',
    sev: 'high',
    desc: { en: 'A .NET XPathException leaks element names; in XPath 2.0 a forced XPTY0004 type error acts as an oracle to confirm and extract structure from error text.', pl: 'Wyjątek XPathException w .NET wycieka nazwy elementów; w XPath 2.0 wymuszony błąd typu XPTY0004 działa jak wyrocznia potwierdzająca i eksfiltrująca strukturę z treści błędu.' },
    payload: "'[   →   XPathException / XPTY0004",
  },
  {
    name: 'XPath Axes Traversal',
    sev: 'high',
    desc: { en: 'ancestor::*, following-sibling::* and parent::* navigate outside the intended query scope, reaching any node in the document regardless of the original predicate.', pl: 'ancestor::*, following-sibling::* i parent::* nawigują poza zamierzony zakres zapytania, sięgając dowolnego węzła dokumentu niezależnie od pierwotnego predykatu.' },
    payload: 'ancestor::* | following-sibling::* | parent::*',
  },
  {
    name: 'Union Operator Abuse',
    sev: 'high',
    desc: { en: 'The | union operator appends unintended node sets — | //password | //secret merges sensitive nodes into the result of an otherwise harmless query.', pl: 'Operator unii | dokleja niezamierzone zbiory węzłów — | //password | //secret scala wrażliwe węzły z wynikiem skądinąd niewinnego zapytania.' },
    payload: '| //password | //secret',
  },
  {
    name: 'XPath 2.0 doc() SSRF',
    sev: 'high',
    desc: { en: "In XPath 2.0 the doc('http://attacker.com/data') function loads an external document over the network, turning an injection point into server-side request forgery.", pl: "W XPath 2.0 funkcja doc('http://attacker.com/data') ładuje zewnętrzny dokument przez sieć, zamieniając punkt wstrzyknięcia w SSRF." },
    payload: "doc('http://attacker.com/data')",
  },
  {
    name: 'SAML / XMLDSig Bypass',
    sev: 'critical',
    desc: { en: 'Manipulating the XPath Filter Transform bypasses the integrity check of an XML Digital Signature, letting an attacker tamper with signed SAML assertions undetected.', pl: 'Manipulacja XPath Filter Transform omija kontrolę integralności podpisu cyfrowego XML, pozwalając niezauważenie modyfikować podpisane asercje SAML.' },
    payload: 'XPath Filter Transform → XMLDSig bypass',
  },
];

const DBS = [
  {
    name: 'Auth bypass probe',
    rows: [
      ['Vector', "' or '1'='1"],
      ['Alt', "x' or 1=1 or 'x'='x"],
      ['Where', 'username / login field'],
      ['Signal', 'login succeeds, no password'],
      ['Filter', "//user[name='' or '1'='1']"],
      ['Confirm', 'access without credentials'],
    ],
  },
  {
    name: 'Boolean differential',
    rows: [
      ['Vector', "' and substring(name(/*[1]),1,1)='a"],
      ['Alt', "...='b"],
      ['Where', 'searchable predicate input'],
      ['Signal', 'different responses a vs b'],
      ['Use', 'char-by-char extraction'],
      ['Confirm', 'state changes by char'],
    ],
  },
  {
    name: 'Error-based',
    rows: [
      ['Vector', "'[  (unclosed bracket)"],
      ['Where', 'any predicate parameter'],
      ['Signal', 'XPath parse error'],
      ['Leak', 'XPath engine / element names'],
      ['Use', 'fingerprint XML backend'],
      ['Confirm', 'error text in response'],
    ],
  },
  {
    name: 'Axes probe',
    rows: [
      ['Vector', "' or ancestor::*"],
      ['Where', 'predicate input field'],
      ['Signal', 'more results returned'],
      ['Method', 'scope-escape via axes'],
      ['Use', 'reach nodes out of scope'],
      ['Confirm', 'extra node set returned'],
    ],
  },
  {
    name: 'XPath 2.0 SSRF test',
    rows: [
      ['Vector', "doc('http://burpcollaborator.net')"],
      ['Where', 'XPath 2.0 capable engine'],
      ['Signal', 'DNS / HTTP callback'],
      ['Confirm', 'doc() availability'],
      ['Impact', 'server-side request forgery'],
      ['Tool', 'OAST / Burp Collaborator'],
    ],
  },
];

const CODE = {
  Java: {
    lang: 'java',
    vuln: `// VULNERABLE — user input concatenated into the XPath expression
String user = request.getParameter("user");
XPath xpath = XPathFactory.newInstance().newXPath();
NodeList r = (NodeList) xpath.evaluate(
    "/users/user[name='" + user + "']", doc, XPathConstants.NODESET);`,
    safe: `// SECURE — XPathVariableResolver binds a compiled variable
String user = request.getParameter("user");
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(v -> "user".equals(v.getLocalPart()) ? user : null);
XPathExpression expr = xpath.compile("/users/user[name=$user]");
NodeList r = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);`,
  },
  'Python (lxml)': {
    lang: 'python',
    vuln: `# VULNERABLE (lxml) — f-string interpolation into the path
user = request.args.get("user")   # could be "' or '1'='1"
nodes = root.xpath(f"//user[name='{user}']")`,
    safe: `# SECURE — lxml keyword arguments bind variables safely
user = request.args.get("user")
nodes = root.xpath("//user[name=$name]", name=user)`,
  },
  PHP: {
    lang: 'php',
    vuln: `<?php // VULNERABLE — raw input concatenated into the query
$user = $_GET['user'];   // ?user=' or '1'='1
$r = $xpath->query("//user[name='" . $user . "']");`,
    safe: `<?php // SECURE — PHP has no native binding: allowlist + escape
if (!preg_match('/^[A-Za-z0-9_]+$/', $_GET['user'])) { http_response_code(400); exit; }
$user = addslashes($_GET['user']);
$r = $xpath->query("//user[name='" . $user . "']");`,
  },
  '.NET': {
    lang: 'csharp',
    vuln: `// VULNERABLE — string concatenation into SelectNodes
string u = Request.QueryString["user"];
XmlNodeList r = doc.SelectNodes("//user[name='" + u + "']");`,
    safe: `// SECURE — XPathNavigator + compiled expr with a variable context
var nav = doc.CreateNavigator();
var ctx = new CustomXsltContext();          // supplies the $user variable
ctx.AddVariable("user", Request.QueryString["user"]);
XPathExpression expr = nav.Compile("//user[name=$user]");
expr.SetContext(ctx);
XPathNodeIterator r = nav.Select(expr);`,
  },
  'Node.js': {
    lang: 'javascript',
    vuln: `// VULNERABLE (xpath) — expression built from input
const u = req.query.user;   // "' or '1'='1"
const r = xpath.select("//user[name='" + u + "']", doc);`,
    safe: `// SECURE — pass variables via the resolver argument
const u = req.query.user;
const r = xpath.select("//user[name=$name]", doc, null, null, { name: u });`,
  },
};

const ORM = [
  { fw: 'Java', api: `evaluate("/users/user[name='"+user+"']")`, note: { en: 'Vulnerable sink — string concatenation. Safe alternative: XPathVariableResolver with a compiled expression and $user variable binding.', pl: 'Podatny sink — konkatenacja stringów. Bezpiecznie: XPathVariableResolver ze skompilowanym wyrażeniem i wiązaniem zmiennej $user.' } },
  { fw: 'Python (lxml)', api: 'root.xpath(f"//user[name=\'{user}\']")', note: { en: 'Vulnerable sink — f-string interpolation. Safe alternative: root.xpath("//user[name=$name]", name=user) keyword binding.', pl: 'Podatny sink — interpolacja f-stringa. Bezpiecznie: root.xpath("//user[name=$name]", name=user) z wiązaniem przez argument.' } },
  { fw: 'PHP', api: `$xpath->query("//user[name='$user']")`, note: { en: 'Vulnerable sink — interpolation; no native parameterization. Safe alternative: allowlist validation + addslashes().', pl: 'Podatny sink — interpolacja; brak natywnej parametryzacji. Bezpiecznie: walidacja allowlist + addslashes().' } },
  { fw: '.NET', api: `doc.SelectNodes("//user[name='"+u+"']")`, note: { en: 'Vulnerable sink — concatenation. Safe alternative: XPathNavigator with a compiled expression and XPathExpression.SetContext().', pl: 'Podatny sink — konkatenacja. Bezpiecznie: XPathNavigator ze skompilowanym wyrażeniem i XPathExpression.SetContext().' } },
  { fw: 'Node.js', api: `xpath.select("//user[name='"+u+"']", doc)`, note: { en: 'Vulnerable sink — concatenation. Safe alternative: xpath.select("//user[name=$name]", doc, null, null, {name: u}).', pl: 'Podatny sink — konkatenacja. Bezpiecznie: xpath.select("//user[name=$name]", doc, null, null, {name: u}).' } },
];

const METHOD = [
  { en: ['Detect', "Send ' or '1'='1 (or x' or 1=1 or 'x'='x) where a value is expected — a login that succeeds without a password reveals injectability."], pl: ['Wykrycie', "Wyślij ' or '1'='1 (lub x' or 1=1 or 'x'='x) tam, gdzie oczekiwana jest wartość — logowanie bez hasła ujawnia podatność."] },
  { en: ['Fingerprint', "Inject an unclosed bracket '[ — the XPath parse error text leaks the engine type and, in .NET, element names from XPathException."], pl: ['Identyfikacja', "Wstrzyknij niezamknięty nawias '[ — treść błędu parsowania XPath zdradza typ silnika, a w .NET nazwy elementów z XPathException."] },
  { en: ['Bypass auth', "Close the predicate with ' or '1'='1 to form an always-true tautology that matches every user node and skips password verification."], pl: ['Obejście logowania', "Zamknij predykat przez ' or '1'='1, tworząc zawsze prawdziwą tautologię pasującą do każdego węzła user i pomijając weryfikację hasła."] },
  { en: ['Extract', "Use substring(//user[1]/password,1,1)='a' boolean differentials to read stored values one character at a time, or /*|//* to dump the whole tree."], pl: ['Ekstrakcja', "Użyj różnic boolean substring(//user[1]/password,1,1)='a', by czytać wartości znak po znaku, lub /*|//*, by zrzucić całe drzewo."] },
  { en: ['Escalate', "Traverse axes (ancestor::*, following-sibling::*) and abuse | to merge //password nodes; in XPath 2.0 call doc('http://oast.me/x') for SSRF."], pl: ['Eskalacja', "Przejdź osie (ancestor::*, following-sibling::*) i nadużyj | by scalić węzły //password; w XPath 2.0 wywołaj doc('http://oast.me/x') dla SSRF."] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Parameterized XPath (variable binding)', pl: 'Parametryzowany XPath (wiązanie zmiennych)' }, kind: 'primary', note: { en: 'Variable binding separates the expression from the data: Java XPathVariableResolver, lxml keyword args, .NET SetContext. Stops injection at the source.', pl: 'Wiązanie zmiennych oddziela wyrażenie od danych: Java XPathVariableResolver, argumenty lxml, .NET SetContext. Zatrzymuje wstrzyknięcie u źródła.' } },
  { rank: 2, eff: 85, label: { en: 'Input allowlisting', pl: 'Allowlista wejścia' }, kind: 'strong', note: { en: "Usernames: alphanumeric only; reject ', \", [, ], /, *, @ before the expression is ever built.", pl: "Loginy: tylko alfanumeryczne; odrzucaj ', \", [, ], /, *, @ zanim wyrażenie powstanie." } },
  { rank: 3, eff: 75, label: { en: 'XML schema validation', pl: 'Walidacja schematu XML' }, kind: 'strong', note: { en: 'Validate document structure with XSD / RelaxNG before querying so unexpected nodes and shapes are rejected upfront.', pl: 'Waliduj strukturę dokumentu przez XSD / RelaxNG przed zapytaniem, by nieoczekiwane węzły i kształty były odrzucane z góry.' } },
  { rank: 4, eff: 60, label: { en: 'Principle of least information', pl: 'Zasada najmniejszej informacji' }, kind: 'mitigation', note: { en: 'Query only the nodes you need; never use // or * wildcards in production paths — limits what a successful injection can reach.', pl: 'Odpytuj tylko potrzebne węzły; nigdy nie używaj wildcardów // ani * w ścieżkach produkcyjnych — ogranicza zasięg udanego wstrzyknięcia.' } },
  { rank: 5, eff: 55, label: { en: 'Disable XPath 2.0 functions', pl: 'Wyłącz funkcje XPath 2.0' }, kind: 'mitigation', note: { en: 'Restrict doc() and collection() to prevent SSRF and external document loading from injected expressions.', pl: 'Ogranicz doc() i collection(), by zapobiec SSRF i ładowaniu zewnętrznych dokumentów z wstrzykniętych wyrażeń.' } },
  { rank: 6, eff: 40, label: { en: 'Error suppression', pl: 'Tłumienie błędów' }, kind: 'mitigation', note: { en: 'Never expose XPath parse errors to clients — error text is an extraction oracle for blind and error-based attacks.', pl: 'Nigdy nie ujawniaj błędów parsowania XPath klientom — treść błędu to wyrocznia ekstrakcji dla ataków ślepych i opartych na błędach.' } },
  { rank: 7, eff: 20, label: { en: 'SAST + WAF (compensating)', pl: 'SAST + WAF (kompensacyjnie)' }, kind: 'weak', note: { en: "Taint-track HTTP params to evaluate/compile sinks; WAF rules block ' or quote/bracket patterns. Easily bypassed — never a primary control.", pl: "Śledź taint od parametrów HTTP do sinków evaluate/compile; reguły WAF blokują ' i wzorce cudzysłowów/nawiasów. Łatwe do obejścia — nigdy jako główna kontrola." } },
];

const INCIDENTS = [
  { org: 'Keycloak', year: 2020, impact: 'CVE-2020-10770', cost: 'CVSS 9.8 · SAML', en: 'Unauthenticated XPath injection in the Keycloak SAML endpoint (CVSS 9.8) — Red Hat identity platform affecting enterprise SSO deployments.', pl: 'Nieautoryzowane wstrzyknięcie XPath w endpoincie SAML Keycloak (CVSS 9.8) — platforma tożsamości Red Hat dotykająca firmowych wdrożeń SSO.' },
  { org: 'Spring Web Services', year: 2019, impact: 'CVE-2019-3773', cost: 'CVSS 9.8', en: 'XPath injection in Spring-WS XML processing (CVSS 9.8) — affects all Spring WS applications parsing user-controlled XML.', pl: 'Wstrzyknięcie XPath w przetwarzaniu XML Spring-WS (CVSS 9.8) — dotyka wszystkich aplikacji Spring WS parsujących XML kontrolowany przez użytkownika.' },
  { org: 'Apache Ant', year: 2020, impact: 'CVE-2020-11979', cost: 'CVSS 9.1', en: 'XPath injection in Apache Ant build-file processing (CVSS 9.1) — malicious build files could manipulate XPath queries during the build.', pl: 'Wstrzyknięcie XPath w przetwarzaniu plików build Apache Ant (CVSS 9.1) — złośliwe pliki build mogły manipulować zapytaniami XPath podczas budowania.' },
  { org: 'Spring Framework', year: 2014, impact: 'CVE-2014-0225', cost: 'Param binding', en: 'XPath injection via HTTP parameter binding into XML queries in the Spring Framework — user parameters flowed into XPath evaluation.', pl: 'Wstrzyknięcie XPath przez wiązanie parametrów HTTP do zapytań XML w Spring Framework — parametry użytkownika trafiały do ewaluacji XPath.' },
  { org: 'SAP NetWeaver UDDI', year: 2016, impact: 'CVE-2016-2386', cost: 'Unauth · extraction', en: 'Unauthenticated XPath injection in the SAP NetWeaver UDDI enterprise service registry, allowing full XML document extraction.', pl: 'Nieautoryzowane wstrzyknięcie XPath w rejestrze usług SAP NetWeaver UDDI, umożliwiające pełną ekstrakcję dokumentu XML.' },
  { org: 'Oracle Portal', year: 2010, impact: 'Credential leak', cost: 'XML config store', en: 'XPath injection in Oracle Portal content queries enabling credential extraction from XML configuration stores.', pl: 'Wstrzyknięcie XPath w zapytaniach treści Oracle Portal umożliwiające ekstrakcję poświadczeń z magazynów konfiguracji XML.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'xpath-injection rules: input → evaluate sink'],
    ['Checkmarx', 'XPath_Injection query'],
    ['Fortify', 'XPath Injection category'],
    ['CodeQL', 'js/xml/java XPath taint queries'],
  ],
  dast: [
    ['Burp Suite', 'Active Scan XPath injection probes'],
    ['OWASP ZAP', 'XPath injection active rules'],
    ['xcat', 'Automated blind XPath extraction'],
    ['Burp Collaborator', 'doc() SSRF / OAST callbacks'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS v4.0', items: ['Req 6.3.1 — XML config files storing card data', 'protected from XPath injection', 'Req 11.3 — penetration testing'] },
  { std: 'SOC 2', items: ['CC6.1 — logical access controls', 'injection-free XML authentication flows', 'CC7.1 — vulnerability scanning evidence'] },
  { std: 'GDPR', items: ['Art. 32 — appropriate technical measures', 'XML directories with PII → breach reportable', 'if extracted via XPath injection'] },
];

const IR = {
  en: [
    'Isolate the affected XML-backed service / XPath endpoint',
    'Preserve application and XML parser logs (queries, doc() calls)',
    'Rotate any credentials stored in queried XML config stores',
    'Assess scope — which nodes / attributes / users were queried or exposed',
    'Patch: bind variables (parameterized XPath), stop concatenation',
    'Disable doc() / collection() and suppress XPath errors to clients',
    'Notify regulators within 72h (GDPR) and affected users',
    'Post-incident: SAST/Burp sweep for sibling evaluate/compile sinks',
  ],
  pl: [
    'Odizoluj dotkniętą usługę opartą o XML / endpoint XPath',
    'Zabezpiecz logi aplikacji i parsera XML (zapytania, wywołania doc())',
    'Zrotuj poświadczenia przechowywane w odpytywanych magazynach XML',
    'Oceń zakres — które węzły / atrybuty / konta odpytano lub ujawniono',
    'Załataj: wiąż zmienne (parametryzowany XPath), porzuć konkatenację',
    'Wyłącz doc() / collection() i tłum błędy XPath wobec klientów',
    'Powiadom regulatorów w 72h (GDPR) i dotkniętych użytkowników',
    'Po incydencie: przegląd SAST/Burp pod kątem bliźniaczych sinków evaluate/compile',
  ],
};

const SOURCES = [
  ['OWASP A03:2021 Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
  ['CWE-643 (MITRE)', 'https://cwe.mitre.org/data/definitions/643.html'],
  ['OWASP XML Security Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html'],
  ['PortSwigger — XPath injection', 'https://portswigger.net/web-security/xpath-injection'],
  ['W3C XPath specification', 'https://www.w3.org/TR/xpath/'],
  ['CVE-2020-10770 (Keycloak)', 'https://nvd.nist.gov/vuln/detail/CVE-2020-10770'],
  ['CVE-2019-3773 (Spring WS)', 'https://nvd.nist.gov/vuln/detail/CVE-2019-3773'],
  ['CVE-2020-11979 (Apache Ant)', 'https://nvd.nist.gov/vuln/detail/CVE-2020-11979'],
  ['CVE-2016-2386 (SAP NetWeaver)', 'https://nvd.nist.gov/vuln/detail/CVE-2016-2386'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="xpathi-code-area">
    <button class="xpathi-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="xpathi-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? "XPath Injection attacks the expression syntax of an XML query rather than a database. User input concatenated into an XPath expression lets an attacker inject metacharacters — ', \", [, ], /, *, | — to rewrite the query logic. A login that builds //user[name=INPUT and password=INPUT] by concatenation can be bypassed with ' or '1'='1, an always-true predicate matching every user node. Beyond auth bypass, axes traversal, the | union operator, and the XPath 2.0 doc() function escalate a single injection point into full document extraction and even SSRF."
    : "XPath Injection atakuje składnię wyrażenia zapytania XML, a nie bazy danych. Wejście użytkownika sklejone z wyrażeniem XPath pozwala wstrzyknąć metaznaki — ', \", [, ], /, *, | — by przepisać logikę zapytania. Logowanie budujące //user[name=INPUT and password=INPUT] przez konkatenację można obejść przez ' or '1'='1, zawsze prawdziwy predykat pasujący do każdego węzła user. Poza obejściem logowania, osie, operator unii | oraz funkcja doc() z XPath 2.0 eskalują pojedynczy punkt wstrzyknięcia do pełnej ekstrakcji dokumentu, a nawet SSRF.";

  return `<section id="xpathi-overview" class="xpathi-section">
    <div class="xpathi-hero">
      <span class="xpathi-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>XPath <span class="grad">Injection</span></h1>
      <span class="xpathi-sev-badge">${lang === 'en' ? 'High severity' : 'Wysoka waga'}</span>
      <p class="xpathi-lead">${lead}</p>
      <div class="xpathi-metrics">
        <div class="xpathi-metric high"><div class="xpathi-metric-k">CWE-643</div><div class="xpathi-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="xpathi-metric high"><div class="xpathi-metric-k">9.8</div><div class="xpathi-metric-v">CVSS · High</div></div>
        <div class="xpathi-metric"><div class="xpathi-metric-k">A03:2021</div><div class="xpathi-metric-v">OWASP Top 10</div></div>
        <div class="xpathi-metric"><div class="xpathi-metric-k">8</div><div class="xpathi-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="xpathi-sources">
        <span class="xpathi-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="xpathi-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/643.html" target="_blank" rel="noopener" class="xpathi-source-link">CWE-643 (MITRE)</a>
        <a href="https://portswigger.net/web-security/xpath-injection" target="_blank" rel="noopener" class="xpathi-source-link">PortSwigger Academy</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html" target="_blank" rel="noopener" class="xpathi-source-link">OWASP Cheat Sheet</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="xpathi-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="xpathi-payload"><span class="xpathi-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('xpathi-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from an always-true auth bypass to XPath 2.0 doc() SSRF and SAML signature bypass.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od zawsze prawdziwego obejścia logowania po SSRF przez doc() w XPath 2.0 i obejście podpisu SAML.',
    `<div class="xpathi-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="xpathi-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="xpathi-db-row"><span class="xpathi-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('xpathi-cheatsheet', lang === 'en' ? 'Detection cheatsheet' : 'Ściąga detekcji',
    lang === 'en' ? 'Five practical methods to confirm an XPath injection point — from auth-bypass probes to out-of-band doc() SSRF callbacks.' : 'Pięć praktycznych metod potwierdzenia punktu wstrzyknięcia XPath — od sond obejścia logowania po callbacki SSRF przez doc() poza pasmem.',
    `<div class="xpathi-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="xpathi-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="xpathi-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="xpathi-vs">
        <div class="xpathi-vs-col vuln"><div class="xpathi-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="xpathi-vs-col safe"><div class="xpathi-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('xpathi-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix across five languages: never concatenate raw input into an XPath expression — bind variables or, where unavailable, allowlist and escape.' : 'Ta sama naprawa w pięciu językach: nigdy nie sklejaj surowego wejścia z wyrażeniem XPath — wiąż zmienne lub, gdy to niemożliwe, stosuj allowlistę i escape.',
    `<div class="xpathi-lang-tabs">${tabs}</div><div class="xpathi-lang-panels">${panels}</div>`);
}

function buildOrm() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="xpathi-orm-row">
      <div class="xpathi-orm-fw">${esc(o.fw)}</div>
      <code class="xpathi-orm-api">${esc(o.api)}</code>
      <div class="xpathi-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('xpathi-orm', lang === 'en' ? 'Language cheatsheet' : 'Ściąga języków',
    lang === 'en' ? 'Per-language vulnerable sinks and their safe alternatives. The pattern is identical everywhere: stop concatenating and start binding variables.' : 'Podatne sinki per język i ich bezpieczne odpowiedniki. Wzorzec jest wszędzie identyczny: przestań sklejać, zacznij wiązać zmienne.',
    `<div class="xpathi-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="xpathi-step">
      <div class="xpathi-step-num">${i + 1}</div>
      <div class="xpathi-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('xpathi-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a probe to full compromise.' : 'Jak atakujący przechodzi od sondy do pełnej kompromitacji.',
    `<div class="xpathi-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="xpathi-def-row ${d.kind}">
      <div class="xpathi-def-rank">#${d.rank}</div>
      <div class="xpathi-def-main">
        <div class="xpathi-def-label">${d.label[lang]}</div>
        <div class="xpathi-def-note">${d.note[lang]}</div>
      </div>
      <div class="xpathi-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('xpathi-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Parameterized XPath is the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Parametryzowany XPath to naprawa; reszta ogranicza skutki.',
    `<div class="xpathi-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="xpathi-incident">
      <div class="xpathi-incident-top"><h4>${esc(i.org)}</h4><span class="xpathi-incident-year">${i.year}</span></div>
      <div class="xpathi-incident-nums"><span class="xpathi-incident-impact">${esc(i.impact)}</span><span class="xpathi-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="xpathi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-10770" target="_blank" rel="noopener">Keycloak CVE-2020-10770</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3773" target="_blank" rel="noopener">Spring WS CVE-2019-3773</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-11979" target="_blank" rel="noopener">Apache Ant CVE-2020-11979</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2016-2386" target="_blank" rel="noopener">SAP CVE-2016-2386</a>
  </div>`;
  return secWrap('xpathi-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'XPath injection is not theoretical — Keycloak and Spring WS each reached CVSS 9.8 unauthenticated, and SAP NetWeaver allowed full XML extraction.' : 'XPath injection nie jest teoretyczne — Keycloak i Spring WS osiągnęły nieautoryzowane CVSS 9.8, a SAP NetWeaver pozwalał na pełną ekstrakcję XML.',
    `<div class="xpathi-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="xpathi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="xpathi-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for XPath expressions built by concatenation — <code>"//user[name=\'" + user</code>, <code>f"//user[name=\'{user}\']"</code>, <code>SelectNodes("//..." +</code> — and for any reachable <code>doc()</code> / <code>collection()</code> call.'
    : '<strong>Kluczowy sygnał:</strong> szukaj wyrażeń XPath budowanych przez konkatenację — <code>"//user[name=\'" + user</code>, <code>f"//user[name=\'{user}\']"</code>, <code>SelectNodes("//..." +</code> — oraz każdego osiągalnego wywołania <code>doc()</code> / <code>collection()</code>.';
  return secWrap('xpathi-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis catches input flowing into evaluate/compile sinks; dynamic tools confirm exploitability. Use both.' : 'Analiza statyczna łapie wejście trafiające do sinków evaluate/compile; narzędzia dynamiczne potwierdzają eksploatowalność. Używaj obu.',
    `<div class="xpathi-tools-grid">
      <div class="xpathi-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="xpathi-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="xpathi-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="xpathi-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="xpathi-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://gdpr-info.eu/art-32-gdpr/" target="_blank" rel="noopener">GDPR Art. 32</a>
    <a href="https://gdpr-info.eu/art-33-gdpr/" target="_blank" rel="noopener">GDPR Art. 33</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
  </div>`;
  return secWrap('xpathi-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where XPath injection prevention maps onto the controls auditors check.' : 'Gdzie zapobieganie XPath injection mapuje się na kontrole sprawdzane przez audytorów.',
    `<div class="xpathi-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="xpathi-ir-item"><span class="xpathi-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('xpathi-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active XPath injection breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku XPath injection przejdź tę listę od góry.',
    `<ol class="xpathi-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="xpathi-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('xpathi-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="xpathi-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="xpathi-section">
    <h2 class="xpathi-h2">${title}</h2>
    <p class="xpathi-section-lead">${lead}</p>
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
    `<footer class="xpathi-footer">Code Guardian — XPath Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.xpathi-copy', panel).forEach((btn) => {
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
  $$('.xpathi-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.xpathi-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.xpathi-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.xpathi-body', panel);
  const links = $$('.xpathi-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.xpathi-section', panel);
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
    <div class="xpathi-topbar">
      <span class="xpathi-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="xpathi-topbar-title">XPath Injection</span>
      <span style="flex:1"></span>
      <button class="xpathi-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="xpathi-shell">
      <nav class="xpathi-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="xpathi-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.xpathi-close', panel).addEventListener('click', close);
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
  document.body.classList.add('xpathi-lock');
  highlightOnce(_panel);
  const body = $('.xpathi-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('xpathi-lock');
}

export function openXpathiPage() { open(); }

export function initXpathiPage() {
  _panel = $('#xpathi-page');
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

  const openBtn = $('#xpathi-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
