/* =========================================================================
   Code Guardian — Server-Side Template Injection (SSTI) deep-dive page
   Standalone full-screen reference panel. Vanilla JS + Prism highlighting.
   Accent: RED (#ef4444) — SSTI is Critical severity.
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
  tab: { en: 'SSTI', pl: 'SSTI' },
  open: { en: 'Open Server-Side Template Injection deep-dive', pl: 'Otwórz przewodnik Server-Side Template Injection' },
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
  { id: 'ssti-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'ssti-types', en: 'Attack types', pl: 'Typy ataków' },
  { id: 'ssti-cheatsheet', en: 'Detection cheatsheet', pl: 'Ściąga detekcji' },
  { id: 'ssti-code', en: 'Vuln vs Secure', pl: 'Podatny vs Bezpieczny' },
  { id: 'ssti-langrisks', en: 'Engine risks', pl: 'Ryzyka per silnik' },
  { id: 'ssti-method', en: 'Methodology', pl: 'Metodyka' },
  { id: 'ssti-defense', en: 'Defense layers', pl: 'Warstwy obrony' },
  { id: 'ssti-incidents', en: 'Real incidents', pl: 'Incydenty' },
  { id: 'ssti-tools', en: 'SAST / DAST', pl: 'SAST / DAST' },
  { id: 'ssti-compliance', en: 'Compliance', pl: 'Zgodność' },
  { id: 'ssti-ir', en: 'Incident response', pl: 'Reagowanie' },
  { id: 'ssti-sources', en: 'Sources', pl: 'Źródła' },
];

const TYPES = [
  {
    name: 'Jinja2 MRO Chain RCE',
    sev: 'critical',
    desc: { en: 'Walk the Python object graph from any string to subprocess. {{\'\'.__class__.__mro__[1].__subclasses__()}} enumerates every loaded class — find the Popen index, then call .__init__.__globals__[\'os\'].popen(\'id\').read(). Flask shortcut: {{lipsum.__globals__[\'os\'].popen(\'id\').read()}}.', pl: 'Przejdź graf obiektów Pythona od dowolnego stringa do subprocess. {{\'\'.__class__.__mro__[1].__subclasses__()}} wylicza każdą załadowaną klasę — znajdź indeks Popen, potem .__init__.__globals__[\'os\'].popen(\'id\').read(). Skrót Flask: {{lipsum.__globals__[\'os\'].popen(\'id\').read()}}.' },
    payload: "{{''.__class__.__mro__[1].__subclasses__()}}",
  },
  {
    name: 'Twig (PHP) Filter Callback RCE',
    sev: 'critical',
    desc: { en: 'Register PHP exec() as an undefined-filter callback, then invoke it. {{_self.env.registerUndefinedFilterCallback(\'exec\')}}{{_self.env.getFilter(\'id\')}} yields RCE — the exact chain behind CVE-2019-9942 in Craft CMS.', pl: 'Zarejestruj PHP exec() jako callback nieznanego filtra, potem go wywołaj. {{_self.env.registerUndefinedFilterCallback(\'exec\')}}{{_self.env.getFilter(\'id\')}} daje RCE — dokładny łańcuch z CVE-2019-9942 w Craft CMS.' },
    payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
  },
  {
    name: 'Freemarker Java Execute class',
    sev: 'critical',
    desc: { en: 'Freemarker\'s ?new() builtin instantiates arbitrary Java classes. The Execute utility runs OS commands directly; ObjectConstructor and JythonRuntime are alternative gadgets when Execute is blocked.', pl: 'Builtin ?new() w Freemarker instancjuje dowolne klasy Java. Narzędzie Execute uruchamia polecenia OS wprost; ObjectConstructor i JythonRuntime to alternatywne gadżety, gdy Execute jest zablokowane.' },
    payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
  },
  {
    name: 'Velocity Java Reflection',
    sev: 'critical',
    desc: { en: 'Velocity has no direct class import, so reach Runtime via reflection. #set($rt=$class.forName(\'java.lang.Runtime\')) then chains getMethod / invoke to call Runtime.exec() without any explicit import.', pl: 'Velocity nie ma bezpośredniego importu klas, więc dotrzyj do Runtime przez refleksję. #set($rt=$class.forName(\'java.lang.Runtime\')) potem łańcuch getMethod / invoke wywołuje Runtime.exec() bez jawnego importu.' },
    payload: "#set($rt=$class.forName('java.lang.Runtime'))",
  },
  {
    name: 'Blind SSTI via Timing',
    sev: 'high',
    desc: { en: 'No output reflected? A heavy expression like {{range(9999999)|list}} or a conditional sleep loop turns response time into an oracle — character-by-character secret extraction takes ~130 timed requests per value.', pl: 'Brak odbitego wyniku? Ciężkie wyrażenie jak {{range(9999999)|list}} lub warunkowa pętla sleep zamienia czas odpowiedzi w wyrocznię — ekstrakcja sekretu znak po znaku to ~130 zmierzonych żądań na wartość.' },
    payload: '{{range(9999999)|list}}',
  },
  {
    name: 'Sandbox Escape (Jinja2)',
    sev: 'critical',
    desc: { en: 'SandboxedEnvironment blocks dunder access — but Flask context objects leak it back. request.__class__._load_form_data.__func__.__globals__ or config.__class__.__init__.__globals__[\'os\'] reach os despite the sandbox.', pl: 'SandboxedEnvironment blokuje dostęp do dunderów — ale obiekty kontekstu Flask zwracają go z powrotem. request.__class__._load_form_data.__func__.__globals__ lub config.__class__.__init__.__globals__[\'os\'] sięgają os mimo sandboxa.' },
    payload: "{{config.__class__.__init__.__globals__['os']}}",
  },
  {
    name: 'WAF Bypass',
    sev: 'high',
    desc: { en: 'Defeat ASCII-regex WAFs: {# comment #} stripping plus Unicode whitespace (U+00A0) breaks signatures; |attr(\'__class__\') avoids dot-notation rules; hex encoding \'\\x5f\\x5fclass\\x5f\\x5f\' reconstructs forbidden dunders.', pl: 'Pokonaj WAF-y na regexach ASCII: usuwanie {# comment #} plus białe znaki Unicode (U+00A0) łamią sygnatury; |attr(\'__class__\') omija reguły notacji kropkowej; kodowanie hex \'\\x5f\\x5fclass\\x5f\\x5f\' rekonstruuje zabronione dundery.' },
    payload: "{{ ''|attr('\\x5f\\x5fclass\\x5f\\x5f') }}",
  },
  {
    name: 'Email / PDF Template SSTI',
    sev: 'critical',
    desc: { en: 'render_template_string() in Flask-Mail evaluates payloads before SMTP send. WeasyPrint chains: inject <img src="http://169.254.169.254/..."> via SSTI and WeasyPrint fetches cloud metadata during PDF render.', pl: 'render_template_string() w Flask-Mail oblicza ładunki przed wysyłką SMTP. Łańcuchy WeasyPrint: wstrzyknij <img src="http://169.254.169.254/..."> przez SSTI, a WeasyPrint pobierze metadane chmury podczas renderu PDF.' },
    payload: '<img src="http://169.254.169.254/latest/meta-data/">',
  },
];

const DBS = [
  {
    name: 'Arithmetic fingerprint',
    rows: [
      ['Jinja2/Twig/Pebble', '{{7*7}} → 49'],
      ['Freemarker/Velocity', '${7*7} → 49'],
      ['Smarty/ERB', '#{7*7} → 49'],
      ['Thymeleaf', '*{7*7} → 49'],
      ['Signal', 'literal evaluated'],
      ['Goal', 'confirm + bracket syntax'],
    ],
  },
  {
    name: 'Engine differentiator',
    rows: [
      ['Probe', "{{7*'7'}}"],
      ['Jinja2', '7777777 (string repeat)'],
      ['Twig', '49 (numeric coerce)'],
      ['Use', 'distinguishes the two'],
      ['Follow-up', 'pick engine-specific RCE'],
      ['Tool', 'manual / tplmap'],
    ],
  },
  {
    name: 'Polyglot error probe',
    rows: [
      ['Vector', "${{<%[%'\"}}%>"],
      ['Effect', 'engine-specific parse error'],
      ['Leak', 'engine name in stack trace'],
      ['Use', 'identify engine when blind'],
      ['Confirm', 'differing 500 text'],
      ['Tool', 'Burp Repeater'],
    ],
  },
  {
    name: 'Blind timing',
    rows: [
      ['Vector', '{{range(9999999)|list}}'],
      ['Signal', 'measurable response delay'],
      ['Use', 'no output reflected'],
      ['Extract', '~130 reqs/char secret'],
      ['Confirm', 'delay correlates'],
      ['Tool', 'Burp Intruder timing'],
    ],
  },
  {
    name: 'OOB callback',
    rows: [
      ['Vector', "subclasses()[407]('curl ...')"],
      ['Channel', 'DNS / HTTP callback'],
      ['Egress', 'oast.me / Collaborator'],
      ['Use', 'confirm blind RCE'],
      ['Confirm', 'inbound DNS/HTTP hit'],
      ['Tool', 'interactsh / Collaborator'],
    ],
  },
];

const CODE = {
  Jinja2: {
    lang: 'python',
    vuln: `# VULNERABLE — user input concatenated into the template source
from jinja2 import Environment
user_input = request.args.get("name")   # e.g. {{7*7}} or MRO chain
Environment().from_string("Hello " + user_input).render()`,
    safe: `# SECURE — fixed template, user input is a render context variable
from jinja2 import Environment
env = Environment()
env.get_template("fixed.html").render(name=request.args.get("name"))`,
  },
  Twig: {
    lang: 'php',
    vuln: `// VULNERABLE — user input IS the template, not the data
$twig->render($user_input, []);
// $user_input = {{_self.env.registerUndefinedFilterCallback('exec')}}...`,
    safe: `// SECURE — fixed template file, untrusted data passed as context
$twig->render('fixed.html', ['name' => $user_input]);
// the template is trusted; $user_input is only ever rendered as text`,
  },
  Freemarker: {
    lang: 'java',
    vuln: `// VULNERABLE — template built from a user-controlled string
Template t = new Template("", new StringReader(userInput), cfg);
// userInput = <#assign ex='...Execute'?new()>\${ex('id')}`,
    safe: `// SECURE — pre-compiled template + restricted class resolver
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
Template t = cfg.getTemplate("fixed.ftl");   // ?new() gadgets blocked`,
  },
  Velocity: {
    lang: 'java',
    vuln: `// VULNERABLE — evaluate() compiles an attacker-supplied string
engine.evaluate(ctx, writer, "id", userInput);
// userInput = #set($rt=$class.forName('java.lang.Runtime'))...`,
    safe: `// SECURE — pre-compiled .vm file + restricted Uberspect
Template t = engine.getTemplate("fixed.vm");
t.merge(ctx, writer);   // no runtime compilation of user input`,
  },
};

const ORM = [
  { fw: 'Jinja2 (Python)', api: "Environment().from_string('Hello '+user_input)", note: { en: 'Concatenating input into the source is the #1 SSTI pattern. Use get_template(\'fixed.html\').render(name=user_input) — the template is fixed, input is context.', pl: 'Konkatenacja wejścia w źródło to wzorzec SSTI nr 1. Użyj get_template(\'fixed.html\').render(name=user_input) — szablon jest stały, wejście to kontekst.' } },
  { fw: 'Twig (PHP)', api: '$twig->render($user_input, [])', note: { en: 'Rendering a user-controlled string as a template = RCE. Pass a fixed file and the input as data: $twig->render(\'fixed.html\', [\'name\'=>$user_input]).', pl: 'Renderowanie stringa od użytkownika jako szablonu = RCE. Przekaż stały plik, a wejście jako dane: $twig->render(\'fixed.html\', [\'name\'=>$user_input]).' } },
  { fw: 'Freemarker (Java)', api: 'new Template("", new StringReader(userInput), cfg)', note: { en: 'Building a Template from user input enables ?new() gadgets. Use pre-compiled templates + cfg.setNewBuiltinClassResolver(SAFER_RESOLVER).', pl: 'Tworzenie Template z wejścia użytkownika umożliwia gadżety ?new(). Użyj prekompilowanych szablonów + cfg.setNewBuiltinClassResolver(SAFER_RESOLVER).' } },
  { fw: 'Thymeleaf (Java)', api: 'templateEngine.process(userInput, ctx)', note: { en: 'Also: view-name injection via return userInput in a controller. Use th:text="${name}" and never inline [[${userInput}]] with untrusted data.', pl: 'Także: wstrzyknięcie nazwy widoku przez return userInput w kontrolerze. Użyj th:text="${name}" i nigdy nie inlinuj [[${userInput}]] z niezaufanymi danymi.' } },
  { fw: 'Velocity (Java)', api: 'engine.evaluate(ctx, writer, "id", userInput)', note: { en: 'evaluate() compiles the string at runtime. Use a pre-compiled .vm file and a restricted Uberspect to block reflection gadgets.', pl: 'evaluate() kompiluje string w czasie wykonania. Użyj prekompilowanego pliku .vm i ograniczonego Uberspect, by zablokować gadżety refleksji.' } },
];

const METHOD = [
  { en: ['Detect', 'Inject {{7*7}}, ${7*7}, #{7*7} and *{7*7} into every parameter that reaches a template; a returned 49 (not the literal) signals injectability.'], pl: ['Wykrycie', 'Wstrzyknij {{7*7}}, ${7*7}, #{7*7} i *{7*7} w każdy parametr trafiający do szablonu; zwrócone 49 (a nie dosłowny ciąg) sygnalizuje podatność.'] },
  { en: ['Identify engine', 'Use {{7*\'7\'}} → 7777777 (Jinja2) vs 49 (Twig), or the polyglot ${{<%[%\'"}}%> to force an engine-specific parse error that names the engine.'], pl: ['Identyfikacja silnika', 'Użyj {{7*\'7\'}} → 7777777 (Jinja2) vs 49 (Twig) lub poliglota ${{<%[%\'"}}%>, by wymusić błąd parsowania zdradzający silnik.'] },
  { en: ['Confirm blind', 'No output? A heavy {{range(9999999)|list}} delays the response, or an OOB curl/DNS callback proves the expression executed.'], pl: ['Potwierdzenie ślepe', 'Brak wyniku? Ciężkie {{range(9999999)|list}} opóźnia odpowiedź lub callback OOB curl/DNS dowodzi wykonania wyrażenia.'] },
  { en: ['Escape sandbox', 'Walk the object graph (__class__ / __mro__ / __subclasses__) or Flask context objects (config, request, lipsum) to reach os / subprocess.'], pl: ['Ucieczka z sandboxa', 'Przejdź graf obiektów (__class__ / __mro__ / __subclasses__) lub obiekty kontekstu Flask (config, request, lipsum), by dotrzeć do os / subprocess.'] },
  { en: ['Escalate', 'Run OS commands, then pivot: read cloud metadata for IAM credentials or chain WeasyPrint/Flask-Mail rendering for SSRF and lateral movement.'], pl: ['Eskalacja', 'Uruchom polecenia OS, potem przeskocz: odczytaj metadane chmury po poświadczenia IAM lub złącz render WeasyPrint/Flask-Mail dla SSRF i ruchu lateralnego.'] },
];

const DEFENSE = [
  { rank: 1, eff: 100, label: { en: 'Never concatenate input into templates', pl: 'Nigdy nie wklejaj wejścia w szablony' }, kind: 'primary', note: { en: 'Always pass user input as render-context variables to a fixed template. The definitive fix — user input must never be template source.', pl: 'Zawsze przekazuj wejście użytkownika jako zmienne kontekstu do stałego szablonu. Ostateczna naprawa — wejście nigdy nie może być źródłem szablonu.' } },
  { rank: 2, eff: 85, label: { en: 'Sandbox + safe APIs', pl: 'Sandbox + bezpieczne API' }, kind: 'strong', note: { en: 'SandboxedEnvironment (Jinja2), SAFER_RESOLVER (Freemarker), th:text only (Thymeleaf), restricted Uberspect (Velocity) — defence when dynamic templates are unavoidable.', pl: 'SandboxedEnvironment (Jinja2), SAFER_RESOLVER (Freemarker), tylko th:text (Thymeleaf), ograniczony Uberspect (Velocity) — obrona, gdy dynamiczne szablony są nieuniknione.' } },
  { rank: 3, eff: 75, label: { en: 'Logic-less engines', pl: 'Silniki bez logiki' }, kind: 'strong', note: { en: 'Use Mustache / Handlebars where dynamic logic is not needed — no expression evaluation means no SSTI-to-RCE surface.', pl: 'Używaj Mustache / Handlebars tam, gdzie dynamiczna logika nie jest potrzebna — brak ewaluacji wyrażeń to brak powierzchni SSTI-do-RCE.' } },
  { rank: 4, eff: 60, label: { en: 'Allowlist template features', pl: 'Allowlista funkcji szablonów' }, kind: 'mitigation', note: { en: 'Disable ?new(), doc(), __class__ and __globals__ access at the engine level so gadget chains have nothing to reach.', pl: 'Wyłącz dostęp do ?new(), doc(), __class__ i __globals__ na poziomie silnika, by łańcuchy gadżetów nie miały do czego sięgać.' } },
  { rank: 5, eff: 50, label: { en: 'Isolated rendering containers', pl: 'Izolowane kontenery renderu' }, kind: 'mitigation', note: { en: 'Render templates in containers with dropped capabilities (seccomp/AppArmor) and no egress — shrinks blast radius if a gadget slips through.', pl: 'Renderuj szablony w kontenerach z odebranymi capabilities (seccomp/AppArmor) i bez ruchu wychodzącego — ogranicza skutki, gdy gadżet się prześlizgnie.' } },
  { rank: 6, eff: 20, label: { en: 'WAF (compensating only)', pl: 'WAF (tylko kompensacyjny)' }, kind: 'weak', note: { en: 'Rules blocking {{, }}, ${, #set, ?new(), __class__, __mro__, subclasses help — but Unicode, |attr() and hex encoding bypass signatures. Detective, never preventive.', pl: 'Reguły blokujące {{, }}, ${, #set, ?new(), __class__, __mro__, subclasses pomagają — ale Unicode, |attr() i kodowanie hex omijają sygnatury. Detekcyjny, nigdy zapobiegawczy.' } },
];

const INCIDENTS = [
  { org: 'Spring Cloud Gateway', year: 2022, impact: 'CVE-2022-22947', cost: 'CVSS 10.0', en: 'SpEL SSTI via Actuator routes, unauthenticated — mass-exploited within days of disclosure across thousands of Spring Gateway deployments.', pl: 'SpEL SSTI przez trasy Actuator, bez uwierzytelnienia — masowo eksploitowane w ciągu dni od ujawnienia na tysiącach wdrożeń Spring Gateway.' },
  { org: 'Spring Cloud Function', year: 2022, impact: 'CVE-2022-22963', cost: 'CVSS 9.8', en: 'SpEL injection via the spring.cloud.function.routing-expression HTTP header — exploited by Mirai botnet variants.', pl: 'Wstrzyknięcie SpEL przez nagłówek HTTP spring.cloud.function.routing-expression — eksploitowane przez warianty botnetu Mirai.' },
  { org: 'Confluence Server', year: 2019, impact: 'CVE-2019-3396', cost: 'CVSS 9.8', en: 'Velocity/OGNL SSTI via the Widget Connector url parameter — unauthenticated RCE used in ransomware campaigns.', pl: 'Velocity/OGNL SSTI przez parametr url Widget Connector — RCE bez uwierzytelnienia użyte w kampaniach ransomware.' },
  { org: 'Uber Bug Bounty', year: 2016, impact: '$10,000', cost: 'Jinja2 SSTI', en: 'Jinja2 SSTI via render_template_string() in an internal tool — full RCE demonstrated with an MRO chain payload.', pl: 'Jinja2 SSTI przez render_template_string() w wewnętrznym narzędziu — pełne RCE pokazane ładunkiem łańcucha MRO.' },
  { org: 'Shopify', year: 2019, impact: '$20,000+', cost: 'Liquid SSTI', en: 'Liquid template injection via Liquid::Template.parse(user_input) — remote code execution on Shopify partner tooling.', pl: 'Wstrzyknięcie szablonu Liquid przez Liquid::Template.parse(user_input) — zdalne wykonanie kodu na narzędziach partnerskich Shopify.' },
  { org: 'Jira Service Mgmt', year: 2023, impact: 'CVE-2023-22501', cost: 'CVSS 9.4', en: 'Velocity SSTI in Jira Service Management allowed unauthenticated account takeover via email-verification templates.', pl: 'Velocity SSTI w Jira Service Management umożliwił przejęcie konta bez uwierzytelnienia przez szablony weryfikacji e-mail.' },
];

const TOOLS = {
  sast: [
    ['Semgrep', 'python.flask.security.audit.render-template-string'],
    ['Bandit', 'B702 — use of mako/template with tainted input'],
    ['CodeQL', 'java/template-injection dataflow query'],
    ['Manual', 'grep from_string / render($input) / evaluate(...)'],
  ],
  dast: [
    ['tplmap', 'Automated SSTI detection & exploitation'],
    ['SSTImap', 'Modern tplmap successor, multi-engine'],
    ['Burp Suite', 'Active Scan + Collaborator for blind OOB'],
    ['interactsh', 'Out-of-band DNS/HTTP callback server'],
  ],
};

const COMPLIANCE = [
  { std: 'PCI DSS v4.0', items: ['6.3.2 — inventory & review custom code', '6.3.3 — patch known vulnerabilities', 'SSTI→RCE = full CDE compromise, hard QSA gate'] },
  { std: 'SOC 2', items: ['CC6.1 — logical access controls', 'CC7.1 — vulnerability detection', 'Code review + SAST gates for template endpoints'] },
  { std: 'GDPR / OWASP', items: ['Art 32/33 — RCE exposes all PII, 72h breach notice', 'A03:2021 — Injection', 'CWE-94 — Code Injection'] },
];

const IR = {
  en: [
    'Segment the network — isolate the host and block outbound egress immediately',
    'Snapshot memory and disk; preserve access logs before they rotate',
    'Identify the template engine and the exact endpoint that compiled user input',
    'Correlate web access logs with the request carrying the {{ }} / ${ } payload',
    'Rotate every credential the host could reach — IAM roles, API keys, SSH keys',
    'Patch: pass input as render context to a fixed template, redeploy with a sandbox',
    'Hunt for persistence — cron, systemd units, authorized_keys, webshells',
    'Notify per PCI DSS / SOC 2 / GDPR obligations and sweep sibling endpoints with Semgrep/tplmap',
  ],
  pl: [
    'Segmentuj sieć — natychmiast odizoluj host i zablokuj ruch wychodzący',
    'Zrób zrzut pamięci i dysku; zabezpiecz logi dostępu zanim się przerotują',
    'Zidentyfikuj silnik szablonów i dokładny endpoint kompilujący wejście użytkownika',
    'Skoreluj logi dostępu WWW z żądaniem niosącym ładunek {{ }} / ${ }',
    'Zrotuj każde poświadczenie w zasięgu hosta — role IAM, klucze API, klucze SSH',
    'Załataj: przekaż wejście jako kontekst do stałego szablonu, wdróż z sandboxem',
    'Poluj na persystencję — cron, jednostki systemd, authorized_keys, webshelle',
    'Powiadom zgodnie z PCI DSS / SOC 2 / GDPR i przeskanuj bliźniacze endpointy Semgrep/tplmap',
  ],
};

const SOURCES = [
  ['OWASP A03:2021 Injection', 'https://owasp.org/Top10/A03_2021-Injection/'],
  ['CWE-94 (MITRE)', 'https://cwe.mitre.org/data/definitions/94.html'],
  ['PortSwigger — Server-Side Template Injection', 'https://portswigger.net/web-security/server-side-template-injection'],
  ['OWASP Injection Prevention Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'],
  ['HackTricks — SSTI', 'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection'],
  ['Spring Cloud Gateway CVE-2022-22947', 'https://nvd.nist.gov/vuln/detail/CVE-2022-22947'],
  ['Spring Cloud Function CVE-2022-22963', 'https://nvd.nist.gov/vuln/detail/CVE-2022-22963'],
  ['Confluence CVE-2019-3396', 'https://nvd.nist.gov/vuln/detail/CVE-2019-3396'],
  ['Jira CVE-2023-22501', 'https://nvd.nist.gov/vuln/detail/CVE-2023-22501'],
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function sevClass(s) {
  return { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low';
}

function codeBlock(lang, code) {
  return `<div class="ssti-code-area">
    <button class="ssti-copy" type="button" title="${tr(TXT.copy)}">${SVG.copy}<span>${tr(TXT.copy)}</span></button>
    <pre><code class="language-${lang}">${esc(code)}</code></pre>
  </div>`;
}

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="ssti-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function buildOverview() {
  const lang = getLang();
  const lead = lang === 'en'
    ? 'Server-Side Template Injection happens when user input is concatenated into a template that the server then evaluates — turning the template engine into a code interpreter for the attacker. A probe like {{7*7}} returning 49 confirms it; from there a Jinja2 MRO chain, a Twig filter callback, or a Freemarker ?new() gadget walks to os / subprocess for remote code execution. Sandboxes are escaped through Flask context objects, blind cases are confirmed by timing and out-of-band callbacks, and the payload often arrives through an email or PDF template. Unauthenticated SSTI rates CVSS 10.0 Critical.'
    : 'Server-Side Template Injection występuje, gdy wejście użytkownika jest sklejane z szablonem, który serwer następnie oblicza — zamieniając silnik szablonów w interpreter kodu atakującego. Sonda {{7*7}} zwracająca 49 to potwierdza; stamtąd łańcuch MRO w Jinja2, callback filtra Twig lub gadżet ?new() Freemarker prowadzi do os / subprocess dla zdalnego wykonania kodu. Sandboxy obchodzi się przez obiekty kontekstu Flask, przypadki ślepe potwierdza timing i callbacki out-of-band, a ładunek często przychodzi przez szablon e-mail lub PDF. Nieuwierzytelnione SSTI to CVSS 10.0 Krytyczne.';

  return `<section id="ssti-overview" class="ssti-section">
    <div class="ssti-hero">
      <span class="ssti-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>Template <span class="grad">Injection</span> (SSTI)</h1>
      <span class="ssti-sev-badge">${lang === 'en' ? 'Critical severity' : 'Krytyczna waga'}</span>
      <p class="ssti-lead">${lead}</p>
      <div class="ssti-metrics">
        <div class="ssti-metric high"><div class="ssti-metric-k">CWE-94</div><div class="ssti-metric-v">${lang === 'en' ? 'Weakness ID' : 'ID słabości'}</div></div>
        <div class="ssti-metric high"><div class="ssti-metric-k">10.0</div><div class="ssti-metric-v">CVSS · Critical</div></div>
        <div class="ssti-metric"><div class="ssti-metric-k">A03:2021</div><div class="ssti-metric-v">OWASP Top 10</div></div>
        <div class="ssti-metric"><div class="ssti-metric-k">8</div><div class="ssti-metric-v">${lang === 'en' ? 'Attack variants' : 'Warianty ataku'}</div></div>
      </div>
      <div class="ssti-sources">
        <span class="ssti-sources-label">${lang === 'en' ? 'Verified sources:' : 'Zweryfikowane źródła:'}</span>
        <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener" class="ssti-source-link">OWASP A03:2021</a>
        <a href="https://cwe.mitre.org/data/definitions/94.html" target="_blank" rel="noopener" class="ssti-source-link">CWE-94 (MITRE)</a>
        <a href="https://portswigger.net/web-security/server-side-template-injection" target="_blank" rel="noopener" class="ssti-source-link">PortSwigger Academy</a>
        <a href="https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener" class="ssti-source-link">OWASP Cheat Sheet</a>
        <a href="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection" target="_blank" rel="noopener" class="ssti-source-link">HackTricks SSTI</a>
      </div>
    </div>
  </section>`;
}

function buildTypes() {
  const lang = getLang();
  const cards = TYPES.map((t) => `
    <article class="ssti-type-card">
      <header>
        <h3>${esc(t.name)}</h3>
        <span class="badge ${sevClass(t.sev)}">${t.sev}</span>
      </header>
      <p>${t.desc[lang]}</p>
      <div class="ssti-payload"><span class="ssti-payload-tag">payload</span><code>${esc(t.payload)}</code></div>
    </article>`).join('');
  return secWrap('ssti-types', lang === 'en' ? 'Attack types' : 'Typy ataków',
    lang === 'en' ? 'Eight ways the same root cause manifests — from a Jinja2 MRO chain to a WeasyPrint PDF render that pulls cloud metadata.' : 'Osiem sposobów, w jakie ta sama przyczyna się ujawnia — od łańcucha MRO w Jinja2 po render PDF WeasyPrint ciągnący metadane chmury.',
    `<div class="ssti-type-grid">${cards}</div>`);
}

function buildCheatsheet() {
  const lang = getLang();
  const cols = DBS.map((db) => `
    <div class="ssti-db-col">
      <h4>${esc(db.name)}</h4>
      ${db.rows.map((r) => `<div class="ssti-db-row"><span class="ssti-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}
    </div>`).join('');
  return secWrap('ssti-cheatsheet', lang === 'en' ? 'Detection cheatsheet' : 'Ściąga detekcji',
    lang === 'en' ? 'Five probe families. Arithmetic fingerprinting, the {{7*\'7\'}} engine differentiator, a polyglot error probe, blind timing and out-of-band callbacks.' : 'Pięć rodzin sond. Fingerprinting arytmetyczny, różnicowanie silnika {{7*\'7\'}}, poliglotowa sonda błędu, ślepy timing i callbacki out-of-band.',
    `<div class="ssti-db-grid">${cols}</div>`);
}

function buildCode() {
  const lang = getLang();
  const langs = Object.keys(CODE);
  const tabs = langs.map((l, i) =>
    `<button class="ssti-lang-tab${i === 0 ? ' active' : ''}" data-lang="${l}" type="button">${l}</button>`).join('');
  const panels = langs.map((l, i) => {
    const c = CODE[l];
    return `<div class="ssti-lang-panel${i === 0 ? ' active' : ''}" data-lang="${l}">
      <div class="ssti-vs">
        <div class="ssti-vs-col vuln"><div class="ssti-vs-head vuln">✗ ${tr(TXT.vuln)}</div>${codeBlock(c.lang, c.vuln)}</div>
        <div class="ssti-vs-col safe"><div class="ssti-vs-head safe">✓ ${tr(TXT.safe)}</div>${codeBlock(c.lang, c.safe)}</div>
      </div>
    </div>`;
  }).join('');
  return secWrap('ssti-code', lang === 'en' ? 'Vulnerable vs Secure' : 'Podatny vs Bezpieczny',
    lang === 'en' ? 'The same fix across four engines: never make user input the template source — render a fixed template and pass the input as a context variable.' : 'Ta sama naprawa w czterech silnikach: nigdy nie czyń wejścia użytkownika źródłem szablonu — renderuj stały szablon i przekaż wejście jako zmienną kontekstu.',
    `<div class="ssti-lang-tabs">${tabs}</div><div class="ssti-lang-panels">${panels}</div>`);
}

function buildLangRisks() {
  const lang = getLang();
  const rows = ORM.map((o) => `
    <div class="ssti-orm-row">
      <div class="ssti-orm-fw">${esc(o.fw)}</div>
      <code class="ssti-orm-api">${esc(o.api)}</code>
      <div class="ssti-orm-note">${o.note[lang]}</div>
    </div>`).join('');
  return secWrap('ssti-langrisks', lang === 'en' ? 'Engine-specific risks' : 'Ryzyka per silnik',
    lang === 'en' ? 'Each engine has a string-rendering API that compiles user input and a safe fixed-template counterpart — concatenation is the root cause in every one.' : 'Każdy silnik ma API renderujące string, które kompiluje wejście użytkownika, i bezpieczny odpowiednik ze stałym szablonem — konkatenacja jest przyczyną w każdym z nich.',
    `<div class="ssti-orm">${rows}</div>`);
}

function buildMethod() {
  const lang = getLang();
  const steps = METHOD.map((m, i) => `
    <div class="ssti-step">
      <div class="ssti-step-num">${i + 1}</div>
      <div class="ssti-step-body"><h4>${m[lang][0]}</h4><p>${m[lang][1]}</p></div>
    </div>`).join('');
  return secWrap('ssti-method', lang === 'en' ? 'Attack methodology' : 'Metodyka ataku',
    lang === 'en' ? 'How an attacker progresses from a {{7*7}} probe to full host compromise.' : 'Jak atakujący przechodzi od sondy {{7*7}} do pełnej kompromitacji hosta.',
    `<div class="ssti-timeline">${steps}</div>`);
}

function buildDefense() {
  const lang = getLang();
  const rows = DEFENSE.map((d) => `
    <div class="ssti-def-row ${d.kind}">
      <div class="ssti-def-rank">#${d.rank}</div>
      <div class="ssti-def-main">
        <div class="ssti-def-label">${d.label[lang]}</div>
        <div class="ssti-def-note">${d.note[lang]}</div>
      </div>
      <div class="ssti-def-bar"><span style="width:${d.eff}%"></span></div>
    </div>`).join('');
  return secWrap('ssti-defense', lang === 'en' ? 'Defense layers, ranked' : 'Warstwy obrony wg skuteczności',
    lang === 'en' ? 'Defense in depth — but not all layers are equal. Never concatenating input into templates is the fix; everything else reduces blast radius.' : 'Obrona w głąb — ale warstwy nie są równe. Niewklejanie wejścia w szablony to naprawa; reszta ogranicza skutki.',
    `<div class="ssti-defense">${rows}</div>`);
}

function buildIncidents() {
  const lang = getLang();
  const cards = INCIDENTS.map((i) => `
    <article class="ssti-incident">
      <div class="ssti-incident-top"><h4>${esc(i.org)}</h4><span class="ssti-incident-year">${i.year}</span></div>
      <div class="ssti-incident-nums"><span class="ssti-incident-impact">${esc(i.impact)}</span><span class="ssti-incident-cost">${esc(i.cost)}</span></div>
      <p>${i[lang]}</p>
    </article>`).join('');
  const sources = `<div class="ssti-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22947" target="_blank" rel="noopener">Spring Gateway CVE-2022-22947</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-22963" target="_blank" rel="noopener">Spring Function CVE-2022-22963</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-3396" target="_blank" rel="noopener">Confluence CVE-2019-3396</a>
    <a href="https://nvd.nist.gov/vuln/detail/CVE-2023-22501" target="_blank" rel="noopener">Jira CVE-2023-22501</a>
  </div>`;
  return secWrap('ssti-incidents', lang === 'en' ? 'Real-world incidents' : 'Rzeczywiste incydenty',
    lang === 'en' ? 'SSTI is not theoretical — these CVEs reached CVSS 10.0, powered Mirai-driven mass exploitation, and earned $20,000+ bug bounties.' : 'SSTI nie jest teoretyczne — te CVE osiągnęły CVSS 10.0, napędziły masową eksploatację przez Mirai i przyniosły nagrody $20,000+.',
    `<div class="ssti-incidents">${cards}</div>${sources}`);
}

function buildTools() {
  const lang = getLang();
  const sast = TOOLS.sast.map((t) => `<div class="ssti-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const dast = TOOLS.dast.map((t) => `<div class="ssti-tool-row"><strong>${esc(t[0])}</strong><span>${esc(t[1])}</span></div>`).join('');
  const note = lang === 'en'
    ? '<strong>Key signal:</strong> grep for <code>render_template_string(tainted)</code>, <code>Environment().from_string(...)</code>, <code>$twig->render($input)</code>, <code>new Template("", new StringReader(input), ...)</code> and <code>engine.evaluate(..., input)</code> — user input as template source is the root cause.'
    : '<strong>Kluczowy sygnał:</strong> szukaj <code>render_template_string(tainted)</code>, <code>Environment().from_string(...)</code>, <code>$twig->render($input)</code>, <code>new Template("", new StringReader(input), ...)</code> i <code>engine.evaluate(..., input)</code> — wejście użytkownika jako źródło szablonu to przyczyna źródłowa.';
  return secWrap('ssti-tools', lang === 'en' ? 'Detection tooling' : 'Narzędzia wykrywania',
    lang === 'en' ? 'Static analysis flags user input flowing into template compilation; dynamic scanners and out-of-band servers confirm blind exploitability. Use both.' : 'Analiza statyczna oznacza wejście użytkownika trafiające do kompilacji szablonu; skanery dynamiczne i serwery out-of-band potwierdzają ślepą eksploatowalność. Używaj obu.',
    `<div class="ssti-tools-grid">
      <div class="ssti-tool-col"><h4>SAST · ${lang === 'en' ? 'Static' : 'Statyczna'}</h4>${sast}</div>
      <div class="ssti-tool-col"><h4>DAST · ${lang === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${dast}</div>
    </div>
    <div class="ssti-callout warn">${note}</div>`);
}

function buildCompliance() {
  const lang = getLang();
  const cards = COMPLIANCE.map((c) => `
    <article class="ssti-comp-card">
      <h4>${esc(c.std)}</h4>
      <ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>
    </article>`).join('');
  const sources = `<div class="ssti-inline-sources">${lang === 'en' ? 'Sources:' : 'Źródła:'}
    <a href="https://www.pcisecuritystandards.org/document_library/" target="_blank" rel="noopener">PCI DSS v4.0</a>
    <a href="https://www.aicpa.org/resources/article/soc-2-reporting-on-an-examination-of-controls-at-a-service-organization-relevant-to-security" target="_blank" rel="noopener">SOC 2 (AICPA)</a>
    <a href="https://cwe.mitre.org/data/definitions/94.html" target="_blank" rel="noopener">CWE-94 (MITRE)</a>
    <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank" rel="noopener">OWASP A03:2021</a>
  </div>`;
  return secWrap('ssti-compliance', lang === 'en' ? 'Compliance quick-reference' : 'Szybka zgodność',
    lang === 'en' ? 'Where SSTI prevention maps onto the hard compliance gates auditors check — because SSTI-to-RCE is a full system and PII compromise.' : 'Gdzie zapobieganie SSTI mapuje się na twarde bramki zgodności sprawdzane przez audytorów — bo SSTI-do-RCE to pełna kompromitacja systemu i PII.',
    `<div class="ssti-comp-grid">${cards}</div>${sources}`);
}

function buildIR() {
  const lang = getLang();
  const items = IR[lang].map((s, i) => `
    <li class="ssti-ir-item"><span class="ssti-ir-check">${i + 1}</span><span>${esc(s)}</span></li>`).join('');
  return secWrap('ssti-ir', lang === 'en' ? 'Incident response checklist' : 'Lista kontrolna reagowania',
    lang === 'en' ? 'If you confirm an active SSTI breach, work this list top to bottom.' : 'Po potwierdzeniu aktywnego wycieku SSTI przejdź tę listę od góry.',
    `<ol class="ssti-ir">${items}</ol>`);
}

function buildSourcesSection() {
  const lang = getLang();
  const links = SOURCES.map((s) =>
    `<a href="${s[1]}" target="_blank" rel="noopener" class="ssti-source-link">${esc(s[0])}</a>`).join('');
  return secWrap('ssti-sources', lang === 'en' ? 'Sources & references' : 'Źródła i odniesienia',
    lang === 'en' ? 'Primary references for the techniques, CVEs, and mitigations described above.' : 'Główne odniesienia do opisanych technik, CVE i środków zaradczych.',
    `<div class="ssti-sources" style="margin-top:0">${links}</div>`);
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="ssti-section">
    <h2 class="ssti-h2">${title}</h2>
    <p class="ssti-section-lead">${lead}</p>
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
    `<footer class="ssti-footer">Code Guardian — Server-Side Template Injection deep-dive · ${getLang() === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`,
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
  $$('.ssti-copy', panel).forEach((btn) => {
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
  $$('.ssti-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.ssti-lang-tab', panel).forEach((t) => t.classList.toggle('active', t === tab));
      $$('.ssti-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.ssti-body', panel);
  const links = $$('.ssti-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.ssti-section', panel);
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
    <div class="ssti-topbar">
      <span class="ssti-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="ssti-topbar-title">Server-Side Template Injection</span>
      <span style="flex:1"></span>
      <button class="ssti-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="ssti-shell">
      <nav class="ssti-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="ssti-body">${buildContent()}</div>
    </div>`;
  highlighted = false;
  $('.ssti-close', panel).addEventListener('click', close);
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
  document.body.classList.add('ssti-lock');
  highlightOnce(_panel);
  const body = $('.ssti-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('ssti-lock');
}

export function openSstiPage() { open(); }

export function initSstiPage() {
  _panel = $('#ssti-page');
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

  const openBtn = $('#ssti-tab');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
