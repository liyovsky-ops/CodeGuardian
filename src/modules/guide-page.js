/* =========================================================================
   Code Guardian — Guide / Legend page
   Standalone full-screen reference panel. Explains every badge/mark so
   readers know how to interpret threat cards.
   Accent: INDIGO (#6366f1) — neutral, not a severity color.
   ========================================================================= */
import { $, $$ } from './dom.js';
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
  book:
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
};

/* ---------- localized micro-strings ---------- */
const TXT = {
  close: { en: 'Close', pl: 'Zamknij' },
};
const tr = (o) => o[getLang()] ?? o.en;
const L = (en, pl) => (getLang() === 'pl' ? pl : en);

/* =========================================================================
   CONTENT DATA
   ========================================================================= */

const NAV = [
  { id: 'guide-overview', en: 'Overview', pl: 'Przegląd' },
  { id: 'guide-card', en: 'Reading a card', pl: 'Czytanie karty' },
  { id: 'guide-severity', en: 'Severity levels', pl: 'Poziomy wagi' },
  { id: 'guide-difficulty', en: 'Detection difficulty', pl: 'Trudność wykrycia' },
  { id: 'guide-confidence', en: 'Confidence levels', pl: 'Poziomy pewności' },
  { id: 'guide-cwe', en: 'CWE references', pl: 'Odniesienia CWE' },
  { id: 'guide-prioritize', en: 'How to prioritize', pl: 'Jak priorytetyzować' },
  { id: 'guide-data', en: 'About the data', pl: 'O danych' },
];

/* ---- Section 1: anatomy of a card ---- */
const ANATOMY = [
  {
    mark: { en: 'Threat ID', pl: 'ID zagrożenia' },
    preview: '<span class="guide-mock-id">1.4</span>',
    desc: {
      en: 'Category number + sequential index within that category. "1.4" means the 4th threat in category 1.',
      pl: 'Numer kategorii + kolejny indeks w tej kategorii. "1.4" oznacza 4. zagrożenie w kategorii 1.',
    },
  },
  {
    mark: { en: 'Threat name', pl: 'Nazwa zagrożenia' },
    preview: '<span class="guide-mock-name">SQL Injection</span>',
    desc: {
      en: 'The name of the vulnerability itself.',
      pl: 'Nazwa samej podatności.',
    },
  },
  {
    mark: { en: 'Severity badge', pl: 'Odznaka wagi' },
    preview: '<span class="badge badge-critical">Critical</span>',
    desc: {
      en: 'How serious the impact is if the vulnerability is exploited. Four levels — see below.',
      pl: 'Jak poważny jest skutek, jeśli podatność zostanie wykorzystana. Cztery poziomy — patrz niżej.',
    },
  },
  {
    mark: { en: 'Difficulty badge', pl: 'Odznaka trudności' },
    preview: '<span class="badge diff easy">Easy</span>',
    desc: {
      en: 'How hard it is to DETECT / FIND the vulnerability in code — not how hard the attack is.',
      pl: 'Jak trudno WYKRYĆ / ZNALEŹĆ podatność w kodzie — nie jak trudny jest atak.',
    },
  },
  {
    mark: { en: 'Confidence badge', pl: 'Odznaka pewności' },
    preview: '<span class="badge conf-iron">Confirmed</span>',
    desc: {
      en: 'How well-established and documented the threat entry is. Three levels — see below.',
      pl: 'Jak dobrze ugruntowane i udokumentowane jest dane zagrożenie. Trzy poziomy — patrz niżej.',
    },
  },
  {
    mark: { en: 'CWE badge', pl: 'Odznaka CWE' },
    preview: '<span class="badge cwe">CWE-89</span>',
    desc: {
      en: 'Links to the standardized Common Weakness Enumeration definition at MITRE.',
      pl: 'Link do standardowej definicji Common Weakness Enumeration w MITRE.',
    },
  },
  {
    mark: { en: 'Deep-dive button', pl: 'Przycisk pogłębiony' },
    preview: '<span class="guide-mock-deep">↗</span>',
    desc: {
      en: 'Opens a detailed research page. Present only on select threats.',
      pl: 'Otwiera szczegółową stronę badawczą. Obecny tylko przy wybranych zagrożeniach.',
    },
  },
  {
    mark: { en: 'Code tabs', pl: 'Zakładki kodu' },
    preview: '<span class="guide-mock-tab vuln">✗ Vulnerable</span><span class="guide-mock-tab safe">✓ Secure</span>',
    desc: {
      en: 'Practical, side-by-side code examples — the vulnerable pattern and its secure fix.',
      pl: 'Praktyczne przykłady kodu obok siebie — podatny wzorzec i jego bezpieczna naprawa.',
    },
  },
];

/* ---- Section 2: severity ---- */
const SEVERITY = [
  {
    badge: '<span class="badge badge-critical">Critical</span>',
    cvss: 'CVSS 9.0–10.0',
    meaning: {
      en: 'Full system compromise possible. Remote code execution, complete data breach, or authentication bypass leading to admin access. Fix immediately.',
      pl: 'Możliwa pełna kompromitacja systemu. Zdalne wykonanie kodu, całkowity wyciek danych lub obejście uwierzytelniania prowadzące do dostępu admina. Naprawiaj natychmiast.',
    },
    example: { en: 'SQL Injection, OS Command Injection', pl: 'SQL Injection, OS Command Injection' },
  },
  {
    badge: '<span class="badge badge-high">High</span>',
    cvss: 'CVSS 7.0–8.9',
    meaning: {
      en: 'Significant impact. Authentication bypass, privilege escalation, or large-scale data exposure. Fix in the current sprint.',
      pl: 'Znaczący skutek. Obejście uwierzytelniania, eskalacja uprawnień lub ekspozycja danych na dużą skalę. Naprawiaj w bieżącym sprincie.',
    },
    example: { en: 'NoSQL Injection, LDAP Injection, SSRF', pl: 'NoSQL Injection, LDAP Injection, SSRF' },
  },
  {
    badge: '<span class="badge badge-medium">Medium</span>',
    cvss: 'CVSS 4.0–6.9',
    meaning: {
      en: 'Limited but real impact. Information disclosure; requires specific conditions or chaining with other bugs. Fix in the next release.',
      pl: 'Ograniczony, lecz realny skutek. Ujawnienie informacji; wymaga specyficznych warunków lub łańcucha z innymi błędami. Naprawiaj w następnym wydaniu.',
    },
    example: { en: 'Verbose error messages, weak session IDs', pl: 'Gadatliwe komunikaty błędów, słabe ID sesji' },
  },
  {
    badge: '<span class="badge badge-low">Low</span>',
    cvss: 'CVSS 0.1–3.9',
    meaning: {
      en: 'Minimal direct impact. Defense-in-depth improvement or hardening. Fix when capacity allows.',
      pl: 'Minimalny bezpośredni skutek. Ulepszenie obrony w głąb lub utwardzenie. Naprawiaj, gdy pozwolą zasoby.',
    },
    example: { en: 'Missing security headers, overly verbose logs', pl: 'Brakujące nagłówki bezpieczeństwa, zbyt gadatliwe logi' },
  },
];

/* ---- Section 3: detection difficulty ---- */
const DIFFICULTY = [
  {
    badge: '<span class="badge diff easy">Easy</span>',
    who: { en: 'Automated scanners', pl: 'Skanery automatyczne' },
    meaning: {
      en: 'SAST tools find it reliably. Obvious sink patterns (e.g. string concatenation into a SQL query). A junior developer can spot it in code review.',
      pl: 'Narzędzia SAST znajdują to niezawodnie. Oczywiste wzorce ujścia (np. konkatenacja stringów do zapytania SQL). Junior wychwyci to w code review.',
    },
    example: { en: 'SQL Injection via string concat', pl: 'SQL Injection przez konkatenację stringów' },
  },
  {
    badge: '<span class="badge diff medium">Medium</span>',
    who: { en: 'SAST with taint tracking', pl: 'SAST ze śledzeniem skażenia' },
    meaning: {
      en: 'Requires data flow / taint analysis. The scanner must trace input across multiple functions. Context matters.',
      pl: 'Wymaga analizy przepływu danych / skażenia. Skaner musi prześledzić wejście przez wiele funkcji. Kontekst ma znaczenie.',
    },
    example: { en: 'Indirect injection through helper functions', pl: 'Pośrednie wstrzyknięcie przez funkcje pomocnicze' },
  },
  {
    badge: '<span class="badge diff hard">Hard</span>',
    who: { en: 'Senior pentesters', pl: 'Doświadczeni pentesterzy' },
    meaning: {
      en: 'Requires runtime analysis or deep manual review. Business logic is involved. SAST often misses it entirely.',
      pl: 'Wymaga analizy w czasie działania lub dogłębnego przeglądu ręcznego. W grę wchodzi logika biznesowa. SAST często to całkowicie pomija.',
    },
    example: { en: 'Auth logic flaws, race conditions', pl: 'Błędy logiki uwierzytelniania, wyścigi' },
  },
  {
    badge: '<span class="badge diff veryhard">Very Hard</span>',
    who: { en: 'Specialists + runtime monitoring', pl: 'Specjaliści + monitoring runtime' },
    meaning: {
      en: 'Only found via active penetration testing, fuzzing, or production monitoring. Near-impossible to detect statically.',
      pl: 'Wykrywalne tylko przez aktywne testy penetracyjne, fuzzing lub monitoring produkcyjny. Niemal niemożliwe do wykrycia statycznie.',
    },
    example: { en: 'Time-of-check/time-of-use bugs, blind injection', pl: 'Błędy TOCTOU, ślepe wstrzyknięcia' },
  },
];

/* ---- Section 4: confidence ---- */
const CONFIDENCE = [
  {
    badge: '<span class="badge conf-iron">Confirmed</span>',
    key: 'IRON',
    meaning: {
      en: 'Fully documented. Multiple CVEs exist. Widely reproduced and verified in real systems. Treat as fact.',
      pl: 'W pełni udokumentowane. Istnieje wiele CVE. Szeroko odtworzone i zweryfikowane w realnych systemach. Traktuj jako fakt.',
    },
  },
  {
    badge: '<span class="badge conf-possible">Probable</span>',
    key: 'POSSIBLE',
    meaning: {
      en: 'Likely real based on evidence but with fewer CVEs or limited reproduction. Worth implementing defenses.',
      pl: 'Prawdopodobnie realne na podstawie dowodów, ale z mniejszą liczbą CVE lub ograniczoną reprodukcją. Warto wdrożyć obronę.',
    },
  },
  {
    badge: '<span class="badge conf-research">Needs research</span>',
    key: 'RESEARCH',
    meaning: {
      en: 'Theoretical, emerging, or conflicting sources. May apply to specific environments only. Verify before prioritizing.',
      pl: 'Teoretyczne, wschodzące lub sprzeczne źródła. Może dotyczyć tylko określonych środowisk. Zweryfikuj przed priorytetyzacją.',
    },
  },
];

/* ---- Section 6: prioritization ---- */
const PRIORITY = [
  {
    kind: 'now',
    label: { en: 'Fix now (this sprint)', pl: 'Naprawiaj teraz (ten sprint)' },
    rule: { en: 'Critical severity + Easy detection', pl: 'Waga Critical + wykrycie Easy' },
    note: {
      en: 'No excuse — your scanner should already flag it.',
      pl: 'Bez wymówek — skaner powinien to już zgłaszać.',
    },
  },
  {
    kind: 'soon',
    label: { en: 'Fix soon', pl: 'Naprawiaj wkrótce' },
    rule: { en: 'Critical + Hard detection, or High + Easy detection', pl: 'Critical + wykrycie Hard, lub High + wykrycie Easy' },
    note: {
      en: 'High impact that needs either manual review or quick attention.',
      pl: 'Duży wpływ, wymagający przeglądu ręcznego lub szybkiej uwagi.',
    },
  },
  {
    kind: 'next',
    label: { en: 'Plan for next release', pl: 'Zaplanuj na następne wydanie' },
    rule: { en: 'Medium severity, any difficulty', pl: 'Waga Medium, dowolna trudność' },
    note: {
      en: 'Real but bounded impact — schedule it deliberately.',
      pl: 'Realny, ale ograniczony skutek — zaplanuj świadomie.',
    },
  },
  {
    kind: 'backlog',
    label: { en: 'Backlog', pl: 'Backlog' },
    rule: { en: 'Low severity', pl: 'Waga Low' },
    note: {
      en: 'Hardening and defense-in-depth — fix when capacity allows.',
      pl: 'Utwardzanie i obrona w głąb — naprawiaj, gdy pozwolą zasoby.',
    },
  },
];

const DATA_POINTS = [
  {
    en: ['ModelArena pipeline', 'Threats were researched using ModelArena — a 3-team AI pipeline (Claude + Gemini + DeepSeek) that independently researches topics and reaches consensus.'],
    pl: ['Pipeline ModelArena', 'Zagrożenia zbadano za pomocą ModelArena — 3-zespołowego pipeline\'u AI (Claude + Gemini + DeepSeek), który niezależnie bada tematy i osiąga konsensus.'],
  },
  {
    en: ['OWASP Top 10', 'Aligned with the OWASP Top 10 (A01–A10, 2021 edition).'],
    pl: ['OWASP Top 10', 'Zgodne z OWASP Top 10 (A01–A10, edycja 2021).'],
  },
  {
    en: ['CWE / MITRE', 'Every threat references its standardized CWE weakness ID from MITRE.'],
    pl: ['CWE / MITRE', 'Każde zagrożenie odwołuje się do standardowego ID słabości CWE z MITRE.'],
  },
  {
    en: ['Real CVEs', 'Real-world CVEs are cited in the deep-dive pages.'],
    pl: ['Realne CVE', 'Realne CVE są cytowane na stronach pogłębionych.'],
  },
  {
    en: ['Illustrative code', 'Code examples are illustrative only — never use a "vulnerable" example in production.'],
    pl: ['Kod poglądowy', 'Przykłady kodu są wyłącznie poglądowe — nigdy nie używaj przykładu "podatnego" na produkcji.'],
  },
];

/* =========================================================================
   RENDERING
   ========================================================================= */

function buildNav() {
  const lang = getLang();
  return NAV.map((n, i) =>
    `<a class="guide-nav-link${i === 0 ? ' active' : ''}" href="#${n.id}" data-target="${n.id}">${n[lang]}</a>`
  ).join('');
}

function secWrap(id, title, lead, inner) {
  return `<section id="${id}" class="guide-section">
    <h2 class="guide-h2">${title}</h2>
    <p class="guide-section-lead">${lead}</p>
    ${inner}
  </section>`;
}

function buildOverview() {
  const lead = L(
    'Every threat card in this atlas is marked with a consistent set of badges. This guide explains exactly what each mark means so you can read a card at a glance — and decide what to fix first.',
    'Każda karta zagrożenia w tym atlasie jest oznaczona spójnym zestawem odznak. Ten przewodnik wyjaśnia dokładnie, co oznacza każda odznaka, byś mógł czytać kartę na pierwszy rzut oka — i zdecydować, co naprawić najpierw.'
  );
  return `<section id="guide-overview" class="guide-section">
    <div class="guide-hero">
      <span class="guide-eyebrow">${SVG.book}<span>Code Guardian · ${L('Guide', 'Przewodnik')}</span></span>
      <h1>Code Guardian <span class="guide-grad">${L('Guide', 'Przewodnik')}</span></h1>
      <p class="guide-subtitle">${L('How to read this atlas', 'Jak czytać ten atlas')}</p>
      <p class="guide-lead">${lead}</p>
    </div>
  </section>`;
}

function buildCard() {
  const rows = ANATOMY.map((a) => `
    <div class="guide-anatomy-row">
      <div class="guide-anatomy-preview">${a.preview}</div>
      <div class="guide-anatomy-body">
        <div class="guide-anatomy-mark">${a.mark[getLang()]}</div>
        <div class="guide-anatomy-desc">${a.desc[getLang()]}</div>
      </div>
    </div>`).join('');

  const example = `
    <div class="guide-card-example">
      <div class="guide-card-example-head">
        <span class="guide-mock-id">1.4</span>
        <span class="guide-mock-name">SQL Injection</span>
        <span class="guide-card-example-spacer"></span>
        <span class="guide-mock-deep" title="Deep-dive">↗</span>
      </div>
      <div class="guide-card-example-badges">
        <span class="badge badge-critical">Critical</span>
        <span class="badge diff easy">Easy</span>
        <span class="badge conf-iron">Confirmed</span>
        <span class="badge cwe">CWE-89</span>
      </div>
      <div class="guide-card-example-tabs">
        <span class="guide-mock-tab vuln">✗ ${L('Vulnerable', 'Podatny')}</span>
        <span class="guide-mock-tab safe">✓ ${L('Secure', 'Bezpieczny')}</span>
      </div>
      <div class="guide-card-example-caption">${L('A sample threat card with every mark labeled below.', 'Przykładowa karta zagrożenia z każdą odznaką opisaną poniżej.')}</div>
    </div>`;

  return secWrap('guide-card',
    L('How to read a threat card', 'Jak czytać kartę zagrożenia'),
    L('The anatomy of a threat card. Every card carries the same marks in the same order.',
      'Anatomia karty zagrożenia. Każda karta nosi te same odznaki w tej samej kolejności.'),
    `${example}<div class="guide-anatomy">${rows}</div>`);
}

function buildSeverity() {
  const rows = SEVERITY.map((s) => `
    <div class="guide-level-row">
      <div class="guide-level-badge">${s.badge}<span class="guide-level-cvss">${s.cvss}</span></div>
      <div class="guide-level-body">
        <p class="guide-level-meaning">${s.meaning[getLang()]}</p>
        <p class="guide-level-example"><span>${L('Example', 'Przykład')}:</span> ${esc(s.example[getLang()])}</p>
      </div>
    </div>`).join('');
  return secWrap('guide-severity',
    L('Severity levels', 'Poziomy wagi'),
    L('How serious the impact is if the vulnerability is exploited. Four levels, aligned to CVSS ranges.',
      'Jak poważny jest skutek wykorzystania podatności. Cztery poziomy, dopasowane do zakresów CVSS.'),
    `<div class="guide-levels">${rows}</div>`);
}

function buildDifficulty() {
  const callout = L(
    '<strong>Important:</strong> "Difficulty" does NOT mean how hard the attack is. It means how hard it is to DETECT the vulnerability in your codebase using code review, SAST tools, or static analysis.',
    '<strong>Ważne:</strong> "Trudność" NIE oznacza, jak trudny jest atak. Oznacza, jak trudno WYKRYĆ podatność w twoim kodzie za pomocą code review, narzędzi SAST lub analizy statycznej.'
  );
  const rows = DIFFICULTY.map((d) => `
    <div class="guide-level-row">
      <div class="guide-level-badge">${d.badge}<span class="guide-level-who">${d.who[getLang()]}</span></div>
      <div class="guide-level-body">
        <p class="guide-level-meaning">${d.meaning[getLang()]}</p>
        <p class="guide-level-example"><span>${L('Example', 'Przykład')}:</span> ${esc(d.example[getLang()])}</p>
      </div>
    </div>`).join('');
  return secWrap('guide-difficulty',
    L('Detection difficulty', 'Trudność wykrycia'),
    L('How hard the vulnerability is to find in code — and who is likely to find it.',
      'Jak trudno znaleźć podatność w kodzie — i kto prawdopodobnie ją znajdzie.'),
    `<div class="guide-callout">${callout}</div><div class="guide-levels">${rows}</div>`);
}

function buildConfidence() {
  const rows = CONFIDENCE.map((c) => `
    <div class="guide-level-row">
      <div class="guide-level-badge">${c.badge}<span class="guide-level-key">${c.key}</span></div>
      <div class="guide-level-body">
        <p class="guide-level-meaning">${c.meaning[getLang()]}</p>
      </div>
    </div>`).join('');
  return secWrap('guide-confidence',
    L('Confidence levels', 'Poziomy pewności'),
    L('How well-established and verified this specific threat entry is.',
      'Jak dobrze ugruntowane i zweryfikowane jest dane zagrożenie.'),
    `<div class="guide-levels">${rows}</div>`);
}

function buildCwe() {
  const body = L(
    'CWE = Common Weakness Enumeration, maintained by MITRE. Every threat links to its CWE ID (for example, <code>CWE-89</code> for SQL Injection). Clicking the badge opens the official MITRE definition. CWE provides a standardized vocabulary shared across security teams, scanners, and compliance frameworks — so a "CWE-89" finding means the same thing everywhere.',
    'CWE = Common Weakness Enumeration, utrzymywane przez MITRE. Każde zagrożenie linkuje do swojego ID CWE (np. <code>CWE-89</code> dla SQL Injection). Kliknięcie odznaki otwiera oficjalną definicję MITRE. CWE zapewnia ustandaryzowane słownictwo wspólne dla zespołów bezpieczeństwa, skanerów i ram zgodności — więc "CWE-89" znaczy wszędzie to samo.'
  );
  return secWrap('guide-cwe',
    L('CWE references', 'Odniesienia CWE'),
    L('A shared, standardized vocabulary for weaknesses.', 'Wspólne, ustandaryzowane słownictwo dla słabości.'),
    `<div class="guide-prose"><p>${body}</p>
      <div class="guide-cwe-demo">
        <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noopener" class="badge cwe">CWE-89</a>
        <span>${L('opens', 'otwiera')}</span>
        <code>cwe.mitre.org/data/definitions/89.html</code>
      </div>
    </div>`);
}

function buildPrioritize() {
  const rows = PRIORITY.map((p) => `
    <div class="guide-prio-row ${p.kind}">
      <div class="guide-prio-label">${p.label[getLang()]}</div>
      <div class="guide-prio-rule">${p.rule[getLang()]}</div>
      <div class="guide-prio-note">${p.note[getLang()]}</div>
    </div>`).join('');
  const warn = L(
    '<strong>The most dangerous combination:</strong> Critical + Very Hard. The vulnerability is catastrophic, but your tooling will not find it automatically — it is your biggest long-term risk. Budget manual review and penetration testing for these.',
    '<strong>Najgroźniejsza kombinacja:</strong> Critical + Very Hard. Podatność jest katastrofalna, ale twoje narzędzia nie znajdą jej automatycznie — to twoje największe długoterminowe ryzyko. Zaplanuj przegląd ręczny i testy penetracyjne.'
  );
  return secWrap('guide-prioritize',
    L('How to prioritize', 'Jak priorytetyzować'),
    L('Combine severity and detection difficulty into a simple priority decision.',
      'Połącz wagę i trudność wykrycia w prostą decyzję priorytetową.'),
    `<div class="guide-prio">${rows}</div><div class="guide-callout warn">${warn}</div>`);
}

function buildData() {
  const cards = DATA_POINTS.map((d) => {
    const [title, body] = d[getLang()];
    return `<article class="guide-data-card">
      <h4>${esc(title)}</h4>
      <p>${esc(body)}</p>
    </article>`;
  }).join('');
  return secWrap('guide-data',
    L('About the data', 'O danych'),
    L('Where the threats, ratings, and references come from.',
      'Skąd pochodzą zagrożenia, oceny i odniesienia.'),
    `<div class="guide-data-grid">${cards}</div>`);
}

function buildContent() {
  return [
    buildOverview(),
    buildCard(),
    buildSeverity(),
    buildDifficulty(),
    buildConfidence(),
    buildCwe(),
    buildPrioritize(),
    buildData(),
    `<footer class="guide-footer">Code Guardian — ${L('Guide', 'Przewodnik')} · ${L('All "vulnerable" examples in this atlas are illustrative only — do not use in production.', 'Wszystkie przykłady "podatne" w tym atlasie są wyłącznie poglądowe — nie używaj na produkcji.')}</footer>`,
  ].join('');
}

/* =========================================================================
   WIRING
   ========================================================================= */

function wireScrollSpy(panel) {
  const body = $('.guide-body', panel);
  const links = $$('.guide-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.guide-section', panel);
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
    <div class="guide-topbar">
      <span class="guide-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="guide-topbar-title">${lang === 'en' ? 'Guide' : 'Przewodnik'}</span>
      <span style="flex:1"></span>
      <button class="guide-close" type="button" aria-label="${tr(TXT.close)}">${SVG.close}<span>${tr(TXT.close)}</span></button>
    </div>
    <div class="guide-shell">
      <nav class="guide-nav" aria-label="${lang === 'en' ? 'Page sections' : 'Sekcje strony'}">${buildNav()}</nav>
      <div class="guide-body">${buildContent()}</div>
    </div>`;
  $('.guide-close', panel).addEventListener('click', close);
  wireScrollSpy(panel);
}

let _panel = null;
let _rendered = false;

function open() {
  if (!_panel) return;
  if (!_rendered) { render(_panel); _rendered = true; }
  _panel.classList.add('open');
  document.body.classList.add('guide-lock');
  const body = $('.guide-body', _panel);
  if (body) body.scrollTop = 0;
}

function close() {
  if (!_panel) return;
  _panel.classList.remove('open');
  document.body.classList.remove('guide-lock');
}

export function openGuidePage() { open(); }

export function initGuidePage() {
  _panel = $('#guide-page');
  if (!_panel) return;

  // Re-render on language change so content tracks the global toggle.
  const langBtn = $('#lang-toggle');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      setTimeout(() => {
        if (_rendered) {
          const wasOpen = _panel.classList.contains('open');
          render(_panel);
          if (wasOpen) _panel.classList.add('open');
        }
      }, 0);
    });
  }

  const openBtn = $('#guide-btn');
  if (openBtn) openBtn.addEventListener('click', open);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel.classList.contains('open')) close();
  });
}
