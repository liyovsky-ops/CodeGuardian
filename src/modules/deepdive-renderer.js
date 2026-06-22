/* =========================================================================
   Code Guardian — generic deep-dive renderer
   Data-driven: one renderer for every threat deep-dive. Content lives in
   src/content/deepdives/*.yaml (imported as JS objects via vite-plugin-yaml).
   ========================================================================= */
import { $, $$ } from './dom.js';
import { highlightElement } from './highlight.js';
import { getLang } from '../i18n/index.js';

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const tr = (o) => (o && typeof o === 'object' ? (o[getLang()] ?? o.en) : o);

const SVG = {
  close: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  shield: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  copy: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
};

const TXT = {
  close: { en: 'Close', pl: 'Zamknij' },
  copy: { en: 'Copy', pl: 'Kopiuj' },
  copied: { en: 'Copied', pl: 'Skopiowano' },
  vuln: { en: 'Vulnerable', pl: 'Podatny' },
  safe: { en: 'Secure', pl: 'Bezpieczny' },
  sources: { en: 'Verified sources:', pl: 'Zweryfikowane źródła:' },
  inlineSources: { en: 'Sources:', pl: 'Źródła:' },
  sectionsLabel: { en: 'Page sections', pl: 'Sekcje strony' },
};
const t = (k) => tr(TXT[k]);
const SEV_LABEL = {
  Critical: { en: 'Critical severity', pl: 'Krytyczna waga' },
  High: { en: 'High severity', pl: 'Wysoka waga' },
  Medium: { en: 'Medium severity', pl: 'Średnia waga' },
  Low: { en: 'Low severity', pl: 'Niska waga' },
};
const sevClass = (s) =>
  ({ critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[s] || 'badge-low');

/* ---------- section builders (keyed by section id) ---------- */
const codeBlock = (lang, code) => `<div class="deepdive-code-area">
  <button class="deepdive-copy" type="button" title="${t('copy')}">${SVG.copy}<span>${t('copy')}</span></button>
  <pre><code class="language-${esc(lang)}">${esc(code)}</code></pre></div>`;

const secWrap = (id, sec, inner) =>
  `<section id="dd-${esc(id)}" class="deepdive-section">
    <h2 class="deepdive-h2">${esc(tr(sec.title))}</h2>
    <p class="deepdive-section-lead">${esc(tr(sec.lead))}</p>
    ${inner}
  </section>`;

const inlineSourcesHtml = (sources) => {
  if (!sources || !sources.length) return '';
  const links = sources
    .map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.label)}</a>`)
    .join('');
  return `<div class="deepdive-inline-sources">${t('inlineSources')} ${links}</div>`;
};

const SECTION_RENDERERS = {
  attacks: (s) => secWrap('types', s, `<div class="deepdive-type-grid">${s.items
    .map((it) => `<article class="deepdive-type-card">
      <header><h3>${esc(it.name)}</h3><span class="badge ${sevClass(it.sev)}">${esc(it.sev)}</span></header>
      <p>${esc(tr(it.description))}</p>
      <div class="deepdive-payload"><span class="deepdive-payload-tag">payload</span><code>${esc(it.payload)}</code></div>
    </article>`).join('')}</div>`),

  cheatsheet: (s) => secWrap('cheatsheet', s, `<div class="deepdive-db-grid">${s.groups
    .map((g) => `<div class="deepdive-db-col"><h4>${esc(g.name)}</h4>${g.rows
      .map((r) => `<div class="deepdive-db-row"><span class="deepdive-db-key">${esc(r[0])}</span><code>${esc(r[1])}</code></div>`).join('')}</div>`).join('')}</div>`),

  code: (s) => {
    const tabs = s.languages
      .map((l, i) => `<button class="deepdive-lang-tab${i === 0 ? ' active' : ''}" data-lang="${esc(l.label)}" type="button">${esc(l.label)}</button>`).join('');
    const panels = s.languages
      .map((l, i) => `<div class="deepdive-lang-panel${i === 0 ? ' active' : ''}" data-lang="${esc(l.label)}">
        <div class="deepdive-vs">
          <div class="deepdive-vs-col vuln"><div class="deepdive-vs-head vuln">✗ ${t('vuln')}</div>${codeBlock(l.lang, l.vulnerable)}</div>
          <div class="deepdive-vs-col safe"><div class="deepdive-vs-head safe">✓ ${t('safe')}</div>${codeBlock(l.lang, l.safe)}</div>
        </div></div>`).join('');
    return secWrap('code', s, `<div class="deepdive-lang-tabs">${tabs}</div><div class="deepdive-lang-panels">${panels}</div>`);
  },

  orm: (s) => secWrap('orm', s, ormRows(s)),
  langRisks: (s) => secWrap('langrisks', s, ormRows(s)),

  method: (s) => secWrap('method', s, `<div class="deepdive-timeline">${s.steps
    .map((m, i) => `<div class="deepdive-step"><div class="deepdive-step-num">${i + 1}</div>
      <div class="deepdive-step-body"><h4>${esc(tr(m.title))}</h4><p>${esc(tr(m.description))}</p></div></div>`).join('')}</div>`),

  defenses: (s) => secWrap('defense', s, `<div class="deepdive-defense">${s.items
    .map((d) => `<div class="deepdive-def-row ${esc(d.kind)}">
      <div class="deepdive-def-rank">#${d.rank}</div>
      <div class="deepdive-def-main"><div class="deepdive-def-label">${esc(tr(d.label))}</div><div class="deepdive-def-note">${esc(tr(d.note))}</div></div>
      <div class="deepdive-def-bar"><span style="width:${d.eff}%"></span></div></div>`).join('')}</div>`),

  incidents: (s) => secWrap('incidents', s, `<div class="deepdive-incidents">${s.items
    .map((i) => `<article class="deepdive-incident">
      <div class="deepdive-incident-top"><h4>${esc(i.org)}</h4><span class="deepdive-incident-year">${esc(i.year)}</span></div>
      <div class="deepdive-incident-nums"><span class="deepdive-incident-impact">${esc(i.impact)}</span><span class="deepdive-incident-cost">${esc(i.cost)}</span></div>
      <p>${esc(tr(i.description))}</p></article>`).join('')}</div>${inlineSourcesHtml(s.inlineSources)}`),

  tools: (s) => {
    const col = (rows) => rows.map((r) => `<div class="deepdive-tool-row"><strong>${esc(r[0])}</strong><span>${esc(r[1])}</span></div>`).join('');
    const note = s.note ? `<div class="deepdive-callout warn">${tr(s.note)}</div>` : '';
    return secWrap('tools', s, `<div class="deepdive-tools-grid">
      <div class="deepdive-tool-col"><h4>SAST · ${getLang() === 'en' ? 'Static' : 'Statyczna'}</h4>${col(s.sast)}</div>
      <div class="deepdive-tool-col"><h4>DAST · ${getLang() === 'en' ? 'Dynamic' : 'Dynamiczna'}</h4>${col(s.dast)}</div>
    </div>${note}`);
  },

  compliance: (s) => secWrap('compliance', s, `<div class="deepdive-comp-grid">${s.items
    .map((c) => `<article class="deepdive-comp-card"><h4>${esc(c.std)}</h4><ul>${c.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul></article>`).join('')}</div>${inlineSourcesHtml(s.inlineSources)}`),

  ir: (s) => secWrap('ir', s, `<ol class="deepdive-ir">${s.steps
    .map((st, i) => `<li class="deepdive-ir-item"><span class="deepdive-ir-check">${i + 1}</span><span>${esc(tr(st))}</span></li>`).join('')}</ol>`),

  migration: (s) => secWrap('migration', s, `<div class="deepdive-mig">${s.steps
    .map((m) => `<div class="deepdive-mig-card"><h4>${esc(tr(m.title))}</h4><p>${esc(tr(m.description))}</p></div>`).join('')}</div>`),

  sources: (s) => `<section id="dd-sources" class="deepdive-section">
    <h2 class="deepdive-h2">${esc(tr(s.title))}</h2>
    <div class="deepdive-sources-list">${s.items
      .map((src) => `<a href="${esc(src.url)}" target="_blank" rel="noopener" class="deepdive-source-link">${esc(src.label)}</a>`).join('')}</div></section>`,
};

function ormRows(s) {
  return `<div class="deepdive-orm">${s.rows
    .map((o) => `<div class="deepdive-orm-row">
      <div class="deepdive-orm-fw">${esc(o.fw)}</div>
      <code class="deepdive-orm-api">${esc(o.api)}</code>
      <div class="deepdive-orm-note">${esc(tr(o.note))}</div></div>`).join('')}</div>`;
}

/* maps a nav section id -> the data.sections key that renders it */
const NAV_TO_SECTION = {
  types: 'attacks', cheatsheet: 'cheatsheet', code: 'code', orm: 'orm',
  langrisks: 'langRisks', method: 'method', defense: 'defenses',
  incidents: 'incidents', tools: 'tools', compliance: 'compliance',
  ir: 'ir', migration: 'migration', sources: 'sources',
};

/* ---------- top-level rendering ---------- */
function buildOverview(data) {
  const lang = getLang();
  const h = data.hero;
  const metrics = (h.metrics || [])
    .map((m, i) => `<div class="deepdive-metric${i < 2 ? ' crit' : ''}"><div class="deepdive-metric-k">${esc(m.k)}</div><div class="deepdive-metric-v">${esc(tr(m.v))}</div></div>`).join('');
  const sources = (h.sources || [])
    .map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener" class="deepdive-source-link">${esc(s.label)}</a>`).join('');
  const sourcesBlock = sources
    ? `<div class="deepdive-sources"><span class="deepdive-sources-label">${t('sources')}</span>${sources}</div>` : '';
  const sevBadge = SEV_LABEL[data.meta.severity]
    ? `<span class="deepdive-sev-badge">${esc(tr(SEV_LABEL[data.meta.severity]))}</span>` : '';
  return `<section id="dd-overview" class="deepdive-section">
    <div class="deepdive-hero">
      <span class="deepdive-eyebrow">${SVG.shield}<span>Code Guardian · Deep-dive</span></span>
      <h1>${esc(h.titleMain)}<span class="grad">${esc(h.titleGrad)}</span>${esc(h.titleTail || '')}</h1>
      ${sevBadge}
      <p class="deepdive-lead">${esc(tr(h.lead))}</p>
      <div class="deepdive-metrics">${metrics}</div>
      ${sourcesBlock}
    </div></section>`;
}

function buildNav(data) {
  const lang = getLang();
  return data.nav
    .map((n, i) => `<a class="deepdive-nav-link${i === 0 ? ' active' : ''}" href="#dd-${esc(n.id)}" data-target="dd-${esc(n.id)}">${esc(n[lang] ?? n.en)}</a>`).join('');
}

function buildContent(data) {
  const lang = getLang();
  const order = data.sectionOrder || data.nav.map((n) => n.id);
  const body = order.map((navId) => {
    if (navId === 'overview') return buildOverview(data);
    const key = NAV_TO_SECTION[navId];
    const sec = data.sections[key];
    const fn = SECTION_RENDERERS[key];
    return sec && fn ? fn(sec) : '';
  }).join('');
  const footer = `<footer class="deepdive-footer">Code Guardian — ${esc(data.hero.topbar)} · ${lang === 'en' ? 'All "VULNERABLE" examples are illustrative only — do not use in production.' : 'Wszystkie przykłady "PODATNY" są wyłącznie poglądowe — nie używaj na produkcji.'}</footer>`;
  return body + footer;
}

/* ---------- create one panel's inner HTML (string) ---------- */
export function createDeepDivePage(data) {
  const lang = getLang();
  return `
    <div class="deepdive-topbar">
      <span class="deepdive-brand">${SVG.shield}<span>Code <span class="grad">Guardian</span></span></span>
      <span class="deepdive-topbar-title">${esc(data.hero.topbar)}</span>
      <span style="flex:1"></span>
      <button class="deepdive-close" type="button" aria-label="${t('close')}">${SVG.close}<span>${t('close')}</span></button>
    </div>
    <div class="deepdive-shell">
      <nav class="deepdive-nav" aria-label="${t('sectionsLabel')}">${buildNav(data)}</nav>
      <div class="deepdive-body">${buildContent(data)}</div>
    </div>`;
}

/* ---------- wiring ---------- */
function wireCopy(panel) {
  $$('.deepdive-copy', panel).forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = $('code', btn.parentElement).textContent;
      const label = $('span', btn);
      const write = () => {
        const old = label.textContent;
        label.textContent = t('copied');
        btn.classList.add('copied');
        setTimeout(() => { label.textContent = old; btn.classList.remove('copied'); }, 1400);
      };
      if (navigator.clipboard?.writeText) navigator.clipboard.writeText(code).then(write, write);
      else write();
    });
  });
}

function wireLangTabs(panel) {
  $$('.deepdive-lang-tab', panel).forEach((tab) => {
    tab.addEventListener('click', () => {
      const l = tab.dataset.lang;
      $$('.deepdive-lang-tab', panel).forEach((x) => x.classList.toggle('active', x === tab));
      $$('.deepdive-lang-panel', panel).forEach((p) => p.classList.toggle('active', p.dataset.lang === l));
    });
  });
}

function wireScrollSpy(panel) {
  const body = $('.deepdive-body', panel);
  const links = $$('.deepdive-nav-link', panel);
  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = $('#' + link.dataset.target, panel);
      if (target) body.scrollTo({ top: target.offsetTop - 24, behavior: 'smooth' });
    });
  });
  const sections = $$('.deepdive-section', panel);
  body.addEventListener('scroll', () => {
    let current = sections[0]?.id;
    for (const s of sections) if (s.offsetTop - 80 <= body.scrollTop) current = s.id;
    links.forEach((l) => l.classList.toggle('active', l.dataset.target === current));
  }, { passive: true });
}

/* ---------- per-panel state registry ---------- */
const PANEL_ID = 'deepdive-page';
let _panel = null;
let _highlighted = false;
let _currentId = null;

function ensurePanel() {
  if (!_panel) _panel = $('#' + PANEL_ID);
  return _panel;
}

function applyAccent(panel, data) {
  panel.style.setProperty('--dd-accent', data.meta.color);
  panel.style.setProperty('--dd-accent-rgb', data.meta.colorRgb);
}

function highlightAll(panel) {
  if (_highlighted) return;
  $$('code[class*="language-"]', panel).forEach((c) => highlightElement(c));
  _highlighted = true;
}

function renderInto(panel, data) {
  applyAccent(panel, data);
  panel.innerHTML = createDeepDivePage(data);
  _highlighted = false;
  $('.deepdive-close', panel).addEventListener('click', closeDeepDivePage);
  wireCopy(panel);
  wireLangTabs(panel);
  wireScrollSpy(panel);
}

export function openDeepDivePage(data) {
  const panel = ensurePanel();
  if (!panel) return;
  // (Re)render whenever a different deep-dive is requested or language changed.
  if (_currentId !== data.meta.id || panel.dataset.lang !== getLang()) {
    renderInto(panel, data);
    _currentId = data.meta.id;
    panel.dataset.lang = getLang();
    panel._data = data;
  }
  panel.classList.add('open');
  document.body.classList.add('deepdive-lock');
  highlightAll(panel);
  const body = $('.deepdive-body', panel);
  if (body) body.scrollTop = 0;
}

export function closeDeepDivePage() {
  const panel = ensurePanel();
  if (!panel) return;
  panel.classList.remove('open');
  document.body.classList.remove('deepdive-lock');
}

/* Wire a button (selector) to open a given data set. */
export function initDeepDivePage(data, buttonSelector) {
  ensurePanel();
  const btn = buttonSelector ? $(buttonSelector) : null;
  if (btn) btn.addEventListener('click', () => openDeepDivePage(data));
}

/* Global wiring shared by all deep-dives: Esc to close + language refresh. */
let _globalWired = false;
export function initAllDeepDives() {
  ensurePanel();
  if (_globalWired) return;
  _globalWired = true;
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel && _panel.classList.contains('open')) closeDeepDivePage();
  });
  const langBtn = $('#lang-toggle');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      setTimeout(() => {
        if (_panel && _panel._data && _panel.classList.contains('open')) {
          renderInto(_panel, _panel._data);
          _panel.dataset.lang = getLang();
          _panel.classList.add('open');
          highlightAll(_panel);
        }
      }, 0);
    });
  }
}
