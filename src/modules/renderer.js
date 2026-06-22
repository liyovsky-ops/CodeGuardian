import DOMPurify from 'dompurify';
import { confidenceBadge, SEV, DIFF, PRISM_LANG } from './badges.js';
import { $, $$ } from './dom.js';
import { highlightElement } from './highlight.js';
import { getLang } from '../i18n/index.js';
import { UI } from '../i18n/ui.js';
import { openDeepDivePage } from './deepdive-renderer.js';
import sqliData from '../content/deepdives/sqli.yaml';
import nosqliData from '../content/deepdives/nosqli.yaml';
import cmdiData from '../content/deepdives/cmdi.yaml';
import ldapiData from '../content/deepdives/ldapi.yaml';
import xpathiData from '../content/deepdives/xpathi.yaml';
import sstiData from '../content/deepdives/ssti.yaml';
import logiData from '../content/deepdives/logi.yaml';

const DEEPDIVE_THREATS = {
  '1.1': () => openDeepDivePage(sqliData),
  '1.2': () => openDeepDivePage(nosqliData),
  '1.3': () => openDeepDivePage(cmdiData),
  '1.4': () => openDeepDivePage(ldapiData),
  '1.5': () => openDeepDivePage(xpathiData),
  '1.6': () => openDeepDivePage(sstiData),
  '1.7': () => openDeepDivePage(logiData),
};

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

function catName(cat) {
  const lang = getLang();
  return lang === 'en' ? (cat.name_en || cat.name) : cat.name;
}

function catDesc(cat) {
  const lang = getLang();
  return lang === 'en' ? (cat.desc_en || cat.desc) : cat.desc;
}

function catVerdict(cat) {
  const lang = getLang();
  return lang === 'en' ? (cat.verdict_en || cat.verdict) : cat.verdict;
}

function threatDesc(t) {
  const lang = getLang();
  return lang === 'en' ? (t.desc_en || t.desc) : t.desc;
}

function threatNote(t) {
  const lang = getLang();
  return lang === 'en' ? (t.note_en || t.note) : t.note;
}

function severityBreakdown(threats) {
  const c = threats.filter((t) => t.severity === 'Critical').length;
  const h = threats.filter((t) => t.severity === 'High').length;
  return `<span class="dot critical">${c}</span><span class="dot high">${h}</span>`;
}

function diffBreakdown(threats) {
  const order = ['Easy', 'Medium', 'Hard', 'Very Hard'];
  return order
    .map((d) => {
      const n = threats.filter((t) => t.difficulty === d).length;
      if (!n) return '';
      return `<span class="badge diff ${DIFF[d]} mini">${esc(d)}: ${n}</span>`;
    })
    .join('');
}

export function buildSidebar(CATEGORIES) {
  const lang = getLang();
  const nav = $('#sidebar-nav');
  nav.innerHTML = CATEGORIES.map((c) => {
    const counts = severityBreakdown(c.threats);
    const threatCountLabel = UI.threatCount[lang](c.threats.length);
    return `
      <a class="side-link" href="#cat-${c.id}" data-cat="${c.id}" style="--accent:${c.color}">
        <span class="side-icon">${c.icon}</span>
        <span class="side-text">
          <span class="side-name">${esc(catName(c))}</span>
          <span class="side-meta">${esc(threatCountLabel)}</span>
        </span>
        <span class="side-count" title="Critical/High/Medium">${counts}</span>
      </a>`;
  }).join('');
}

export function buildHeroCards(CATEGORIES) {
  const lang = getLang();
  const wrap = $('#hero-cards');
  wrap.innerHTML = CATEGORIES.map(
    (c) => {
      const catNumLabel = UI.catNum[lang](c.num);
      const threatCountLabel = UI.threatCount[lang](c.threats.length);
      return `
    <a class="cat-card" href="#cat-${c.id}" style="--accent:${c.color}">
      <span class="cat-card-icon">${c.icon}</span>
      <span class="cat-card-num">${esc(catNumLabel)}</span>
      <span class="cat-card-name">${esc(catName(c))}</span>
      <span class="cat-card-count">${esc(threatCountLabel)} · ${esc(c.difficulty)}</span>
    </a>`;
    }
  ).join('');
}

export function threatCard(t, cat) {
  const lang = getLang();
  const sev = SEV[t.severity] || SEV.Medium;
  const diffCls = DIFF[t.difficulty] || 'medium';
  const cweBadges = (t.cwe || [])
    .map(
      (w) =>
        `<a class="badge cwe" target="_blank" rel="noopener"
            href="https://cwe.mitre.org/data/definitions/${w.replace('CWE-', '')}.html">${esc(w)}</a>`
    )
    .join('');

  const hasCode = t.vuln || t.safe;
  const refNote = t.ref
    ? `<div class="ref-note">${lang === 'en' ? 'Details in section' : 'Szczegóły w sekcji'} <a href="#threat-${t.ref}" class="ref-link">${esc(t.ref)}</a></div>`
    : '';
  const desc = threatDesc(t);
  const note = threatNote(t);
  const extraNote = note ? `<div class="threat-note">${esc(note)}</div>` : '';

  let codeBlock = '';
  if (hasCode) {
    const vlang = PRISM_LANG[t.lang] || 'none';
    const vulnLabel = lang === 'en' ? 'Vulnerable code' : 'Podatny kod';
    const safeLabel = lang === 'en' ? 'Secure code' : 'Bezpieczny kod';
    const copyLabel = UI.copyBtn[lang];
    codeBlock = `
      <div class="code-area">
        <div class="tabs" role="tablist">
          <button class="tab active" data-tab="vuln" role="tab">${vulnLabel}</button>
          ${t.safe ? `<button class="tab" data-tab="safe" role="tab">${safeLabel}</button>` : ''}
        </div>
        <div class="tab-panel active" data-panel="vuln">
          <button class="copy-btn" title="${lang === 'en' ? 'Copy vulnerable code example' : 'Skopiuj przykład podatnego kodu'}">${copyLabel}</button>
          <pre class="line-numbers"><code class="language-${vlang}">${esc(t.vuln)}</code></pre>
        </div>
        ${
          t.safe
            ? `<div class="tab-panel" data-panel="safe">
                 <button class="copy-btn" title="${lang === 'en' ? 'Copy secure code example' : 'Skopiuj bezpieczny kod'}">${copyLabel}</button>
                 <pre class="line-numbers"><code class="language-${vlang}">${esc(t.safe)}</code></pre>
               </div>`
            : ''
        }
      </div>`;
  }

  const confCls = t.confidence === 'RESEARCH' ? ' conf-research' : '';
  const deepDiveBtn = DEEPDIVE_THREATS[t.id]
    ? `<button class="deepdive-btn" data-threat-id="${esc(t.id)}" title="${lang === 'en' ? 'Open deep-dive' : 'Otwórz szczegóły'}" aria-label="${lang === 'en' ? 'Open SQL Injection deep-dive' : 'Otwórz szczegóły SQL Injection'}">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        <span>${lang === 'en' ? 'Deep-dive' : 'Szczegóły'}</span>
      </button>`
    : '';
  return `
    <article class="threat${confCls}" id="threat-${t.id}"
             data-sev="${t.severity}" data-diff="${t.difficulty}"
             data-name="${esc(t.name.toLowerCase())}" data-cat="${cat.id}">
      <header class="threat-head" tabindex="0" role="button" aria-expanded="false">
        <span class="threat-id">${esc(t.id)}</span>
        <span class="threat-title">${esc(t.name)}${confidenceBadge(t.confidence)}</span>
        <span class="badges">
          <span class="badge badge-${sev.cls}">${esc(t.severity)}</span>
          <span class="badge diff ${diffCls}">${esc(t.difficulty)}</span>
          ${deepDiveBtn}
        </span>
        <span class="chevron" aria-hidden="true">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </header>
      <div class="threat-body">
        <p class="threat-desc">${esc(desc)}</p>
        ${extraNote}
        <div class="cwe-row">${cweBadges}</div>
        ${codeBlock}
        ${refNote}
      </div>
    </article>`;
}

export function buildCategories(CATEGORIES) {
  const lang = getLang();
  const main = $('#categories');
  main.innerHTML = CATEGORIES.map((cat) => {
    const diffSummary = diffBreakdown(cat.threats);
    const threatCountLabel = UI.threatCount[lang](cat.threats.length);
    const detectionLabel = UI.detectionDiff[lang];
    const verdictLabel = UI.staticRuntime[lang];
    return `
    <section class="category" id="cat-${cat.id}" style="--accent:${cat.color}">
      <div class="cat-header">
        <div class="cat-title-row">
          <span class="cat-icon">${cat.icon}</span>
          <h2>${cat.num}. ${esc(catName(cat))}</h2>
          <span class="cat-pill">${esc(threatCountLabel)}</span>
        </div>
        <p class="cat-desc">${esc(catDesc(cat))}</p>
        <div class="cat-meta">
          <span class="cat-difficulty">${esc(detectionLabel)}: <strong>${esc(cat.difficulty)}</strong></span>
          <span class="cat-diffsummary">${diffSummary}</span>
        </div>
      </div>
      <div class="threats">
        ${cat.threats.map((t) => threatCard(t, cat)).join('')}
      </div>
      <div class="cat-verdict">
        <span class="verdict-label">${esc(verdictLabel)}</span>
        <p>${esc(catVerdict(cat))}</p>
      </div>
    </section>`;
  }).join('');
}

export function buildMatrix(MATRIX) {
  const tbody = $('#matrix-body');
  tbody.innerHTML = MATRIX.map(
    (row) => `<tr>${row.map((cell, i) =>
      i === 0 ? `<th scope="row">${esc(cell)}</th>` : `<td>${esc(cell)}</td>`
    ).join('')}</tr>`
  ).join('');
}

export function buildConclusions(CONCLUSIONS) {
  const wrap = $('#conclusions-list');
  wrap.innerHTML = CONCLUSIONS.map(
    (c, i) => `
    <div class="conclusion">
      <span class="conclusion-num">${i + 1}</span>
      <div>
        <h3>${esc(c.title)}</h3>
        <p>${DOMPurify.sanitize(c.body, { ALLOWED_TAGS: ['strong', 'em', 'code'] })}</p>
      </div>
    </div>`
  ).join('');
}

export function buildStats(CATEGORIES) {
  const cats = CATEGORIES.length;
  const total = CATEGORIES.reduce((n, c) => n + c.threats.length, 0);
  const crit = CATEGORIES.reduce(
    (n, c) => n + c.threats.filter((t) => t.severity === 'Critical').length,
    0
  );
  $('#stat-cats').textContent = cats;
  $('#stat-threats').textContent = total + '+';
  $('#stat-crit').textContent = crit;
}

export function highlightCard(card) {
  $$('code', card).forEach((c) => {
    if (!c.dataset.highlighted) {
      highlightElement(c);
      c.dataset.highlighted = '1';
    }
  });
}
