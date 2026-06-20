import DOMPurify from 'dompurify';
import { confidenceBadge, SEV, DIFF, PRISM_LANG } from './badges.js';
import { $, $$ } from './dom.js';
import { highlightElement } from './highlight.js';

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

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
  const nav = $('#sidebar-nav');
  nav.innerHTML = CATEGORIES.map((c) => {
    const counts = severityBreakdown(c.threats);
    return `
      <a class="side-link" href="#cat-${c.id}" data-cat="${c.id}" style="--accent:${c.color}">
        <span class="side-icon">${c.icon}</span>
        <span class="side-text">
          <span class="side-name">${esc(c.name)}</span>
          <span class="side-meta">${c.threats.length} zagrożeń</span>
        </span>
        <span class="side-count" title="Critical/High/Medium">${counts}</span>
      </a>`;
  }).join('');
}

export function buildHeroCards(CATEGORIES) {
  const wrap = $('#hero-cards');
  wrap.innerHTML = CATEGORIES.map(
    (c) => `
    <a class="cat-card" href="#cat-${c.id}" style="--accent:${c.color}">
      <span class="cat-card-icon">${c.icon}</span>
      <span class="cat-card-num">Kategoria ${c.num}</span>
      <span class="cat-card-name">${esc(c.name)}</span>
      <span class="cat-card-count">${c.threats.length} zagrożeń · ${esc(c.difficulty)}</span>
    </a>`
  ).join('');
}

export function threatCard(t, cat) {
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
    ? `<div class="ref-note">Szczegóły w sekcji <a href="#threat-${t.ref}" class="ref-link">${esc(t.ref)}</a></div>`
    : '';
  const extraNote = t.note ? `<div class="threat-note">${esc(t.note)}</div>` : '';

  let codeBlock = '';
  if (hasCode) {
    const vlang = PRISM_LANG[t.lang] || 'none';
    codeBlock = `
      <div class="code-area">
        <div class="tabs" role="tablist">
          <button class="tab active" data-tab="vuln" role="tab">Podatny kod</button>
          ${t.safe ? `<button class="tab" data-tab="safe" role="tab">Bezpieczny kod</button>` : ''}
        </div>
        <div class="tab-panel active" data-panel="vuln">
          <button class="copy-btn" title="Skopiuj przykład podatnego kodu">Kopiuj</button>
          <pre class="line-numbers"><code class="language-${vlang}">${esc(t.vuln)}</code></pre>
        </div>
        ${
          t.safe
            ? `<div class="tab-panel" data-panel="safe">
                 <button class="copy-btn" title="Skopiuj bezpieczny kod">Kopiuj</button>
                 <pre class="line-numbers"><code class="language-${vlang}">${esc(t.safe)}</code></pre>
               </div>`
            : ''
        }
      </div>`;
  }

  return `
    <article class="threat" id="threat-${t.id}"
             data-sev="${t.severity}" data-diff="${t.difficulty}"
             data-name="${esc(t.name.toLowerCase())}" data-cat="${cat.id}">
      <header class="threat-head" tabindex="0" role="button" aria-expanded="false">
        <span class="threat-id">${esc(t.id)}</span>
        <span class="threat-title">${esc(t.name)}${confidenceBadge(t.confidence)}</span>
        <span class="badges">
          <span class="badge badge-${sev.cls}">${esc(t.severity)}</span>
          <span class="badge diff ${diffCls}">${esc(t.difficulty)}</span>
        </span>
        <span class="chevron" aria-hidden="true">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </header>
      <div class="threat-body">
        <p class="threat-desc">${esc(t.desc)}</p>
        ${extraNote}
        <div class="cwe-row">${cweBadges}</div>
        ${codeBlock}
        ${refNote}
      </div>
    </article>`;
}

export function buildCategories(CATEGORIES) {
  const main = $('#categories');
  main.innerHTML = CATEGORIES.map((cat) => {
    const diffSummary = diffBreakdown(cat.threats);
    return `
    <section class="category" id="cat-${cat.id}" style="--accent:${cat.color}">
      <div class="cat-header">
        <div class="cat-title-row">
          <span class="cat-icon">${cat.icon}</span>
          <h2>${cat.num}. ${esc(cat.name)}</h2>
          <span class="cat-pill">${cat.threats.length} zagrożeń</span>
        </div>
        <p class="cat-desc">${esc(cat.desc)}</p>
        <div class="cat-meta">
          <span class="cat-difficulty">Trudność wykrycia: <strong>${esc(cat.difficulty)}</strong></span>
          <span class="cat-diffsummary">${diffSummary}</span>
        </div>
      </div>
      <div class="threats">
        ${cat.threats.map((t) => threatCard(t, cat)).join('')}
      </div>
      <div class="cat-verdict">
        <span class="verdict-label">Static vs runtime</span>
        <p>${esc(cat.verdict)}</p>
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
