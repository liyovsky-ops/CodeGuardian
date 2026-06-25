import { $, $$ } from './dom.js';
import { SEARCH_DEBOUNCE_MS } from '../config.js';

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

export function initFilters(CATEGORIES) {
  const input = $('#search');
  const sevSel = $('#filter-sev');
  const diffSel = $('#filter-diff');
  const langSel = $('#filter-lang');
  const heroSearch = $('#hero-search');
  const noResults = $('#no-results');
  const filterCount = $('#filter-count');
  const toggleResearchBtn = $('#toggle-research');
  const researchCount = $('#research-count');

  let showResearch = false;

  const researchCards = $$('.threat.conf-research');
  if (researchCount && researchCards.length > 0) {
    researchCount.textContent = `(${researchCards.length})`;
  }

  const totalThreats = CATEGORIES.reduce((n, c) => n + c.threats.length, 0);

  function apply() {
    const q = input.value.trim().toLowerCase();
    const sv = sevSel.value;
    const df = diffSel.value;
    const ln = langSel ? langSel.value : '';
    let visibleTotal = 0;

    CATEGORIES.forEach((cat) => {
      const section = $('#cat-' + cat.id);
      let shown = 0;
      $$('.threat', section).forEach((card) => {
        const isResearch = card.classList.contains('conf-research');
        if (isResearch && !showResearch) {
          card.classList.add('hidden');
          return;
        }
        const name = card.dataset.name;
        const cardLang = card.dataset.lang || '';
        const matchQ =
          !q ||
          name.includes(q) ||
          card.dataset.cat.includes(q) ||
          cat.name.toLowerCase().includes(q);
        const matchS = !sv || card.dataset.sev === sv;
        const matchD = !df || card.dataset.diff === df;
        const matchL = !ln || cardLang === ln;
        const ok = matchQ && matchS && matchD && matchL;
        card.classList.toggle('hidden', !ok);
        if (ok) { shown++; visibleTotal++; }
      });
      section.classList.toggle('hidden', shown === 0);
    });
    noResults.classList.toggle('hidden', visibleTotal > 0);

    if (filterCount) {
      const hasFilter = q || sv || df || ln;
      if (hasFilter) {
        filterCount.textContent = `Showing ${visibleTotal} of ${totalThreats}`;
        filterCount.classList.remove('hidden');
      } else {
        filterCount.classList.add('hidden');
      }
    }
  }

  if (toggleResearchBtn) {
    toggleResearchBtn.addEventListener('click', () => {
      showResearch = !showResearch;
      toggleResearchBtn.classList.toggle('active', !showResearch);
      apply();
    });
  }

  input.addEventListener('input', debounce(apply, SEARCH_DEBOUNCE_MS));
  sevSel.addEventListener('change', apply);
  diffSel.addEventListener('change', apply);
  if (langSel) langSel.addEventListener('change', apply);

  // Language badge clicks on threat cards → set language filter
  document.addEventListener('click', (e) => {
    const badge = e.target.closest('.lang-badge[data-filter-lang]');
    if (badge && langSel) {
      e.stopPropagation();
      langSel.value = badge.dataset.filterLang;
      apply();
      const filterBar = $('#filter-bar');
      if (filterBar) filterBar.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  if (heroSearch) {
    heroSearch.addEventListener('input', () => {
      input.value = heroSearch.value;
      apply();
      $('#filter-bar').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  $('#clear-filters').addEventListener('click', () => {
    input.value = '';
    sevSel.value = '';
    diffSel.value = '';
    if (langSel) langSel.value = '';
    if (heroSearch) heroSearch.value = '';
    apply();
  });

  apply();

  return apply;
}
