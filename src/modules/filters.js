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
  const heroSearch = $('#hero-search');
  const noResults = $('#no-results');

  function apply() {
    const q = input.value.trim().toLowerCase();
    const sv = sevSel.value;
    const df = diffSel.value;
    let visibleTotal = 0;

    CATEGORIES.forEach((cat) => {
      const section = $('#cat-' + cat.id);
      let shown = 0;
      $$('.threat', section).forEach((card) => {
        const name = card.dataset.name;
        const matchQ =
          !q ||
          name.includes(q) ||
          card.dataset.cat.includes(q) ||
          cat.name.toLowerCase().includes(q);
        const matchS = !sv || card.dataset.sev === sv;
        const matchD = !df || card.dataset.diff === df;
        const ok = matchQ && matchS && matchD;
        card.classList.toggle('hidden', !ok);
        if (ok) { shown++; visibleTotal++; }
      });
      section.classList.toggle('hidden', shown === 0);
    });
    noResults.classList.toggle('hidden', visibleTotal > 0);
  }

  input.addEventListener('input', debounce(apply, SEARCH_DEBOUNCE_MS));
  sevSel.addEventListener('change', apply);
  diffSel.addEventListener('change', apply);

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
    if (heroSearch) heroSearch.value = '';
    apply();
  });
}
