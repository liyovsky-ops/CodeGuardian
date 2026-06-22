import {
  buildSidebar,
  buildHeroCards,
  buildCategories,
  buildMatrix,
  buildConclusions,
  buildStats,
} from './modules/renderer.js';
import { initFilters } from './modules/filters.js';
import { initTheme } from './modules/theme.js';
import { initClipboard } from './modules/clipboard.js';
import { initInteractions, wireDynamicInteractions } from './modules/interactions.js';
import { initLang } from './modules/lang.js';
import { initSqliPage } from './modules/sqli-page.js';
import './sqli-page.css';
import { initNosqliPage } from './modules/nosqli-page.js';
import './nosqli-page.css';
import { initCmdiPage } from './modules/cmdi-page.js';
import './cmdi-page.css';
import { initLdapiPage } from './modules/ldapi-page.js';
import './ldapi-page.css';
import { initXpathiPage } from './modules/xpathi-page.js';
import './xpathi-page.css';
import { initSstiPage } from './modules/ssti-page.js';
import './ssti-page.css';
import { initLogiPage } from './modules/logi-page.js';
import './logi-page.css';
import { initGuidePage } from './modules/guide-page.js';
import './guide-page.css';

import { CATEGORIES } from './data/index.js';
import { getMatrix } from './data/matrix.js';
import { getConclusions } from './data/conclusions.js';
import { getLang } from './i18n/index.js';
import { UI } from './i18n/ui.js';

export { CATEGORIES };

function updateUI() {
  const lang = getLang();

  // hero
  const eyebrow = document.getElementById('hero-eyebrow');
  if (eyebrow) eyebrow.textContent = UI.heroEyebrow[lang];

  const h1 = document.getElementById('hero-h1');
  if (h1) h1.innerHTML = UI.heroH1[lang];

  const heroSub = document.getElementById('hero-sub');
  if (heroSub) heroSub.textContent = UI.heroSub[lang];

  const heroHint = document.getElementById('hero-hint');
  if (heroHint) heroHint.textContent = UI.heroHint[lang];

  const heroSearch = document.getElementById('hero-search');
  if (heroSearch) heroSearch.placeholder = UI.searchPlaceholder[lang];

  // stat labels
  const statLabelCats = document.getElementById('stat-label-cats');
  if (statLabelCats) statLabelCats.textContent = UI.statCats[lang];

  const statLabelThreats = document.getElementById('stat-label-threats');
  if (statLabelThreats) statLabelThreats.textContent = UI.statThreats[lang];

  const statLabelCrit = document.getElementById('stat-label-crit');
  if (statLabelCrit) statLabelCrit.textContent = UI.statCrit[lang];

  // section browse
  const browseTitle = document.getElementById('section-browse-title');
  if (browseTitle) browseTitle.textContent = UI.sectionBrowse[lang];

  const browseLead = document.getElementById('section-browse-lead');
  if (browseLead) browseLead.textContent = UI.sectionBrowseLead[lang];

  // filter bar
  const searchInput = document.getElementById('search');
  if (searchInput) searchInput.placeholder = UI.filterPlaceholder[lang];

  const filterSevAll = document.getElementById('filter-sev-all');
  if (filterSevAll) filterSevAll.textContent = UI.filterAllSev[lang];

  const filterDiffAll = document.getElementById('filter-diff-all');
  if (filterDiffAll) filterDiffAll.textContent = UI.filterAllDiff[lang];

  const clearBtn = document.getElementById('clear-filters');
  if (clearBtn) clearBtn.textContent = UI.clearFilters[lang];

  const researchLabel = document.getElementById('research-btn-label');
  if (researchLabel) researchLabel.textContent = UI.researchBtn[lang];

  const noResults = document.getElementById('no-results');
  if (noResults) noResults.textContent = UI.noResults[lang];

  // matrix section
  const matrixTitle = document.getElementById('matrix-title');
  if (matrixTitle) matrixTitle.textContent = UI.matrixTitle[lang];

  const matrixLead = document.getElementById('matrix-lead');
  if (matrixLead) matrixLead.textContent = UI.matrixLead[lang];

  const mh1 = document.getElementById('matrix-h1');
  if (mh1) mh1.textContent = UI.matrixH1[lang];

  const mh2 = document.getElementById('matrix-h2');
  if (mh2) mh2.textContent = UI.matrixH2[lang];

  const mh3 = document.getElementById('matrix-h3');
  if (mh3) mh3.textContent = UI.matrixH3[lang];

  const mh4 = document.getElementById('matrix-h4');
  if (mh4) mh4.textContent = UI.matrixH4[lang];

  // conclusions section
  const conclusionsTitle = document.getElementById('conclusions-title');
  if (conclusionsTitle) conclusionsTitle.textContent = UI.conclusionsTitle[lang];

  const conclusionsLead = document.getElementById('conclusions-lead');
  if (conclusionsLead) conclusionsLead.textContent = UI.conclusionsLead[lang];

  // sidebar
  const sidebarTitle = document.getElementById('sidebar-title');
  if (sidebarTitle) sidebarTitle.textContent = UI.sidebarTitle[lang];

  // footer
  const footerText = document.getElementById('footer-text');
  if (footerText) footerText.textContent = UI.footerText[lang];

  const disclaimer = document.getElementById('disclaimer');
  if (disclaimer) disclaimer.textContent = UI.disclaimer[lang];

  // html lang attribute
  document.documentElement.lang = lang;
}

let _filtersApplyFn = null;

function render() {
  buildSidebar(CATEGORIES);
  buildHeroCards(CATEGORIES);
  buildCategories(CATEGORIES);
  buildMatrix(getMatrix());
  buildConclusions(getConclusions());
  buildStats(CATEGORIES);
  updateUI();
  // Re-attach clipboard listeners (copy-btn elements are regenerated by render)
  initClipboard();
  // Re-wire collapsible threat cards and tabs (DOM is rebuilt)
  wireDynamicInteractions();
  // Re-apply current filter state so cards aren't all shown after rerender
  if (_filtersApplyFn) _filtersApplyFn();
}

// Module scripts are always deferred — DOM is ready when this runs
try {
  render();
  _filtersApplyFn = initFilters(CATEGORIES);
  initTheme();
  initInteractions(CATEGORIES);
  initLang(render);
  initSqliPage();
  initNosqliPage();
  initCmdiPage();
  initLdapiPage();
  initXpathiPage();
  initSstiPage();
  initLogiPage();
  initGuidePage();
} catch (err) {
  console.error('[CodeGuardian] Bootstrap failed:', err);
  const main = document.querySelector('main') || document.body;
  main.innerHTML = `
    <div class="error-state" role="alert">
      <h2>⚠️ Failed to load the threat atlas</h2>
      <p>Refresh the page. If the problem persists, open the browser console.</p>
    </div>`;
}
