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
import { initInteractions } from './modules/interactions.js';

import { CATEGORIES } from './data/index.js';
import { MATRIX } from './data/matrix.js';
import { CONCLUSIONS } from './data/conclusions.js';

export { CATEGORIES };

function render() {
  buildSidebar(CATEGORIES);
  buildHeroCards(CATEGORIES);
  buildCategories(CATEGORIES);
  buildMatrix(MATRIX);
  buildConclusions(CONCLUSIONS);
  buildStats(CATEGORIES);
}

// Module scripts are always deferred — DOM is ready when this runs
try {
  render();
  initClipboard();
  initFilters(CATEGORIES);
  initTheme();
  initInteractions(CATEGORIES);
} catch (err) {
  console.error('[CodeGuardian] Bootstrap failed:', err);
  const main = document.querySelector('main') || document.body;
  main.innerHTML = `
    <div class="error-state" role="alert">
      <h2>⚠️ Nie udało się wczytać atlasu zagrożeń</h2>
      <p>Odśwież stronę. Jeśli problem się powtarza, otwórz konsolę przeglądarki.</p>
    </div>`;
}
