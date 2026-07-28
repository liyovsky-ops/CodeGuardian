import { $ } from './dom.js';
import { getStats, exportProgress, importProgress } from './progress.js';

function allThreatIds(CATEGORIES) {
  return CATEGORIES.flatMap((c) => c.threats.map((t) => t.id));
}

function renderStats(CATEGORIES) {
  const stats = getStats(allThreatIds(CATEGORIES));
  const el = $('#progress-stats');
  if (!el) return;
  const rows = [
    ['Read', stats.read],
    ['Quizzed', stats.quizzed],
    ['Labs completed', stats.labCompleted],
    ['Applied to real code', stats.applied],
  ];
  el.innerHTML = rows
    .map(
      ([label, count]) => `
        <div class="progress-stat-row">
          <span class="progress-stat-label">${label}</span>
          <span class="progress-stat-value">${count} / ${stats.total}</span>
        </div>`
    )
    .join('');
}

export function initProgressWidget(CATEGORIES) {
  const btn = $('#progress-btn');
  const panel = $('#progress-panel');
  const closeBtn = $('#progress-panel-close');
  const exportBtn = $('#progress-export');
  const importBtn = $('#progress-import');
  const importInput = $('#progress-import-input');
  if (!btn || !panel) return;

  const open = () => {
    renderStats(CATEGORIES);
    panel.classList.remove('hidden');
  };
  const close = () => panel.classList.add('hidden');

  btn.addEventListener('click', open);
  closeBtn?.addEventListener('click', close);
  panel.addEventListener('click', (e) => {
    if (e.target === panel) close();
  });

  exportBtn?.addEventListener('click', () => exportProgress());

  importBtn?.addEventListener('click', () => importInput?.click());
  importInput?.addEventListener('change', async () => {
    const file = importInput.files?.[0];
    if (!file) return;
    try {
      await importProgress(file);
      renderStats(CATEGORIES);
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert(`Could not import progress file: ${err.message}`);
    } finally {
      importInput.value = '';
    }
  });
}
