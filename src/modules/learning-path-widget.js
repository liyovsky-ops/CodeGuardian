import { $ } from './dom.js';
import { getPathOverview } from './learning-path.js';
import { openQuizPage } from './quiz-renderer.js';
import { QUIZZES } from '../data/threat-features.js';
import { getLang } from '../i18n/index.js';

const STATUS_ICON = {
  completed: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
  unlocked: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
  locked: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
};

const STATUS_LABEL = {
  completed: { en: 'Completed', pl: 'Ukończone' },
  unlocked: { en: 'Ready to practice', pl: 'Gotowe do ćwiczenia' },
  locked: { en: 'Locked', pl: 'Zablokowane' },
};

function renderPath() {
  const lang = getLang();
  const el = $('#learning-path-list');
  if (!el) return;
  const overview = getPathOverview();
  el.innerHTML = overview
    .map((stage) => {
      const title = stage.quizTitle ? (stage.quizTitle[lang] ?? stage.quizTitle.en) : stage.threatId;
      return `
        <div class="lp-stage lp-${stage.status}">
          <span class="lp-stage-num">${stage.index + 1}</span>
          <span class="lp-stage-icon">${STATUS_ICON[stage.status]}</span>
          <div class="lp-stage-body">
            <div class="lp-stage-title">${title}</div>
            <div class="lp-stage-status">${STATUS_LABEL[stage.status][lang]}</div>
          </div>
          ${stage.status !== 'locked' ? `<button type="button" class="lp-stage-btn" data-threat-id="${stage.threatId}">${lang === 'en' ? 'Open' : 'Otwórz'}</button>` : ''}
        </div>`;
    })
    .join('');

  el.querySelectorAll('.lp-stage-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const data = QUIZZES[btn.dataset.threatId];
      if (data) openQuizPage(data);
    });
  });
}

export function initLearningPathWidget() {
  const btn = $('#learning-path-btn');
  const panel = $('#learning-path-panel');
  const closeBtn = $('#learning-path-panel-close');
  if (!btn || !panel) return;

  const open = () => {
    renderPath();
    panel.classList.remove('hidden');
  };
  const close = () => panel.classList.add('hidden');

  btn.addEventListener('click', open);
  closeBtn?.addEventListener('click', close);
  panel.addEventListener('click', (e) => {
    if (e.target === panel) close();
  });

  // Keep the panel's stage list fresh if a quiz is passed while it's open.
  document.addEventListener('cg:quiz-graded', () => {
    if (!panel.classList.contains('hidden')) renderPath();
  });
}
