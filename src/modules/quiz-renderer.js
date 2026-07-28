/* =========================================================================
   CodeGuardian — generic quiz renderer
   Data-driven, structurally mirrors deepdive-renderer.js: one reusable panel,
   content from src/content/quizzes/*.yaml (validated by quiz.schema.js).
   Tests APPLICATION of knowledge (is this vulnerable / pick the real fix),
   not recall — grading is exact-match on structured answers, not free-text.
   ========================================================================= */
import { $, $$ } from './dom.js';
import { highlightElement } from './highlight.js';
import { getLang } from '../i18n/index.js';
import { recordQuizAttempt } from './progress.js';

const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const tr = (o) => (o && typeof o === 'object' ? (o[getLang()] ?? o.en) : o);

const SVG = {
  close: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  target: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
};

const TXT = {
  close: { en: 'Close', pl: 'Zamknij' },
  submit: { en: 'Check my answers', pl: 'Sprawdź odpowiedzi' },
  retry: { en: 'Try again', pl: 'Spróbuj ponownie' },
  vulnerable: { en: 'Vulnerable', pl: 'Podatny' },
  notVulnerable: { en: 'Not vulnerable', pl: 'Niepodatny' },
  correct: { en: 'Correct', pl: 'Poprawnie' },
  incorrect: { en: 'Incorrect', pl: 'Niepoprawnie' },
  yourScore: { en: 'Your score', pl: 'Twój wynik' },
  passed: { en: 'Passed — nice work.', pl: 'Zaliczone — dobra robota.' },
  notPassed: { en: 'Not quite — review the explanations below and try again.', pl: 'Jeszcze nie — przejrzyj wyjaśnienia poniżej i spróbuj ponownie.' },
};
const t = (k) => tr(TXT[k]);

/* ---------- question renderers ---------- */

function renderSnippet(snippet) {
  if (!snippet) return '';
  return `<pre class="quiz-snippet"><code class="language-${esc(snippet.lang)}">${esc(snippet.code)}</code></pre>`;
}

function renderMultipleChoice(q, i) {
  const multi = q.correctChoiceIds.length > 1;
  const inputType = multi ? 'checkbox' : 'radio';
  const choices = q.choices
    .map(
      (c) => `
      <label class="quiz-choice">
        <input type="${inputType}" name="q${i}" value="${esc(c.id)}" />
        <span>${esc(tr(c.label))}</span>
      </label>`
    )
    .join('');
  return `<div class="quiz-choices">${choices}</div>`;
}

function renderPickTheFix(q, i) {
  const variants = q.variants
    .map(
      (v) => `
      <label class="quiz-variant">
        <input type="radio" name="q${i}" value="${esc(v.id)}" />
        <pre><code class="language-${esc(v.lang)}">${esc(v.code)}</code></pre>
      </label>`
    )
    .join('');
  return `<div class="quiz-variants">${variants}</div>`;
}

function renderVulnOrNot(i) {
  return `<div class="quiz-choices quiz-choices-inline">
    <label class="quiz-choice"><input type="radio" name="q${i}" value="yes" /><span>${t('vulnerable')}</span></label>
    <label class="quiz-choice"><input type="radio" name="q${i}" value="no" /><span>${t('notVulnerable')}</span></label>
  </div>`;
}

function renderQuestion(q, i) {
  let body;
  if (q.type === 'multiple-choice') body = renderMultipleChoice(q, i);
  else if (q.type === 'pick-the-fix') body = renderPickTheFix(q, i);
  else body = renderVulnOrNot(i);

  return `<div class="quiz-question" data-index="${i}" data-type="${q.type}">
    <div class="quiz-question-prompt"><span class="quiz-question-num">${i + 1}.</span> ${esc(tr(q.prompt))}</div>
    ${renderSnippet(q.snippet)}
    ${body}
    <div class="quiz-feedback hidden"></div>
  </div>`;
}

/* ---------- grading ---------- */

function gradeQuestion(q, panel, i) {
  const container = $(`.quiz-question[data-index="${i}"]`, panel);
  const inputs = $$(`input[name="q${i}"]`, container);
  const selected = inputs.filter((el) => el.checked).map((el) => el.value);

  let correct;
  if (q.type === 'multiple-choice') {
    const expected = new Set(q.correctChoiceIds);
    correct = selected.length === expected.size && selected.every((v) => expected.has(v));
  } else if (q.type === 'pick-the-fix') {
    correct = selected[0] === q.correctVariantId;
  } else {
    correct = selected[0] === (q.isVulnerable ? 'yes' : 'no');
  }

  container.classList.toggle('quiz-question-correct', correct);
  container.classList.toggle('quiz-question-incorrect', !correct);
  const feedback = $('.quiz-feedback', container);
  feedback.classList.remove('hidden');
  feedback.innerHTML = `<strong>${correct ? t('correct') : t('incorrect')}.</strong> ${esc(tr(q.explanation))}`;

  return correct;
}

/* ---------- panel creation ---------- */

function createQuizPage(data) {
  const questions = data.questions.map((q, i) => renderQuestion(q, i)).join('');
  return `
    <div class="quiz-topbar">
      <span class="quiz-brand">${SVG.target}<span>${esc(tr(data.title))}</span></span>
      <span style="flex:1"></span>
      <button class="quiz-close" type="button" aria-label="${t('close')}">${SVG.close}<span>${t('close')}</span></button>
    </div>
    <div class="quiz-body">
      <form class="quiz-form">${questions}</form>
      <div class="quiz-result hidden"></div>
      <div class="quiz-actions">
        <button type="button" class="quiz-submit-btn">${t('submit')}</button>
      </div>
    </div>`;
}

/* ---------- wiring ---------- */

function wireSubmit(panel, data) {
  const submitBtn = $('.quiz-submit-btn', panel);
  submitBtn.addEventListener('click', () => {
    let correctCount = 0;
    data.questions.forEach((q, i) => {
      if (gradeQuestion(q, panel, i)) correctCount++;
    });
    const score = Math.round((correctCount / data.questions.length) * 100);
    const passed = score >= (data.passScore ?? 80);

    const resultEl = $('.quiz-result', panel);
    resultEl.classList.remove('hidden');
    resultEl.classList.toggle('quiz-result-pass', passed);
    resultEl.classList.toggle('quiz-result-fail', !passed);
    resultEl.innerHTML = `
      <div class="quiz-score">${t('yourScore')}: <strong>${score}%</strong> (${correctCount}/${data.questions.length})</div>
      <div class="quiz-verdict">${passed ? t('passed') : t('notPassed')}</div>`;

    recordQuizAttempt(data.threatId, score);
    submitBtn.textContent = t('retry');
    resultEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
}

/* ---------- per-panel state ---------- */
const PANEL_ID = 'quiz-page';
let _panel = null;

function ensurePanel() {
  if (!_panel) _panel = $('#' + PANEL_ID);
  return _panel;
}

export function openQuizPage(data) {
  const panel = ensurePanel();
  if (!panel) return;
  panel.innerHTML = createQuizPage(data);
  $('.quiz-close', panel).addEventListener('click', closeQuizPage);
  wireSubmit(panel, data);
  $$('code[class*="language-"]', panel).forEach((c) => highlightElement(c));
  panel.classList.add('open');
  document.body.classList.add('deepdive-lock');
}

export function closeQuizPage() {
  const panel = ensurePanel();
  if (!panel) return;
  panel.classList.remove('open');
  document.body.classList.remove('deepdive-lock');
}

let _globalWired = false;
export function initAllQuizzes() {
  ensurePanel();
  if (_globalWired) return;
  _globalWired = true;
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _panel && _panel.classList.contains('open')) closeQuizPage();
  });
}
