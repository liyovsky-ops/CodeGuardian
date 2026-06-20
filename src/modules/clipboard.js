import { $, $$ } from './dom.js';
import { COPY_FEEDBACK_MS } from '../config.js';

function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); cb(); } catch (e) { console.warn('Copy failed:', e); }
  document.body.removeChild(ta);
}

export function initClipboard() {
  $$('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const code = $('code', btn.parentElement).textContent;
      const done = () => {
        const old = btn.textContent;
        btn.textContent = 'Skopiowano';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = old;
          btn.classList.remove('copied');
        }, COPY_FEEDBACK_MS);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(code).then(done, () => fallbackCopy(code, done));
      } else {
        fallbackCopy(code, done);
      }
    });
  });
}
