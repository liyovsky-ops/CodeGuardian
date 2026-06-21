import { getLang, setLang } from '../i18n/index.js';

export function initLang(rerender) {
  const btn = document.getElementById('lang-toggle');
  const label = document.getElementById('lang-current');

  const update = () => {
    const lang = getLang();
    label.textContent = lang.toUpperCase();
    btn.setAttribute('aria-label', lang === 'en' ? 'Przełącz na polski' : 'Switch to English');
  };

  btn.addEventListener('click', () => {
    const next = getLang() === 'en' ? 'pl' : 'en';
    setLang(next);
    update();
    rerender();
  });

  update();
}
