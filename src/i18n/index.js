const LANG_KEY = 'cg-lang';

export function getLang() {
  return localStorage.getItem(LANG_KEY) || 'en';
}

export function setLang(lang) {
  localStorage.setItem(LANG_KEY, lang);
}

export function t(strings, lang = getLang()) {
  return strings[lang] ?? strings.en ?? '';
}
