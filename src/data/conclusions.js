import conclusionsData from '../content/conclusions.yaml';
import { getLang } from '../i18n/index.js';

export function getConclusions() {
  const lang = getLang();
  return conclusionsData.conclusions.map(c => ({
    title: lang === 'en' ? (c.title_en || c.title) : c.title,
    body: lang === 'en' ? (c.body_en || c.body) : c.body,
  }));
}

// Backward compat (Polish)
export const CONCLUSIONS = conclusionsData.conclusions;
