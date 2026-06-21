import { getLang } from '../i18n/index.js';
import { UI } from '../i18n/ui.js';

export function confidenceBadge(confidence) {
  const lang = getLang();
  const map = {
    IRON:     ['conf-iron',     UI.confirmed[lang]],
    POSSIBLE: ['conf-possible', UI.probable[lang]],
    RESEARCH: ['conf-research', UI.needsResearch[lang]],
  };
  const [cls, label] = map[confidence] || map.RESEARCH;
  return `<span class="badge ${cls}">${label}</span>`;
}

export const SEV = {
  Critical: { cls: 'critical' },
  High:     { cls: 'high' },
  Medium:   { cls: 'medium' },
  Low:      { cls: 'low' },
};

export const DIFF = {
  Easy:        'easy',
  Medium:      'medium',
  Hard:        'hard',
  'Very Hard': 'veryhard',
};

export const PRISM_LANG = {
  python: 'python', javascript: 'javascript', c: 'c', php: 'php',
  json: 'json', yaml: 'yaml', http: 'http', text: 'none',
};
