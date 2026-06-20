export function confidenceBadge(confidence) {
  const map = {
    IRON:     ['conf-iron',     'Potwierdzone'],
    POSSIBLE: ['conf-possible', 'Prawdopodobne'],
    RESEARCH: ['conf-research', 'Do weryfikacji'],
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
