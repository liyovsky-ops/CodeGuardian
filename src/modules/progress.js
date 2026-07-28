const KEY = 'cg-progress-v1';
const VERSION = 1;

function load() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { version: VERSION, threats: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !parsed.threats) {
      return { version: VERSION, threats: {} };
    }
    return parsed;
  } catch {
    return { version: VERSION, threats: {} };
  }
}

function save(state) {
  localStorage.setItem(KEY, JSON.stringify(state));
}

function entry(state, threatId) {
  if (!state.threats[threatId]) {
    state.threats[threatId] = { read: null, quiz: null, lab: null, applied: null };
  }
  return state.threats[threatId];
}

export function getProgress() {
  return load();
}

export function markRead(threatId) {
  const state = load();
  const e = entry(state, threatId);
  if (!e.read) {
    e.read = new Date().toISOString();
    save(state);
  }
  return state;
}

export function recordQuizAttempt(threatId, score) {
  const state = load();
  const e = entry(state, threatId);
  const prevAttempts = e.quiz?.attempts ?? 0;
  const prevBest = e.quiz?.bestScore ?? 0;
  e.quiz = {
    attempts: prevAttempts + 1,
    bestScore: Math.max(prevBest, score),
    lastScore: score,
    at: new Date().toISOString(),
  };
  save(state);
  return state;
}

// status: 'not-started' | 'in-progress' | 'completed' — self-reported, not verified by the site
export function setLabStatus(threatId, status) {
  const state = load();
  const e = entry(state, threatId);
  e.lab = { status, at: new Date().toISOString() };
  save(state);
  return state;
}

export function setAppliedNote(threatId, note) {
  const state = load();
  const e = entry(state, threatId);
  e.applied = note ? { note, at: new Date().toISOString() } : null;
  save(state);
  return state;
}

export function getThreatStatus(threatId) {
  const state = load();
  return state.threats[threatId] ?? { read: null, quiz: null, lab: null, applied: null };
}

export function getStats(allThreatIds) {
  const state = load();
  let read = 0, quizzed = 0, labCompleted = 0, applied = 0;
  for (const id of allThreatIds) {
    const e = state.threats[id];
    if (!e) continue;
    if (e.read) read++;
    if (e.quiz) quizzed++;
    if (e.lab?.status === 'completed') labCompleted++;
    if (e.applied) applied++;
  }
  return { total: allThreatIds.length, read, quizzed, labCompleted, applied };
}

export function exportProgress() {
  const state = load();
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `codeguardian-progress-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// mode: 'merge' (default, keeps newer per-threat data) or 'replace'
// `file` is anything exposing `.text(): Promise<string>` — a real File/Blob
// in the browser, or a plain stub in tests (jsdom's File lacks .text()).
export async function importProgress(file, mode = 'merge') {
  const text = await file.text();
  const incoming = JSON.parse(text);
  if (!incoming || typeof incoming !== 'object' || !incoming.threats) {
    throw new Error('Invalid progress file: missing "threats" object');
  }
  if (mode === 'replace') {
    save({ version: VERSION, threats: incoming.threats });
    return load();
  }
  const state = load();
  for (const [threatId, incomingEntry] of Object.entries(incoming.threats)) {
    const current = state.threats[threatId];
    if (!current) {
      state.threats[threatId] = incomingEntry;
      continue;
    }
    // merge field-by-field, keeping whichever side has the later timestamp
    for (const field of ['read', 'quiz', 'lab', 'applied']) {
      const currAt = field === 'read' ? current.read : current[field]?.at;
      const incAt = field === 'read' ? incomingEntry.read : incomingEntry[field]?.at;
      if (incAt && (!currAt || incAt > currAt)) {
        current[field] = incomingEntry[field];
      }
    }
  }
  save(state);
  return state;
}
