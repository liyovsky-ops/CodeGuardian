// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import {
  getProgress,
  markRead,
  recordQuizAttempt,
  setLabStatus,
  setAppliedNote,
  getThreatStatus,
  getStats,
  importProgress,
} from '../modules/progress.js';

beforeEach(() => {
  localStorage.clear();
});

describe('progress tracking', () => {
  it('starts empty', () => {
    expect(getProgress()).toEqual({ version: 1, threats: {} });
  });

  it('markRead records a timestamp once, idempotently', () => {
    markRead('1.1');
    const first = getThreatStatus('1.1').read;
    expect(first).toBeTruthy();
    markRead('1.1');
    expect(getThreatStatus('1.1').read).toBe(first); // does not overwrite
  });

  it('recordQuizAttempt tracks attempts and keeps the best score', () => {
    recordQuizAttempt('1.1', 60);
    recordQuizAttempt('1.1', 90);
    recordQuizAttempt('1.1', 70);
    const quiz = getThreatStatus('1.1').quiz;
    expect(quiz.attempts).toBe(3);
    expect(quiz.bestScore).toBe(90);
    expect(quiz.lastScore).toBe(70);
  });

  it('setLabStatus is self-reported and overwritable', () => {
    setLabStatus('1.1', 'in-progress');
    expect(getThreatStatus('1.1').lab.status).toBe('in-progress');
    setLabStatus('1.1', 'completed');
    expect(getThreatStatus('1.1').lab.status).toBe('completed');
  });

  it('setAppliedNote can be set and cleared', () => {
    setAppliedNote('1.1', 'Used parameterized queries in project X');
    expect(getThreatStatus('1.1').applied.note).toContain('parameterized');
    setAppliedNote('1.1', '');
    expect(getThreatStatus('1.1').applied).toBeNull();
  });

  it('getStats aggregates across a threat id list', () => {
    markRead('1.1');
    markRead('1.2');
    recordQuizAttempt('1.1', 100);
    setLabStatus('1.2', 'completed');
    const stats = getStats(['1.1', '1.2', '1.3']);
    expect(stats).toEqual({ total: 3, read: 2, quizzed: 1, labCompleted: 1, applied: 0 });
  });

  // jsdom's File/Blob polyfill doesn't implement .text(), so tests use a
  // minimal stub matching the interface importProgress actually depends on
  // (real browsers pass a genuine File, which does support .text()).
  const fileStub = (contents) => ({ text: async () => contents });

  it('importProgress merges, keeping the newer entry per threat', async () => {
    markRead('1.1'); // local, "now"
    const older = new Date(Date.now() - 100000).toISOString();
    const newer = new Date(Date.now() + 100000).toISOString();

    const file = fileStub(JSON.stringify({
      version: 1,
      threats: {
        '1.1': { read: older, quiz: null, lab: null, applied: null },
        '1.2': { read: newer, quiz: null, lab: null, applied: null },
      },
    }));

    await importProgress(file);
    // 1.1: local read is newer than imported -> local wins
    expect(getThreatStatus('1.1').read).not.toBe(older);
    // 1.2: didn't exist locally -> imported value wins
    expect(getThreatStatus('1.2').read).toBe(newer);
  });

  it('importProgress rejects a file without a threats object', async () => {
    const file = fileStub('{"foo":"bar"}');
    await expect(importProgress(file)).rejects.toThrow(/Invalid progress file/);
  });
});
