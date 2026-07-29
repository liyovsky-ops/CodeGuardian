// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { LEARNING_PATH } from '../data/learning-path.js';
import { recordQuizAttempt } from '../modules/progress.js';
import { isUnlocked, getStageStatus, prerequisiteFor, getPathOverview } from '../modules/learning-path.js';

beforeEach(() => {
  localStorage.clear();
});

describe('learning path gates', () => {
  it('always unlocks the first stage', () => {
    expect(isUnlocked(LEARNING_PATH[0])).toBe(true);
    expect(getStageStatus(LEARNING_PATH[0])).toBe('unlocked');
  });

  it('locks the second stage until the first is passed', () => {
    expect(isUnlocked(LEARNING_PATH[1])).toBe(false);
    expect(getStageStatus(LEARNING_PATH[1])).toBe('locked');
  });

  it('unlocks the second stage once the first quiz is passed at >= 80', () => {
    recordQuizAttempt(LEARNING_PATH[0], 80);
    expect(isUnlocked(LEARNING_PATH[1])).toBe(true);
    expect(getStageStatus(LEARNING_PATH[1])).toBe('unlocked');
  });

  it('does not unlock the second stage on a failing score', () => {
    recordQuizAttempt(LEARNING_PATH[0], 60);
    expect(isUnlocked(LEARNING_PATH[1])).toBe(false);
  });

  it('marks a stage completed once its own quiz is passed', () => {
    recordQuizAttempt(LEARNING_PATH[0], 80);
    expect(getStageStatus(LEARNING_PATH[0])).toBe('completed');
  });

  it('keeps the best score — a later lower attempt does not re-lock the next stage', () => {
    recordQuizAttempt(LEARNING_PATH[0], 90);
    recordQuizAttempt(LEARNING_PATH[0], 50);
    expect(isUnlocked(LEARNING_PATH[1])).toBe(true);
  });

  it('reports null prerequisite for the first stage and the prior stage id otherwise', () => {
    expect(prerequisiteFor(LEARNING_PATH[0])).toBeNull();
    expect(prerequisiteFor(LEARNING_PATH[1])).toBe(LEARNING_PATH[0]);
  });

  it('getPathOverview returns one entry per stage in order with a status', () => {
    const overview = getPathOverview();
    expect(overview).toHaveLength(LEARNING_PATH.length);
    expect(overview[0].threatId).toBe(LEARNING_PATH[0]);
    expect(overview[0].status).toBe('unlocked');
    expect(overview[1].status).toBe('locked');
  });
});
