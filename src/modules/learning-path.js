import { LEARNING_PATH } from '../data/learning-path.js';
import { QUIZZES } from '../data/threat-features.js';
import { getThreatStatus } from './progress.js';

function passScoreFor(threatId) {
  return QUIZZES[threatId]?.passScore ?? 80;
}

function passed(threatId) {
  const status = getThreatStatus(threatId);
  const best = status.quiz?.bestScore ?? 0;
  return best >= passScoreFor(threatId);
}

// index 0 is always unlocked; stage N unlocks once stage N-1's quiz is passed.
export function isUnlocked(threatId) {
  const index = LEARNING_PATH.indexOf(threatId);
  if (index <= 0) return true;
  return passed(LEARNING_PATH[index - 1]);
}

export function getStageStatus(threatId) {
  if (!isUnlocked(threatId)) return 'locked';
  return passed(threatId) ? 'completed' : 'unlocked';
}

// threatId of the stage that must be passed to unlock this one (or null).
export function prerequisiteFor(threatId) {
  const index = LEARNING_PATH.indexOf(threatId);
  return index > 0 ? LEARNING_PATH[index - 1] : null;
}

export function getPathOverview() {
  return LEARNING_PATH.map((threatId, index) => ({
    threatId,
    index,
    status: getStageStatus(threatId),
    quizTitle: QUIZZES[threatId]?.title,
  }));
}
