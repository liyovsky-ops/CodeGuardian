import { describe, it, expect } from 'vitest';
import { QuizSchema } from '../schemas/quiz.schema.js';

const bilingual = (en, pl = en) => ({ en, pl });

function validQuiz(overrides = {}) {
  return {
    threatId: '1.1',
    title: bilingual('SQL Injection Practice'),
    passScore: 80,
    questions: [
      {
        id: 'q1',
        type: 'vuln-or-not',
        prompt: bilingual('Is this vulnerable?'),
        snippet: { lang: 'python', code: "q = \"SELECT * FROM t WHERE x='\" + x + \"'\"" },
        isVulnerable: true,
        cwe: 'CWE-89',
        explanation: bilingual('String concatenation into SQL is the classic injection pattern.'),
      },
      {
        id: 'q2',
        type: 'multiple-choice',
        prompt: bilingual('Which fixes it?'),
        choices: [
          { id: 'a', label: bilingual('Parameterized query') },
          { id: 'b', label: bilingual('More string escaping by hand') },
        ],
        correctChoiceIds: ['a'],
        explanation: bilingual('Parameterization separates code from data.'),
      },
      {
        id: 'q3',
        type: 'pick-the-fix',
        prompt: bilingual('Pick the safe variant.'),
        variants: [
          { id: 'v1', lang: 'python', code: 'db.execute(q, (x,))' },
          { id: 'v2', lang: 'python', code: 'db.execute(q + x)' },
        ],
        correctVariantId: 'v1',
        explanation: bilingual('v1 uses a bound parameter; v2 still concatenates.'),
      },
    ],
    ...overrides,
  };
}

describe('QuizSchema', () => {
  it('accepts a well-formed quiz with all three question types', () => {
    const result = QuizSchema.safeParse(validQuiz());
    expect(result.success).toBe(true);
  });

  it('rejects fewer than 3 questions', () => {
    const quiz = validQuiz();
    quiz.questions = quiz.questions.slice(0, 2);
    const result = QuizSchema.safeParse(quiz);
    expect(result.success).toBe(false);
  });

  it('rejects a multiple-choice question whose correctChoiceIds references an unknown choice', () => {
    const quiz = validQuiz();
    quiz.questions[1].correctChoiceIds = ['does-not-exist'];
    const result = QuizSchema.safeParse(quiz);
    expect(result.success).toBe(false);
    expect(result.error.issues.some((i) => i.message.includes('unknown choice id'))).toBe(true);
  });

  it('rejects a pick-the-fix question whose correctVariantId does not match any variant', () => {
    const quiz = validQuiz();
    quiz.questions[2].correctVariantId = 'nope';
    const result = QuizSchema.safeParse(quiz);
    expect(result.success).toBe(false);
    expect(result.error.issues.some((i) => i.message.includes('does not match any variant'))).toBe(true);
  });

  it('rejects a missing explanation', () => {
    const quiz = validQuiz();
    delete quiz.questions[0].explanation;
    const result = QuizSchema.safeParse(quiz);
    expect(result.success).toBe(false);
  });

  it('defaults passScore to 80 when omitted', () => {
    const quiz = validQuiz();
    delete quiz.passScore;
    const result = QuizSchema.safeParse(quiz);
    expect(result.success).toBe(true);
    expect(result.data.passScore).toBe(80);
  });
});
