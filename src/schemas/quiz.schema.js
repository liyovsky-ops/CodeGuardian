import { z } from 'zod';

// A bilingual text block — same shape as deepdive.schema.js's BilingualString,
// duplicated here (not imported) to keep the two schema modules independent;
// they're allowed to diverge later without one file quietly breaking the other.
const BilingualString = z.object({
  en: z.string().min(1),
  pl: z.string().min(1),
});

const Snippet = z.object({
  lang: z.string().min(1),
  code: z.string().min(1),
});

const QuestionBase = {
  id: z.string().min(1),
  prompt: BilingualString,
  snippet: Snippet.optional(),
};

const MultipleChoiceQuestion = z.object({
  ...QuestionBase,
  type: z.literal('multiple-choice'),
  choices: z.array(z.object({
    id: z.string().min(1),
    label: BilingualString,
  })).min(2),
  correctChoiceIds: z.array(z.string().min(1)).min(1),
  explanation: BilingualString,
});

const PickTheFixQuestion = z.object({
  ...QuestionBase,
  type: z.literal('pick-the-fix'),
  variants: z.array(z.object({
    id: z.string().min(1),
    lang: z.string().min(1),
    code: z.string().min(1),
  })).min(2),
  correctVariantId: z.string().min(1),
  explanation: BilingualString,
});

const VulnOrNotQuestion = z.object({
  ...QuestionBase,
  type: z.literal('vuln-or-not'),
  isVulnerable: z.boolean(),
  cwe: z.string().optional(),
  explanation: BilingualString,
});

const Question = z.discriminatedUnion('type', [
  MultipleChoiceQuestion,
  PickTheFixQuestion,
  VulnOrNotQuestion,
]);

export const QuizSchema = z.object({
  threatId: z.string().min(1),
  title: BilingualString,
  passScore: z.number().min(0).max(100).default(80),
  questions: z.array(Question).min(3),
}).superRefine((quiz, ctx) => {
  // Cross-field checks Zod's base schema can't express declaratively.
  quiz.questions.forEach((q, i) => {
    if (q.type === 'multiple-choice') {
      const choiceIds = new Set(q.choices.map((c) => c.id));
      for (const id of q.correctChoiceIds) {
        if (!choiceIds.has(id)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['questions', i, 'correctChoiceIds'],
            message: `correctChoiceIds references unknown choice id "${id}"`,
          });
        }
      }
    }
    if (q.type === 'pick-the-fix') {
      const variantIds = new Set(q.variants.map((v) => v.id));
      if (!variantIds.has(q.correctVariantId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['questions', i, 'correctVariantId'],
          message: `correctVariantId "${q.correctVariantId}" does not match any variant id`,
        });
      }
    }
  });
});

export default QuizSchema;
