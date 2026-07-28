import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';
import yaml from 'js-yaml';
import { QuizSchema } from './quiz.schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const QUIZ_DIR = join(__dirname, '..', 'content', 'quizzes');

/**
 * Validate every YAML quiz file against QuizSchema.
 * Unlike validate-deepdives.js, an empty/missing directory is NOT an error —
 * quiz content is authored incrementally and the infra should work with zero
 * quizzes present. Throws on the first invalid file found.
 */
export function validateQuizzes() {
  if (!existsSync(QUIZ_DIR)) return [];

  const files = readdirSync(QUIZ_DIR)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort();

  for (const file of files) {
    const path = join(QUIZ_DIR, file);
    let data;
    try {
      data = yaml.load(readFileSync(path, 'utf8'));
    } catch (err) {
      throw new Error(`[quiz-validation] ${file} — YAML parse error: ${err.message}`);
    }

    const result = QuizSchema.safeParse(data);
    if (!result.success) {
      const issues = result.error.issues
        .map((i) => `  • ${i.path.join('.') || '<root>'}: ${i.message}`)
        .join('\n');
      throw new Error(`[quiz-validation] ${file} failed schema validation:\n${issues}`);
    }
  }

  return files;
}

// Allow running directly:  node src/schemas/validate-quizzes.js
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const files = validateQuizzes();
    console.log(`[quiz-validation] OK — ${files.length} file(s) valid:`);
    for (const f of files) console.log(`  ✓ ${basename(f)}`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
