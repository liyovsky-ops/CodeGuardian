import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, basename } from 'node:path';
import yaml from 'js-yaml';
import { z } from 'zod';
import { DeepDiveSchema } from './deepdive.schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEEPDIVE_DIR = join(__dirname, '..', 'content', 'deepdives');

/**
 * Validate every YAML deep-dive file against DeepDiveSchema.
 * Throws an Error (with filename + per-field details) on the first invalid file.
 * Returns the list of validated filenames on success.
 */
export function validateDeepDives() {
  const files = readdirSync(DEEPDIVE_DIR)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort();

  if (files.length === 0) {
    throw new Error(`[deepdive-validation] No YAML files found in ${DEEPDIVE_DIR}`);
  }

  for (const file of files) {
    const path = join(DEEPDIVE_DIR, file);
    let data;
    try {
      data = yaml.load(readFileSync(path, 'utf8'));
    } catch (err) {
      throw new Error(`[deepdive-validation] ${file} — YAML parse error: ${err.message}`);
    }

    const result = DeepDiveSchema.safeParse(data);
    if (!result.success) {
      const issues = result.error.issues
        .map((i) => `  • ${i.path.join('.') || '<root>'}: ${i.message}`)
        .join('\n');
      throw new Error(
        `[deepdive-validation] ${file} failed schema validation:\n${issues}`
      );
    }
  }

  return files;
}

// Allow running directly:  node src/schemas/validate-deepdives.js
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const files = validateDeepDives();
    console.log(`[deepdive-validation] OK — ${files.length} files valid:`);
    for (const f of files) console.log(`  ✓ ${basename(f)}`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
