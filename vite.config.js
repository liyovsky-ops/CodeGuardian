import { defineConfig } from 'vite';
import ViteYaml from '@modyfi/vite-plugin-yaml';
import { validateDeepDives } from './src/schemas/validate-deepdives.js';
import { validateQuizzes } from './src/schemas/validate-quizzes.js';

// Fail the build if any deep-dive YAML drifts from DeepDiveSchema.
function validateDeepDivesPlugin() {
  return {
    name: 'validate-deepdives',
    buildStart() {
      const files = validateDeepDives(); // throws on invalid file
      this.info?.(`validated ${files.length} deep-dive YAML files`);
    },
  };
}

// Fail the build if any quiz YAML drifts from QuizSchema.
function validateQuizzesPlugin() {
  return {
    name: 'validate-quizzes',
    buildStart() {
      const files = validateQuizzes(); // throws on invalid file
      this.info?.(`validated ${files.length} quiz YAML file(s)`);
    },
  };
}

export default defineConfig({
  root: '.',
  base: '/CodeGuardian/',
  publicDir: 'public',
  plugins: [validateDeepDivesPlugin(), validateQuizzesPlugin(), ViteYaml()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // Rolldown (Vite 8) requires the function form of manualChunks.
        manualChunks(id) {
          if (id.includes('node_modules/prismjs')) return 'vendor-prism';
          if (id.includes('node_modules/dompurify')) return 'vendor-dompurify';
          if (
            id.includes('/src/modules/deepdive-renderer.js') ||
            id.includes('/src/content/deepdives/')
          ) {
            return 'deepdives';
          }
        },
      },
    },
  },
  server: {
    port: 5173,
  },
});
