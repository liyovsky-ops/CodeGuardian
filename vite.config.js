import { defineConfig } from 'vite';
import ViteYaml from '@modyfi/vite-plugin-yaml';
import { validateDeepDives } from './src/schemas/validate-deepdives.js';

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

export default defineConfig({
  root: '.',
  base: '/CodeGuardian/',
  publicDir: 'public',
  plugins: [validateDeepDivesPlugin(), ViteYaml()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
  },
  server: {
    port: 5173,
  },
});
