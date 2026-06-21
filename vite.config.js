import { defineConfig } from 'vite';
import ViteYaml from '@modyfi/vite-plugin-yaml';

export default defineConfig({
  root: '.',
  base: '/CodeGuardian/',
  publicDir: 'public',
  plugins: [ViteYaml()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
  },
  server: {
    port: 5173,
  },
});
