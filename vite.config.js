import { defineConfig } from 'vite';
import ViteYaml from '@modyfi/vite-plugin-yaml';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  root: '.',
  base: './',
  publicDir: 'public',
  plugins: [ViteYaml(), viteSingleFile()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 800,
    cssCodeSplit: false,
  },
  server: {
    port: 5173,
    open: true,
  },
});
