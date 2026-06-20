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
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/prismjs')) return 'prism';
        },
      },
    },
    chunkSizeWarningLimit: 600,
    cssCodeSplit: false,
  },
  server: {
    port: 5173,
    open: true,
  },
});
