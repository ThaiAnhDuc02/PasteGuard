import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `vite preview` serves the production build with the same CSP as nginx, so a
// CSP regression (e.g. Monaco reaching for a CDN) shows up before deploying.
const PROD_CSP = /Content-Security-Policy\s+"([^"]+)"/.exec(readFileSync('./security-headers.conf', 'utf8'))?.[1]

export default defineConfig({
  plugins: [react()],
  preview: {
    headers: PROD_CSP ? { 'Content-Security-Policy': PROD_CSP } : {},
  },
  build: {
    target: 'es2022',
    // Source maps stay local for debugging but are not shipped to production.
    sourcemap: false,
    // Monaco (~4 MB, ~1 MB gzipped) is large by nature; it lives in its own
    // long-cached chunk so app updates don't re-download it.
    chunkSizeWarningLimit: 4500,
    rollupOptions: {
      output: {
        // Vite 8 (Rolldown) only accepts the function form of manualChunks.
        manualChunks(id: string) {
          if (id.includes('node_modules/monaco-editor')) return 'monaco-editor'
          if (id.includes('node_modules/react') || id.includes('node_modules/scheduler')) return 'react'
          return undefined
        },
      },
    },
  },
  worker: {
    format: 'es',
  },
  test: {
    globals: true,
    // Engine tests need no DOM; the node environment is much faster than jsdom.
    environment: 'node',
    setupFiles: ['./src/tests/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/', 'src/tests/'],
    },
  },
})
