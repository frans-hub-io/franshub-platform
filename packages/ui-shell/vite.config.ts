import { readdirSync, readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';

const EXTERNAL = ['react', 'react-dom', '@mantine/core', '@mantine/hooks'];
const FONTS = new URL('./src/assets/fonts/', import.meta.url);

/**
 * Ships the fonts as files in `dist/fonts/` (library mode would inline them into the stylesheet as base64),
 * with their OFL texts, and puts their `@font-face` rules at the top of `styles.css`.
 */
function fonts(): Plugin {
  return {
    name: 'franshub-fonts',
    apply: 'build',
    generateBundle: {
      order: 'post',
      handler(_options, bundle) {
        for (const name of readdirSync(FONTS)) {
          if (name.endsWith('.woff2') || name.endsWith('.txt')) {
            this.emitFile({ type: 'asset', fileName: `fonts/${name}`, source: readFileSync(new URL(name, FONTS)) });
          }
        }
        const css = bundle['styles.css'];
        if (css?.type !== 'asset') throw new Error('styles.css was not emitted');
        const faces = readFileSync(new URL('fonts.css', FONTS), 'utf8').replaceAll('url("./', 'url("./fonts/');
        css.source = `${faces}\n${String(css.source)}`;
      },
    },
  };
}

export default defineConfig({
  plugins: [react(), fonts()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    lib: {
      entry: { index: 'src/entry.ts' },
      formats: ['es'],
      fileName: (_format, name) => `${name}.js`,
      cssFileName: 'styles',
    },
    rolldownOptions: {
      external: (id: string) => EXTERNAL.some((dep) => id === dep || id.startsWith(`${dep}/`)),
    },
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    testTimeout: 30000,
  },
});
