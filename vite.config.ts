import { defineConfig } from 'vite';

// GitHub Pages project site lives at https://<user>.github.io/crypto-lab-jwt-forge/,
// so production assets must be served from that sub-path. Dev/preview stay at root.
// NOTE: if the Parts 0 + A–E standardization pass changes the deploy target, update
// the `base` below to match.
export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/crypto-lab-jwt-forge/' : '/',
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.test.ts'],
  },
}));
