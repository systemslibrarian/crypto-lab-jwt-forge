import { defineConfig } from 'vite';

// GitHub Pages project site lives at https://<user>.github.io/crypto-lab-jwt-forge/,
// so production assets must be served from that sub-path. Using the same base for
// build AND preview keeps `vite preview` (which serves the built HTML that already
// hard-codes /crypto-lab-jwt-forge/ asset URLs) working — otherwise the assets 404.
export default defineConfig(() => ({
  base: '/crypto-lab-jwt-forge/',
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.test.ts'],
  },
}));
