import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['**/*.spec.ts'],
    globals: true,
    testTimeout: 30000
  },
});
