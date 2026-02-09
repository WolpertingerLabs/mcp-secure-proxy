import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/test-integration.ts',
        'src/cli/**',
        'src/mcp-server.ts',
        'src/remote-server.ts',
        'src/protocol/messages.ts',
        'src/crypto/index.ts',
        'src/protocol/index.ts',
      ],
      reporter: ['text', 'text-summary', 'lcov'],
      thresholds: {
        statements: 50,
        branches: 40,
        functions: 50,
        lines: 50,
      },
    },
  },
});
