import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/contracts/**/*.test.ts", "tests/upstream/**/*.test.ts"],
    testTimeout: 30000,
    hookTimeout: 30000,
    maxWorkers: 2,
  },
});
