import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/crypto/**", "src/pki/**", "src/land/**"],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 80 },
    },
  },
});
