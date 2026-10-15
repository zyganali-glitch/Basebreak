import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.js",
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        vars: {
          BASEBREAK_ADMIN_KEY: "test_admin_secret_key_123",
        },
      },
    }),
  ],
  test: {
    include: ["test/worker.runtime.test.js"],
  },
});
