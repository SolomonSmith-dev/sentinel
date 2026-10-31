import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        remoteBindings: false,
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: { TEST_MIGRATIONS: migrations, SENTINEL_TOKEN: "test-token", TELEMETRY_READS_ENABLED: "true", ACCESS_AUD: "test-aud", ACCESS_ISSUER: "https://sentinel-test.cloudflareaccess.com", ACCESS_EMAIL: "owner@example.test" },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
    },
  };
});
