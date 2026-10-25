import { applyD1Migrations, env } from "cloudflare:test";
import { beforeEach } from "vitest";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Start every test from empty tables regardless of the pool's storage isolation mode.
beforeEach(async () => {
  await env.DB.batch(
    ["devices", "windows", "alerts", "ingest_log", "idempotency", "seed_marker"].map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
  );
});
