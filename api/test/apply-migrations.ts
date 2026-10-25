import { applyD1Migrations, env } from "cloudflare:test";
import { beforeEach } from "vitest";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Start every test from empty tables regardless of the pool's storage isolation mode.
beforeEach(async () => {
  // The unauthenticated ingest_log throttle markers live in the Cache API, which outlives a test.
  const cache = (caches as unknown as { default: Cache }).default;
  const m = Math.floor(Date.now() / 60_000);
  await Promise.all(
    [401, 413, 429, 503].flatMap((st) =>
      [m - 1, m, m + 1].map((x) => cache.delete(new Request(`https://sentinel.internal/_throttle/ingest-log/${st}/${x}`))),
    ),
  );
  await env.DB.batch(
    ["devices", "windows", "alerts", "ingest_log", "idempotency", "seed_marker"].map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
  );
});
