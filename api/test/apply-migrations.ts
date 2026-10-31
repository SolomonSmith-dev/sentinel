import { applyD1Migrations, env } from "cloudflare:test";
import { beforeEach } from "vitest";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Start every test from empty tables regardless of the pool's storage isolation mode.
beforeEach(async () => {
  // The unauthenticated ingest_log throttle markers live in the Cache API, which outlives a test.
  const cache = (caches as unknown as { default: Cache }).default;
  const m = Math.floor(Date.now() / 60_000);
  // Public cache keys now ignore test-only query parameters too.
  const readKeys = ["metrics", "devices", "alerts"].map((p) => `https://sentinel.test/api/${p}`);
  for (const p of ["flows", "top"]) {
    for (const minutes of [5, 30, 60, 1440]) readKeys.push(`https://sentinel.test/api/${p}?minutes=${minutes}`);
  }
  for (const limit of [1, 50, 200]) {
    for (const since of [0, m * 60 - 48]) readKeys.push(`https://sentinel.test/api/alerts?limit=${limit}&since=${since}`);
  }
  await Promise.all(readKeys.map((key) => cache.delete(new Request(key))));
  await Promise.all(
    [401, 413, 429, 503].flatMap((st) =>
      [m - 1, m, m + 1].map((x) => cache.delete(new Request(`https://sentinel.internal/_throttle/ingest-log/${st}/${x}`))),
    ),
  );
  await env.DB.batch(
    ["devices", "windows", "alerts", "ingest_log", "idempotency", "seed_marker", "row_counts"].map((t) => env.DB.prepare(`DELETE FROM ${t}`)),
  );
});
