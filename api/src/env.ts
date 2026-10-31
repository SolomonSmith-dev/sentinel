export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  INGEST_LIMITER: RateLimit;
  READ_LIMITER: RateLimit;
  READ_MISS_LIMITER: RateLimit;
  INGEST_ENABLED: string;
  TELEMETRY_READS_ENABLED?: string;
  ACCESS_AUD?: string;
  ACCESS_ISSUER?: string;
  ACCESS_EMAIL?: string;
  SENTINEL_TOKEN?: string;
}

export type AppEnv = { Bindings: Env };

export const now = (): number => Math.floor(Date.now() / 1000);
