export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  INGEST_LIMITER: RateLimit;
  INGEST_ENABLED: string;
  SENTINEL_TOKEN?: string;
}

export type AppEnv = { Bindings: Env };

export const now = (): number => Math.floor(Date.now() / 1000);
