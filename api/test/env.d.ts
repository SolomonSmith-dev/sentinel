import type { D1Migration } from "@cloudflare/vitest-plugin";
import type { Env } from "../src/env";

declare global {
  namespace Cloudflare {
    interface Env extends ProjectEnv {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}
type ProjectEnv = Env;
