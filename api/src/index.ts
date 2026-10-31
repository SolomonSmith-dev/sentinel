import { Hono } from "hono";
import { scheduled } from "./cron";
import type { AppEnv, Env } from "./env";
import { errorResponse, jsonWithEtag, withSecurityHeaders } from "./http";
import { handleIngest } from "./ingest";
import { alerts, devices, flows, metrics, top } from "./reads";

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  await next();
  c.res = withSecurityHeaders(c.res);
});

app.use("/api/*", async (c, next) => {
  if (c.req.method === "GET" && c.req.path !== "/api/health") {
    const ip = c.req.header("cf-connecting-ip") ?? "unknown";
    if (!(await c.env.READ_LIMITER.limit({ key: `read:${ip}` })).success) {
      return errorResponse(429, "rate_limited", "Too many read requests", { "retry-after": "60", "cache-control": "no-store" });
    }
  }
  await next();
});

app.post("/api/ingest", (c) => handleIngest(c.req.raw, c.env, c.executionCtx as ExecutionContext));
app.get("/api/health", (c) => jsonWithEtag(c.req.raw, { ok: true }));
app.get("/api/flows", flows);
app.get("/api/alerts", alerts);
app.get("/api/devices", devices);
app.get("/api/top", top);
app.get("/api/metrics", metrics);

app.all("/api/*", () => errorResponse(404, "not_found", "No such endpoint"));
// Anything else that reaches the Worker is a static asset / SPA route.
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

app.onError((err, c) => {
  console.error(JSON.stringify({ event: "unhandled", path: new URL(c.req.url).pathname, err: String(err) }));
  return errorResponse(500, "internal", "Internal error");
});

export default {
  fetch: app.fetch,
  scheduled,
} satisfies ExportedHandler<Env>;
