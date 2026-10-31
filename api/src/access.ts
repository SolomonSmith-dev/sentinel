import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { Env } from "./env";

const keysets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Fail closed even if the edge Access application is accidentally removed. */
export async function authorizedReader(req: Request, env: Env, keys?: JWTVerifyGetKey): Promise<boolean> {
  if (env.TELEMETRY_READS_ENABLED !== "true" || !env.ACCESS_AUD || !env.ACCESS_ISSUER || !env.ACCESS_EMAIL) return false;
  const token = req.headers.get("cf-access-jwt-assertion");
  if (!token) return false;
  try {
    if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_ISSUER)) return false;
    if (!keys) {
      if (!keysets.has(env.ACCESS_ISSUER)) keysets.set(env.ACCESS_ISSUER,
        createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`)));
      keys = keysets.get(env.ACCESS_ISSUER)!;
    }
    const { payload } = await jwtVerify(token, keys, {
      issuer: env.ACCESS_ISSUER, audience: env.ACCESS_AUD, algorithms: ["RS256"],
      requiredClaims: ["exp", "iat", "sub", "email"],
    });
    return payload.email === env.ACCESS_EMAIL && payload.type === "app";
  } catch {
    return false;
  }
}
