import { expect, it } from "vitest";
import { createLocalJWKSet, generateKeyPair, SignJWT } from "jose";
import { authorizedReader } from "../src/access";
import { env, fetchWorker } from "./helpers";
import { accessToken, pair, publicJwk, signAccess } from "./access-fixture";

const keys = createLocalJWKSet({ keys: [publicJwk] });
const request = (token: string) => new Request("https://sentinel.test/api/devices", { headers: { "cf-access-jwt-assertion": token } });

it("validates signature, issuer, audience, expiry and owner identity", async () => {
  expect(await authorizedReader(request(await accessToken), env, keys)).toBe(true);
  for (const overrides of [{ email: "stranger@example.test" }, { type: "meta" }]) {
    expect(await authorizedReader(request(await signAccess(overrides)), env, keys)).toBe(false);
  }
  const other = await generateKeyPair("RS256");
  expect(await authorizedReader(request(await signAccess({}, other.privateKey)), env, keys)).toBe(false);
  for (const [issuer, audience, exp] of [
    ["https://wrong.cloudflareaccess.com", "test-aud", "1h"],
    ["https://sentinel-test.cloudflareaccess.com", "wrong", "1h"],
    ["https://sentinel-test.cloudflareaccess.com", "test-aud", "-1h"],
  ]) {
    const token = await new SignJWT({ email: "owner@example.test", type: "app" })
      .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setSubject("owner")
      .setIssuer(issuer!).setAudience(audience!).setIssuedAt().setExpirationTime(exp!).sign(pair.privateKey);
    expect(await authorizedReader(request(token), env, keys)).toBe(false);
  }
});

it("rejects missing and forged assertions even with a warm cache", async () => {
  expect((await fetchWorker("/api/devices")).status).toBe(200);
  for (const token of ["", "forged.payload.signature"]) {
    const response = await fetchWorker("/api/devices", { headers: { "cf-access-jwt-assertion": token } });
    expect(response.status).toBe(403);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  }
});


it.each(["HEAD", "POST", "PUT", "DELETE"])("denies unauthenticated %s telemetry requests", async (method) => {
  expect((await fetchWorker("/api/devices", { method, headers: { "cf-access-jwt-assertion": "" } })).status).toBe(403);
});
