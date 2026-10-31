import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const pair = await generateKeyPair("RS256", { extractable: true });
export const publicJwk = { ...await exportJWK(pair.publicKey), kid: "test-key", alg: "RS256" };
export function signAccess(overrides: Record<string, unknown> = {}, key = pair.privateKey) {
  return new SignJWT({ email: "owner@example.test", type: "app", ...overrides })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer("https://sentinel-test.cloudflareaccess.com").setAudience("test-aud")
    .setSubject("test-owner").setIssuedAt().setExpirationTime("1h").sign(key);
}
export const accessToken = signAccess();
