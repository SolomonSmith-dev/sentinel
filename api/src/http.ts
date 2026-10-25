export function errorResponse(status: number, error: string, message: string, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify({ error, message }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extra },
  });
}

export async function sha256Hex(data: BufferSource | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time string comparison via digest equality (lengths may differ). */
export async function timingSafeEqualStr(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: (x: ArrayBuffer, y: ArrayBuffer) => boolean };
  if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(da, db) && a.length === b.length;
  const x = new Uint8Array(da);
  const y = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i]! ^ y[i]!;
  return diff === 0 && a.length === b.length;
}

export class TooLargeError extends Error {}

/** Read a stream into memory, aborting once more than `max` bytes arrive. */
export async function readCapped(stream: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new TooLargeError();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export const READ_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "public, max-age=10",
};

/** JSON response with a strong ETag; 304 when If-None-Match matches. */
export async function jsonWithEtag(req: Request, body: unknown): Promise<Response> {
  const text = JSON.stringify(body);
  const etag = `"${(await sha256Hex(text)).slice(0, 32)}"`;
  const res = new Response(text, { status: 200, headers: { ...READ_HEADERS, etag } });
  return conditional(req, res);
}

export function etagMatches(ifNoneMatch: string | null, etag: string | null): boolean {
  if (!ifNoneMatch || !etag) return false;
  const strip = (t: string) => t.trim().replace(/^W\//, "");
  const target = strip(etag);
  return ifNoneMatch.split(",").some((t) => t.trim() === "*" || strip(t) === target);
}

/** Turn a 200 into a 304 if the client already has this ETag. */
export function conditional(req: Request, res: Response): Response {
  const etag = res.headers.get("etag");
  if (etagMatches(req.headers.get("if-none-match"), etag)) {
    return new Response(null, {
      status: 304,
      headers: { etag: etag!, "cache-control": READ_HEADERS["cache-control"] },
    });
  }
  return res;
}

export function intParam(raw: string | undefined, def: number, min: number, max: number): number {
  if (raw === undefined || raw === "") return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

/** Security headers for every response. Mirrored in dashboard/public/_headers for static assets. */
export const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy": [
    "default-src 'self'",
    "script-src 'self' https://static.cloudflareinsights.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://cloudflareinsights.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "),
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-frame-options": "DENY",
};

/** Copy a response with the security headers set. Rebuilds it because ASSETS responses have immutable headers. */
export function withSecurityHeaders(res: Response): Response {
  if (res.status === 101 || res.webSocket) return res;
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  return out;
}
