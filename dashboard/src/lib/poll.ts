import { useEffect, useState, useSyncExternalStore } from "react";

export const POLL_MS = 10_000;
/** A panel is stale when its last good response is older than this. */
export const STALE_MS = POLL_MS * 3;

interface CacheEntry { etag: string | null; data: unknown }
// Last ETag + body per URL. Survives range switches so 1h -> 6h -> 1h is instant.
const cache = new Map<string, CacheEntry>();

export interface PollState<T> {
  data: T | undefined;
  /** Message of the most recent failure, cleared on the next good response. */
  error: string | undefined;
  /** ms epoch of the last 200 or 304. */
  updatedAt: number | undefined;
  /** True while the first response for the current URL is outstanding. */
  pending: boolean;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const j = (await res.json()) as { error?: string; message?: string };
    if (j.message || j.error) return `${res.status} ${j.error ?? ""}${j.message ? `: ${j.message}` : ""}`.trim();
  } catch { /* not JSON */ }
  return `HTTP ${res.status}`;
}

/**
 * Poll a same-origin JSON endpoint every POLL_MS with If-None-Match.
 * 304 keeps the cached body. Polling pauses while the tab is hidden and
 * fires immediately when it becomes visible again.
 */
export function usePoll<T>(url: string): PollState<T> {
  const [state, setState] = useState<PollState<T>>(() => {
    const hit = cache.get(url);
    return { data: hit?.data as T | undefined, error: undefined, updatedAt: undefined, pending: !hit };
  });
  useEffect(() => {
    const hit = cache.get(url);
    setState((s) => ({ ...s, data: (hit?.data as T | undefined) ?? s.data, pending: !hit, error: undefined }));

    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let inFlight = false;
    let ctrl: AbortController | undefined;

    const schedule = () => {
      clearTimeout(timer);
      if (!disposed && document.visibilityState === "visible") timer = setTimeout(tick, POLL_MS);
    };

    const tick = async () => {
      if (disposed || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      ctrl = new AbortController();
      const entry = cache.get(url);
      try {
        const res = await fetch(url, {
          headers: entry?.etag ? { "If-None-Match": entry.etag, Accept: "application/json" } : { Accept: "application/json" },
          cache: "no-store", // we do conditional requests ourselves
          signal: ctrl.signal,
        });
        if (disposed) return;
        if (res.status === 304 && entry) {
          setState({ data: entry.data as T, error: undefined, updatedAt: Date.now(), pending: false });
        } else if (res.ok) {
          const data = (await res.json()) as T;
          if (disposed) return;
          cache.set(url, { etag: res.headers.get("ETag"), data });
          setState({ data, error: undefined, updatedAt: Date.now(), pending: false });
        } else {
          const msg = await errorMessage(res);
          if (!disposed) setState((s) => ({ ...s, error: msg, pending: false }));
        }
      } catch (e) {
        if (disposed || (e instanceof DOMException && e.name === "AbortError")) return;
        setState((s) => ({ ...s, error: e instanceof SyntaxError ? "Bad JSON from server" : "Network error", pending: false }));
      } finally {
        inFlight = false;
        schedule();
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") tick();
      else clearTimeout(timer);
    };

    document.addEventListener("visibilitychange", onVisibility);
    tick();
    return () => {
      disposed = true;
      clearTimeout(timer);
      ctrl?.abort();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [url]);

  return state;
}

// One shared 1 s clock for every "N s ago" label.
let now = Date.now();
const listeners = new Set<() => void>();
let clock: ReturnType<typeof setInterval> | undefined;
function subscribe(fn: () => void) {
  listeners.add(fn);
  if (!clock) clock = setInterval(() => { now = Date.now(); listeners.forEach((l) => l()); }, 1000);
  return () => {
    listeners.delete(fn);
    if (!listeners.size && clock) { clearInterval(clock); clock = undefined; }
  };
}
export const useNow = () => useSyncExternalStore(subscribe, () => now, () => now);
