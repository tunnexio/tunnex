// @tunnex/shared — the single source of API types + a typed client, all derived
// from openapi/openapi.yaml via `make generate`. Consumed by the web app, the
// Electron client, and the CLI. Do not hand-edit api.d.ts.

import createClient, { type Client } from "openapi-fetch";
import type { paths, components } from "./api";

export type { paths, components };

// S14.1 — design tokens. The ONE authored form for colour/typography, shared with the desktop client per
// Item A ruling A3 (own components, shared tokens). See ./tokens.ts.
export * from "./tokens";

// Convenience aliases for the schemas used across the apps.
export type HealthResponse = components["schemas"]["HealthResponse"];
export type ApiError = components["schemas"]["Error"];

export type TunnexClient = Client<paths>;

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Desktop transport switch (S6.2). The web SPA is same-origin (baseUrl "/"), but
// the Electron renderer loads over app:// and must reach the CONFIGURED server
// origin. setApiOrigin rewrites the ORIGIN of every request URL at the client
// layer — one bundle, runtime branch, no build fork. Null (the default) leaves
// requests same-origin, so the browser build is unaffected. Auth is untouched
// here: the desktop bearer is injected by the Electron MAIN process on the
// configured origin (S6.1), never by this middleware — the token never enters
// renderer JS.
let apiOrigin: string | null = null;
export function setApiOrigin(origin: string | null): void {
  // Pin to a bare origin (scheme://host[:port]) — self-defending against a
  // caller passing a path/garbage. Empty/invalid → disabled (same-origin).
  if (!origin) {
    apiOrigin = null;
    return;
  }
  try {
    apiOrigin = new URL(origin).origin;
  } catch {
    apiOrigin = null;
  }
}

/**
 * Create a typed Tunnex API client. baseUrl defaults to same-origin ("/").
 *
 * Every unsafe-method request carries the X-Tunnex-CSRF header AT THE CLIENT
 * LAYER, so no call site can forget it. The server's csrfGuard requires the
 * header whenever a request CARRIES the session cookie — including a stale,
 * already-revoked cookie — so pre-auth calls (login/signup/reset) need it too:
 * a browser holding a revoked session cookie would otherwise be locked out of
 * login until the cookie expires (Round-2 walk, bug B1). The header is
 * presence-only (a cross-site form cannot set custom headers), so sending it
 * on every mutation is always correct and never leaks anything.
 */
export function createTunnexClient(baseUrl = "/"): TunnexClient {
  const client = createClient<paths>({ baseUrl });
  client.use({
    async onRequest({ request }) {
      let req = request;
      // Desktop: re-home the request onto the configured server origin (path +
      // query preserved). Rebuild rather than mutate (Request.url is read-only).
      // The body is BUFFERED (arrayBuffer) rather than passed as a stream:
      // Blink rejects a streaming body without `duplex: 'half'` (which the
      // Request object doesn't expose), so `new Request(url, request)` throws in
      // the Electron renderer for any body-bearing call. Buffering sidesteps it
      // and works identically in the browser and Node.
      if (apiOrigin) {
        const u = new URL(request.url);
        const hasBody = req.method !== "GET" && req.method !== "HEAD";
        const body = hasBody ? await request.arrayBuffer() : undefined;
        req = new Request(apiOrigin + u.pathname + u.search, {
          method: request.method,
          headers: request.headers,
          body,
          signal: request.signal,
          redirect: request.redirect,
        });
      }
      if (UNSAFE_METHODS.has(req.method)) {
        req.headers.set("X-Tunnex-CSRF", "1");
      }
      return req;
    },
  });
  return client;
}
