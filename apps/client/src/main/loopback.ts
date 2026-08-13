import * as crypto from "node:crypto";
import * as http from "node:http";
import { AddressInfo } from "node:net";

// The loopback login flow — the desktop reuse of the S5.1 CLI flow. Same
// discipline: single-shot listener, STATE CHECKED FIRST (a mismatch never reads
// the code), explicit success/failure pages, ~2-minute bound. Runs in the
// Electron MAIN process; the browser is the SYSTEM browser (opened by the
// caller), never an embedded webview.

export const LISTENER_TIMEOUT_MS = 2 * 60 * 1000;

export interface Pkce {
  verifier: string;
  challenge: string;
}

export function generatePkce(): Pkce {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function randomState(): string {
  return base64url(crypto.randomBytes(32));
}

function base64url(b: Buffer): string {
  return b.toString("base64url");
}

export interface CallbackResult {
  code?: string;
  error?: string;
}

// handleCallback is the pure single-shot decision for one /callback request.
// STATE FIRST: a mismatch returns an error WITHOUT reading the code.
export function evalCallback(expectedState: string, query: URLSearchParams): { status: number; title: string; body: string; result: CallbackResult } {
  if (query.get("state") !== expectedState) {
    return {
      status: 403,
      title: "Sign-in failed",
      body: "The response did not match this sign-in attempt (state mismatch). Close this window and try again.",
      result: { error: "state mismatch on the loopback callback — no exchange attempted" },
    };
  }
  const code = query.get("code");
  if (!code) {
    return { status: 400, title: "Sign-in failed", body: "No authorization code was returned. Close this window and try again.", result: { error: "callback carried no code" } };
  }
  return { status: 200, title: "Signed in", body: "Tunnex is connected. You can close this window and return to the app.", result: { code } };
}

function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><title>Tunnex — ${title}</title>
<body style="font-family:system-ui;background:#0b0b12;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0">
<div style="max-width:26rem;text-align:center"><h1 style="font-size:1.2rem">${title}</h1><p style="color:#94a3b8">${body}</p></div>`;
}

export interface LoopbackListener {
  redirectUri: string;
  wait(): Promise<CallbackResult>;
  close(): void;
}

// startLoopback opens a single-shot 127.0.0.1:0 listener and returns the exact
// redirect_uri + a wait() that resolves on the (single) callback or the timeout.
export function startLoopback(expectedState: string): Promise<LoopbackListener> {
  return new Promise((resolve, reject) => {
    let done = false;
    let settle: (r: CallbackResult) => void;
    const resultP = new Promise<CallbackResult>((res) => {
      settle = res;
    });
    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/callback") {
        res.writeHead(404).end();
        return;
      }
      if (done) {
        res.writeHead(410, { "content-type": "text/html" }).end(page("Already completed", "This sign-in was already handled."));
        return;
      }
      done = true;
      const out = evalCallback(expectedState, url.searchParams);
      res.writeHead(out.status, { "content-type": "text/html" }).end(page(out.title, out.body));
      settle(out.result);
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      const timer = setTimeout(() => {
        if (!done) {
          done = true;
          settle({ error: `timed out after ${LISTENER_TIMEOUT_MS / 1000}s waiting for the browser sign-in` });
        }
      }, LISTENER_TIMEOUT_MS);
      timer.unref?.();
      resolve({
        redirectUri: `http://127.0.0.1:${port}/callback`,
        wait: () => resultP,
        close: () => {
          clearTimeout(timer);
          server.close();
        },
      });
    });
  });
}
