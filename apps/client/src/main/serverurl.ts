// Server-URL logic — pure, testable, no Electron. The URL lives in the
// main-process config (it's where the auth flow + updater point); the renderer
// only reads it over the bridge.

export type Fetchish = (url: string) => Promise<{ ok: boolean; status: number }>;

// normalizeServerUrl trims and validates the shape: http(s), a host, no path/
// query/fragment (the base URL only). Returns the canonical origin or throws.
export function normalizeServerUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error("not a valid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("server URL must be http(s)");
  }
  if ((u.pathname && u.pathname !== "/") || u.search || u.hash) {
    throw new Error("server URL must be a base URL (no path, query, or fragment)");
  }
  return u.origin;
}

// validateServer confirms the URL is a live Tunnex control plane by hitting
// /healthz BEFORE it is accepted (a typo'd or dead server is rejected at set
// time, not on the first silent auth failure).
export async function validateServer(raw: string, fetchish: Fetchish): Promise<string> {
  const origin = normalizeServerUrl(raw);
  let res: { ok: boolean; status: number };
  try {
    res = await fetchish(origin + "/healthz");
  } catch (e) {
    throw new Error(`could not reach ${origin} (${(e as Error).message})`);
  }
  if (!res.ok) {
    throw new Error(`${origin}/healthz returned ${res.status} — not a Tunnex server?`);
  }
  return origin;
}

// serverChangeRequiresRelogin decides whether switching from `current` to `next`
// must revoke + clear the local credential. A credential is minted against ONE
// server and must NEVER be sent to another (the desktop cousin of the loopback
// exact-binding discipline). Same origin (incl. first-set from empty) → no
// forced relogin; a different non-empty origin with a credential present → yes.
export function serverChangeRequiresRelogin(current: string, next: string, hasCredential: boolean): boolean {
  if (!hasCredential) return false;
  if (!current) return false; // first set
  return normalizeServerUrl(current) !== normalizeServerUrl(next);
}
