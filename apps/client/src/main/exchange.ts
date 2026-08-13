import { StoredCredential } from "./credential";

// The code→credential exchange (POST /api/v1/auth/cli/token) and the consent URL
// builder. Pure over an injected poster so it is testable without Electron/net.

export type Poster = (url: string, body: unknown) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

// consentUrl is where the SYSTEM browser is opened: the SPA's /cli-auth page
// (the human checkpoint) with our loopback redirect + PKCE challenge + state.
export function consentUrl(server: string, redirectUri: string, challenge: string, state: string): string {
  const q = new URLSearchParams({ redirect_uri: redirectUri, code_challenge: challenge, state });
  return `${server}/cli-auth?${q.toString()}`;
}

export async function exchangeCode(
  server: string,
  code: string,
  codeVerifier: string,
  redirectUri: string,
  post: Poster,
): Promise<StoredCredential> {
  const res = await post(`${server}/api/v1/auth/cli/token`, {
    code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error?.message ?? `token exchange failed (HTTP ${res.status})`;
    throw new Error(msg);
  }
  return { server, token: data.token, fingerprint: data.fingerprint, expiresAt: data.expires_at };
}
