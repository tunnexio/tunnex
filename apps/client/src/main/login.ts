import { shell } from "electron";
import { generatePkce, randomState, startLoopback } from "./loopback";
import { consentUrl, exchangeCode, Poster } from "./exchange";
import { CredentialStore } from "./credential";

const post: Poster = (url, body) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

// runLogin drives the desktop reuse of the S5.1 flow: PKCE + state, a single-shot
// loopback listener, the SYSTEM browser opened to /cli-auth (the human
// checkpoint — never an embedded webview), then code→credential exchange into
// the keychain. Refuses if the store can't persist securely (unless opted in).
export async function runLogin(server: string, store: CredentialStore): Promise<{ fingerprint: string; expiresAt: string }> {
  if (!store.available()) {
    throw new Error("no OS keychain available — re-run with --allow-insecure-credential-storage, or use device-code login");
  }
  const { verifier, challenge } = generatePkce();
  const state = randomState();
  const listener = await startLoopback(state);
  try {
    await shell.openExternal(consentUrl(server, listener.redirectUri, challenge, state));
    const res = await listener.wait();
    if (res.error || !res.code) {
      throw new Error(res.error ?? "sign-in did not complete");
    }
    const cred = await exchangeCode(server, res.code, verifier, listener.redirectUri, post);
    store.save(cred);
    return { fingerprint: cred.fingerprint, expiresAt: cred.expiresAt };
  } finally {
    listener.close();
  }
}

// runLogout revokes the credential server-side (best-effort) and clears the
// local keychain entry.
export async function runLogout(store: CredentialStore): Promise<void> {
  const cred = store.load();
  if (cred) {
    try {
      const list = await fetch(`${cred.server}/api/v1/auth/cli/credentials`, { headers: { Authorization: `Bearer ${cred.token}` } });
      if (list.ok) {
        const rows: Array<{ id: string; fingerprint: string }> = await list.json();
        const mine = rows.find((r) => r.fingerprint === cred.fingerprint);
        if (mine) {
          await fetch(`${cred.server}/api/v1/auth/cli/credentials/${mine.id}`, { method: "DELETE", headers: { Authorization: `Bearer ${cred.token}` } });
        }
      }
    } catch {
      /* server unreachable — still clear locally */
    }
  }
  store.clear();
}
