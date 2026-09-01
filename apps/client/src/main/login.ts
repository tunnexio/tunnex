import { shell } from "electron";
import { generatePkce, randomState, startLoopback } from "./loopback";
import { consentUrl, exchangeCode, Poster } from "./exchange";
import { CredentialStore } from "./credential";
import { controlPlaneRequest } from "./controlplanerequest";

const post: Poster = (url, body) =>
  controlPlaneRequest(
    url,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
    async (response) => new Response(await response.arrayBuffer(), {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    }),
  );

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
      await controlPlaneRequest(
        `${cred.server}/api/v1/auth/cli/credentials`,
        { headers: { Authorization: `Bearer ${cred.token}` } },
        async (list) => {
          if (!list.ok) return;
          const rows: Array<{ id: string; fingerprint: string }> = await list.json();
          const mine = rows.find((row) => row.fingerprint === cred.fingerprint);
          if (!mine) return;
          await controlPlaneRequest(
            `${cred.server}/api/v1/auth/cli/credentials/${encodeURIComponent(mine.id)}`,
            { method: "DELETE", headers: { Authorization: `Bearer ${cred.token}` } },
            async () => undefined,
          );
        },
      );
    } catch {
      /* server unreachable — still clear locally */
    }
  }
  store.clear();
}
