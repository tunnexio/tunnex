import { Session } from "electron";
import { CredentialStore, StoredCredential } from "./credential";

// bearerFor is the PURE decision of whether (and what) Authorization header to
// attach to a request. Defense-in-depth for the never-cross-servers invariant:
// the token is attached ONLY when the request targets the configured origin AND
// that origin is EXACTLY the server the credential was minted against AND the
// credential is not locally expired. So even if config + credential ever get out
// of sync (e.g. mid-server-change), the injector itself never sends a token to a
// server it wasn't minted for.
export function bearerFor(url: string, origin: string, cred: StoredCredential | null, now: Date): string | null {
  if (!origin || !cred) return null;
  if (cred.server !== origin) return null; // exact-server binding, enforced here
  if (!url.startsWith(origin + "/")) return null; // origin-scoped (defeats sub-origin/userinfo tricks)
  if (CredentialStore.isExpired(cred, now)) return null;
  return `Bearer ${cred.token}`;
}

// attachBearer injects the header on requests to the configured API origin. The
// raw token lives in main + the keychain and is added here per request — it
// NEVER crosses into the renderer (no getToken).
export function attachBearer(session: Session, getOrigin: () => string, store: CredentialStore): void {
  session.webRequest.onBeforeSendHeaders((details, callback) => {
    const auth = bearerFor(details.url, getOrigin(), store.load(), new Date());
    if (auth) {
      callback({ requestHeaders: { ...details.requestHeaders, Authorization: auth } });
      return;
    }
    callback({ requestHeaders: details.requestHeaders });
  });
}
