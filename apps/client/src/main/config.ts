import Store from "electron-store";
import { normalizeServerUrl, validateServer, serverChangeRequiresRelogin } from "./serverurl";

// An empty selection preserves RC20's legacy imported-profile fallback. This explicit sentinel
// means a person chose their managed Tunnex account, even if that legacy file is still retained.
export const MANAGED_PROFILE_SELECTION = "managed";

// Config owns the server URL (a MAIN-process concern — it's where auth + the
// updater point; the renderer only reads it over the bridge). Backed by
// electron-store in userData.
//
// validate and commit are SEPARATE so the caller can clear the old credential
// BEFORE the new URL is persisted — otherwise there is a window where the
// configured origin is the new server while the old credential still exists
// (a cross-server token-attach risk).
export class Config {
  private store: Store<{ serverUrl: string; importedProfileId: string }>;

  constructor(store?: Store<{ serverUrl: string; importedProfileId: string }>) {
    this.store = store ?? new Store<{ serverUrl: string; importedProfileId: string }>({ name: "tunnex", defaults: { serverUrl: "", importedProfileId: "" } });
  }

  getServerUrl(): string {
    return this.store.get("serverUrl", "");
  }

  getImportedProfileId(): string {
    return this.store.get("importedProfileId", "");
  }

  setImportedProfileId(id: string): void {
    this.store.set("importedProfileId", id);
  }

  useManagedProfile(): void {
    this.store.set("importedProfileId", MANAGED_PROFILE_SELECTION);
  }

  isManagedProfileSelected(): boolean {
    return this.getImportedProfileId() === MANAGED_PROFILE_SELECTION;
  }

  // validateServerUrl checks shape + a live /healthz and reports whether the
  // change would require a forced re-login. It does NOT persist.
  async validateServerUrl(raw: string, hasCredential: boolean): Promise<{ url: string; reloginRequired: boolean; wasUnset: boolean }> {
    const current = this.getServerUrl();
    const url = await validateServer(raw, (u) => fetch(u, { method: "GET" }));
    return { url, reloginRequired: serverChangeRequiresRelogin(current, url, hasCredential), wasUnset: current === "" };
  }

  // commitServerUrl persists a URL that validateServerUrl already accepted.
  commitServerUrl(url: string): void {
    this.store.set("serverUrl", normalizeServerUrl(url));
  }

  requireServerUrl(): string {
    const u = this.getServerUrl();
    if (!u) throw new Error("no server configured");
    return normalizeServerUrl(u);
  }
}
