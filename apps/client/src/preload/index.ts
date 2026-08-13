import { contextBridge, ipcRenderer } from "electron";

// The ONLY privileged surface exposed to the renderer (contextIsolation on,
// nodeIntegration off, sandbox on). VERB-SPECIFIC + promise-based — NO generic
// invoke(channel, args) passthrough, which would make the allowlist decorative.
// The raw bearer token is NEVER exposed here (no getToken): main attaches it on
// requests via the session injector. tunnel.* is reserved for S6.3.
const api = {
  auth: {
    login: (): Promise<{ fingerprint: string; expiresAt: string }> => ipcRenderer.invoke("auth:login"),
    logout: (): Promise<void> => ipcRenderer.invoke("auth:logout"),
    removeDevice: (): Promise<void> => ipcRenderer.invoke("auth:removeDevice"),
    status: (): Promise<{ loggedIn: boolean; expired?: boolean; fingerprint?: string; expiresAt?: string; secureStorage: boolean }> =>
      ipcRenderer.invoke("auth:status"),
  },
  // ⛔ TROUBLESHOOTING IS A FEATURE, NOT A DOCS PAGE. A user who hits a failure needs the log in
  // one click; telling them a path in a README means the path is wrong the moment it changes, and
  // this one already sent someone to the wrong directory once (npm SCOPE, not product name).
  diag: {
    logPath: (): Promise<string> => ipcRenderer.invoke("diag:logPath"),
    openLogs: (): Promise<void> => ipcRenderer.invoke("diag:openLogs"),
    readLog: (): Promise<string> => ipcRenderer.invoke("diag:readLog"),
    /** Resolves to the chosen path, or null if the user cancelled the save dialog. */
    exportLog: (): Promise<string | null> => ipcRenderer.invoke("diag:exportLog"),
    appInfo: (): Promise<AppInfo> => ipcRenderer.invoke("diag:appInfo"),
    checkRelease: (): Promise<ReleaseCheck> => ipcRenderer.invoke("diag:checkRelease"),
    openReleaseDownload: (): Promise<void> => ipcRenderer.invoke("diag:openReleaseDownload"),
  },
  config: {
    getServerUrl: (): Promise<string> => ipcRenderer.invoke("config:getServerUrl"),
    setServerUrl: (url: string): Promise<{ url: string; reloginRequired: boolean }> => ipcRenderer.invoke("config:setServerUrl", url),
  },
  // S6.3 tunnel control. Verb-specific like the rest — up/down/status only. The
  // renderer holds NO tunnel secret: main resolves the WG config (bearer-fetched)
  // and forwards it to the privileged helper; the renderer only sees status.
  tunnel: {
    // fullTunnel is the split-tunnel toggle INTENT (S6.4); it only takes effect when
    // a device is minted (get-or-create) — an existing config is reused as-is.
    up: (fullTunnel = false): Promise<TunnelStatus> => ipcRenderer.invoke("tunnel:up", fullTunnel),
    down: (): Promise<void> => ipcRenderer.invoke("tunnel:down"),
    status: (): Promise<TunnelStatus> => ipcRenderer.invoke("tunnel:status"),
    // ⛔ THE RENDERER NEVER SEES THE FILE. It asks main to open a picker and parse; the WireGuard
    // private key inside stays in main, the same rule the minted path already follows.
    importConfig: (): Promise<ImportedProfile | null> => ipcRenderer.invoke("tunnel:importConfig"),
    importedInfo: (): Promise<ImportedProfile | null> => ipcRenderer.invoke("tunnel:importedInfo"),
    importedProfiles: (): Promise<ImportedProfile[]> => ipcRenderer.invoke("tunnel:importedProfiles"),
    selectImportedProfile: (id: string): Promise<ImportedProfile[]> => ipcRenderer.invoke("tunnel:selectImportedProfile", id),
    useManagedProfile: (): Promise<ImportedProfile[]> => ipcRenderer.invoke("tunnel:useManagedProfile"),
    forgetImported: (id?: string): Promise<ImportedProfile[]> => ipcRenderer.invoke("tunnel:forgetImported", id),
    // Push channel for live status + the LOUD fail-closed signal (main forwards
    // the helper heartbeat / onLost). Returns an unsubscribe fn. Carries no secret.
    onStatusChanged: (cb: (s: TunnelStatus) => void): (() => void) => {
      const listener = (_e: unknown, s: TunnelStatus) => cb(s);
      ipcRenderer.on("tunnel:status-changed", listener);
      return () => ipcRenderer.removeListener("tunnel:status-changed", listener);
    },
  },
};

// TunnelStatus mirrors apps/helper (no secrets — never carries key material).
// "revoked" is CLIENT-synthesized (the helper never emits it): main sets it when the
// proactive revocation monitor detects this device was revoked/deleted server-side.
/** What main reports about an imported profile — never the key material. */
export interface ImportedProfile {
  id: string;
  name: string;
  address?: string;
  endpoint?: string;
  fullTunnel: boolean;
  active: boolean;
}

export interface AppInfo {
  version: string;
  update:
    | { kind: "disabled"; reason: string; detail: string }
    | { kind: "no_feed"; reason: string; detail: string }
    | { kind: "ready" };
}

export type ReleaseCheck =
  | { kind: "available"; version: string }
  | { kind: "current"; version: string }
  | { kind: "unavailable"; reason: string };

export interface TunnelStatus {
  state: "down" | "up" | "failed" | "revoked" | "pending_approval" | "migrate_failed" | "posture_warning" | "posture_blocked";
  interface?: string;
  last_handshake_sec?: number;
  rx_bytes?: number;
  tx_bytes?: number;
  // ⛔ THE TYPE OMITTED A FIELD THAT WAS ALREADY BEING SENT. `TunnelController.withAddress`
  // decorates every status with the device's tunnel address, and this mirror never declared it —
  // so the renderer received the value and TypeScript said it did not exist. A type that
  // under-describes the wire is the same defect as one that over-describes it, just quieter: the
  // data is there, and the only thing missing is permission to use it.
  address?: string;
  failed_checks?: Array<{ kind: string; mode: string }>;
}

contextBridge.exposeInMainWorld("tunnex", api);

export type TunnexBridge = typeof api;
