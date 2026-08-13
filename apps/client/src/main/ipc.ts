import * as fs from "node:fs";
import { randomUUID } from "node:crypto";
import * as path from "node:path";
import { ipcMain, BrowserWindow, dialog } from "electron";
import { parseWgConf } from "./wgconf";
import { Config, MANAGED_PROFILE_SELECTION } from "./config";
import { CredentialStore } from "./credential";
import { runLogin, runLogout } from "./login";
import { TunnelController, helperSocketPath } from "./tunnel";
import { TunnelConfigStore, importedProfileOrigin } from "./tunnelstore";
import { HttpDeviceApi } from "./httpdeviceapi";
import { resolveTunnelConfig, removeManagedTunnelConfigForOrigin, migrateLegacyConfig, DeviceRevokedError, PendingApprovalError } from "./deviceconfig";
import { signOutPreservingDevice } from "./sessionlifecycle";
import { RevocationMonitor } from "./revocation";
import { RoutedRangesMonitor } from "./routedrangesmonitor";
import { ApprovalMonitor } from "./approvalmonitor";
import { HealthMonitor } from "./healthmonitor";
import type { HealthFacts, HealthReportResult } from "./deviceconfig";
import { postureBlockedOverridesTransport, postureVisibilityChanged, postureVisibilityFor, postureWarningOverridesTransport, type PostureVisibility } from "./posturevisibility";
import { ensureHelperInstalled } from "./helperinstall";
import { postServerUrlAction } from "./entry";
import { notifyTunnel } from "./notify";
import { trayStateFor, type TrayState } from "./tray";
import type { TunnelStatus } from "./helperclient";

// Desktop default: split-tunnel (org network only), matching the CLI default. The UI
// may pass a full-tunnel INTENT at connect (S6.4 split-tunnel toggle); the helper
// enforces both-family completeness when it IS full. Switching split↔full preserves
// the device identity and changes its issued routing mode.
const DEFAULT_FULL_TUNNEL = false;

// ClientTunnelStatus is what main forwards: the helper's TunnelStatus plus the
// client-synthesized states the helper never emits — "revoked", "pending_approval",
// (S7.3: enrolled but awaiting admin approval; the helper is never armed for it), and
// "migrate_failed" (S7.3: a legacy-config replacement didn't complete — the ONE bounded
// failure outcome of the migration path, made legible in the window/tray so it never
// reads as a bare "Disconnected"; the helper is never armed for it).
type ClientTunnelStatus =
  | TunnelStatus
  | { state: "revoked" }
  | { state: "pending_approval" }
  | { state: "migrate_failed" }
  | { state: "posture_warning"; failed_checks: HealthReportResult["failed_checks"] }
  | { state: "posture_blocked"; failed_checks: HealthReportResult["failed_checks"] };

// TunnelControls is what registerIpc returns so the tray (built in index.ts) can drive
// the SAME connect/disconnect path the renderer uses — no duplicated tunnel logic, one
// source of truth for monitor + notification + state emission.
export interface TunnelControls {
  connect(fullTunnel: boolean): Promise<ClientTunnelStatus>;
  disconnect(): Promise<void>;
  currentState(): TrayState;
  subscribe(cb: (s: TrayState) => void): () => void;
}

// The IPC handlers behind the preload allowlist. VERB-SPECIFIC — there is no generic
// invoke(channel,args); each channel validates its own inputs in main (never trust the
// renderer). Registered ONCE at app ready (ipcMain is app-global). `getWindow` resolves
// the CURRENT window (or null when closed) so the tunnel + monitor outlive any window.
export function registerIpc(
  getWindow: () => BrowserWindow | null,
  config: Config,
  store: CredentialStore,
  tunnelStore: TunnelConfigStore,
): TunnelControls {
  // The bearer is bound to the origin it was minted against (store.load().server);
  // build the device API + resolve config against exactly that origin so a config
  // is never fetched/used cross-origin.
  const deviceApiFor = (origin: string) => new HttpDeviceApi(origin, () => store.load()?.token ?? null);

  const activeImportedProfile = () => {
    const selected = config.getImportedProfileId();
    if (selected === MANAGED_PROFILE_SELECTION) return null;
    const active = selected ? tunnelStore.importedProfile(selected) : null;
    // RC20 and earlier had one profile at imported:local. Preserve it across upgrade
    // until the user explicitly selects/removes a profile; never guess between new rows.
    return active ?? (!selected ? tunnelStore.importedProfile("legacy") : null);
  };

  const importedProfileSummary = () =>
    tunnelStore.importedProfiles().map((profile) => ({
      id: profile.id,
      name: profile.name,
      address: profile.config.address,
      endpoint: profile.config.endpoint,
      fullTunnel: profile.config.full_tunnel,
      active: activeImportedProfile()?.id === profile.id,
    }));

  // --- tunnel state fan-out (renderer push channel + tray subscribers) -----------
  const subscribers = new Set<(s: TrayState) => void>();
  let trayState: TrayState = "disconnected";
  // lastSynth holds a CLIENT-synthesized state so it
  // survives a renderer remount/reload: the helper can't report "revoked", so
  // tunnel:status returns this until the next connect/disconnect clears it.
  let lastSynth: Exclude<ClientTunnelStatus, TunnelStatus> | null = null;
  // A posture verdict is policy state layered over a live helper status. Retain
  // that helper payload so a warning cannot blank the graph and counters.
  let lastTransport: TunnelStatus | null = null;

  const emitTray = (s: TrayState): void => {
    trayState = s;
    for (const cb of subscribers) cb(s);
  };
  // pushRenderer sends to the live window's onStatusChanged channel. GUARDED: a closed/
  // destroyed window is a no-op (never throws) — so callers' tray + notification side
  // effects always run, they don't ride behind a throwing send.
  const pushRenderer = (s: ClientTunnelStatus): void => {
    const w = getWindow();
    if (!w || w.isDestroyed()) return;
    try {
      w.webContents.send("tunnel:status-changed", s);
    } catch {
      /* webContents torn down mid-send — the tray/notification path still runs */
    }
  };
  // emit forwards a status to BOTH the renderer and the tray. The tray reflects the
  // handshake-liveness nuance (up-but-stale → "connecting") so it never disagrees with
  // the window (trayStateFor mirrors TunnelControl's derivation).
  const emit = (s: ClientTunnelStatus): void => {
    // A policy block is authoritative over helper transport chatter. The
    // gateway has already removed this peer, and a following heartbeat's
    // generic up/down must not replace the explicit posture remedy with a
    // misleading "Disconnected" screen. Explicit disconnect clears lastSynth
    // first; a compliant health verdict does the same.
    const postureOverridesTransport =
      (lastSynth?.state === "posture_blocked" && postureBlockedOverridesTransport(s.state)) ||
      (lastSynth?.state === "posture_warning" && postureWarningOverridesTransport(s.state));
    const visible = postureOverridesTransport
      // Warn mode deliberately leaves the tunnel alive, so keep its measured
      // transport fields. Require-mode block must never reuse stale traffic as
      // though the now-removed peer were still connected.
      ? (lastSynth?.state === "posture_warning"
          ? ({ ...(lastTransport ?? {}), ...lastSynth } as ClientTunnelStatus)
          : lastSynth!)
      : s;
    pushRenderer(visible);
    emitTray(trayStateFor(visible));
  };

  // --- revocation monitor (proactive, client-side; S6.4) -------------------------
  let monitor: RevocationMonitor | null = null;
  let routedRangesMonitor: RoutedRangesMonitor | null = null; // S8.5: volatile-routes poll (split-tunnel only)
  const stopMonitor = (): void => {
    monitor?.stop();
    monitor = null;
    routedRangesMonitor?.stop();
    routedRangesMonitor = null;
  };
  // onRevoked is the definitive-gone teardown: tear the dead tunnel down, retain a local
  // terminal revocation marker (never auto-enroll around an administrator's decision), then surface the distinct revoked state LOUDLY
  // (renderer banner + tray + notification). All best-effort; the local state is
  // authoritative. Runs at most once per monitor (RevocationMonitor fires once).
  const onRevoked = async (origin: string): Promise<void> => {
    stopMonitor();
    stopHealthMonitor(); // the device is gone — nothing left to report on
    await tunnel.down().catch(() => {});
    const sc = tunnelStore.get(origin);
    if (sc) tunnelStore.put({ ...sc, pending: false, revoked: true });
    lastSynth = { state: "revoked" }; // survive a renderer remount until next connect/disconnect
    emit({ state: "revoked" });
    notifyTunnel("revoked");
  };

  // --- awaiting-approval poll (S7.3 — sibling of the revocation monitor) ----------
  // App-level SINGLETON (never per-window, the S6.4 root-fix class). Runs only while a
  // pending device is awaiting approval for the current origin; stops on resolution.
  let approvalMonitor: ApprovalMonitor | null = null;
  const stopApprovalMonitor = (): void => {
    approvalMonitor?.stop();
    approvalMonitor = null;
  };
  // onApproved: the admin approved the device. Clear the pending flag so a user-initiated
  // connect reuses the SAME stored config (no re-mint), surface it, notify. Deliberately
  // does NOT auto-connect — a background poll must never arm the kill-switch / trigger the
  // helper privilege flow; the human clicks Connect.
  const onApproved = (origin: string): void => {
    stopApprovalMonitor();
    const sc = tunnelStore.get(origin);
    if (sc?.pending) tunnelStore.put({ ...sc, pending: false });
    lastSynth = null;
    emit({ state: "down" }); // now connectable
    notifyTunnel("approved");
  };
  // onRejected: the pending device was rejected/deleted — a genuine revocation. Route
  // through the ONE teardown path (onRevoked): clear the dead config + best-effort revoke
  // + the loud revoked notification. (No tunnel is up; tunnel.down is a no-op.)
  const onRejected = async (origin: string): Promise<void> => {
    stopApprovalMonitor();
    await onRevoked(origin);
  };

  // --- device-health report monitor (S7.5.3 — sibling of the revocation monitor) --
  // App-level SINGLETON. Runs while connected; self-reports posture facts on the
  // 10-min jittered cadence. Stops on disconnect / logout / origin change, and
  // stops ITSELF on a terminal server answer (403 open-edition / 404 gone).
  let healthMonitor: HealthMonitor | null = null;
  // postureVisibility latches the server verdict so repeated report cycles do not
  // spam alerts. lastSynth makes a warning/block survive a renderer reload.
  let postureVisibility: PostureVisibility = "clear";
  const stopHealthMonitor = (): void => {
    healthMonitor?.stop();
    healthMonitor = null;
    postureVisibility = "clear";
  };
  // onHealthResult makes BOTH warn-mode and require-mode posture failures visible.
  // Native macOS notifications are best effort; this status path is what guarantees
  // a warning/block remains visible inside the client and its tray.
  const onHealthResult = (r: HealthReportResult): void => {
    const next = postureVisibilityFor(r);
    if (!postureVisibilityChanged(postureVisibility, next)) return;
    postureVisibility = next;
    if (next === "clear") {
      lastSynth = null;
      emit({ state: "up" });
      return;
    }
    const state = next === "blocked"
      ? ({ state: "posture_blocked", failed_checks: r.failed_checks } as const)
      : ({ state: "posture_warning", failed_checks: r.failed_checks } as const);
    lastSynth = state;
    emit(state);
    notifyTunnel(next === "blocked" ? "posture_blocked" : "posture_warning", r.failed_checks);
  };
  // collectHealthFacts gathers what main can read directly (platform, OS product
  // version) + the privileged fact via the helper's read-only posture verb. A fact
  // that can't be determined (helper old/unreachable, query failed) is OMITTED —
  // reported absent, never guessed (the taxonomy's absence class).
  const collectHealthFacts = async (): Promise<HealthFacts> => {
    const platform =
      process.platform === "darwin" ? "macos" : process.platform === "win32" ? "windows" : process.platform === "linux" ? "linux" : "other";
    const os_version = (process as NodeJS.Process & { getSystemVersion?: () => string }).getSystemVersion?.() ?? "";
    const facts: HealthFacts = { platform, os_version };
    try {
      const p = await tunnel.posture();
      if (typeof p.disk_encrypted === "boolean") facts.disk_encrypted = p.disk_encrypted;
    } catch {
      /* helper old (unknown_verb) or unreachable — the fact stays absent */
    }
    return facts;
  };

  // --- the tunnel controller -----------------------------------------------------
  let requestedFullTunnel = DEFAULT_FULL_TUNNEL; // set by connect() before up()
  const tunnel = new TunnelController(
    helperSocketPath(),
    async () => {
      // ⛔ AN IMPORTED PROFILE SHORT-CIRCUITS THE MINT PATH — AND ONLY THAT PATH.
      //
      // It has no credential, so the check below would reject it; it has no deviceId, so
      // resolveTunnelConfig would drop it as a legacy config and try to create a fresh device.
      // Both are correct for a minted config and wrong for this one. Returned as-is: the file is
      // the whole truth about this tunnel, which is exactly why the mode is degraded.
      const imported = activeImportedProfile();
      if (imported) return imported.config;
      const cred = store.load();
      if (!cred) throw new Error("not_authenticated");
      return resolveTunnelConfig(cred.server, requestedFullTunnel, deviceApiFor(cred.server), tunnelStore);
    },
    (status) => {
      // Live heartbeat status + the LOUD fail-closed signal (onLost → state "failed").
      lastTransport = status;
      emit(status);
      if (status.state === "failed") {
        // The helper died / fail-closed: the monitor is moot (no tunnel to watch) and
        // the user must be told loudly. onLost fires once, so this fires once.
        // The health monitor is connection-scoped too (its posture reads ride the
        // same helper connection) — it restarts on the next connect.
        stopMonitor();
        stopHealthMonitor();
        notifyTunnel("failed");
      }
    },
  );

  const connect = async (fullTunnel: boolean): Promise<ClientTunnelStatus> => {
    // First-connect on an unsigned macOS build: install the privileged helper via one
    // GUI admin prompt (no-op if already installed / off macOS). Throws
    // helper_install_canceled|failed|asset_missing → surfaced by the renderer.
    await ensureHelperInstalled();
    // Stop any prior monitors FIRST, unconditionally — even if we can't resolve a new
    // deviceId below, an old monitor must not linger and later tear down THIS tunnel.
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    lastSynth = null; // a fresh connect clears any stale revoked/pending state
    requestedFullTunnel = fullTunnel;
    // LEGACY MIGRATION (reduction 2, TERMINAL FORM — outcome-degraded): a stored config from
    // before the orgId field can't be monitored. Handle it DETERMINISTICALLY AT DETECTION,
    // terminal for THIS connect — there is NO tunnel.up on the legacy path, so no helper-arm
    // failure can race the notice, no create/revoke atomicity, no cap collision. migrateLegacyConfig
    // is REVOKE-FIRST (frees the per-user cap slot before clearing; config KEPT on any failure so
    // the slot handle survives). This block degrades on OUTCOME, not error type — there are exactly
    // TWO outcomes, both bounded and both ending in a connectable "down":
    //   completed        -> "migrated"; the NEXT connect is an ordinary fresh create (slot free, orgId present)
    //   failed FOR ANY REASON -> config KEPT + honest recoverable down ("couldn't replace device;
    //                            reconnect to retry / contact admin if it persists")
    // We do NOT catch-and-branch on which error it was: a failed migration is a failed migration.
    // This structurally removes the two failure classes the whole arc produced — there is NO path
    // from a failed migration to (a) a raw renderer reject or (b) an unbounded loop. Transient
    // self-heals on the next connect; persistent is bounded-by-honest-message, never a crash, never
    // a silent lockout. (Fourth and final touch on this surface — see docs/S7.3-decisions.md.)
    const preCred = store.load();
    if (preCred) {
      const preSc = tunnelStore.get(preCred.server);
      if (preSc && !preSc.orgId) {
        try {
          await migrateLegacyConfig(preCred.server, preSc.deviceId, deviceApiFor(preCred.server), tunnelStore);
          notifyTunnel("migrated");
          const down: ClientTunnelStatus = { state: "down" };
          emit(down);
          return down; // terminal — next connect is an ordinary fresh create
        } catch {
          // ANY failure -> the ONE bounded outcome ("not replaced"). Config is still stored
          // (revoke-first kept it), so the next connect re-detects + retries; the slot handle
          // is retained. No re-throw, no branch on error type. Surface it as a DISTINCT synth
          // state (mirrors "revoked"/"pending_approval") so the window/tray shows it legibly
          // even when OS notifications are off — never a bare "Disconnected". Latched so it
          // survives a renderer remount until the next connect/disconnect.
          notifyTunnel("migrate_retry");
          const s: ClientTunnelStatus = { state: "migrate_failed" };
          lastSynth = s;
          emit(s);
          return s; // terminal — the user reconnects to retry the update
        }
      }
    }
    let status: TunnelStatus;
    try {
      status = await tunnel.up(); // resolves + persists the device, arms the helper
    } catch (e) {
      if (e instanceof DeviceRevokedError) {
        const revoked: ClientTunnelStatus = { state: "revoked" };
        lastSynth = revoked;
        emit(revoked);
        notifyTunnel("revoked");
        return revoked;
      }
      // S7.3 GATE: the device is awaiting admin approval. resolveTunnelConfig threw BEFORE
      // arming the helper (no dead tunnel, no RevocationMonitor that would misread pending
      // as revoked). Show the stable awaiting state + start the ApprovalMonitor instead.
      if (e instanceof PendingApprovalError) {
        const cred = store.load();
        const pending: ClientTunnelStatus = { state: "pending_approval" };
        lastSynth = pending;
        emit(pending);
        notifyTunnel("pending");
        if (cred) {
          const orgId = tunnelStore.get(cred.server)?.orgId ?? ""; // persisted before the throw
          approvalMonitor = new ApprovalMonitor(
            e.deviceId,
            orgId,
            deviceApiFor(cred.server),
            () => onApproved(cred.server),
            () => onRejected(cred.server),
          );
          approvalMonitor.start();
        }
        return pending;
      }
      throw e;
    }
    // Start the proactive revocation monitor for the device we just brought up.
    const cred = store.load();
    const sc = cred ? tunnelStore.get(cred.server) : undefined;
    if (cred && sc?.deviceId) {
      monitor = new RevocationMonitor(sc.deviceId, sc.orgId, deviceApiFor(cred.server), () => onRevoked(cred.server));
      monitor.start();
      // S8.5 routed-subnets push (#5: runs in BOTH modes): poll the org's declared ranges + reachable DNS
      // forwards and live-apply each tier via the helper — ranges → set_allowed_ips, forwards →
      // set_resolvers. The ROUTES tier is enabled only for SPLIT-tunnel (a full tunnel's 0.0.0.0/0 subsumes
      // every range — no route calls). The RESOLVER tier runs in BOTH: full-tunnel's baked DNS (1.1.1.1)
      // cannot answer internal cross-site zones, so it needs the forwards just as split-tunnel does.
      routedRangesMonitor = new RoutedRangesMonitor(
        sc.orgId,
        tunnel.baseAllowedIPs(),
        deviceApiFor(cred.server),
        (set) => tunnel.setAllowedIPs(set),
        (fwds) => tunnel.setResolvers(fwds),
        undefined, // baseMs (default cadence)
        undefined, // maxMs (default ceiling)
        undefined, // setTimer (default)
        undefined, // clearTimer (default)
        !requestedFullTunnel, // routesEnabled: routes tier split-only; resolver tier always
        sc.deviceId, // WF-A: scope the dial to THIS device
        (endpoint, pubkey) => tunnel.setGatewayPeer(pubkey, endpoint), // WF-A: re-home on active-hub move
        true, // dialEnabled: BOTH modes now (D-WFA-4 carve-out landed); the helper refuses a full-tunnel
        //        re-home only where its carve-out is absent (Windows) → the dial tier fail-statics there.
        { endpoint: sc.config.endpoint, pubkey: sc.config.peer_public_key }, // seed = the minted peer
      );
      routedRangesMonitor.start();
      // S7.5.3: self-report posture while connected. First report early (~15s),
      // then every 10min (+ fixed jitter). Terminal 403 (open edition) stops it
      // until the next connect. onHealthResult surfaces a require-mode block as the
      // posture_blocked state so a server-side disconnect is never silent ([2]).
      healthMonitor = new HealthMonitor(sc.deviceId, sc.orgId, deviceApiFor(cred.server), collectHealthFacts, onHealthResult);
      healthMonitor.start();
    }
    lastTransport = status;
    emit(status);
    notifyTunnel("connected");
    return status;
  };

  const disconnect = async (): Promise<void> => {
    stopMonitor();
    stopApprovalMonitor(); // also cancel any awaiting-approval poll (disconnect = stop waiting)
    stopHealthMonitor();
    lastSynth = null;
    await tunnel.down();
    emit({ state: "down" });
    notifyTunnel("disconnected");
  };

  // --- auth --------------------------------------------------------------------
  ipcMain.handle("auth:status", () => {
    const cred = store.load();
    if (!cred) return { loggedIn: false, secureStorage: store.available() };
    const expired = CredentialStore.isExpired(cred, new Date());
    return { loggedIn: !expired, expired, fingerprint: cred.fingerprint, expiresAt: cred.expiresAt, secureStorage: store.available() };
  });

  ipcMain.handle("auth:login", async () => {
    const server = config.requireServerUrl(); // throws if unset
    const r = await runLogin(server, store);
    getWindow()?.webContents.reload(); // the injected bearer now authenticates the SPA
    return r;
  });

  ipcMain.handle("auth:logout", async () => {
    // Sign-out is session-only. The encrypted device config stays so the next sign-in
    // can validate and reuse the same server-side device instead of minting another row.
    try {
      await signOutPreservingDevice({
        stopMonitors: () => { stopMonitor(); stopApprovalMonitor(); stopHealthMonitor(); },
        clearSynthesizedState: () => { lastSynth = null; },
        downTunnel: () => tunnel.down(),
        emitDisconnected: () => emitTray("disconnected"),
        logoutSession: () => runLogout(store),
      });
    } finally {
      getWindow()?.webContents.reload();
    }
  });

  ipcMain.handle("auth:removeDevice", async () => {
    const cred = store.load();
    if (!cred) throw new Error("not_authenticated");
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    lastSynth = null;
    await tunnel.down().catch(() => {});
    emitTray("disconnected");
    await removeManagedTunnelConfigForOrigin(cred.server, deviceApiFor(cred.server), tunnelStore);
  });

  // --- tunnel (S6.3 control + S6.4 UX) -----------------------------------------
  ipcMain.handle("tunnel:up", (_e, fullTunnel: unknown) => connect(fullTunnel === true));
  ipcMain.handle("tunnel:down", () => disconnect());
  ipcMain.handle("tunnel:status", async () => {
    // A synthesized "revoked" state must survive a renderer remount — the helper only
    // knows up/down/failed, so return the latched synth state until the next connect.
    if (lastSynth)
      return lastSynth.state === "posture_warning"
        ? ({ ...(lastTransport ?? await tunnel.status()), ...lastSynth } as ClientTunnelStatus)
        : lastSynth;
    const status = await tunnel.status();
    lastTransport = status;
    return status;
  });

  // --- config ------------------------------------------------------------------
  ipcMain.handle("config:getServerUrl", () => config.getServerUrl());

  /**
   * ⛔ IMPORT A `.conf` — parsed in MAIN, never in the renderer.
   *
   * The file contains a WireGuard PRIVATE KEY. `parseWgConf` already runs in main for exactly this
   * reason, and the same rule holds here: the renderer asks for a file to be imported and is told
   * whether it worked. It never sees the bytes.
   *
   * ⚠ `full_tunnel` IS INFERRED FROM THE FILE, NOT FROM THE UI TOGGLE. A minted config carries the
   * intent that produced it; an imported one carries only AllowedIPs, so a default route in the
   * file IS the full-tunnel declaration. Taking it from the toggle would let the UI claim a routing
   * mode the file does not implement.
   */
  ipcMain.handle("tunnel:importConfig", async () => {
    const res = await dialog.showOpenDialog({
      title: "Import a WireGuard configuration",
      filters: [{ name: "WireGuard", extensions: ["conf"] }],
      properties: ["openFile"],
    });
    if (res.canceled || res.filePaths.length === 0) return null;
    const text = fs.readFileSync(res.filePaths[0], "utf8");
    const parsed = parseWgConf(text); // strict — throws rather than half-parsing
    const fullTunnel = (parsed.allowed_ips ?? []).some(
      (a) => a === "0.0.0.0/0" || a === "::/0",
    );
    const id = randomUUID();
    const name = path.basename(res.filePaths[0], ".conf").trim().slice(0, 120) || "Imported profile";
    tunnelStore.put({
      origin: importedProfileOrigin(id),
      deviceId: "",
      orgId: "",
      config: { ...parsed, full_tunnel: fullTunnel },
      imported: true,
      importedName: name,
    });
    // Preserve the old single-import behaviour for a first profile. Adding another
    // profile must never silently drop a live connection; the user selects it first.
    if (!activeImportedProfile() && !config.isManagedProfileSelected()) config.setImportedProfileId(id);
    return { id, name, address: parsed.address, endpoint: parsed.endpoint, fullTunnel, active: activeImportedProfile()?.id === id };
  });

  ipcMain.handle("tunnel:importedProfiles", () => importedProfileSummary());

  ipcMain.handle("tunnel:selectImportedProfile", async (_e, rawId: unknown) => {
    if (typeof rawId !== "string" || !/^(legacy|[0-9a-f-]{36})$/i.test(rawId)) throw new Error("invalid_imported_profile");
    if (!tunnelStore.importedProfile(rawId)) throw new Error("imported_profile_not_found");
    // Switching is a deliberate disconnect. Stop every old-profile monitor before
    // changing the selected origin so it cannot mutate the next profile's state.
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    await tunnel.down().catch(() => {});
    config.setImportedProfileId(rawId);
    lastSynth = null;
    emitTray("disconnected");
    return importedProfileSummary();
  });

  /** Choose the enrolled-account path without deleting any imported WireGuard file. */
  ipcMain.handle("tunnel:useManagedProfile", async () => {
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    await tunnel.down().catch(() => {});
    config.useManagedProfile();
    lastSynth = null;
    emitTray("disconnected");
    return importedProfileSummary();
  });

  /** Remove one imported profile. Removing the active profile tears down its key first. */
  ipcMain.handle("tunnel:forgetImported", async (_e, rawId?: unknown) => {
    const id = rawId === undefined ? activeImportedProfile()?.id : rawId;
    if (typeof id !== "string" || !/^(legacy|[0-9a-f-]{36})$/i.test(id)) throw new Error("invalid_imported_profile");
    const profile = tunnelStore.importedProfile(id);
    if (!profile) throw new Error("imported_profile_not_found");
    if (activeImportedProfile()?.id === id) {
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      await tunnel.down().catch(() => {});
      config.setImportedProfileId("");
      lastSynth = null;
    }
    tunnelStore.remove(importedProfileOrigin(id));
    emitTray("disconnected");
    return importedProfileSummary();
  });

  /** Legacy, active-profile-only read retained for pre-multiple-profile renderers. */
  ipcMain.handle("tunnel:importedInfo", () => {
    const profile = activeImportedProfile();
    return profile
      ? { id: profile.id, name: profile.name, address: profile.config.address, endpoint: profile.config.endpoint, fullTunnel: profile.config.full_tunnel, active: true }
      : null;
  });


  ipcMain.handle("config:setServerUrl", async (_e, url: unknown) => {
    if (typeof url !== "string" || url.length === 0 || url.length > 2000) {
      throw new Error("invalid server url");
    }
    const hasCred = store.load() !== null;
    const { url: accepted, reloginRequired, wasUnset } = await config.validateServerUrl(url, hasCred);
    // A credential must never reach a server it wasn't minted against: on a real
    // change, revoke + clear the old credential BEFORE the new URL is persisted,
    // so there is no window where (origin=new, credential=old) can attach.
    if (reloginRequired) {
      // Stop BOTH monitors + tunnel (they belong to the OLD origin) — the awaiting-approval
      // poll must also stop, else it keeps polling the old origin with a stale bearer
      // (finding #5: origin-lifecycle stop). Per the signed-off amendment we do NOT
      // auto-revoke the old-origin device/config — it stays origin-keyed for the UI.
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      lastSynth = null;
      await tunnel.down().catch(() => {});
      emitTray("disconnected");
      await runLogout(store);
    }
    config.commitServerUrl(accepted);
    // First run (unset → set) must LOAD the renderer — reload() would re-load the
    // current (setup data:) URL and cannot change origin. Otherwise a plain
    // reload picks up the new auth/config state.
    //
    // ⛔ THIS LINE STILL SAID `index.html` AFTER STEP 3 — so the FIRST RUN, the one path every new
    // install takes, landed on the web dashboard and only a second launch reached the client. One
    // constant now, in entry.ts, because two literals in two files are two constants.
    const w = getWindow();
    const act = postServerUrlAction(wasUnset);
    if (act.kind === "load") {
      void w?.loadURL(act.url);
    } else {
      w?.webContents.reload();
    }
    return { url: accepted, reloginRequired };
  });

  return {
    connect,
    disconnect,
    currentState: () => trayState,
    subscribe: (cb) => {
      subscribers.add(cb);
      return () => subscribers.delete(cb);
    },
  };
}
