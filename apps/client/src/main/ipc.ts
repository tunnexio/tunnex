import * as fs from "node:fs";
import { randomUUID } from "node:crypto";
import * as path from "node:path";
import { ipcMain, BrowserWindow, dialog } from "electron";
import { Config, MANAGED_PROFILE_SELECTION } from "./config";
import { CredentialStore } from "./credential";
import type { EnrollmentAnchorStore } from "./enrollmentanchor";
import { runLogin, runLogout } from "./login";
import { TunnelController, helperSocketPath } from "./tunnel";
import { TunnelConfigStore, importedProfileOrigin } from "./tunnelstore";
import { HttpDeviceApi } from "./httpdeviceapi";
import {
  commitManagedDeviceOwnerProof,
  consumeManagedEnrollmentAbandonProof,
  enrollmentAnchorOrganizationForUser,
  proveManagedDeviceOwner,
  proveManagedEnrollmentAbandonment,
  proveLegacyManagedDeviceOwner,
  revokeAndClearManagedDevice,
  revokeAndClearLegacyManagedDevice,
  resolveTunnelConfig,
  parseImportedTunnelConfig,
  DeviceRevokedError,
  PendingApprovalError,
  type LegacyManagedDeviceProof,
  type ManagedEnrollmentAbandonProof,
  type ManagedDeviceOwnerProof,
} from "./deviceconfig";
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
import type { TunnelConfig, TunnelStatus } from "./helperclient";
import { ManagedOrganizationSelector, NoOrganizationError, OrganizationSelectionRequiredError, type LiveOrganization } from "./orgselection";
import {
  ManagedLifecycleCoordinator,
  StaleManagedLeaseError,
  type ManagedLease,
} from "./managedlifecycle";
import {
  buildManagedConnectPreparation,
  runManagedConnectFlow,
  runManagedDisconnectFlow,
  runManagedRemoveFlow,
  runTerminalRevocationFlow,
  type FixedManagedConnectContext,
} from "./managedlifecycleflows";
import { projectTransportStatus, SingleFlightStatusReader } from "./statusreader";
import { isCanonicalUuid } from "./uuid";

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

type ManagedConnectContext = FixedManagedConnectContext<HttpDeviceApi> & {
  readonly ownerProof: ManagedDeviceOwnerProof | null;
};

type ManagedRemoveContext =
  | { readonly kind: "bound"; readonly proof: ManagedDeviceOwnerProof; readonly api: HttpDeviceApi }
  | { readonly kind: "legacy"; readonly proof: LegacyManagedDeviceProof }
  | { readonly kind: "anchor"; readonly proof: ManagedEnrollmentAbandonProof; readonly api: HttpDeviceApi };

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
  showWindow: () => BrowserWindow,
  config: Config,
  store: CredentialStore,
  tunnelStore: TunnelConfigStore,
  enrollmentAnchorStore: EnrollmentAnchorStore,
  lifecycle: ManagedLifecycleCoordinator,
): TunnelControls {
  // Every managed API is pinned to the immutable credential carried by the
  // operation lease. No request can observe a later store replacement.
  const deviceApiFor = (lease: ManagedLease) =>
    new HttpDeviceApi(lease.credential.server, lease.credential.token);
  const captureManagedLease = () => lifecycle.capture((credential) =>
    new HttpDeviceApi(credential.server, credential.token).currentUserId());
  const guardedValue = async <T>(lease: ManagedLease, effect: () => Promise<T>): Promise<T> => {
    const value = await lifecycle.guarded(lease, effect);
    if (value === undefined) throw new StaleManagedLeaseError();
    return value;
  };
  const organizationSelector = new ManagedOrganizationSelector({
    get: (key) => config.getManagedOrganizationSelection(key),
    set: (key, organizationId) => config.setManagedOrganizationSelection(key, organizationId),
  });

  const organizationContext = async (lease: ManagedLease): Promise<{
    userId: string;
    organizations: LiveOrganization[];
    enrolledOrganizationId: string | null;
    hasStoredManagedRecord: boolean;
    enrollmentRecoveryRequired: boolean;
  }> => {
    const organizations = await deviceApiFor(lease).organizations();
    lifecycle.assertCurrent(lease);
    const stored = tunnelStore.get(lease.credential.server);
    const anchoredOrganizationId = enrollmentAnchorOrganizationForUser(
      enrollmentAnchorStore.get(lease.credential.server),
      lease.credential.server,
      lease.userId,
    );
    return {
      userId: lease.userId,
      organizations,
      enrolledOrganizationId: stored?.orgId || anchoredOrganizationId,
      hasStoredManagedRecord: (stored !== null && stored.imported !== true) || anchoredOrganizationId !== null,
      enrollmentRecoveryRequired: stored === null && anchoredOrganizationId !== null,
    };
  };

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
  let organizationSelectionRequiredPending = false;
  // lastSynth holds a CLIENT-synthesized state so it
  // survives a renderer remount/reload: the helper can't report "revoked", so
  // tunnel:status returns this until the next connect/disconnect clears it.
  let lastSynth: Exclude<ClientTunnelStatus, TunnelStatus> | null = null;
  // A posture verdict is policy state layered over a live helper status. Retain
  // that helper payload so a warning cannot blank the graph and counters.
  let lastTransport: TunnelStatus | null = null;

  const recordTransportStatus = (status: TunnelStatus): void => {
    const projected = projectTransportStatus(lastSynth, status);
    lastSynth = projected.synthetic;
    lastTransport = projected.transport;
  };

  const emitTray = (s: TrayState): void => {
    trayState = s;
    for (const cb of subscribers) {
      try {
        cb(s);
      } catch {
        /* one stale tray subscriber cannot block transport-truth publication */
      }
    }
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
  // A tray connect has no caller surface for a rejected Promise. Missing tenant
  // choice therefore opens/focuses the client and sends the same explicit event the
  // renderer connect path receives. If the window had to be recreated, wait for its
  // document before sending so the preload listener exists.
  const surfaceOrganizationSelectionRequired = (): void => {
    organizationSelectionRequiredPending = true;
    const w = showWindow();
    const send = (): void => {
      if (w.isDestroyed()) return;
      try {
        w.webContents.send("tunnel:organization-selection-required");
      } catch {
        /* the selection remains discoverable through managedOrganizations() */
      }
    };
    if (w.webContents.isLoading()) {
      w.webContents.once("did-finish-load", send);
    } else {
      send();
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
  // Publish the one truthful state shared by every successful quiescence before
  // any later helper install, server revoke, store write, or profile mutation can
  // fail. Callers invoke this only after tunnel.down() resolves; a teardown
  // refusal therefore preserves the prior renderer, tray, and synthesized state.
  const publishConfirmedDown = (): ClientTunnelStatus => {
    const down: ClientTunnelStatus = { state: "down" };
    lastSynth = null;
    lastTransport = down;
    emit(down);
    return down;
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
  // onRevoked is the definitive-gone teardown. The server verdict is already
  // terminal, but local helper cleanup still has its own truth: only confirmed
  // down may surface Revoked. A refusal is forced fail-closed and surfaced as
  // Failed so retry/cleanup remains actionable rather than falsely claiming down.
  const onRevoked = async (lease: ManagedLease, deviceId: string): Promise<void> => {
    // The monitor's fixed-token read has already established the terminal
    // result. guarded() revalidates its exact credential+epoch before any
    // helper, store, renderer, tray, or notification effect below.
    const origin = lease.credential.server;
    await runTerminalRevocationFlow({
      stopMonitors: () => {
        stopMonitor();
        stopHealthMonitor(); // the device is gone — nothing left to report on
      },
      downTunnel: () => tunnel.down(),
      forceFailClosed: () => tunnel.failClosed(),
      retainTerminalRecord: () => {
        const sc = tunnelStore.get(origin);
        if (
          sc?.deviceId === deviceId &&
          sc.ownerUserId === lease.userId
        ) {
          tunnelStore.put({ ...sc, pending: false, revoked: true });
        }
      },
      publishRevoked: () => {
        lastSynth = { state: "revoked" }; // survive a renderer remount until next connect/disconnect
        emit({ state: "revoked" });
        try {
          notifyTunnel("revoked");
        } catch {
          /* OS notification failure cannot roll back terminal transport truth */
        }
      },
      publishFailed: () => {
        const failed: ClientTunnelStatus = { state: "failed" };
        recordTransportStatus(failed);
        emit(failed);
        try {
          notifyTunnel("failed");
        } catch {
          /* OS notification failure cannot roll back terminal transport truth */
        }
      },
      reportProblems: (problems) => {
        // Preserve exact errors in the flow result for deterministic callers,
        // but keep logs secret-safe: categories are enough to diagnose which
        // independent terminal effects need operator attention.
        console.error(`Terminal revocation incomplete: ${Object.keys(problems).join(", ")}`);
      },
    });
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
  const onApproved = (lease: ManagedLease, deviceId: string): void => {
    stopApprovalMonitor();
    const sc = tunnelStore.get(lease.credential.server);
    if (
      !sc ||
      sc.deviceId !== deviceId ||
      !sc.pending ||
      sc.ownerUserId !== lease.userId
    ) {
      return;
    }
    tunnelStore.put({ ...sc, pending: false });
    lastSynth = null;
    emit({ state: "down" }); // now connectable
    notifyTunnel("approved");
  };
  // onRejected: the pending device was rejected/deleted — a genuine revocation. Route
  // through the ONE teardown path (onRevoked): clear the dead config + best-effort revoke
  // + the loud revoked notification. (No tunnel is up; tunnel.down is a no-op.)
  const onRejected = async (lease: ManagedLease, deviceId: string): Promise<void> => {
    stopApprovalMonitor();
    await onRevoked(lease, deviceId);
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
  // The controller is app-lifetime, but every up receives its own immutable
  // provider. activeManagedLease only labels heartbeat/onLost effects; it never
  // supplies credentials or enrollment inputs.
  let activeManagedLease: ManagedLease | null = null;
  const applyTunnelStatus = (status: TunnelStatus): void => {
    const wasFailed = lastTransport?.state === "failed";
    recordTransportStatus(status);
    emit(status);
    if (status.state === "failed") {
      stopMonitor();
      stopHealthMonitor();
      if (!wasFailed) {
        try {
          notifyTunnel("failed");
        } catch {
          /* a notification failure must not reject a truthful Failed status read */
        }
      }
    }
  };
  const tunnel = new TunnelController(
    helperSocketPath(),
    (status) => {
      // Live heartbeat status + the LOUD fail-closed signal (onLost → failed).
      // A managed callback enters the same FIFO lane and is discarded if its
      // connection lease was invalidated by logout/profile/server replacement.
      const lease = activeManagedLease;
      if (lease) {
        const apply = () => {
          applyTunnelStatus(status);
        };
        void (status.state === "failed"
          ? lifecycle.terminal(lease, apply)
          : lifecycle.guarded(lease, apply));
      } else {
        applyTunnelStatus(status); // imported profiles carry no managed credential
      }
    },
  );
  // The renderer polls once per second. Share one lifecycle ticket and one
  // helper request across every overlapping poll so a wedged helper can delay a
  // mutation by at most one bounded read, never an ever-growing FIFO backlog.
  const statusReader = new SingleFlightStatusReader<ClientTunnelStatus>(() =>
    lifecycle.serial(async () => {
      const synthesized = lastSynth;
      if (synthesized?.state === "posture_warning" || synthesized?.state === "posture_blocked") {
        let status: TunnelStatus;
        try {
          status = await tunnel.status();
        } catch {
          // A transient read error is inconclusive. Preserve the existing
          // posture overlay; only successful helper Failed truth supersedes it.
          return synthesized.state === "posture_warning"
            ? ({ ...(lastTransport ?? {}), ...synthesized } as ClientTunnelStatus)
            : synthesized;
        }
        if (status.state === "failed") {
          applyTunnelStatus(status);
          return status;
        }
        recordTransportStatus(status);
        return synthesized.state === "posture_warning"
          ? ({ ...status, ...synthesized } as ClientTunnelStatus)
          : synthesized;
      }
      if (synthesized) return synthesized;
      const status = await tunnel.status();
      if (status.state === "failed") {
        applyTunnelStatus(status);
      } else {
        recordTransportStatus(status);
      }
      return status;
    }));

  const connect = (fullTunnel: boolean): Promise<ClientTunnelStatus> => lifecycle.serial(async (owner) => {
    const importedAtStart = activeImportedProfile();

    // Imported WireGuard files have no managed credential. They still enter the
    // lifecycle lane and invalidate/stop every managed callback before helper
    // work, while their exact config stays invocation-local.
    if (importedAtStart) {
      await tunnel.down();
      organizationSelectionRequiredPending = false;
      publishConfirmedDown();
      owner.invalidate();
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      activeManagedLease = null;
      await ensureHelperInstalled();
      const status = await tunnel.up(async () => importedAtStart.config);
      activeManagedLease = null;
      lastTransport = status;
      emit(status);
      notifyTunnel("connected");
      return status;
    }

    const lease = await captureManagedLease();
    const origin = lease.credential.server;
    const api = deviceApiFor(lease);
    // LEGACY MIGRATION (reduction 2, TERMINAL FORM): a stored config from before
    // orgId cannot be monitored. Prove ownership while the old lifecycle is live;
    // only then quiesce, advance, stop, and consume the opaque revoke-first proof.
    // Proof failure is the bounded retry state. Helper teardown refusal remains a
    // distinct rejection with zero epoch/monitor/store/UI mutation.
    // Every managed connect binds the encrypted device to the fixed authenticated
    // human before a helper prompt, helper mutation, status read, mode update, or
    // monitor can run. A failed/inconclusive proof leaves helper+monitors untouched.
    const preSc = tunnelStore.get(origin);
    if (preSc && !preSc.orgId) {
      let proof: LegacyManagedDeviceProof;
      try {
        // Prove the exact current user without touching helper ownership or
        // monitors. Failure is the bounded legacy outcome; helper teardown
        // refusal remains a distinct zero-effect rejection below.
        proof = await proveLegacyManagedDeviceOwner(
          origin,
          preSc.deviceId,
          lease.userId,
          api,
          tunnelStore,
          () => lifecycle.assertCurrent(lease),
        );
      } catch {
        notifyTunnel("migrate_retry");
        const s: ClientTunnelStatus = { state: "migrate_failed" };
        lastSynth = s;
        emit(s);
        return s;
      }

      // Keep teardown outside the migration-outcome catch. A refusal preserves
      // epoch, monitors, store, renderer, and tray exactly as they were.
      await tunnel.down();
      const down = publishConfirmedDown();
      organizationSelectionRequiredPending = false;
      const activeLease = owner.advance(lease);
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      activeManagedLease = null;

      try {
        await revokeAndClearLegacyManagedDevice(
          proof,
          () => lifecycle.assertCurrent(activeLease),
        );
        notifyTunnel("migrated");
        return down; // terminal — next connect is an ordinary fresh create
      } catch {
        // The helper is already truthfully down. Keep the encrypted recovery
        // handle and surface one bounded retry state for revoke/clear failure.
        notifyTunnel("migrate_retry");
        const s: ClientTunnelStatus = { state: "migrate_failed" };
        lastSynth = s;
        emit(s);
        return s;
      }
    }

    return runManagedConnectFlow<ManagedConnectContext, TunnelConfig, TunnelStatus, ClientTunnelStatus>(owner, {
      proveAndPrepare: async () => {
        const ownerProof = await proveManagedDeviceOwner(
          origin,
          lease.userId,
          api,
          tunnelStore,
          () => lifecycle.assertCurrent(lease),
        );
        let enrollmentOrganizationId: string;
        if (ownerProof) {
          enrollmentOrganizationId = ownerProof.organizationId;
        } else {
          try {
            const organizations = await api.organizations();
            lifecycle.assertCurrent(lease);
            enrollmentOrganizationId = organizationSelector.requireFreshEnrollment(
              origin,
              lease.userId,
              organizations,
            );
          } catch (error) {
            if (error instanceof OrganizationSelectionRequiredError || error instanceof NoOrganizationError) {
              surfaceOrganizationSelectionRequired();
            }
            throw error;
          }
        }

        const prepared = buildManagedConnectPreparation({
          lease,
          organizationId: enrollmentOrganizationId,
          fullTunnel,
          origin,
          api,
          resolveConfig: (fixed) => resolveTunnelConfig(
            fixed.origin,
            fixed.fullTunnel,
            fixed.api,
            tunnelStore,
            fixed.organizationId,
            fixed.userId,
            {
              anchorStore: enrollmentAnchorStore,
              credentialFingerprint: fixed.credential.fingerprint,
            },
          ),
        });
        return Object.freeze({
          ...prepared,
          context: Object.freeze({ ...prepared.context, ownerProof }),
        });
      },
      quiesceExisting: async () => {
        await tunnel.down();
        organizationSelectionRequiredPending = false;
      },
      publishQuiesced: () => {
        publishConfirmedDown();
      },
      prepareRuntime: (connection) => {
        if (connection.context.ownerProof) {
          commitManagedDeviceOwnerProof(
            connection.context.ownerProof,
            () => lifecycle.assertCurrent(connection.lease),
          );
        }
        stopMonitor();
        stopApprovalMonitor();
        stopHealthMonitor();
        // Label socket callbacks with the new fixed lease before install/up.
        // Terminal callbacks retain it as a stale tombstone, so a heartbeat
        // resumed after teardown refusal is guard-discarded rather than treated
        // as an imported-profile status.
        activeManagedLease = connection.lease;
      },
      // First-connect on an unsigned macOS build: install the privileged helper via one
      // GUI admin prompt (no-op if already installed / off macOS). This is deliberately
      // after fixed identity, owner, and organization proof.
      installHelper: () => ensureHelperInstalled(),
      up: (configProvider) => tunnel.up(configProvider),
      onUpError: (e, connection) => {
        const connectionLease = connection.lease;
        const { origin: connectionOrigin, api: connectionApi } = connection.context;
        if (e instanceof DeviceRevokedError) {
          // This is terminal for the newly prepared managed lease. Fence it but
          // retain activeManagedLease as a stale tombstone so any delayed helper
          // callback is guard-discarded instead of entering the imported path.
          owner.invalidate();
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
          const pending: ClientTunnelStatus = { state: "pending_approval" };
          lastSynth = pending;
          emit(pending);
          notifyTunnel("pending");
          const pendingConfig = tunnelStore.get(connectionOrigin); // persisted before the throw
          if (!pendingConfig?.ownerUserId || pendingConfig.ownerUserId !== connectionLease.userId) throw e;
          approvalMonitor = new ApprovalMonitor(
            e.deviceId,
            pendingConfig.orgId,
            {
              deviceStatus: (deviceId, orgId) => guardedValue(
                connectionLease,
                () => connectionApi.deviceStatus(deviceId, orgId),
              ),
            },
            () => lifecycle.guarded(connectionLease, () => onApproved(connectionLease, e.deviceId)),
            () => lifecycle.terminal(connectionLease, () => {
              return onRejected(connectionLease, e.deviceId);
            }),
          );
          approvalMonitor.start();
          return pending;
        }
        throw e;
      },
      publish: (connection, status) => {
        const connectionLease = connection.lease;
        const { origin: connectionOrigin, api: connectionApi } = connection.context;
        activeManagedLease = connectionLease;
        // Start the proactive revocation monitor for the device we just brought up.
        const sc = tunnelStore.get(connectionOrigin);
        if (sc?.deviceId) {
          if (sc.ownerUserId !== connectionLease.userId) throw new Error("managed_device_owner_unconfirmed");
          const monitoredDeviceId = sc.deviceId;
          monitor = new RevocationMonitor(
            monitoredDeviceId,
            sc.orgId,
            {
              deviceExists: (deviceId, orgId) => guardedValue(
                connectionLease,
                () => connectionApi.deviceExists(deviceId, orgId),
              ),
            },
            () => lifecycle.terminal(
              connectionLease,
              () => {
                return onRevoked(connectionLease, monitoredDeviceId);
              },
            ),
          );
          monitor.start();
          // S8.5 routed-subnets push (#5: runs in BOTH modes): poll the org's declared ranges + reachable DNS
          // forwards and live-apply each tier via the helper — ranges → set_allowed_ips, forwards →
          // set_resolvers. The ROUTES tier is enabled only for SPLIT-tunnel (a full tunnel's 0.0.0.0/0 subsumes
          // every range — no route calls). The RESOLVER tier runs in BOTH: full-tunnel's baked DNS (1.1.1.1)
          // cannot answer internal cross-site zones, so it needs the forwards just as split-tunnel does.
          routedRangesMonitor = new RoutedRangesMonitor(
            sc.orgId,
            tunnel.baseAllowedIPs(),
            {
              routedConfig: (orgId, deviceId) => guardedValue(
                connectionLease,
                () => connectionApi.routedConfig(orgId, deviceId),
              ),
            },
            async (set) => { await lifecycle.guarded(connectionLease, () => tunnel.setAllowedIPs(set)); },
            async (fwds) => { await lifecycle.guarded(connectionLease, () => tunnel.setResolvers(fwds)); },
            undefined, // baseMs (default cadence)
            undefined, // maxMs (default ceiling)
            undefined, // setTimer (default)
            undefined, // clearTimer (default)
            !connection.fullTunnel, // routesEnabled: routes tier split-only; resolver tier always
            sc.deviceId, // WF-A: scope the dial to THIS device
            async (endpoint, pubkey) => {
              await lifecycle.guarded(connectionLease, () => tunnel.setGatewayPeer(pubkey, endpoint));
            }, // WF-A: re-home on active-hub move
            true, // dialEnabled: BOTH modes now (D-WFA-4 carve-out landed); the helper refuses a full-tunnel
            //        re-home only where its carve-out is absent (Windows) → the dial tier fail-statics there.
            { endpoint: sc.config.endpoint, pubkey: sc.config.peer_public_key }, // seed = the minted peer
          );
          routedRangesMonitor.start();
          // S7.5.3: self-report posture while connected. First report early (~15s),
          // then every 10min (+ fixed jitter). Terminal 403 (open edition) stops it
          // until the next connect. onHealthResult surfaces a require-mode block as the
          // posture_blocked state so a server-side disconnect is never silent ([2]).
          healthMonitor = new HealthMonitor(
            sc.deviceId,
            sc.orgId,
            {
              reportHealth: (deviceId, orgId, facts) => guardedValue(
                connectionLease,
                () => connectionApi.reportHealth(deviceId, orgId, facts),
              ),
            },
            () => guardedValue(connectionLease, collectHealthFacts),
            (result) => { void lifecycle.guarded(connectionLease, () => onHealthResult(result)); },
          );
          healthMonitor.start();
        }
        lastTransport = status;
        emit(status);
        notifyTunnel("connected");
        return status;
      },
    });
  });

  const disconnect = (): Promise<void> => lifecycle.serial((owner) =>
    runManagedDisconnectFlow(owner, {
      quiesceExisting: () => tunnel.down(),
      stopMonitors: () => {
        stopMonitor();
        stopApprovalMonitor(); // also cancel any awaiting-approval poll (disconnect = stop waiting)
        stopHealthMonitor();
        activeManagedLease = null;
      },
      publishDown: () => { publishConfirmedDown(); },
      notifyDisconnected: () => { notifyTunnel("disconnected"); },
    }));

  // --- auth --------------------------------------------------------------------
  ipcMain.handle("auth:status", () => {
    const cred = store.load();
    if (!cred) return { loggedIn: false, secureStorage: store.available() };
    const expired = CredentialStore.isExpired(cred, new Date());
    return { loggedIn: !expired, expired, fingerprint: cred.fingerprint, expiresAt: cred.expiresAt, secureStorage: store.available() };
  });

  ipcMain.handle("auth:login", async () => {
    const r = await lifecycle.replaceLogin({
      resolveServer: () => config.requireServerUrl(), // resolved only after login owns the FIFO turn
      sessionIsValid: async (credential) => !CredentialStore.isExpired(credential, new Date()),
      stopMonitors: () => {
        organizationSelectionRequiredPending = false;
        stopMonitor();
        stopApprovalMonitor();
        stopHealthMonitor();
        lastSynth = null;
        activeManagedLease = null;
      },
      // An inactive controller is an idempotent zero-wire success. If an active
      // helper refuses teardown, propagate it: credential B must not replace A
      // until A's live tunnel has actually been brought down.
      downTunnel: () => tunnel.down(),
      publishDown: () => { publishConfirmedDown(); },
      saveCredential: (server) => runLogin(server, store),
    });
    getWindow()?.webContents.reload(); // the injected bearer now authenticates the SPA
    return r;
  });

  ipcMain.handle("auth:logout", async () => {
    // Sign-out is session-only. The encrypted device config stays so the next sign-in
    // can validate and reuse the same server-side device instead of minting another row.
    await lifecycle.serial(async (owner) => {
      await signOutPreservingDevice({
        retireLifecycle: () => {
          owner.invalidate();
          activeManagedLease = null;
        },
        stopMonitors: () => {
          organizationSelectionRequiredPending = false;
          stopMonitor();
          stopApprovalMonitor();
          stopHealthMonitor();
        },
        clearSynthesizedState: () => { lastSynth = null; },
        downTunnel: () => tunnel.down(),
        emitDisconnected: () => { publishConfirmedDown(); },
        logoutSession: () => runLogout(store),
      });
    });
    // Reload only after logout completed. A teardown refusal must remain visible
    // to the calling renderer rather than destroying it in a finally block.
    getWindow()?.webContents.reload();
  });

  ipcMain.handle("auth:removeDevice", () => lifecycle.serial(async (owner) => {
    return runManagedRemoveFlow<ManagedRemoveContext, boolean>(owner, {
      proveOwner: async () => {
        const lease = await captureManagedLease();
        const api = deviceApiFor(lease);
        // Ownership must be proved while the current tunnel and monitors are still
        // untouched. A foreign or inconclusive sign-in therefore cannot stop the
        // helper, revoke a peer, or clear another user's encrypted credential.
        const origin = lease.credential.server;
        const stored = tunnelStore.get(origin);
        if (!stored) {
          const organizations = await api.organizations();
          lifecycle.assertCurrent(lease);
          const anchor = enrollmentAnchorStore.get(origin);
          const organizationId = enrollmentAnchorOrganizationForUser(anchor, origin, lease.userId);
          if (!anchor || !organizationId) return null;
          const proof = await proveManagedEnrollmentAbandonment(
            origin,
            lease.userId,
            organizationId,
            lease.credential.fingerprint,
            organizations.map((organization) => organization.id),
            api,
            enrollmentAnchorStore,
            () => lifecycle.assertCurrent(lease),
          );
          if (!proof) return null;
          return { lease, context: { kind: "anchor", proof, api } };
        }
        if (!stored.orgId) {
          const proof = await proveLegacyManagedDeviceOwner(
            origin,
            stored.deviceId,
            lease.userId,
            api,
            tunnelStore,
            () => lifecycle.assertCurrent(lease),
          );
          return { lease, context: { kind: "legacy", proof } };
        }
        const proof = await proveManagedDeviceOwner(
          origin,
          lease.userId,
          api,
          tunnelStore,
          () => lifecycle.assertCurrent(lease),
        );
        if (!proof) return null;
        return {
          lease,
          context: { kind: "bound", proof, api },
        };
      },
      stopMonitors: () => {
        organizationSelectionRequiredPending = false;
        stopMonitor();
        stopApprovalMonitor();
        stopHealthMonitor();
        lastSynth = null;
        activeManagedLease = null;
      },
      quiesceExisting: async (removal) => {
        await tunnel.down();
        if (removal.context.kind === "anchor") {
          let status = await tunnel.status();
          if (status.state !== "down") {
            await tunnel.down();
            status = await tunnel.status();
          }
          if (status.state !== "down") throw new Error("managed_enrollment_helper_down_unconfirmed");
        }
        publishConfirmedDown();
      },
      revokeAndClear: async (removal) => {
        if (removal.context.kind === "legacy") {
          await revokeAndClearLegacyManagedDevice(
            removal.context.proof,
            () => lifecycle.assertCurrent(removal.lease),
          );
          return true;
        }
        if (removal.context.kind === "anchor") {
          await consumeManagedEnrollmentAbandonProof(
            removal.context.proof,
            removal.context.api,
            () => lifecycle.assertCurrent(removal.lease),
          );
          return true;
        }
        await revokeAndClearManagedDevice(
          removal.context.proof,
          removal.context.api,
          () => lifecycle.assertCurrent(removal.lease),
        );
        return true;
      },
    });
  }));

  // --- tunnel (S6.3 control + S6.4 UX) -----------------------------------------
  ipcMain.handle("tunnel:up", (_e, fullTunnel: unknown) => connect(fullTunnel === true));
  ipcMain.handle("tunnel:down", () => disconnect());
  ipcMain.handle("tunnel:status", () => statusReader.read());
  ipcMain.handle("tunnel:managedOrganizations", () => lifecycle.serial(async () => {
    const lease = await captureManagedLease();
    const context = await organizationContext(lease);
    const view = organizationSelector.organizations(
      lease.credential.server,
      context.userId,
      context.organizations,
      context.enrolledOrganizationId,
      context.hasStoredManagedRecord,
    );
    if (view.organizations.some((organization) => organization.selected)) {
      organizationSelectionRequiredPending = false;
    }
    return { ...view, enrollmentRecoveryRequired: context.enrollmentRecoveryRequired };
  }));
  ipcMain.handle("tunnel:organizationSelectionRequired", () => organizationSelectionRequiredPending);
  ipcMain.handle("tunnel:selectManagedOrganization", (_e, rawId: unknown) => lifecycle.serial(async () => {
    if (!isCanonicalUuid(rawId)) {
      throw new Error("invalid_organization");
    }
    const lease = await captureManagedLease();
    const context = await organizationContext(lease);
    const organizations = organizationSelector.select(
      lease.credential.server,
      context.userId,
      context.organizations,
      rawId,
      context.enrolledOrganizationId,
      context.hasStoredManagedRecord,
    );
    organizationSelectionRequiredPending = false;
    return { ...organizations, enrollmentRecoveryRequired: context.enrollmentRecoveryRequired };
  }));

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
    // Validate the complete helper-facing config before entering the lifecycle
    // lane. Invalid input therefore cannot quiesce the prior session, mutate the
    // helper/store/selection, or expose its secret-bearing bytes in an error.
    const importedConfig = parseImportedTunnelConfig(text);
    const fullTunnel = importedConfig.full_tunnel === true;
    const id = randomUUID();
    const name = path.basename(res.filePaths[0], ".conf").trim().slice(0, 120) || "Imported profile";
    return lifecycle.serial(async (owner) => {
      // Preserve the old single-import behaviour for a first profile, but fence
      // and tear down the prior managed lifecycle before changing the selection.
      const activate = !activeImportedProfile() && !config.isManagedProfileSelected();
      if (activate) {
        await tunnel.down();
        organizationSelectionRequiredPending = false;
        publishConfirmedDown();
        owner.invalidate();
        stopMonitor();
        stopApprovalMonitor();
        stopHealthMonitor();
        activeManagedLease = null;
      }
      tunnelStore.put({
        origin: importedProfileOrigin(id),
        deviceId: "",
        orgId: "",
        config: importedConfig,
        imported: true,
        importedName: name,
      });
      if (activate) config.setImportedProfileId(id);
      return { id, name, address: importedConfig.address, endpoint: importedConfig.endpoint, fullTunnel, active: activeImportedProfile()?.id === id };
    });
  });

  ipcMain.handle("tunnel:importedProfiles", () => importedProfileSummary());

  ipcMain.handle("tunnel:selectImportedProfile", (_e, rawId: unknown) => lifecycle.serial(async (owner) => {
    if (typeof rawId !== "string" || !/^(legacy|[0-9a-f-]{36})$/i.test(rawId)) throw new Error("invalid_imported_profile");
    if (!tunnelStore.importedProfile(rawId)) throw new Error("imported_profile_not_found");
    await tunnel.down();
    organizationSelectionRequiredPending = false;
    publishConfirmedDown();
    owner.invalidate();
    // Switching is a deliberate disconnect. Stop every old-profile monitor before
    // changing the selected origin so it cannot mutate the next profile's state.
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    activeManagedLease = null;
    config.setImportedProfileId(rawId);
    return importedProfileSummary();
  }));

  /** Choose the enrolled-account path without deleting any imported WireGuard file. */
  ipcMain.handle("tunnel:useManagedProfile", () => lifecycle.serial(async (owner) => {
    await tunnel.down();
    organizationSelectionRequiredPending = false;
    publishConfirmedDown();
    owner.invalidate();
    stopMonitor();
    stopApprovalMonitor();
    stopHealthMonitor();
    activeManagedLease = null;
    config.useManagedProfile();
    return importedProfileSummary();
  }));

  /** Remove one imported profile. Removing the active profile tears down its key first. */
  ipcMain.handle("tunnel:forgetImported", (_e, rawId?: unknown) => lifecycle.serial(async (owner) => {
    const id = rawId === undefined ? activeImportedProfile()?.id : rawId;
    if (typeof id !== "string" || !/^(legacy|[0-9a-f-]{36})$/i.test(id)) throw new Error("invalid_imported_profile");
    const profile = tunnelStore.importedProfile(id);
    if (!profile) throw new Error("imported_profile_not_found");
    const removingActive = activeImportedProfile()?.id === id;
    if (removingActive) {
      await tunnel.down();
      organizationSelectionRequiredPending = false;
      publishConfirmedDown();
      owner.invalidate();
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      activeManagedLease = null;
      config.setImportedProfileId("");
    }
    tunnelStore.remove(importedProfileOrigin(id));
    return importedProfileSummary();
  }));

  /** Legacy, active-profile-only read retained for pre-multiple-profile renderers. */
  ipcMain.handle("tunnel:importedInfo", () => {
    const profile = activeImportedProfile();
    return profile
      ? { id: profile.id, name: profile.name, address: profile.config.address, endpoint: profile.config.endpoint, fullTunnel: profile.config.full_tunnel, active: true }
      : null;
  });


  ipcMain.handle("config:setServerUrl", (_e, url: unknown) => lifecycle.serial(async (owner) => {
    if (typeof url !== "string" || url.length === 0 || url.length > 2000) {
      throw new Error("invalid server url");
    }
    const hasCred = store.load() !== null;
    const { url: accepted, reloginRequired, wasUnset } = await config.validateServerUrl(url, hasCred);
    // A credential must never reach a server it wasn't minted against: on a real
    // change, revoke + clear the old credential BEFORE the new URL is persisted,
    // so there is no window where (origin=new, credential=old) can attach.
    if (reloginRequired) {
      await tunnel.down();
      organizationSelectionRequiredPending = false;
      publishConfirmedDown();
      owner.invalidate();
      // Stop BOTH monitors + tunnel (they belong to the OLD origin) — the awaiting-approval
      // poll must also stop, else it keeps polling the old origin with a stale bearer
      // (finding #5: origin-lifecycle stop). Per the signed-off amendment we do NOT
      // auto-revoke the old-origin device/config — it stays origin-keyed for the UI.
      stopMonitor();
      stopApprovalMonitor();
      stopHealthMonitor();
      activeManagedLease = null;
      await runLogout(store);
    } else {
      organizationSelectionRequiredPending = false;
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
  }));

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
