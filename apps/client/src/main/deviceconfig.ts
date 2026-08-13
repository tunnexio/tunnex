import { parseWgConf } from "./wgconf";
import type { TunnelConfigStore } from "./tunnelstore";
import type { ResolverForward, TunnelConfig } from "./helperclient";

// RoutedConfig is the S8.5 volatile-routes channel body: the org's declared routed ranges AND the DNS
// forwards REACHABLE via those ranges (Slice 3, D4 — server-gated). ONE poll carries both; NEVER identity
// (the never-re-fetch invariant holds — routes and forwards were never identity). Empty on both is a
// first-class answer.
export interface RoutedConfig {
  ranges: string[];
  forwards: ResolverForward[];
  // dial is the device's ACTIVE-HUB gateway (WF-A): the endpoint + peer public key it should dial RIGHT
  // NOW, derived server-side from the hub set's active primary. null when the server does not derive one
  // (single-gateway org, no hub set, an older server) — the client then keeps its current peer (fail-static).
  // A routing FACT about the network, NEVER device identity — the never-re-fetch invariant holds.
  dial: DialTarget | null;
}

// DialTarget is the re-home target's public routing facts (WF-A) — mirrors the RoutedRanges dial fields.
export interface DialTarget {
  endpoint: string;
  pubkey: string;
}

// DeviceApi is the seam over the tenant API (called from MAIN with the bearer).
// The concrete HTTP adapter mirrors the CLI's device flow (pick org + active node
// → POST create-device → the ONE-TIME .conf text). Kept an interface so the D2
// get-or-create + explicit device-removal logic below is unit-tested without a live server.
export interface DeviceApi {
  // createDevice creates a device for the current tenant and returns the one-time
  // config text + the new device id. pendingApproval is true when the org requires
  // device approval (S7.3): the device is enrolled but BLOCKED until an admin approves.
  // It is called ONLY when no config is stored for the origin (D2: never a re-fetch).
  createDevice(fullTunnel: boolean): Promise<{ deviceId: string; confText: string; pendingApproval: boolean; orgId: string }>;
  // Update routing mode in-place. The server preserves device identity and returns
  // mutable config facts; the locally-held private key is never re-issued.
  updateDeviceMode?(deviceId: string, orgId: string, fullTunnel: boolean): Promise<{
    fullTunnel: boolean;
    address: string;
    addresses?: string[];
    endpoint: string;
    peerPublicKey: string;
    allowedIPs: string[];
    dns?: string[];
    mtu?: number;
    persistentKeepalive?: number;
  }>;
  // revokeDevice revokes a device against its recorded organization. orgId is absent
  // only for a legacy migration that predates storing the device's organization.
  revokeDevice(deviceId: string, orgId?: string): Promise<void>;
  // deviceStatus is the definitive server status (S7.3): "pending" | "active" | "gone".
  // Queried against the device's OWN org (persisted at create) so a transient list that
  // omits that org can't read as a false "gone" (finding #4). Throws on any read error
  // (inconclusive fail-safe) — a blip never reads as a transition.
  deviceStatus(deviceId: string, orgId: string): Promise<"active" | "pending" | "gone">;
  // deviceExists = deviceStatus === "active" (finding #6: ONE fail-safe, no divergence).
  // Self-heals a stale cached config (device revoked/GC'd) — an EXISTENCE check, not a
  // config re-fetch, so D2 holds. orgId is always known (legacy configs re-mint, never query).
  deviceExists(deviceId: string, orgId: string): Promise<boolean>;
  // reportHealth self-reports posture facts (S7.5.3). Terminal non-retryable answers are
  // RETURNED (not thrown) so the monitor can stop cleanly: "unsupported" = 403 (open
  // edition / no permission — reporting is pointless until something changes),
  // "gone" = 404/410 (device no longer exists). Any other failure THROWS (inconclusive
  // — retry with backoff, same discipline as deviceStatus).
  reportHealth(deviceId: string, orgId: string, facts: HealthFacts): Promise<HealthReportResult | "unsupported" | "gone">;
  // routedConfig fetches the org's declared routed LAN ranges + the reachable DNS forwards (S8.5) + the
  // device's active-hub dial (WF-A) — the volatile-FACTS channel (routes/forwards/dial only, NEVER identity
  // — the never-re-fetch invariant holds). deviceId scopes the dial to THIS device (the server refuses any
  // other device's dial, no-oracle); absent → no dial derived. Throws on any read error (inconclusive: the
  // RoutedRangesMonitor keeps its last-applied sets, fail-static).
  routedConfig(orgId: string, deviceId?: string): Promise<RoutedConfig>;
}

// HealthFacts are the client-collected posture facts (S7.5.3). disk_encrypted is
// OMITTED when the helper could not determine it — reported absent, never guessed.
export interface HealthFacts {
  platform: "macos" | "windows" | "linux" | "other";
  os_version: string;
  disk_encrypted?: boolean;
}

// HealthReportResult is the server's evaluation of one report.
export interface HealthReportResult {
  state: "compliant" | "noncompliant";
  blocked: boolean;
  failed_checks: Array<{ kind: string; mode: string }>;
}

// PendingApprovalError aborts the ConfigProvider (resolveTunnelConfig) when the device
// is awaiting approval (S7.3): the helper is NEVER armed for a pending device (no dead
// tunnel, no spurious "revoked" from the RevocationMonitor). connect() catches it, shows
// the stable "awaiting approval" state, and starts the ApprovalMonitor. The deviceId is
// carried so the poll knows what to watch.
export class PendingApprovalError extends Error {
  constructor(public readonly deviceId: string) {
    super("device is awaiting admin approval");
    this.name = "PendingApprovalError";
  }
}

// DeviceRevokedError is terminal for a managed device. A server-side revocation
// is an administrator's access decision, not a retryable enrollment failure.
export class DeviceRevokedError extends Error {
  constructor(public readonly deviceId: string) {
    super("device was revoked by an administrator");
    this.name = "DeviceRevokedError";
  }
}

function markDeviceRevoked(existing: NonNullable<ReturnType<TunnelConfigStore["get"]>>, store: TunnelConfigStore): void {
  store.put({ ...existing, pending: false, revoked: true });
}

// resolveTunnelConfig is the ConfigProvider body: GET-OR-CREATE, origin-keyed.
// If a config is stored for this origin, reuse it (never re-fetch). Otherwise the
// desktop OWNS creation — create a device, capture its one-time config, persist it,
// and return it. full_tunnel is set from the create INTENT (the helper enforces
// both-family completeness when true).
// cpEndpointFromOrigin derives the tenant API host:port from the server origin (WF-A / D-WFA-4), for the
// helper's full-tunnel kill-switch carve-out. Default port 443 (https). Returns "" if the origin can't be
// parsed — the helper then simply gets no carve-out (full-tunnel re-home fail-static, honest degrade).
export function cpEndpointFromOrigin(origin: string): string {
  try {
    const u = new URL(origin);
    if (!u.hostname) return "";
    const port = u.port || (u.protocol === "http:" ? "80" : "443");
    return `${u.hostname}:${port}`;
  } catch {
    return "";
  }
}

export async function resolveTunnelConfig(
  origin: string,
  fullTunnel: boolean,
  api: DeviceApi,
  store: TunnelConfigStore,
): Promise<TunnelConfig> {
  // WF-A: for a FULL tunnel, attach the CP endpoint so the helper carves the kill-switch to it (the control
  // channel must survive the tunnel going down to re-home). NEVER persisted — it's an origin-derived routing
  // fact, re-attached each connect on top of the stored identity-only config. Split → no carve-out.
  const withCP = (cfg: TunnelConfig): TunnelConfig =>
    fullTunnel ? { ...cfg, control_plane_endpoint: cpEndpointFromOrigin(origin) } : cfg;
  let existing = store.get(origin);
  if (existing && !existing.orgId) {
    // DEFENSE (reduction 2): connect() migrates a legacy (no-orgId) config BEFORE tunnel.up —
    // clears + best-effort revokes it, terminal for that connect — so this ConfigProvider
    // should never see one. NEVER query or arm a no-orgId config: drop it and fall through to
    // a fresh create. This belt guarantees resolveTunnelConfig can't arm a legacy config even
    // if reached; connect() owns the cap-freeing revoke + the user-facing notice.
    store.remove(origin);
    existing = null;
  }
  if (existing?.revoked) throw new DeviceRevokedError(existing.deviceId);
  if (existing?.pending) {
    // A pending credential is never armed, but it still must belong to the newly
    // authenticated user before the client resumes its approval poll. This is the
    // pending counterpart to the active-device ownership validation below.
    let status: "active" | "pending" | "gone";
    try {
      status = await api.deviceStatus(existing.deviceId, existing.orgId);
    } catch {
      // An inconclusive read must not turn a pending credential into a new enrollment.
      throw new PendingApprovalError(existing.deviceId);
    }
    if (status === "pending") throw new PendingApprovalError(existing.deviceId);
    if (status === "gone") {
      markDeviceRevoked(existing, store);
      throw new DeviceRevokedError(existing.deviceId);
    } else {
      existing = { ...existing, pending: false };
      store.put(existing);
    }
  }
  if (existing && existing.config.full_tunnel !== fullTunnel) {
    // MODE CHANGED (split↔full): mutate the existing device identity in place. The API
    // returns route/config facts only; preserve the locally-held private key atomically.
    if (existing.pending) throw new PendingApprovalError(existing.deviceId);
    // Verify terminal existence before asking that device to change mode. A 404
    // means the control plane revoked/deleted that identity; it must NEVER turn
    // into a silent fresh enrollment, because that could bypass an admin revoke.
    // A read failure remains inconclusive and deliberately preserves the device.
    let stillThere = true;
    try {
      stillThere = await api.deviceExists(existing.deviceId, existing.orgId);
    } catch {
      stillThere = true;
    }
    if (!stillThere) {
      markDeviceRevoked(existing, store);
      throw new DeviceRevokedError(existing.deviceId);
    }
  }
  if (existing && existing.config.full_tunnel !== fullTunnel) {
    // MODE CHANGED (split↔full): mutate the existing device identity in place. The API
    // returns route/config facts only; preserve the locally-held private key atomically.
    if (!api.updateDeviceMode) throw new Error("device_mode_update_unsupported");
    const mode = await api.updateDeviceMode(existing.deviceId, existing.orgId, fullTunnel);
    const config: TunnelConfig = {
      ...existing.config,
      address: mode.address,
      addresses: mode.addresses,
      endpoint: mode.endpoint,
      peer_public_key: mode.peerPublicKey,
      allowed_ips: mode.allowedIPs,
      dns: mode.dns,
      mtu: mode.mtu,
      persistent_keepalive: mode.persistentKeepalive,
      full_tunnel: mode.fullTunnel,
    };
    store.put({ ...existing, config, pending: false });
    return withCP(config);
  } else if (existing) {
    // Same mode: a definitive missing device is terminal, not an invitation to
    // mint another credential. A transient read error keeps the config intact.
    let stillThere = true;
    try {
      stillThere = await api.deviceExists(existing.deviceId, existing.orgId);
    } catch {
      stillThere = true;
    }
    if (stillThere) return withCP(existing.config);
    markDeviceRevoked(existing, store);
    throw new DeviceRevokedError(existing.deviceId);
  }

  const { deviceId, confText, pendingApproval, orgId } = await api.createDevice(fullTunnel);
  const config: TunnelConfig = { ...parseWgConf(confText), full_tunnel: fullTunnel };
  // Persist BEFORE the pending gate so the ApprovalMonitor + a later connect have the device
  // (config is valid now; the gateway just won't serve the peer until approved). orgId is
  // persisted so the monitors query the device's OWN org directly (finding #4).
  store.put({ origin, deviceId, orgId, config, pending: pendingApproval });
  if (pendingApproval) {
    throw new PendingApprovalError(deviceId); // S7.3: abort — do NOT arm the helper
  }
  return withCP(config);
}

// migrateLegacyConfig migrates a LEGACY (no-orgId) config with REVOKE-FIRST ordering (S7.3
// reduction 2). The revoke's SUCCESS is what frees the per-user cap slot the NEXT connect's fresh
// create needs, so revoke BEFORE clearing and clear ONLY on revoke success. On SUCCESS it returns
// (config cleared); on ANY failure it THROWS with the config KEPT (the slot handle survives). The
// caller (ipc connect) degrades on OUTCOME: success -> "migrated"; throw -> honest recoverable
// down — it does NOT branch on the error type. So this helper only needs the one guarantee: never
// clear the config unless the revoke that frees the slot actually succeeded. Whether a failure is
// transient (next connect self-heals) or persistent (bounded-by-honest-message) is the caller's
// single soft-down outcome, not N cases handled here.
// DOCTRINE REFINEMENT: best-effort-revoke-and-orphan is correct where the orphan is COSMETIC;
// where a subsequent operation DEPENDS on the revoke (here, the freed cap slot), REVOKE-FIRST-
// VERIFY is required. (Recurs wherever a revoke frees a resource something else immediately claims.)
export async function migrateLegacyConfig(
  origin: string,
  deviceId: string,
  api: DeviceApi,
  store: TunnelConfigStore,
): Promise<void> {
  await api.revokeDevice(deviceId); // frees the cap slot; throws on a blip (config untouched -> retry)
  store.remove(origin); // clear ONLY after the revoke succeeded
}

// discardTunnelConfigForOrigin drops a config only after the server has already
// declared it terminal (revocation/rejection). It intentionally makes no network
// request: normal sign-out is not a terminal state and never calls this helper.
export function discardTunnelConfigForOrigin(
  origin: string,
  store: TunnelConfigStore,
): void {
  store.remove(origin);
}

// removeManagedTunnelConfigForOrigin is the explicit, destructive device action.
// Revoke first: if the server cannot confirm removal, keep the encrypted local
// credential so the user can retry instead of orphaning a still-active peer.
export async function removeManagedTunnelConfigForOrigin(
  origin: string,
  api: DeviceApi,
  store: TunnelConfigStore,
): Promise<boolean> {
  const existing = store.get(origin);
  if (!existing) return false;
  await api.revokeDevice(existing.deviceId, existing.orgId);
  store.remove(origin);
  return true;
}
