import { isIP } from "node:net";
import { parseWgConf } from "./wgconf";
import type { StoredTunnelConfig, TunnelConfigStore } from "./tunnelstore";
import type { ResolverForward, TunnelConfig } from "./helperclient";
import {
  deriveWireGuardPublicKey,
  EnrollmentAnchorClearAfterUnlinkError,
  EnrollmentAnchorStoreCorruptError,
  generateWireGuardKeyPair,
  type EnrollmentAnchor,
  type EnrollmentAnchorStore,
} from "./enrollmentanchor";
import { OrganizationSelectionConflictError, OrganizationSelectionRequiredError } from "./orgselection";
import { isCanonicalUuid } from "./uuid";

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

export interface DeviceModeConfig {
  deviceId: string;
  ownerUserId: string;
  nodeId: string;
  publicKey: string;
  status: "active" | "pending";
  fullTunnel: boolean;
  address: string;
  addresses?: string[];
  endpoint: string;
  peerPublicKey: string;
  allowedIPs: string[];
  dns?: string[];
  mtu?: number;
  persistentKeepalive?: number;
}

export interface ManagedEnrollmentPreparation {
  nodeId: string;
  name: string;
  platform: string;
}

export interface ManagedEnrollmentCreate {
  organizationId: string;
  nodeId: string;
  name: string;
  platform: string;
  fullTunnel: boolean;
  publicKey: string;
}

export interface ManagedEnrollmentDevice {
  deviceId: string;
  ownerUserId: string;
  nodeId: string;
  publicKey: string;
  status: "active" | "pending" | "gone";
}

export interface ManagedEnrollmentRecoveryContext {
  anchorStore: EnrollmentAnchorStore;
  credentialFingerprint: string;
}

const managedEnrollmentAbandonProofBrand: unique symbol = Symbol("ManagedEnrollmentAbandonProof");

export interface ManagedEnrollmentAbandonProof {
  readonly [managedEnrollmentAbandonProofBrand]: true;
}

interface ManagedEnrollmentAbandonProofState {
  readonly origin: string;
  readonly ownerUserId: string;
  readonly organizationId: string;
  readonly credentialFingerprint: string;
  readonly anchorSnapshot: string;
  readonly apiIdentity: object;
  readonly api: Pick<DeviceApi, "devicesByPublicKey" | "revokeDevice">;
  readonly anchorStore: EnrollmentAnchorStore;
}

const managedEnrollmentAbandonProofs = new WeakMap<
  ManagedEnrollmentAbandonProof,
  ManagedEnrollmentAbandonProofState
>();

// DeviceApi is the seam over the tenant API (called from MAIN with the bearer).
// Managed desktop enrollment sends a locally generated public key; the API
// returns only public identity and mutable routing facts. Kept an interface so
// crash recovery + explicit device removal are unit-tested without a live server.
export interface DeviceApi {
  // Fresh enrollment resolves its gateway/name before any POST so that exact
  // intent can be durably anchored beside the locally generated keypair.
  prepareDeviceEnrollment(organizationId: string): Promise<ManagedEnrollmentPreparation>;
  // Recovery lists the complete visible roster match for one public key before
  // deciding whether an idempotent create retry is necessary. The server's
  // org-locked full-history guard remains authoritative for hidden retired or
  // foreign rows.
  devicesByPublicKey(organizationId: string, publicKey: string): Promise<ManagedEnrollmentDevice[]>;
  // createDevice sends a client public key and returns public identity facts
  // only. A private key or config in the HTTP response is invalid.
  createDevice(intent: ManagedEnrollmentCreate): Promise<ManagedEnrollmentDevice>;
  // Update routing mode in-place. The server preserves device identity and returns
  // mutable config facts; the locally-held private key is never re-issued.
  updateDeviceMode?(deviceId: string, orgId: string, fullTunnel: boolean): Promise<DeviceModeConfig>;
  // revokeDevice revokes a bound device against its recorded organization. A
  // legacy record without orgId uses the separate complete-scan proof below.
  revokeDevice(deviceId: string, orgId: string): Promise<void>;
  // discoverLegacyDevice is the read-only compatibility proof for a record
  // predating orgId. It returns the one exact current-user organization only
  // after scanning every live membership; absence/foreign/ambiguity refuses.
  // The lifecycle owner re-checks its credential before a separate revoke.
  discoverLegacyDevice(deviceId: string, expectedOwnerUserId: string): Promise<string>;
  // deviceRecord is the ownership proof primitive. Unlike deviceStatus it does
  // not collapse a foreign row and an absent row into the same "gone" answer.
  deviceRecord(deviceId: string, orgId: string): Promise<DeviceRecord | null>;
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

export interface DeviceRecord {
  status: "active" | "pending" | "gone";
  userId: string;
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

export class ManagedDeviceOwnerMismatchError extends Error {
  constructor() {
    super("managed_device_owner_mismatch");
    this.name = "ManagedDeviceOwnerMismatchError";
  }
}

export class ManagedDeviceOwnerUnconfirmedError extends Error {
  constructor() {
    super("managed_device_owner_unconfirmed");
    this.name = "ManagedDeviceOwnerUnconfirmedError";
  }
}

function nonEmptyIdentity(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validWireGuardKey(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64");
    // Go's base64 decoder (used by the helper) accepts historical keys whose
    // unused padding bits are non-zero. Preserve those already-stored records
    // while still requiring the exact WireGuard alphabet, padding, and 32-byte
    // decoded key length.
    return decoded.length === 32;
  } catch {
    return false;
  }
}

function validCIDR(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  const slash = trimmed.lastIndexOf("/");
  if (slash <= 0 || slash === trimmed.length - 1) return false;
  const address = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  if (!/^\d+$/.test(prefixText)) return false;
  const family = isIP(address);
  const prefix = Number(prefixText);
  return family !== 0 && prefix >= 0 && prefix <= (family === 4 ? 32 : 128);
}

function validDNSName(value: string): boolean {
  const host = value.endsWith(".") ? value.slice(0, -1) : value;
  if (host.length === 0 || host.length > 253) return false;
  return host.split(".").every((label) => (
    label.length >= 1
    && label.length <= 63
    && !label.startsWith("-")
    && !label.endsWith("-")
    && /^[A-Za-z0-9-]+$/.test(label)
  ));
}

function validEndpointHost(host: string): boolean {
  const family = isIP(host);
  if (family === 0) return validDNSName(host);
  if (family === 4) {
    const octets = host.split(".").map(Number);
    return !(octets[0] === 127
      || (octets[0] === 169 && octets[1] === 254)
      || (octets[0] >= 224 && octets[0] <= 239)
      || octets.every((octet) => octet === 0));
  }

  // WHATWG URL parsing gives one canonical IPv6 spelling, including compressed
  // and IPv4-mapped input. Mirror the helper's endpoint exclusions: unspecified,
  // loopback, link-local unicast, and multicast are never valid dial targets.
  try {
    const canonical = new URL(`http://[${host}]/`).hostname.slice(1, -1).toLowerCase();
    if (canonical === "::" || canonical === "::1" || canonical.startsWith("ff")) return false;
    const first = Number.parseInt(canonical.split(":", 1)[0] || "0", 16);
    return first < 0xfe80 || first > 0xfebf;
  } catch {
    return false;
  }
}

function validEndpoint(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const endpoint = value.trim();
  let host: string;
  let portText: string;
  if (endpoint.startsWith("[")) {
    const close = endpoint.lastIndexOf("]");
    if (close < 0 || endpoint[close + 1] !== ":") return false;
    host = endpoint.slice(1, close);
    portText = endpoint.slice(close + 2);
  } else {
    const colon = endpoint.lastIndexOf(":");
    if (colon <= 0 || colon === endpoint.length - 1 || endpoint.slice(0, colon).includes(":")) return false;
    host = endpoint.slice(0, colon);
    portText = endpoint.slice(colon + 1);
  }
  if (!/^\d+$/.test(portText)) return false;
  const port = Number(portText);
  return port >= 1 && port <= 65535 && validEndpointHost(host);
}

function validStringArray(value: unknown, item: (candidate: unknown) => boolean, requireOne = false): boolean {
  return Array.isArray(value) && (!requireOne || value.length > 0) && value.every(item);
}

const managedTunnelFieldKeys = new Set([
  "peer_public_key", "endpoint", "address", "addresses", "allowed_ips",
  "full_tunnel", "dns", "mtu", "persistent_keepalive", "dns_forwards",
  "control_plane_endpoint",
]);
const managedTunnelConfigKeys = new Set([...managedTunnelFieldKeys, "private_key"]);

function hasOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function validManagedTunnelFields(
  value: unknown,
  requireFullTunnel: boolean,
  includePrivateKey: boolean,
): value is Omit<TunnelConfig, "private_key"> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const config = value as Record<string, unknown>;
  if (!hasOnlyKeys(config, includePrivateKey ? managedTunnelConfigKeys : managedTunnelFieldKeys)) return false;
  if (
    !validWireGuardKey(config.peer_public_key)
    || !validEndpoint(config.endpoint)
    || !validCIDR(config.address)
    || !validStringArray(config.allowed_ips, validCIDR, true)
    || (requireFullTunnel
      ? typeof config.full_tunnel !== "boolean"
      : config.full_tunnel !== undefined && typeof config.full_tunnel !== "boolean")
  ) return false;
  if (config.addresses !== undefined && !validStringArray(config.addresses, validCIDR)) return false;
  if (config.dns !== undefined && !validStringArray(config.dns, (candidate) => typeof candidate === "string" && isIP(candidate.trim()) !== 0)) return false;
  if (config.mtu !== undefined && (!Number.isInteger(config.mtu) || (config.mtu !== 0 && (Number(config.mtu) < 1280 || Number(config.mtu) > 1500)))) return false;
  if (config.persistent_keepalive !== undefined && (!Number.isInteger(config.persistent_keepalive) || Number(config.persistent_keepalive) < 0 || Number(config.persistent_keepalive) > 65535)) return false;
  if (config.dns_forwards !== undefined && !validStringArray(config.dns_forwards, (candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
    const forward = candidate as Record<string, unknown>;
    return Object.keys(forward).length === 2
      && Object.hasOwn(forward, "domain")
      && Object.hasOwn(forward, "resolver_ip")
      && nonEmptyIdentity(forward.domain)
      && typeof forward.resolver_ip === "string"
      && isIP(forward.resolver_ip.trim()) !== 0;
  })) return false;
  if (config.control_plane_endpoint !== undefined && !validEndpoint(config.control_plane_endpoint)) return false;
  const defaults = (config.allowed_ips as string[]).filter((candidate) => {
    const trimmed = candidate.trim();
    const slash = trimmed.lastIndexOf("/");
    return slash > 0 && Number(trimmed.slice(slash + 1)) === 0;
  });
  const hasV4Default = defaults.some((candidate) => isIP(candidate.trim().slice(0, candidate.trim().lastIndexOf("/"))) === 4);
  const hasAnyDefault = defaults.length > 0;
  // Product full-tunnel support is IPv4-required and IPv6-optional. Any default
  // route therefore requires full-tunnel intent (and its kill-switch), while a
  // full-tunnel intent without the IPv4 default is incomplete.
  if ((config.full_tunnel === true) !== hasV4Default) return false;
  if (config.full_tunnel !== true && hasAnyDefault) return false;
  return true;
}

// Stored managed records are decrypted JSON, so TypeScript cannot establish
// their runtime shape. Validate the complete helper-facing structure before an
// owner fast path can perform a live read or return config to the helper. Fields
// introduced after the original store format remain optional for compatibility.
export function isValidManagedTunnelConfig(value: unknown): value is TunnelConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const config = value as Record<string, unknown>;
  return validWireGuardKey(config.private_key) && validManagedTunnelFields(config, false, true);
}

// Mode updates never re-issue the locally-held private key. Their remaining
// helper-facing facts use the exact same canonical validator, with explicit
// full-tunnel intent required for this response rather than legacy-optional.
export function isValidManagedTunnelModeConfig(value: unknown): value is Omit<TunnelConfig, "private_key"> {
  return validManagedTunnelFields(value, true, false);
}

// Imported `.conf` bytes are untrusted and contain a private key. Parse and
// validate them entirely in main before entering any lifecycle turn. The only
// observable failure is static; neither a raw line nor a config value escapes.
export function parseImportedTunnelConfig(text: string): TunnelConfig {
  try {
    const parsed = parseWgConf(text);
    const fullTunnel = parsed.allowed_ips.some(
      (allowedIP) => allowedIP === "0.0.0.0/0" || allowedIP === "::/0",
    );
    const config: TunnelConfig = { ...parsed, full_tunnel: fullTunnel };
    if (!isValidManagedTunnelConfig(config)) throw new Error("invalid");
    return config;
  } catch {
    throw new Error("invalid_imported_config");
  }
}

const legacyManagedDeviceProofBrand: unique symbol = Symbol("LegacyManagedDeviceProof");

// A caller can carry this proof across helper teardown, but cannot inspect or
// manufacture its destructive identity. Runtime provenance is also checked by
// the module-private WeakMap before any revoke is attempted.
export interface LegacyManagedDeviceProof {
  readonly [legacyManagedDeviceProofBrand]: true;
}

interface LegacyManagedDeviceProofState {
  readonly origin: string;
  readonly deviceId: string;
  readonly authenticatedUserId: string;
  readonly organizationId: string;
  readonly recordSnapshot: string;
  readonly api: Pick<DeviceApi, "discoverLegacyDevice" | "revokeDevice">;
  readonly store: TunnelConfigStore;
}

const legacyManagedDeviceProofs = new WeakMap<LegacyManagedDeviceProof, LegacyManagedDeviceProofState>();

function storedRecordSnapshot(record: StoredTunnelConfig): string {
  try {
    const snapshot = JSON.stringify(record);
    if (typeof snapshot !== "string") throw new Error("invalid record");
    return snapshot;
  } catch {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
}

function exactLegacyManagedRecord(
  origin: string,
  deviceId: string,
  authenticatedUserId: string,
  store: TunnelConfigStore,
  expectedSnapshot?: string,
): StoredTunnelConfig {
  if (!nonEmptyIdentity(origin) || !isCanonicalUuid(deviceId) || !isCanonicalUuid(authenticatedUserId)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  const existing = store.get(origin);
  if (!existing) throw new ManagedDeviceOwnerUnconfirmedError();

  // Once a live proof exists, any byte-visible stored-record change is a race,
  // not a new fact that proof may silently inherit. Check it before owner detail
  // so a replacement record cannot become an identity oracle.
  if (expectedSnapshot !== undefined && storedRecordSnapshot(existing) !== expectedSnapshot) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }

  const rawOrgId = (existing as StoredTunnelConfig & { orgId?: unknown }).orgId;
  const rawImported = (existing as StoredTunnelConfig & { imported?: unknown }).imported;
  if (
    existing.origin !== origin
    || existing.deviceId !== deviceId
    || (rawOrgId !== undefined && rawOrgId !== "")
    || (rawImported !== undefined && rawImported !== false)
    || !isValidManagedTunnelConfig((existing as StoredTunnelConfig & { config?: unknown }).config)
  ) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }

  const storedOwner = (existing as StoredTunnelConfig & { ownerUserId?: unknown }).ownerUserId;
  if (storedOwner !== undefined) {
    if (!isCanonicalUuid(storedOwner)) throw new ManagedDeviceOwnerUnconfirmedError();
    if (storedOwner !== authenticatedUserId) throw new ManagedDeviceOwnerMismatchError();
  }
  return existing;
}

// Read-only full-membership proof for the compatibility record that predates
// orgId. Discovery must establish one exact current-user match; then both the
// credential lease and the complete encrypted record are rechecked before an
// opaque proof can cross into the destructive remove phase.
export async function proveLegacyManagedDeviceOwner(
  origin: string,
  deviceId: string,
  authenticatedUserId: string,
  api: Pick<DeviceApi, "discoverLegacyDevice" | "revokeDevice">,
  store: TunnelConfigStore,
  assertLeaseCurrent: () => void,
): Promise<LegacyManagedDeviceProof> {
  const existing = exactLegacyManagedRecord(origin, deviceId, authenticatedUserId, store);
  const recordSnapshot = storedRecordSnapshot(existing);
  const organizationId = await api.discoverLegacyDevice(deviceId, authenticatedUserId);
  if (!isCanonicalUuid(organizationId)) throw new ManagedDeviceOwnerUnconfirmedError();

  assertLeaseCurrent();
  exactLegacyManagedRecord(origin, deviceId, authenticatedUserId, store, recordSnapshot);

  const proof = Object.freeze({
    [legacyManagedDeviceProofBrand]: true as const,
  });
  legacyManagedDeviceProofs.set(proof, Object.freeze({
    origin,
    deviceId,
    authenticatedUserId,
    organizationId,
    recordSnapshot,
    api,
    store,
  }));
  return proof;
}

// Consume only a proof minted above. The caller supplies the lifecycle check
// for the active remove lease (which may be the advanced successor of the
// proof-time lease). Lease + exact record are rechecked immediately before the
// POST and again after its await, immediately before local clear.
export async function revokeAndClearLegacyManagedDevice(
  proof: LegacyManagedDeviceProof,
  assertLeaseCurrent: () => void,
): Promise<void> {
  const state = legacyManagedDeviceProofs.get(proof);
  if (!state) throw new ManagedDeviceOwnerUnconfirmedError();
  // A proof authorizes one destructive attempt only. Burn it before even the
  // lease/store preflight so a failed attempt, a lost response, or recreation
  // of byte-identical local state can never replay the same authorization.
  legacyManagedDeviceProofs.delete(proof);

  assertLeaseCurrent();
  exactLegacyManagedRecord(
    state.origin,
    state.deviceId,
    state.authenticatedUserId,
    state.store,
    state.recordSnapshot,
  );
  await state.api.revokeDevice(state.deviceId, state.organizationId);

  assertLeaseCurrent();
  exactLegacyManagedRecord(
    state.origin,
    state.deviceId,
    state.authenticatedUserId,
    state.store,
    state.recordSnapshot,
  );
  state.store.remove(state.origin);
}

function assertManagedRecordStructure(
  origin: string,
  existing: StoredTunnelConfig,
): void {
  if (
    existing.imported
    || existing.origin !== origin
    || !isCanonicalUuid(existing.deviceId)
    || !isCanonicalUuid(existing.orgId)
    || !isValidManagedTunnelConfig((existing as StoredTunnelConfig & { config?: unknown }).config)
    || (existing.pending !== undefined && typeof existing.pending !== "boolean")
    || (existing.revoked !== undefined && typeof existing.revoked !== "boolean")
  ) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
}

function assertBoundManagedDeviceOwner(
  origin: string,
  existing: StoredTunnelConfig,
  authenticatedUserId: string | undefined,
): void {
  assertManagedRecordStructure(origin, existing);
  if (!isCanonicalUuid(authenticatedUserId)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  const storedOwner = (existing as StoredTunnelConfig & { ownerUserId?: unknown }).ownerUserId;
  if (!isCanonicalUuid(storedOwner)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  if (storedOwner !== authenticatedUserId) {
    throw new ManagedDeviceOwnerMismatchError();
  }
}

const managedDeviceOwnerProofBrand: unique symbol = Symbol("ManagedDeviceOwnerProof");

// Safe routing identity may cross the proof/quiesce boundary, but the owner,
// store, and exact encrypted record remain module-private. The WeakMap is the
// runtime provenance check: the public shape alone cannot authorize a commit.
export interface ManagedDeviceOwnerProof {
  readonly [managedDeviceOwnerProofBrand]: true;
  readonly deviceId: string;
  readonly organizationId: string;
}

interface ManagedDeviceOwnerProofState {
  readonly origin: string;
  readonly authenticatedUserId: string;
  readonly recordSnapshot: string;
  readonly apiIdentity: Pick<DeviceApi, "deviceRecord">;
  readonly store: TunnelConfigStore;
}

const managedDeviceOwnerProofs = new WeakMap<ManagedDeviceOwnerProof, ManagedDeviceOwnerProofState>();

function exactManagedRecord(
  origin: string,
  authenticatedUserId: string,
  store: TunnelConfigStore,
  expectedSnapshot: string,
): StoredTunnelConfig {
  const current = store.get(origin);
  if (!current || storedRecordSnapshot(current) !== expectedSnapshot) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  assertManagedRecordStructure(origin, current);
  const storedOwner = (current as StoredTunnelConfig & { ownerUserId?: unknown }).ownerUserId;
  if (storedOwner !== undefined) {
    assertBoundManagedDeviceOwner(origin, current, authenticatedUserId);
  }
  return current;
}

// Mint a read-only proof before helper quiescence. An ownerless compatibility
// record is checked against the live exact device row, but is deliberately not
// upgraded here: a failed helper down must leave the encrypted record unchanged.
export async function proveManagedDeviceOwner(
  origin: string,
  authenticatedUserId: string,
  api: Pick<DeviceApi, "deviceRecord">,
  store: TunnelConfigStore,
  assertLeaseCurrent: () => void,
): Promise<ManagedDeviceOwnerProof | null> {
  if (!isCanonicalUuid(authenticatedUserId)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  const existing = store.get(origin);
  if (!existing) return null;

  assertManagedRecordStructure(origin, existing);
  const recordSnapshot = storedRecordSnapshot(existing);
  const storedOwner = (existing as StoredTunnelConfig & { ownerUserId?: unknown }).ownerUserId;
  if (storedOwner !== undefined) {
    assertBoundManagedDeviceOwner(origin, existing, authenticatedUserId);
  } else {
    // Throws remain inconclusive and therefore fail closed. Every live row fact
    // is validated before its owner can authorize a later local write.
    const record = await api.deviceRecord(existing.deviceId, existing.orgId);
    if (!record || !isCanonicalUuid(record.userId) || !["active", "pending", "gone"].includes(record.status)) {
      throw new ManagedDeviceOwnerUnconfirmedError();
    }
    if (record.userId !== authenticatedUserId) {
      throw new ManagedDeviceOwnerMismatchError();
    }
  }

  assertLeaseCurrent();
  exactManagedRecord(origin, authenticatedUserId, store, recordSnapshot);

  const proof = Object.freeze({
    [managedDeviceOwnerProofBrand]: true as const,
    deviceId: existing.deviceId,
    organizationId: existing.orgId,
  });
  managedDeviceOwnerProofs.set(proof, Object.freeze({
    origin,
    authenticatedUserId,
    recordSnapshot,
    apiIdentity: api,
    store,
  }));
  return proof;
}

// Consume one proof only after helper quiescence. Burn it before the first
// check, then revalidate the active successor lease and the byte-exact record.
// A bound record is a no-write success; only an ownerless record is upgraded.
export function commitManagedDeviceOwnerProof(
  proof: ManagedDeviceOwnerProof,
  assertLeaseCurrent: () => void,
): void {
  consumeManagedDeviceOwnerProof(proof, assertLeaseCurrent);
}

interface ConsumedManagedDeviceOwnerProof {
  readonly state: ManagedDeviceOwnerProofState;
  readonly recordSnapshot: string;
}

function consumeManagedDeviceOwnerProof(
  proof: ManagedDeviceOwnerProof,
  assertLeaseCurrent: () => void,
): ConsumedManagedDeviceOwnerProof {
  const state = managedDeviceOwnerProofs.get(proof);
  if (!state) throw new ManagedDeviceOwnerUnconfirmedError();
  managedDeviceOwnerProofs.delete(proof);

  assertLeaseCurrent();
  const current = exactManagedRecord(
    state.origin,
    state.authenticatedUserId,
    state.store,
    state.recordSnapshot,
  );
  const storedOwner = (current as StoredTunnelConfig & { ownerUserId?: unknown }).ownerUserId;
  if (storedOwner === undefined) {
    state.store.put({ ...current, ownerUserId: state.authenticatedUserId });
  }

  const committed = state.store.get(state.origin);
  if (!committed) throw new ManagedDeviceOwnerUnconfirmedError();
  assertBoundManagedDeviceOwner(state.origin, committed, state.authenticatedUserId);
  return Object.freeze({
    state,
    recordSnapshot: storedRecordSnapshot(committed),
  });
}

// Consume the same pre-quiesce proof for explicit removal. The proof's fixed
// device/org facts are the only POST target; the active successor lease and
// byte-exact committed record are checked immediately before the POST and again
// before local clear. A lost/refused response therefore retains a retryable,
// owner-bound recovery handle, while token or record drift can never clear it.
export async function revokeAndClearManagedDevice(
  proof: ManagedDeviceOwnerProof,
  api: Pick<DeviceApi, "revokeDevice">,
  assertLeaseCurrent: () => void,
): Promise<void> {
  const proofState = managedDeviceOwnerProofs.get(proof);
  if (!proofState || (api as object) !== (proofState.apiIdentity as object)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  const consumed = consumeManagedDeviceOwnerProof(proof, assertLeaseCurrent);
  const { state, recordSnapshot } = consumed;

  assertLeaseCurrent();
  exactManagedRecord(
    state.origin,
    state.authenticatedUserId,
    state.store,
    recordSnapshot,
  );
  await api.revokeDevice(proof.deviceId, proof.organizationId);

  assertLeaseCurrent();
  exactManagedRecord(
    state.origin,
    state.authenticatedUserId,
    state.store,
    recordSnapshot,
  );
  state.store.remove(state.origin);
}

// bindManagedDeviceOwner is the ONLY upgrade path for an ownerless managed
// record that already has an orgId. A complete live record for the exact
// device must name the current user; a foreign/absent/malformed/inconclusive
// read leaves the encrypted record untouched. Records older than orgId use the
// separate revoke-first legacy migration and are deliberately not bound here.
export async function bindManagedDeviceOwner(
  origin: string,
  authenticatedUserId: string,
  api: Pick<DeviceApi, "deviceRecord">,
  store: TunnelConfigStore,
): Promise<StoredTunnelConfig | null> {
  const proof = await proveManagedDeviceOwner(
    origin,
    authenticatedUserId,
    api,
    store,
    () => {},
  );
  if (!proof) return null;
  commitManagedDeviceOwnerProof(proof, () => {});
  const bound = store.get(origin);
  if (!bound) throw new ManagedDeviceOwnerUnconfirmedError();
  assertBoundManagedDeviceOwner(origin, bound, authenticatedUserId);
  return bound;
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

function enrollmentConflict(): Error {
  return new Error("device_key_recovery_conflict");
}

function enrollmentAbandonRefused(): Error {
  return new Error("managed_enrollment_abandon_refused");
}

function anchorSnapshot(anchor: EnrollmentAnchor): string {
  try {
    const snapshot = JSON.stringify(anchor);
    if (!snapshot) throw new Error("invalid");
    return snapshot;
  } catch {
    throw enrollmentAbandonRefused();
  }
}

function exactAbandonAnchor(
  store: EnrollmentAnchorStore,
  origin: string,
  ownerUserId: string,
  organizationId: string,
  credentialFingerprint: string,
  expectedSnapshot?: string,
): EnrollmentAnchor | null {
  const anchor = store.get(origin);
  if (!anchor) return null;
  if (
    anchor.origin !== origin
    || anchor.ownerUserId !== ownerUserId
    || anchor.organizationId !== organizationId
    || anchor.credentialFingerprint !== credentialFingerprint
    || (expectedSnapshot !== undefined && anchorSnapshot(anchor) !== expectedSnapshot)
  ) throw enrollmentAbandonRefused();
  return anchor;
}

function validateAbandonRoster(rows: ManagedEnrollmentDevice[], publicKey: string): void {
  if (!Array.isArray(rows)) throw enrollmentAbandonRefused();
  for (const row of rows) {
    if (
      !row
      || !isCanonicalUuid(row.deviceId)
      || !isCanonicalUuid(row.ownerUserId)
      || !isCanonicalUuid(row.nodeId)
      || row.publicKey !== publicKey
      || (row.status !== "active" && row.status !== "pending" && row.status !== "gone")
    ) throw enrollmentAbandonRefused();
  }
}

// This is the public-only selection projection for an unresolved anchor. The
// keypair, fingerprint, node and device facts remain in MAIN.
export function enrollmentAnchorOrganizationForUser(
  anchor: EnrollmentAnchor | null,
  origin: string,
  ownerUserId: string,
): string | null {
  return anchor?.origin === origin && anchor.ownerUserId === ownerUserId
    ? anchor.organizationId
    : null;
}

// Proof happens before helper teardown so an unavailable or malformed roster
// cannot disrupt the current transport. The roster is deliberately discarded:
// consumeManagedEnrollmentAbandonProof reads it again after exact helper Down.
export async function proveManagedEnrollmentAbandonment(
  origin: string,
  ownerUserId: string,
  organizationId: string,
  credentialFingerprint: string,
  liveOrganizationIds: readonly string[],
  api: Pick<DeviceApi, "devicesByPublicKey" | "revokeDevice">,
  anchorStore: EnrollmentAnchorStore,
  assertLeaseCurrent: () => void,
): Promise<ManagedEnrollmentAbandonProof | null> {
  if (!liveOrganizationIds.includes(organizationId)) throw enrollmentAbandonRefused();
  const anchor = exactAbandonAnchor(
    anchorStore,
    origin,
    ownerUserId,
    organizationId,
    credentialFingerprint,
  );
  if (!anchor) return null;
  const snapshot = anchorSnapshot(anchor);
  const rows = await api.devicesByPublicKey(organizationId, anchor.publicKey);
  validateAbandonRoster(rows, anchor.publicKey);
  assertLeaseCurrent();
  exactAbandonAnchor(
    anchorStore,
    origin,
    ownerUserId,
    organizationId,
    credentialFingerprint,
    snapshot,
  );
  const proof = Object.freeze({ [managedEnrollmentAbandonProofBrand]: true as const });
  managedEnrollmentAbandonProofs.set(proof, Object.freeze({
    origin,
    ownerUserId,
    organizationId,
    credentialFingerprint,
    anchorSnapshot: snapshot,
    apiIdentity: api as object,
    api,
    anchorStore,
  }));
  return proof;
}

// Consumed only after the caller has proved the privileged helper Down and
// advanced the fixed lifecycle lease. The current roster owns the decision;
// the pre-quiesce roster above is never reused as destructive authority.
export async function consumeManagedEnrollmentAbandonProof(
  proof: ManagedEnrollmentAbandonProof,
  api: Pick<DeviceApi, "devicesByPublicKey" | "revokeDevice">,
  assertLeaseCurrent: () => void,
): Promise<void> {
  const state = managedEnrollmentAbandonProofs.get(proof);
  if (!state || (api as object) !== state.apiIdentity) throw enrollmentAbandonRefused();
  managedEnrollmentAbandonProofs.delete(proof);

  const readAnchor = (): EnrollmentAnchor => {
    const anchor = exactAbandonAnchor(
      state.anchorStore,
      state.origin,
      state.ownerUserId,
      state.organizationId,
      state.credentialFingerprint,
      state.anchorSnapshot,
    );
    if (!anchor) throw enrollmentAbandonRefused();
    return anchor;
  };

  assertLeaseCurrent();
  let anchor = readAnchor();
  let rows = await state.api.devicesByPublicKey(state.organizationId, anchor.publicKey);
  validateAbandonRoster(rows, anchor.publicKey);
  assertLeaseCurrent();
  anchor = readAnchor();

  const exactLive = rows.filter((row) =>
    (row.status === "active" || row.status === "pending")
    && row.ownerUserId === state.ownerUserId
    && (anchor.deviceId === undefined || row.deviceId === anchor.deviceId));
  const rowToRevoke = exactLive.length === 1
    && (rows.length === 1 || anchor.deviceId !== undefined)
    ? exactLive[0]
    : null;

  if (rowToRevoke) {
    await state.api.revokeDevice(rowToRevoke.deviceId, state.organizationId);
    assertLeaseCurrent();
    anchor = readAnchor();
    rows = await state.api.devicesByPublicKey(state.organizationId, anchor.publicKey);
    validateAbandonRoster(rows, anchor.publicKey);
    if (rows.some((row) =>
      row.deviceId === rowToRevoke.deviceId
      && row.ownerUserId === state.ownerUserId
      && (row.status === "active" || row.status === "pending"))) {
      throw enrollmentAbandonRefused();
    }
    assertLeaseCurrent();
    readAnchor();
  }

  let removed: EnrollmentAnchor | null;
  try {
    removed = state.anchorStore.remove(state.origin);
  } catch (error) {
    if (!(error instanceof EnrollmentAnchorClearAfterUnlinkError)) throw error;

    // The exact clear crossed unlink but did not prove its namespace durable.
    // Stay inside the consumed lifecycle proof, recheck its lease, then use the
    // store's trusted read path to sync the parent and prove the old anchor is
    // absent. This invocation never generates or POSTs a replacement key.
    assertLeaseCurrent();
    const recovered = state.anchorStore.reproveClearAfterUnlink(error, state.origin);
    if (recovered === null) return;
    if (anchorSnapshot(recovered) === state.anchorSnapshot) {
      throw enrollmentAbandonRefused();
    }
    throw new EnrollmentAnchorStoreCorruptError();
  }
  if (!removed || anchorSnapshot(removed) !== state.anchorSnapshot) {
    throw enrollmentAbandonRefused();
  }
}

function assertAnchorContext(
  anchor: EnrollmentAnchor,
  origin: string,
  organizationId: string,
  ownerUserId: string,
): void {
  if (
    anchor.origin !== origin
    || anchor.organizationId !== organizationId
    || anchor.ownerUserId !== ownerUserId
  ) throw enrollmentConflict();
}

function exactEnrollmentDevice(
  anchor: EnrollmentAnchor,
  rows: ManagedEnrollmentDevice[],
): ManagedEnrollmentDevice | null {
  if (rows.length === 0) return null;
  if (rows.length !== 1) throw enrollmentConflict();
  const row = rows[0];
  if (!isCanonicalUuid(row.deviceId) || !isCanonicalUuid(row.ownerUserId)) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  if (row.ownerUserId !== anchor.ownerUserId) throw new ManagedDeviceOwnerMismatchError();
  if (
    !isCanonicalUuid(row.nodeId)
    || row.publicKey !== anchor.publicKey
    || (row.status !== "active" && row.status !== "pending")
    || (anchor.deviceId !== undefined && row.deviceId !== anchor.deviceId)
  ) throw enrollmentConflict();
  return row;
}

function finalRecordMatchesAnchor(existing: StoredTunnelConfig, anchor: EnrollmentAnchor): boolean {
  if (
    !anchor.deviceId
    || existing.origin !== anchor.origin
    || existing.deviceId !== anchor.deviceId
    || existing.orgId !== anchor.organizationId
    || existing.ownerUserId !== anchor.ownerUserId
    || !isValidManagedTunnelConfig(existing.config)
  ) return false;
  try {
    return deriveWireGuardPublicKey(existing.config.private_key) === anchor.publicKey
      && existing.config.private_key === anchor.privateKey;
  } catch {
    return false;
  }
}

async function finishManagedEnrollment(
  origin: string,
  organizationId: string,
  ownerUserId: string,
  requestedFullTunnel: boolean,
  api: DeviceApi,
  store: TunnelConfigStore,
  recovery: ManagedEnrollmentRecoveryContext,
): Promise<StoredTunnelConfig> {
  if (!recovery.credentialFingerprint) throw new Error("managed_enrollment_context_required");
  let anchor = recovery.anchorStore.get(origin);
  if (anchor) {
    assertAnchorContext(anchor, origin, organizationId, ownerUserId);
    // A replacement token may resume only after IPC has fixed the exact origin,
    // current human and live organization membership into this invocation. The
    // token stays in the lease; only its non-secret fingerprint is rebound.
    if (anchor.credentialFingerprint !== recovery.credentialFingerprint) {
      anchor = recovery.anchorStore.rebindCredential(origin, recovery.credentialFingerprint);
    }
  } else {
    const preparation = await api.prepareDeviceEnrollment(organizationId);
    if (
      !isCanonicalUuid(preparation.nodeId)
      || typeof preparation.name !== "string"
      || preparation.name.length === 0
      || typeof preparation.platform !== "string"
      || preparation.platform.length === 0
    ) throw new Error("create_device_failed: invalid_response");
    const keyPair = generateWireGuardKeyPair();
    anchor = {
      version: 1,
      origin,
      organizationId,
      ownerUserId,
      credentialFingerprint: recovery.credentialFingerprint,
      nodeId: preparation.nodeId,
      name: preparation.name,
      platform: preparation.platform,
      fullTunnel: requestedFullTunnel,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
    // This exact decrypted readback completes before the first list or POST.
    recovery.anchorStore.put(anchor);
  }

  const visible = await api.devicesByPublicKey(anchor.organizationId, anchor.publicKey);
  let device = exactEnrollmentDevice(anchor, visible);
  if (!device) {
    device = await api.createDevice({
      organizationId: anchor.organizationId,
      nodeId: anchor.nodeId,
      name: anchor.name,
      platform: anchor.platform,
      fullTunnel: anchor.fullTunnel,
      publicKey: anchor.publicKey,
    });
    device = exactEnrollmentDevice(anchor, [device]);
    if (!device) throw new Error("create_device_failed: invalid_response");
  }
  if (!anchor.deviceId) {
    anchor = recovery.anchorStore.bind(origin, device.deviceId);
  } else if (anchor.deviceId !== device.deviceId) {
    throw enrollmentConflict();
  }
  const boundDeviceId = anchor.deviceId;
  if (!boundDeviceId) throw enrollmentConflict();

  if (!api.updateDeviceMode) throw new Error("device_mode_update_unsupported");
  const mode = await api.updateDeviceMode(boundDeviceId, anchor.organizationId, requestedFullTunnel);
  if (
    mode.deviceId !== boundDeviceId
    || mode.ownerUserId !== anchor.ownerUserId
    || !isCanonicalUuid(mode.nodeId)
    || mode.publicKey !== anchor.publicKey
    || (mode.status !== "active" && mode.status !== "pending")
    || mode.fullTunnel !== requestedFullTunnel
  ) throw enrollmentConflict();
  const config: TunnelConfig = {
    private_key: anchor.privateKey,
    peer_public_key: mode.peerPublicKey,
    endpoint: mode.endpoint,
    address: mode.address,
    addresses: mode.addresses,
    allowed_ips: mode.allowedIPs,
    dns: mode.dns,
    mtu: mode.mtu,
    persistent_keepalive: mode.persistentKeepalive,
    full_tunnel: mode.fullTunnel,
  };
  if (!isValidManagedTunnelConfig(config)) {
    throw new Error("create_device_failed: invalid_response");
  }
  const published: StoredTunnelConfig = {
    origin,
    deviceId: boundDeviceId,
    orgId: anchor.organizationId,
    ownerUserId: anchor.ownerUserId,
    config,
    pending: mode.status === "pending",
  };
  // The final encrypted record is durably published and read back while the
  // anchor still exists. Only that proof authorizes anchor removal.
  store.put(published);
  recovery.anchorStore.remove(origin);
  return published;
}

export async function resolveTunnelConfig(
  origin: string,
  fullTunnel: boolean,
  api: DeviceApi,
  store: TunnelConfigStore,
  enrollmentOrganizationId?: string,
  authenticatedUserId?: string,
  enrollmentRecovery?: ManagedEnrollmentRecoveryContext,
): Promise<TunnelConfig> {
  // WF-A: for a FULL tunnel, attach the CP endpoint so the helper carves the kill-switch to it (the control
  // channel must survive the tunnel going down to re-home). NEVER persisted — it's an origin-derived routing
  // fact, re-attached each connect on top of the stored identity-only config. Split → no carve-out.
  const withCP = (cfg: TunnelConfig): TunnelConfig =>
    fullTunnel ? { ...cfg, control_plane_endpoint: cpEndpointFromOrigin(origin) } : cfg;
  let existing = store.get(origin);
  const unresolvedAnchor = enrollmentRecovery?.anchorStore.get(origin) ?? null;
  if (existing && unresolvedAnchor) {
    if (!isCanonicalUuid(authenticatedUserId)) throw new ManagedDeviceOwnerUnconfirmedError();
    if (authenticatedUserId !== unresolvedAnchor.ownerUserId) throw new ManagedDeviceOwnerMismatchError();
    if (enrollmentOrganizationId && enrollmentOrganizationId !== unresolvedAnchor.organizationId) {
      throw new OrganizationSelectionConflictError();
    }
    if (!finalRecordMatchesAnchor(existing, unresolvedAnchor)) throw enrollmentConflict();
    enrollmentRecovery?.anchorStore.remove(origin);
  }
  if (existing) {
    // IPC performs the live owner-binding preflight before helper installation.
    // This local assertion is the final belt before status/mode reads or a
    // config can leave main for the helper.
    assertBoundManagedDeviceOwner(origin, existing, authenticatedUserId);
  }
  if (existing?.orgId && enrollmentOrganizationId && existing.orgId !== enrollmentOrganizationId) {
    throw new OrganizationSelectionConflictError();
  }
  if (existing && !existing.orgId) {
    // connect() owns the exact current-user scan + revoke-first migration. If
    // that preflight was skipped, retain the record and refuse: this function
    // must never convert unproven absence into a local clear + fresh identity.
    throw new ManagedDeviceOwnerUnconfirmedError();
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
    if (mode.fullTunnel !== fullTunnel) throw new Error("update_device_mode_failed: invalid_response");
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
    // The HTTP adapter validates its response, but DeviceApi is a seam. Re-run
    // the same canonical helper-facing check on the final composition so no
    // adapter can persist or hand off one malformed first-use config.
    if (!isValidManagedTunnelConfig(config)) {
      throw new Error("update_device_mode_failed: invalid_response");
    }
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

  if (!enrollmentOrganizationId) throw new OrganizationSelectionRequiredError();
  if (!isCanonicalUuid(enrollmentOrganizationId)) throw new OrganizationSelectionConflictError();
  if (!isCanonicalUuid(authenticatedUserId)) throw new ManagedDeviceOwnerUnconfirmedError();
  if (!enrollmentRecovery) throw new Error("managed_enrollment_context_required");
  const published = await finishManagedEnrollment(
    origin,
    enrollmentOrganizationId,
    authenticatedUserId,
    fullTunnel,
    api,
    store,
    enrollmentRecovery,
  );
  if (published.pending) {
    throw new PendingApprovalError(published.deviceId); // S7.3: abort — do NOT arm the helper
  }
  return withCP(published.config);
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
  authenticatedUserId: string,
  api: Pick<DeviceApi, "discoverLegacyDevice" | "revokeDevice">,
  store: TunnelConfigStore,
  assertLeaseCurrent: () => void,
): Promise<void> {
  const proof = await proveLegacyManagedDeviceOwner(
    origin,
    deviceId,
    authenticatedUserId,
    api,
    store,
    assertLeaseCurrent,
  );
  await revokeAndClearLegacyManagedDevice(proof, assertLeaseCurrent);
}

// discardTunnelConfigForOrigin drops a config only after the server has already
// declared it terminal (revocation/rejection). It intentionally makes no network
// request: normal sign-out is not a terminal state and never calls this helper.
export function discardTunnelConfigForOrigin(
  origin: string,
  authenticatedUserId: string,
  store: TunnelConfigStore,
): void {
  const existing = store.get(origin);
  if (!existing) return;
  assertBoundManagedDeviceOwner(origin, existing, authenticatedUserId);
  store.remove(origin);
}

// removeManagedTunnelConfigForOrigin is the explicit, destructive device action.
// Revoke first: if the server cannot confirm removal, keep the encrypted local
// credential so the user can retry instead of orphaning a still-active peer.
export async function removeManagedTunnelConfigForOrigin(
  origin: string,
  authenticatedUserId: string,
  api: DeviceApi,
  store: TunnelConfigStore,
): Promise<boolean> {
  const existing = await bindManagedDeviceOwner(origin, authenticatedUserId, api, store);
  if (!existing) return false;
  if (!isCanonicalUuid(existing.orgId)) throw new ManagedDeviceOwnerUnconfirmedError();
  await api.revokeDevice(existing.deviceId, existing.orgId);
  // The revoke was for this exact bound record. Refuse to clear if another
  // operation replaced the local identity while it was in flight.
  const proven = store.get(origin);
  if (!proven) throw new ManagedDeviceOwnerUnconfirmedError();
  assertBoundManagedDeviceOwner(origin, proven, authenticatedUserId);
  if (proven.deviceId !== existing.deviceId || proven.orgId !== existing.orgId) {
    throw new ManagedDeviceOwnerUnconfirmedError();
  }
  store.remove(origin);
  return true;
}
