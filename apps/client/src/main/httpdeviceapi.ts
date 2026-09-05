import os from "node:os";
import {
  isValidManagedTunnelModeConfig,
  type DeviceApi,
  type DeviceModeConfig,
  type DeviceRecord,
  type HealthFacts,
  type HealthReportResult,
  type ManagedEnrollmentCreate,
  type ManagedEnrollmentDevice,
  type ManagedEnrollmentPreparation,
  type RoutedConfig,
} from "./deviceconfig";
import type { ResolverForward } from "./helperclient";
import { encodeUuidPathSegment, isCanonicalUuid } from "./uuid";
import { controlPlaneRequest, CONTROL_PLANE_REQUEST_TIMEOUT_MS } from "./controlplanerequest";

export interface OrganizationMembership {
  id: string;
  name: string;
  slug: string;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validWireGuardKey(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  return Buffer.from(value, "base64").length === 32;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function hasRequiredAllowedKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  allowed: ReadonlySet<string>,
): boolean {
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

const deviceModeResponseDeviceKeys = new Set([
  "id", "user_id", "owner_email", "node_id", "name", "platform", "kind",
  "public_key", "full_tunnel", "assigned_ip", "needs_reexport", "status",
  "approved_by", "created_at", "last_handshake_at", "online", "rx_bytes",
  "tx_bytes", "health_state", "health_blocked", "health_os_version",
  "health_disk_encrypted", "health_reported_at", "health_failed_checks",
]);

const deviceModeResponseConfigKeys = new Set([
  "address", "addresses", "endpoint", "peer_public_key", "allowed_ips", "dns",
  "mtu", "persistent_keepalive",
]);

function validOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

function validOptionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === "boolean";
}

function validOptionalInteger(value: unknown): boolean {
  return value === undefined || Number.isInteger(value);
}

function validDeviceHealthChecks(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
    const check = raw as Record<string, unknown>;
    return hasExactKeys(check, ["kind", "mode"])
      && (check.kind === "os_version" || check.kind === "disk_encryption")
      && (check.mode === "warn" || check.mode === "require");
  }));
}

function validDeviceModeResponseDevice(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const device = value as Record<string, unknown>;
  if (!hasRequiredAllowedKeys(
    device,
    ["id", "user_id", "node_id", "name", "status", "public_key", "created_at", "full_tunnel"],
    deviceModeResponseDeviceKeys,
  )) return false;
  return isCanonicalUuid(device.id)
    && isCanonicalUuid(device.user_id)
    && isCanonicalUuid(device.node_id)
    && typeof device.name === "string"
    && nonEmptyString(device.public_key)
    && nonEmptyString(device.created_at)
    && typeof device.full_tunnel === "boolean"
    && ["active", "revoked", "pending", "suspended"].includes(String(device.status))
    && (device.owner_email === undefined || device.owner_email === null || typeof device.owner_email === "string")
    && validOptionalString(device.platform)
    && (device.kind === undefined || device.kind === "human" || device.kind === "agent")
    && validOptionalString(device.assigned_ip)
    && validOptionalBoolean(device.needs_reexport)
    && (device.approved_by === undefined || device.approved_by === null || isCanonicalUuid(device.approved_by))
    && validOptionalString(device.last_handshake_at)
    && validOptionalBoolean(device.online)
    && validOptionalInteger(device.rx_bytes)
    && validOptionalInteger(device.tx_bytes)
    && (device.health_state === undefined || ["compliant", "noncompliant", "unknown"].includes(String(device.health_state)))
    && validOptionalBoolean(device.health_blocked)
    && validOptionalString(device.health_os_version)
    && validOptionalBoolean(device.health_disk_encrypted)
    && validOptionalString(device.health_reported_at)
    && validDeviceHealthChecks(device.health_failed_checks);
}

function healthReportResult(body: unknown): HealthReportResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("report_health_failed: invalid_response");
  }
  const result = body as Record<string, unknown>;
  if (
    !hasExactKeys(result, ["state", "blocked", "failed_checks"])
    || (result.state !== "compliant" && result.state !== "noncompliant")
    || typeof result.blocked !== "boolean"
    || !Array.isArray(result.failed_checks)
  ) {
    throw new Error("report_health_failed: invalid_response");
  }

  const failedChecks: HealthReportResult["failed_checks"] = [];
  const seenKinds = new Set<string>();
  for (const raw of result.failed_checks) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("report_health_failed: invalid_response");
    }
    const check = raw as Record<string, unknown>;
    if (
      !hasExactKeys(check, ["kind", "mode"])
      || (check.kind !== "os_version" && check.kind !== "disk_encryption")
      || (check.mode !== "warn" && check.mode !== "require")
      || seenKinds.has(check.kind)
    ) {
      throw new Error("report_health_failed: invalid_response");
    }
    seenKinds.add(check.kind);
    failedChecks.push({ kind: check.kind, mode: check.mode });
  }

  // The evaluator starts compliant, flips noncompliant for every failed check,
  // and sets blocked iff at least one failed check is require-mode. Reject an
  // internally inconsistent 2xx rather than manufacturing operator posture.
  const expectedState = failedChecks.length === 0 ? "compliant" : "noncompliant";
  const expectedBlocked = failedChecks.some((check) => check.mode === "require");
  if (result.state !== expectedState || result.blocked !== expectedBlocked) {
    throw new Error("report_health_failed: invalid_response");
  }
  return { state: result.state, blocked: result.blocked, failed_checks: failedChecks };
}

function deviceRecords(body: unknown): Array<{ id: string; record: DeviceRecord }> {
  if (!Array.isArray(body)) throw new Error("list_devices_failed: invalid_response");
  return body.map((raw) => {
    if (!raw || typeof raw !== "object") throw new Error("list_devices_failed: invalid_response");
    const row = raw as { id?: unknown; user_id?: unknown; status?: unknown };
    if (!isCanonicalUuid(row.id) || !isCanonicalUuid(row.user_id) || !["active", "pending", "revoked", "suspended"].includes(String(row.status))) {
      throw new Error("list_devices_failed: invalid_response");
    }
    const status: DeviceRecord["status"] = row.status === "active" ? "active" : row.status === "pending" ? "pending" : "gone";
    return { id: row.id, record: { status, userId: row.user_id } };
  });
}

function enrollmentDevice(row: Record<string, unknown>, requirePublicKey: boolean): ManagedEnrollmentDevice {
  if (
    !isCanonicalUuid(row.id)
    || !isCanonicalUuid(row.user_id)
    || !isCanonicalUuid(row.node_id)
    || typeof row.public_key !== "string"
    || (requirePublicKey ? !validWireGuardKey(row.public_key) : row.public_key !== "" && !validWireGuardKey(row.public_key))
    || !["active", "pending", "revoked", "suspended"].includes(String(row.status))
  ) throw new Error("list_devices_failed: invalid_response");
  return {
    deviceId: row.id,
    ownerUserId: row.user_id,
    nodeId: row.node_id,
    publicKey: row.public_key,
    status: row.status === "active" ? "active" : row.status === "pending" ? "pending" : "gone",
  };
}

async function responseErrorCode(r: Response): Promise<string | null> {
  try {
    const body: unknown = await r.json();
    if (!body || typeof body !== "object") return null;
    const error = (body as { error?: unknown }).error;
    if (!error || typeof error !== "object") return null;
    const code = (error as { code?: unknown }).code;
    return typeof code === "string" ? code : null;
  } catch {
    return null;
  }
}

// createErr surfaces the server's TYPED error code (body.error.code) when present, so
// a caller can match on it — e.g. the S3.7 `gateway_no_egress` full-tunnel refusal the
// UI mirrors cleanly. Falls back to the status when the body isn't the typed shape.
async function createErr(r: Response): Promise<string> {
  const code = await responseErrorCode(r);
  if (code) {
    // Keep BOTH the numeric status (diagnosable: 401 vs 403 vs 5xx) AND the typed code
    // (matchable: e.g. the future S3.7 gateway_no_egress). friendly() uses .includes()
    // so either substring still matches.
    return `create_device_failed: ${r.status} ${code}`;
  }
  return `create_device_failed: ${r.status}`;
}

// HttpDeviceApi is the concrete DeviceApi over the tenant REST API, called from
// MAIN with the bearer (never the renderer). It mirrors the CLI's device flow:
// use the caller's explicitly resolved org + an active gateway node, POST
// create-device, and capture the ONE-TIME .conf. Runtime is human-smoke (needs
// a live tenant); the shape is tsc-checked against the OpenAPI contract.
export class HttpDeviceApi implements DeviceApi {
  constructor(
    private readonly origin: string,
    private readonly token: string,
    private readonly requestTimeoutMs = CONTROL_PLANE_REQUEST_TIMEOUT_MS,
  ) {}

  private headers(): Record<string, string> {
    const t = this.token;
    if (!t) throw new Error("not_authenticated");
    // Bearer requests carry no cookie, so the server's CSRF guard is inert; the
    // header is presence-only and harmless (matches the shared client posture).
    return { authorization: `Bearer ${t}`, "content-type": "application/json", "x-tunnex-csrf": "1" };
  }

  // Keep the deadline alive until the response body has been consumed by the
  // callback. Fetch resolves when headers arrive, so bounding only that await
  // would still let a stalled JSON body own the lifecycle FIFO indefinitely.
  private async request<T>(
    path: string,
    init: RequestInit,
    consume: (response: Response) => Promise<T>,
  ): Promise<T> {
    return controlPlaneRequest(`${this.origin}${path}`, init, consume, this.requestTimeoutMs);
  }

  private async activeNodeId(orgId: string): Promise<string> {
    const orgPath = encodeUuidPathSegment(orgId, "list_nodes_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/nodes`, { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`list_nodes_failed: ${r.status}`);
      const body: unknown = await r.json();
      if (!Array.isArray(body)) throw new Error("list_nodes_failed: invalid_response");
      const nodes = body.map((raw): { id: string; status: "active" | "revoked" } => {
        if (!raw || typeof raw !== "object") throw new Error("list_nodes_failed: invalid_response");
        const node = raw as { id?: unknown; status?: unknown };
        if (!isCanonicalUuid(node.id) || (node.status !== "active" && node.status !== "revoked")) {
          throw new Error("list_nodes_failed: invalid_response");
        }
        return { id: node.id, status: node.status };
      });
      const active = nodes.find((n) => n.status === "active");
      if (!active) throw new Error("no_active_gateway");
      return active.id;
    });
  }

  async prepareDeviceEnrollment(orgId: string): Promise<ManagedEnrollmentPreparation> {
    if (!isCanonicalUuid(orgId)) throw new Error("organization_selection_required");
    return {
      nodeId: await this.activeNodeId(orgId),
      name: `tunnex-desktop-${os.hostname()}`,
      platform: process.platform,
    };
  }

  async devicesByPublicKey(orgId: string, publicKey: string): Promise<ManagedEnrollmentDevice[]> {
    const orgPath = encodeUuidPathSegment(orgId, "list_devices_failed: invalid_request");
    if (!validWireGuardKey(publicKey)) throw new Error("list_devices_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/devices`, { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`list_devices_failed: ${r.status}`);
      const body: unknown = await r.json();
      if (!Array.isArray(body)) throw new Error("list_devices_failed: invalid_response");
      const rows = body.map((raw) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
          throw new Error("list_devices_failed: invalid_response");
        }
        return enrollmentDevice(raw as Record<string, unknown>, false);
      });
      return rows.filter((row) => row.publicKey === publicKey);
    });
  }

  async createDevice(intent: ManagedEnrollmentCreate): Promise<ManagedEnrollmentDevice> {
    if (
      !isCanonicalUuid(intent.organizationId)
      || !isCanonicalUuid(intent.nodeId)
      || !validWireGuardKey(intent.publicKey)
      || !nonEmptyString(intent.name)
      || !nonEmptyString(intent.platform)
    ) throw new Error("create_device_failed: invalid_request");
    const orgPath = encodeUuidPathSegment(intent.organizationId, "organization_selection_required");
    return this.request(`/api/v1/organizations/${orgPath}/devices`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        name: intent.name,
        node_id: intent.nodeId,
        full_tunnel: intent.fullTunnel,
        platform: intent.platform,
        kind: "human",
        provisioning: "managed",
        public_key: intent.publicKey,
      }),
    }, async (r) => {
      if (!r.ok) throw new Error(await createErr(r));
      let body: unknown;
      try {
        body = await r.json();
      } catch {
        throw new Error("create_device_failed: invalid_response");
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        throw new Error("create_device_failed: invalid_response");
      }
      const response = body as Record<string, unknown>;
      // The client-key flow has no one-time server secret. Reject even a
      // nominally successful response that attempts to send private_key/config.
      if (!hasRequiredAllowedKeys(response, ["device"], new Set(["device", "pending_approval"]))) {
        throw new Error("create_device_failed: invalid_response");
      }
      if (!response.device || typeof response.device !== "object" || Array.isArray(response.device)) {
        throw new Error("create_device_failed: invalid_response");
      }
      let device: ManagedEnrollmentDevice;
      try {
        device = enrollmentDevice(response.device as Record<string, unknown>, true);
      } catch {
        throw new Error("create_device_failed: invalid_response");
      }
      if (
        device.publicKey !== intent.publicKey
        || (device.status !== "active" && device.status !== "pending")
        || (response.pending_approval !== undefined && typeof response.pending_approval !== "boolean")
        || (response.pending_approval === true) !== (device.status === "pending")
      ) throw new Error("create_device_failed: invalid_response");
      return device;
    });
  }

  async updateDeviceMode(deviceId: string, orgId: string, fullTunnel: boolean): Promise<DeviceModeConfig> {
    const orgPath = encodeUuidPathSegment(orgId, "update_device_mode_failed: invalid_request");
    const devicePath = encodeUuidPathSegment(deviceId, "update_device_mode_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/devices/${devicePath}/mode?full_tunnel=${fullTunnel}`, {
      method: "PATCH", headers: this.headers(),
    }, async (r) => {
      if (!r.ok) throw new Error(`update_device_mode_failed: ${r.status}`);
      let body: unknown;
      try {
        body = await r.json();
      } catch {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      const response = body as Record<string, unknown>;
      if (
        !hasExactKeys(response, ["device", "config"])
        || !validDeviceModeResponseDevice(response.device)
        || !response.config || typeof response.config !== "object" || Array.isArray(response.config)
      ) {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      const device = response.device;
      const config = response.config as Record<string, unknown>;
      if (device.id !== deviceId || !validWireGuardKey(device.public_key)) {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      if (!hasRequiredAllowedKeys(
        config,
        ["address", "endpoint", "peer_public_key", "allowed_ips"],
        deviceModeResponseConfigKeys,
      )) {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      const candidate: unknown = {
        full_tunnel: device.full_tunnel,
        address: config.address,
        addresses: config.addresses,
        endpoint: config.endpoint,
        peer_public_key: config.peer_public_key,
        allowed_ips: config.allowed_ips,
        dns: config.dns,
        mtu: config.mtu,
        persistent_keepalive: config.persistent_keepalive,
      };
      if (!isValidManagedTunnelModeConfig(candidate) || candidate.full_tunnel !== fullTunnel) {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      if (device.status !== "active" && device.status !== "pending") {
        throw new Error("update_device_mode_failed: invalid_response");
      }
      return {
        deviceId: device.id as string,
        ownerUserId: device.user_id as string,
        nodeId: device.node_id as string,
        publicKey: device.public_key as string,
        status: device.status,
        fullTunnel: candidate.full_tunnel as boolean,
        address: candidate.address,
        addresses: candidate.addresses,
        endpoint: candidate.endpoint,
        peerPublicKey: candidate.peer_public_key,
        allowedIPs: candidate.allowed_ips,
        dns: candidate.dns,
        mtu: candidate.mtu,
        persistentKeepalive: candidate.persistent_keepalive,
      };
    });
  }

  async deviceStatus(deviceId: string, orgId: string): Promise<"active" | "pending" | "gone"> {
    // Direct query against the device's OWN org. A fetch error THROWS (inconclusive — a blip
    // never reads as a transition); "gone" only when that org's real list omits the id (no
    // cross-org scan that a transient omit could false-"gone"). orgId is ALWAYS present: new
    // configs persist it at create, and a LEGACY config (no orgId) is re-minted before any
    // monitor runs (the reduction — resolveTunnelConfig + connect never query a no-orgId
    // config). A blank orgId here is a bug, not a fallback: throw rather than build a malformed
    // /organizations//devices URL.
    if (!orgId) throw new Error("no_org: inconclusive");
    const [device, currentUserId] = await Promise.all([
      this.deviceRecord(deviceId, orgId),
      this.currentUserId(),
    ]);
    // Members only receive their own rows, but org managers receive the whole roster.
    // A persisted config must still belong to the CURRENT authenticated user; otherwise
    // a shared laptop could arm another user's WireGuard credential after sign-in.
    if (!device || device.userId !== currentUserId) return "gone";
    return device.status;
  }

  // deviceExists is deviceStatus === "active" (finding #6): ONE fail-safe implementation,
  // so the RevocationMonitor (deviceExists) and ApprovalMonitor (deviceStatus) can never
  // disagree on when a device is "gone" vs inconclusive.
  async deviceExists(deviceId: string, orgId: string): Promise<boolean> {
    return (await this.deviceStatus(deviceId, orgId)) === "active";
  }

  // routedConfig GETs the org's declared routed ranges + reachable DNS forwards (S8.5) + this device's
  // active-hub dial (WF-A, when deviceId is passed). Throws on a non-OK read (inconclusive — the monitor
  // keeps its last-applied sets, never strip-to-baked). The dial is present only when the server derives
  // one (multi-gateway hub set) AND device_id was sent; a null/absent pair means keep the current peer.
  async routedConfig(orgId: string, deviceId?: string): Promise<RoutedConfig> {
    const orgPath = encodeUuidPathSegment(orgId, "routed_ranges_failed: invalid_request");
    const q = deviceId === undefined
      ? ""
      : `?device_id=${encodeUuidPathSegment(deviceId, "routed_ranges_failed: invalid_request")}`;
    return this.request(`/api/v1/organizations/${orgPath}/routed-ranges${q}`, { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`routed_ranges_failed: ${r.status}`);
      const body = (await r.json()) as {
        ranges?: string[];
        forwards?: ResolverForward[];
        dial_endpoint?: string | null;
        dial_pubkey?: string | null;
      };
      const dial = body.dial_endpoint && body.dial_pubkey ? { endpoint: body.dial_endpoint, pubkey: body.dial_pubkey } : null;
      return { ranges: body.ranges ?? [], forwards: body.forwards ?? [], dial };
    });
  }

  // deviceRecord fetches ONE complete org device list and returns the exact
  // record's owner/status. Every row is validated before absence can be trusted;
  // malformed or failed reads throw and remain inconclusive.
  async deviceRecord(deviceId: string, orgId: string): Promise<DeviceRecord | null> {
    const orgPath = encodeUuidPathSegment(orgId, "list_devices_failed: invalid_request");
    if (!isCanonicalUuid(deviceId)) throw new Error("list_devices_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/devices`, { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`list_devices_failed: ${r.status}`);
      const matches = deviceRecords(await r.json()).filter((row) => row.id === deviceId);
      if (matches.length > 1) throw new Error("list_devices_failed: ambiguous_record");
      return matches[0]?.record ?? null;
    });
  }

  async currentUserId(): Promise<string> {
    return this.request("/api/v1/auth/me", { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`current_user_failed: ${r.status}`);
      const body: unknown = await r.json();
      if (!body || typeof body !== "object" || Array.isArray(body) || !isCanonicalUuid((body as { id?: unknown }).id)) {
        throw new Error("current_user_failed: invalid_response");
      }
      return (body as { id: string }).id;
    });
  }

  async organizations(): Promise<OrganizationMembership[]> {
    return this.request("/api/v1/organizations", { headers: this.headers() }, async (r) => {
      if (!r.ok) throw new Error(`list_organizations_failed: ${r.status}`);
      const orgs: unknown = await r.json();
      if (!Array.isArray(orgs) || orgs.some((o) => (
        !o || typeof o !== "object" || Array.isArray(o)
        || !isCanonicalUuid((o as { id?: unknown }).id)
        || typeof (o as { name?: unknown }).name !== "string"
        || typeof (o as { slug?: unknown }).slug !== "string"
      ))) {
        throw new Error("list_organizations_failed: invalid_response");
      }
      const memberships = orgs as Array<{ id: string; name: string; slug: string }>;
      if (new Set(memberships.map((organization) => organization.id)).size !== memberships.length) {
        throw new Error("list_organizations_failed: invalid_response");
      }
      return memberships.map((organization) => ({
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
      }));
    });
  }

  // reportHealth POSTs one posture self-report (S7.5.3). Terminal answers RETURN
  // ("unsupported" on 403 — open edition; "gone" on 404 — device no longer exists)
  // so the monitor stops cleanly; anything else throws (inconclusive → backoff).
  async reportHealth(deviceId: string, orgId: string, facts: HealthFacts): Promise<HealthReportResult | "unsupported" | "gone"> {
    const orgPath = encodeUuidPathSegment(orgId, "report_health_failed: invalid_request");
    const devicePath = encodeUuidPathSegment(deviceId, "report_health_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/devices/${devicePath}/health`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(facts),
    }, async (r) => {
      if (r.status === 403) return "unsupported";
      if (r.status === 404 || r.status === 410) return "gone";
      if (!r.ok) throw new Error(`report_health_failed: ${r.status}`);
      let body: unknown;
      try {
        body = await r.json();
      } catch {
        throw new Error("report_health_failed: invalid_response");
      }
      return healthReportResult(body);
    });
  }

  async revokeDevice(deviceId: string, orgId: string): Promise<void> {
    const orgPath = encodeUuidPathSegment(orgId, "revoke_device_failed: invalid_request");
    const devicePath = encodeUuidPathSegment(deviceId, "revoke_device_failed: invalid_request");
    return this.request(`/api/v1/organizations/${orgPath}/devices/${devicePath}/revoke`, {
      method: "POST",
      headers: this.headers(),
    }, async (r) => {
      if (r.ok || r.status === 404) return;
      // A completed revoke whose response was lost is retryable: the API reports
      // that exact state as typed 409 already_revoked. Never accept a generic 409;
      // other conflicts still retain the encrypted recovery record for retry.
      if (r.status === 409 && await responseErrorCode(r) === "already_revoked") return;
      throw new Error(`revoke_device_failed: ${r.status}`);
    });
  }

  async discoverLegacyDevice(deviceId: string, expectedOwnerUserId: string): Promise<string> {
    if (!isCanonicalUuid(deviceId) || !isCanonicalUuid(expectedOwnerUserId)) {
      throw new Error("legacy_device_owner_unconfirmed");
    }
    const [organizations, currentUserId] = await Promise.all([this.organizations(), this.currentUserId()]);
    if (currentUserId !== expectedOwnerUserId) throw new Error("managed_device_owner_mismatch");
    if (!organizations.length) throw new Error("legacy_device_owner_unconfirmed");

    // Every list must succeed and validate before a match is considered. Count
    // ALL exact-id rows, not only current-user rows, so a foreign duplicate plus
    // an owned row is ambiguity rather than permission to mutate.
    const matches = (await Promise.all(organizations.map(async (organization) => ({
      organizationId: organization.id,
      device: await this.deviceRecord(deviceId, organization.id),
    })))).filter(({ device }) => device !== null);
    if (matches.length === 0) throw new Error("legacy_device_owner_unconfirmed");
    if (matches.length !== 1) throw new Error("legacy_device_organization_ambiguous");
    if (matches[0].device?.userId !== expectedOwnerUserId) throw new Error("managed_device_owner_mismatch");

    // Discovery is read-only by construction. The lifecycle owner re-checks its
    // exact credential lease before separately calling revokeDevice.
    return matches[0].organizationId;
  }
}
