import os from "node:os";
import type { DeviceApi, HealthFacts, HealthReportResult, RoutedConfig } from "./deviceconfig";
import type { ResolverForward } from "./helperclient";

// createErr surfaces the server's TYPED error code (body.error.code) when present, so
// a caller can match on it — e.g. the S3.7 `gateway_no_egress` full-tunnel refusal the
// UI mirrors cleanly. Falls back to the status when the body isn't the typed shape.
async function createErr(r: Response): Promise<string> {
  try {
    const body = (await r.json()) as { error?: { code?: string } };
    // Keep BOTH the numeric status (diagnosable: 401 vs 403 vs 5xx) AND the typed code
    // (matchable: e.g. the future S3.7 gateway_no_egress). friendly() uses .includes()
    // so either substring still matches.
    if (body?.error?.code) return `create_device_failed: ${r.status} ${body.error.code}`;
  } catch {
    /* non-JSON body — fall through to the status */
  }
  return `create_device_failed: ${r.status}`;
}

// HttpDeviceApi is the concrete DeviceApi over the tenant REST API, called from
// MAIN with the bearer (never the renderer). It mirrors the CLI's device flow:
// pick the caller's org + an active gateway node, POST create-device, and capture
// the ONE-TIME .conf. Runtime is human-smoke (needs a live tenant); the shape is
// tsc-checked against the OpenAPI contract.
export class HttpDeviceApi implements DeviceApi {
  constructor(
    private readonly origin: string,
    private readonly getToken: () => string | null,
  ) {}

  private headers(): Record<string, string> {
    const t = this.getToken();
    if (!t) throw new Error("not_authenticated");
    // Bearer requests carry no cookie, so the server's CSRF guard is inert; the
    // header is presence-only and harmless (matches the shared client posture).
    return { authorization: `Bearer ${t}`, "content-type": "application/json", "x-tunnex-csrf": "1" };
  }

  private async firstOrgId(): Promise<string> {
    const ids = await this.orgIds(); // finding #4: one org-list fetch implementation
    if (!ids.length) throw new Error("no_organization");
    return ids[0];
  }

  private async activeNodeId(orgId: string): Promise<string> {
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/nodes`, { headers: this.headers() });
    if (!r.ok) throw new Error(`list_nodes_failed: ${r.status}`);
    const nodes = (await r.json()) as Array<{ id: string; status: string }>;
    const active = nodes.find((n) => n.status === "active");
    if (!active) throw new Error("no_active_gateway");
    return active.id;
  }

  async createDevice(fullTunnel: boolean): Promise<{ deviceId: string; confText: string; pendingApproval: boolean; orgId: string }> {
    const orgId = await this.firstOrgId();
    const nodeId = await this.activeNodeId(orgId);
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/devices`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        name: `tunnex-desktop-${os.hostname()}`,
        node_id: nodeId,
        full_tunnel: fullTunnel,
        platform: process.platform,
      }),
    });
    if (!r.ok) throw new Error(await createErr(r));
    // The config is issued at enrollment even when pending (S7.3 D2) — the peer just
    // isn't served by the gateway until approved. pending_approval tells the caller to
    // hold: gate the tunnel + start the awaiting-approval poll, don't arm the helper.
    const body = (await r.json()) as { device: { id: string }; config?: string; pending_approval?: boolean };
    if (!body.config) throw new Error("no_config_returned"); // server-generated flow only
    return { deviceId: body.device.id, confText: body.config, pendingApproval: body.pending_approval === true, orgId };
  }

  async updateDeviceMode(deviceId: string, orgId: string, fullTunnel: boolean): Promise<{
    fullTunnel: boolean; address: string; addresses?: string[]; endpoint: string;
    peerPublicKey: string; allowedIPs: string[]; dns?: string[]; mtu?: number;
    persistentKeepalive?: number;
  }> {
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/devices/${deviceId}/mode?full_tunnel=${fullTunnel}`, {
      method: "PATCH", headers: this.headers(),
    });
    if (!r.ok) throw new Error(`update_device_mode_failed: ${r.status}`);
    const body = (await r.json()) as { device: { full_tunnel: boolean }; config: {
      address: string; addresses?: string[]; endpoint: string; peer_public_key: string;
      allowed_ips: string[]; dns?: string[]; mtu?: number; persistent_keepalive?: number;
    } };
    return {
      fullTunnel: body.device.full_tunnel,
      address: body.config.address, addresses: body.config.addresses,
      endpoint: body.config.endpoint, peerPublicKey: body.config.peer_public_key,
      allowedIPs: body.config.allowed_ips, dns: body.config.dns,
      mtu: body.config.mtu, persistentKeepalive: body.config.persistent_keepalive,
    };
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
      this.deviceInOrg(orgId, deviceId),
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
    const q = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/routed-ranges${q}`, { headers: this.headers() });
    if (!r.ok) throw new Error(`routed_ranges_failed: ${r.status}`);
    const body = (await r.json()) as {
      ranges?: string[];
      forwards?: ResolverForward[];
      dial_endpoint?: string | null;
      dial_pubkey?: string | null;
    };
    const dial = body.dial_endpoint && body.dial_pubkey ? { endpoint: body.dial_endpoint, pubkey: body.dial_pubkey } : null;
    return { ranges: body.ranges ?? [], forwards: body.forwards ?? [], dial };
  }

  // deviceInOrg fetches ONE org's device list and maps the device's status/owner, or null if it is
  // not in that org. Throws on a non-OK read (inconclusive — a blip never reads as gone).
  private async deviceInOrg(orgId: string, deviceId: string): Promise<{ status: "active" | "pending" | "gone"; userId: string } | null> {
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/devices`, { headers: this.headers() });
    if (!r.ok) throw new Error(`list_devices_failed: ${r.status}`);
    const devices = (await r.json()) as Array<{ id: string; status: string; user_id?: string }>;
    const d = devices.find((x) => x.id === deviceId);
    if (!d || !d.user_id) return null;
    const status = d.status === "active" ? "active" : d.status === "pending" ? "pending" : "gone";
    return { status, userId: d.user_id };
  }

  private async currentUserId(): Promise<string> {
    const r = await fetch(`${this.origin}/api/v1/auth/me`, { headers: this.headers() });
    if (!r.ok) throw new Error(`current_user_failed: ${r.status}`);
    const body = (await r.json()) as { id?: string };
    if (!body.id) throw new Error("current_user_failed: missing_id");
    return body.id;
  }

  private async orgIds(): Promise<string[]> {
    const r = await fetch(`${this.origin}/api/v1/organizations`, { headers: this.headers() });
    if (!r.ok) throw new Error(`list_organizations_failed: ${r.status}`);
    const orgs = (await r.json()) as Array<{ id: string }>;
    return orgs.map((o) => o.id);
  }

  // reportHealth POSTs one posture self-report (S7.5.3). Terminal answers RETURN
  // ("unsupported" on 403 — open edition; "gone" on 404 — device no longer exists)
  // so the monitor stops cleanly; anything else throws (inconclusive → backoff).
  async reportHealth(deviceId: string, orgId: string, facts: HealthFacts): Promise<HealthReportResult | "unsupported" | "gone"> {
    if (!orgId) throw new Error("no_org: inconclusive");
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/devices/${deviceId}/health`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(facts),
    });
    if (r.status === 403) return "unsupported";
    if (r.status === 404 || r.status === 410) return "gone";
    if (!r.ok) throw new Error(`report_health_failed: ${r.status}`);
    return (await r.json()) as HealthReportResult;
  }

  async revokeDevice(deviceId: string, knownOrgId?: string): Promise<void> {
    const orgId = knownOrgId ?? await this.firstOrgId();
    const r = await fetch(`${this.origin}/api/v1/organizations/${orgId}/devices/${deviceId}/revoke`, {
      method: "POST",
      headers: this.headers(),
    });
    // 404 = already gone: fine for a best-effort revoke.
    if (!r.ok && r.status !== 404) throw new Error(`revoke_device_failed: ${r.status}`);
  }
}
