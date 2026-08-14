import { useEffect, useState } from "react";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  type Node,
  type Org,
  type Meta,
} from "../lib/api";
import { policyHealthBadge, badgeClass } from "../lib/healthview";
import { relativeAge } from "../lib/format";
import { CeilingUpgrade, ceilingKind } from "./CeilingUpgrade";
import { Button, Card, ErrorText, Field, Input } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";

// enrollCommand builds the COMPLETE, copy-paste command an operator runs in their Tunnex install
// folder to bring a gateway online (S6.6 / POC ledger item 6): the join-token env INLINE plus the
// full `docker compose … up -d --force-recreate node-agent` — the piece a POC operator had to know
// by heart. A pinned node_name is shell-quoted (arbitrary charset) so a space can't silently
// truncate it and resurrect the node_name_mismatch loop.
export function enrollCommand(
  token: string,
  pinnedName: string | null,
  image: string = GATEWAY_IMAGE,
): string {
  const name = pinnedName
    ? ` TUNNEX_NODE_NAME="${pinnedName.replace(/(["\\$`])/g, "\\$1")}"`
    : "";
  const agentImage = image.trim() || GATEWAY_IMAGE;
  // Compose reads this value during interpolation. Pin it in the command so
  // an enrolment cannot silently fall back to the mutable :latest tag.
  return `TUNNEX_JOIN_TOKEN=${token}${name} TUNNEX_NODE_AGENT_IMAGE="${agentImage.replace(/(["\\$`])/g, "\\$1")}" docker compose -f tunnex.yml up -d --force-recreate node-agent`;
}

// The published gateway image (S6.6 zero-build deploy). Pulled by the emitted docker run — nothing builds.
export const GATEWAY_IMAGE = "ghcr.io/tunnexio/tunnex-node-agent:latest";

export interface RemoteEnrollOpts {
  token: string;
  name: string | null;
  endpoint: string | null; // public ip:port peers dial (D4a: admin-entered). null → NAT'd spoke, no endpoint.
  apiURL: string; // public CP REST origin (nginx), e.g. https://cp.example.com
  agentURL: string; // public CP agent TLS channel, e.g. https://cp.example.com:8443
  serverName: string; // CP cert SAN the agent pins, e.g. tunnex-control
  image: string; // WF-2: the agent image (CP-configured, digest-pinnable). One-truth over the artifact version.
}

// remoteEnrollCommand builds the ONE true `docker run` for a REMOTE cloud gateway (S8.2c D4) — a SINGLE
// LINE (D4b: a multi-line/compose line LOOKS copyable and got mis-pasted twice in the cross-cloud demo; a
// one-line docker run with every env inline cannot be). It bakes in EVERYTHING the demo needed by hand:
// `--network host` (so wg0 lives on the host + reaches real host LANs, not the bridge), `wgctrl` (real
// WireGuard, not the mem fake), `/dev/net/tun` + NET_ADMIN, the public CP URLs + servername, the token,
// the optional public endpoint. Pasted verbatim on a clean VM it reaches agent_ready with ZERO edits.
// q shell-quotes an env VALUE (single charset, one rule for the whole command — review: an unquoted
// space/metachar in ANY operator-supplied value corrupts the zero-touch command). Applied uniformly to the
// name, endpoint AND the CP urls (the urls now come from operator config, not the browser origin).
const q = (s: string) => `"${s.replace(/(["\\$`])/g, "\\$1")}"`;

export function remoteEnrollCommand(o: RemoteEnrollOpts): string {
  const nameEnv = o.name ? ` -e TUNNEX_NODE_NAME=${q(o.name)}` : "";
  const endpointEnv = o.endpoint
    ? ` -e TUNNEX_NODE_ENDPOINT=${q(o.endpoint)}`
    : "";
  return (
    `docker run -d --name tunnex-node --restart unless-stopped --network host ` +
    `--cap-add NET_ADMIN --device /dev/net/tun -v tunnex_node_state:/var/lib/tunnex-node ` +
    `-e TUNNEX_JOIN_TOKEN=${o.token}${nameEnv}${endpointEnv} ` +
    `-e TUNNEX_API_URL=${q(o.apiURL)} -e TUNNEX_AGENT_URL=${q(o.agentURL)} ` +
    `-e TUNNEX_AGENT_SERVERNAME=${q(o.serverName)} -e TUNNEX_WG_BACKEND=wgctrl ${o.image}`
  );
}

// CpEndpoints is a DISCRIMINATED result (re-review budget-rule reduce: one state model for CP-url consumption
// instead of scattered empty-string sentinels). The emitted command must NEVER silently carry a broken url.
//   { ok: true }  — usable urls; usedFallback=true means we used the dashboard origin (the CP has no
//                   configured public url), which the caller flags when the meta fetch FAILED (vs was unset).
//   { ok: false } — the CP's CONFIGURED public url is unparseable (operator APP_BASE_URL typo); the caller
//                   BLOCKS token mint on this (a one-time token minted against a broken url is worse than the
//                   block) and surfaces `reason`.
export type CpEndpoints =
  | {
      ok: true;
      apiURL: string;
      agentURL: string;
      serverName: string;
      usedFallback: boolean;
    }
  | { ok: false; reason: string };

// cpEndpoints derives the public CP urls the remote agent dials from the CP's OWN configured public base URL
// (meta.public_base_url — AUTHORITATIVE), NOT window.location: the browser URL is whatever path the admin
// happened to use (a tunnel / internal alias / bare IP), which would bake an unreachable endpoint into the
// pasted command. Falls back to the dashboard origin ONLY when the CP didn't configure a public url. REST
// rides the origin (nginx); the agent TLS channel is :8443 with the standard cert SAN. PURE.
export function cpEndpoints(
  publicBaseURL: string | undefined,
  fallbackOrigin: string,
  gatewayControlURL?: string,
): CpEndpoints {
  const configured =
    publicBaseURL && publicBaseURL.trim() ? publicBaseURL.trim() : "";
  const usedFallback = configured === "";
  const base = configured || fallbackOrigin;
  let u: URL;
  try {
    u = new URL(base);
  } catch {
    // Only a CONFIGURED url reaches here (the browser origin always parses) → an operator APP_BASE_URL typo.
    return {
      ok: false,
      reason: `The control plane's configured public URL (${base}) is not a valid URL.`,
    };
  }
  if (!u.hostname)
    return {
      ok: false,
      reason: `The control plane's configured public URL (${base}) has no host.`,
    };
  let agentURL = `https://${u.hostname}:8443`;
  const configuredAgent = gatewayControlURL?.trim() || "";
  if (configuredAgent) {
    let agent: URL;
    try {
      agent = new URL(configuredAgent);
    } catch {
      return { ok: false, reason: "The configured gateway control URL is not a valid URL." };
    }
    if (agent.protocol !== "https:" || !agent.hostname || agent.pathname !== "/" || agent.search || agent.hash || agent.username || agent.password) {
      return { ok: false, reason: "The configured gateway control URL must be an https URL with no path, query or fragment." };
    }
    agentURL = agent.origin;
  }
  return {
    ok: true,
    apiURL: u.origin,
    agentURL,
    serverName: "tunnex-control",
    usedFallback,
  };
}

/**
 * Gateways renders a org's enrolled tunnex-node agents and the enroll ceremony
 * (S4.7). Enrolling mints a ONE-TIME join token — a secret with the same handling
 * as the device config (S4.5 ceremony): it exists only in page state, is never
 * re-fetched (the server shows it exactly once), and must be explicitly
 * acknowledged to dismiss. The token is redeemed by the agent on its first
 * connect, at which point the node appears in this list.
 */
export function Gateways({
  org,
  nodes,
  onNodesChanged,
  renderList = true,
}: {
  org: Org;
  nodes: Node[];
  onNodesChanged?: () => void;
  /**
   * ⛔ S14.6: the PAGE owns the fleet list now, and this component keeps the ENROLMENT CEREMONY.
   *
   * Set false when a caller renders its own list. The alternative was to extract the ceremony into a third
   * component in the same commit that added the health grouping — a move and a rewrite together, which is
   * the diff nobody can read. One prop, one seam, and the extraction can happen on its own later.
   *
   * DEFAULT TRUE so the component's existing contract is unchanged for anyone still rendering it whole.
   */
  renderList?: boolean;
}) {
  const [open, setOpen] = useState(false);
  // WF-S11-9: which gateway is awaiting a revoke confirmation. Two-step rather than a window.confirm — the
  // consequence needs naming in the UI, and a native dialog cannot say "every device homed here loses its
  // tunnel". Mirrors the MfaSettings disable ceremony.
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  // S13.1 Slice 7: which REVOKED gateway is having its devices restored, and onto which replacement.
  // WF-S11-9 is the precedent that makes this non-optional: a capability that exists only in the API is a
  // capability the product does not have, and that finding was about this exact page.
  const [restoreFrom, setRestoreFrom] = useState<string | null>(null);
  const [restoreTarget, setRestoreTarget] = useState<string>("");
  const [restoring, setRestoring] = useState(false);
  const [restoreResult, setRestoreResult] = useState<string | null>(null);
  const [nodeName, setNodeName] = useState("");
  const [endpoint, setEndpoint] = useState(""); // D4a: admin-entered public ip:port (blank = NAT'd spoke)
  const [pinnedEndpoint, setPinnedEndpoint] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  // The name the token was PINNED to at issue time — the server refuses this
  // token from an agent enrolling under any other name, so the ceremony must
  // hand the operator the COMPLETE env line. (Round-2 friction F1: the modal
  // omitted TUNNEX_NODE_NAME and the agent looped node_name_mismatch.)
  const [pinnedName, setPinnedName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ceiling, setCeiling] = useState<"gateway" | "organization" | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  // The CP's authoritative public base URL for the emitted command (review #1 — not window.location).
  // metaError distinguishes "fetch FAILED" from "fetch ok, field unset" (re-review #2): both leave
  // publicBaseURL undefined, but only a genuine unset is a clean origin-fallback; a failure that silently
  // falls back must be flagged, else a tunnel/alias origin gets baked in with no signal.
  // metaLoaded makes the IN-FLIGHT fetch a first-class state (re-review round-3, budget-rule reduce
  // COMPLETION): before it settles, publicBaseURL is undefined so ep transiently narrows to the origin
  // fallback — minting THEN would either strand the token (a late-arriving broken URL flips ep.ok false and
  // hides the modal) or silently bake the browser origin. Gate the mint on metaLoaded so the emitted command
  // is only ever built from a SETTLED CP address — the whole in-flight window becomes a disabled button.
  const [publicBaseURL, setPublicBaseURL] = useState<string | undefined>(
    undefined,
  );
  const [nodeAgentImage, setNodeAgentImage] = useState<string | undefined>(
    undefined,
  ); // WF-2: CP-configured (digest-pinnable) agent image
  const [metaError, setMetaError] = useState(false);
  const [metaLoaded, setMetaLoaded] = useState(false);
  const [gatewayControlURL, setGatewayControlURL] = useState<string | undefined>(undefined);
  const [gatewayEndpointAccess, setGatewayEndpointAccess] = useState(false);
  const [gatewayEndpointDraft, setGatewayEndpointDraft] = useState("");
  const [gatewayEndpointBusy, setGatewayEndpointBusy] = useState(false);
  useEffect(() => {
    api
      .GET("/api/v1/meta")
      .then(({ data }) => {
        setPublicBaseURL((data as Meta | undefined)?.public_base_url);
        const configuredGateway = (data as Meta | undefined)?.gateway_control_url?.trim() || "";
        setGatewayControlURL(configuredGateway || undefined);
        setGatewayEndpointDraft(configuredGateway);
        setNodeAgentImage((data as Meta | undefined)?.node_agent_image);
        setMetaError(false);
      })
      .catch(() => setMetaError(true))
      .finally(() => setMetaLoaded(true));
  }, []);
  // ONE derivation of the CP urls (re-review budget-rule reduce). Recomputed each render — cheap + pure.
  const ep = cpEndpoints(publicBaseURL, window.location.origin, gatewayControlURL);

  useEffect(() => {
    api.GET("/api/v1/admin/gateway-endpoint").then(({ data }) => {
      if (data) {
        setGatewayEndpointAccess(true);
        setGatewayEndpointDraft(data.url);
        setGatewayControlURL(data.configured ? data.url : undefined);
      }
    }).catch(() => setGatewayEndpointAccess(false));
  }, []);

  async function saveGatewayEndpoint() {
    setGatewayEndpointBusy(true);
    setError(null);
    try {
      const { data, error: saveError } = await api.PUT("/api/v1/admin/gateway-endpoint", { body: { url: gatewayEndpointDraft.trim() } });
      if (saveError || !data) {
        setError(apiErrorMessage(saveError, "Could not save the gateway control endpoint."));
        return;
      }
      setGatewayControlURL(data.url);
    } catch {
      setError("Could not reach the API.");
    } finally {
      setGatewayEndpointBusy(false);
    }
  }

  async function issue() {
    setBusy(true);
    setError(null);
    const pinned = nodeName.trim() || null;
    try {
      const { data, error } = await api.POST(
        "/api/v1/organizations/{orgId}/nodes/join-token",
        {
          params: { path: { orgId: org.id } },
          // node_name is optional; only send it when the user named the gateway.
          body: pinned ? { node_name: pinned } : {},
        },
      );
      if (error || !data) {
        // ⛔ THE CEILING REFUSAL IS THE ONE ERROR HERE THAT IS NOT A FAULT — it is the product working,
        // at the exact moment the operator was deciding to add a gateway. Rendering it as a generic red
        // string told them no and offered nowhere to go.
        setCeiling(ceilingKind(apiErrorCode(error)));
        setError(apiErrorMessage(error, "Could not issue a join token."));
        return;
      }
      setCeiling(null);
      setToken(data.join_token); // shown once — never re-served
      setPinnedName(pinned);
      setPinnedEndpoint(endpoint.trim() || null);
      setOpen(false);
      setNodeName("");
      setEndpoint("");
    } catch {
      // A network-level failure rejects instead of returning {error}; without this
      // the button would stay stuck on "Generating…".
      setError("Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  // WF-S11-9: the API has always had POST /nodes/{nodeId}/revoke, and the UI never exposed it — so the
  // documented gateway-recovery path (revoke, then re-enroll) was unreachable from the product. Revocation is
  // the mechanism the whole security model rests on (short certs + refused renewal), which makes a
  // revoke-you-cannot-reach worse than a missing convenience.
  async function revoke(nodeId: string) {
    setError(null);
    setRevoking(nodeId);
    try {
      const { error: e } = await api.POST(
        "/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke",
        {
          params: { path: { orgId: org.id, nodeId } },
        },
      );
      if (e) {
        setError(apiErrorMessage(e, "Could not revoke the gateway."));
        return;
      }
      setConfirmRevoke(null);
      onNodesChanged?.();
    } catch {
      setError("Could not reach the API.");
    } finally {
      setRevoking(null);
    }
  }

  // S13.1 Slice 7. Revoking a gateway cascade-revokes every device homed on it, and re-key REFUSES a revoked
  // node (D3) — a proof of possession must never overturn a human decision. So the ONLY way those users come
  // back is a human asking, which is what this is: a deliberate operator act, permissioned (device:restore) and
  // audited with the actor, naming the LIVE gateway they are restored onto. Restoring onto the revoked gateway
  // is refused by the server, because active devices pointing at a dead gateway read healthy everywhere and
  // work nowhere.
  async function restoreDevices(sourceNodeId: string) {
    setError(null);
    setRestoring(true);
    try {
      const { data, error: e } = await api.POST(
        "/api/v1/organizations/{orgId}/nodes/{nodeId}/restore-devices",
        {
          params: { path: { orgId: org.id, nodeId: sourceNodeId } },
          body: { target_node_id: restoreTarget },
        },
      );
      if (e) {
        setError(
          apiErrorMessage(e, "Could not restore this gateway's devices."),
        );
        return;
      }
      const restored = data?.restored ?? 0;
      const readdressed = data?.readdressed ?? 0;
      // The re-address count is stated rather than buried: each of those users must re-import a config, and
      // the device list marks them "config out of date". Reporting only the total would hide the work.
      setRestoreResult(
        restored === 0
          ? "No devices needed restoring — nothing was revoked as a cascade from this gateway."
          : `Restored ${restored} device${restored === 1 ? "" : "s"}` +
              (readdressed > 0
                ? `. ${readdressed} could not reclaim its original address and must re-import a config — they are marked "config out of date" in Devices.`
                : ", each keeping its original address, so existing configs keep working."),
      );
      setRestoreFrom(null);
      setRestoreTarget("");
      onNodesChanged?.();
    } catch {
      setError("Could not reach the API.");
    } finally {
      setRestoring(false);
    }
  }

  const liveGateways = nodes.filter((n) => n.status === "active");

  return (
    <Card>
      {gatewayEndpointAccess && (
        <div className="mb-4 rounded-lg border border-white/10 bg-ink-900 p-4">
          <div className="text-sm font-semibold text-white">Gateway control endpoint</div>
          <p className="mt-1 text-xs text-slate-400">Deployment-wide raw mTLS URL used in new join commands. Keep this hostname DNS-only or behind TCP passthrough on port 8443.</p>
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <div className="min-w-[18rem] flex-1">
              <Field label="Gateway control URL">
                <Input value={gatewayEndpointDraft} onChange={(e) => setGatewayEndpointDraft(e.target.value)} placeholder="https://agent.example.com:8443" maxLength={300} />
              </Field>
            </div>
            <Button onClick={saveGatewayEndpoint} disabled={gatewayEndpointBusy || gatewayEndpointDraft.trim() === ""}>
              {gatewayEndpointBusy ? "Saving…" : "Save endpoint"}
            </Button>
          </div>
        </div>
      )}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">Gateways</h2>
        <Button variant="ghost" onClick={() => setOpen((v) => !v)}>
          Enroll gateway
        </Button>
      </div>

      {open && (
        <div className="mt-3 flex flex-wrap items-end gap-3 border-t border-white/5 pt-3">
          <div className="min-w-[12rem] flex-1">
            <Field label="Gateway name (optional)">
              <Input
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                placeholder="office-gw"
                maxLength={100}
              />
            </Field>
          </div>
          <div className="min-w-[12rem] flex-1">
            <Field label="Public endpoint (optional: the ip:port peers dial)">
              <Input
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="203.0.113.7:51820"
                maxLength={100}
              />
            </Field>
          </div>
          <Button onClick={issue} disabled={busy || !metaLoaded || !ep.ok}>
            {busy
              ? "Generating…"
              : !metaLoaded
                ? "Checking control plane…"
                : "Generate join token"}
          </Button>
        </div>
      )}

      {/* Block the mint (not just the emit) when the CP's configured public URL is unparseable — a one-time
          token minted against a broken URL is worse than refusing. The remedy is operator-side (APP_BASE_URL).
          Only judged once meta has SETTLED (metaLoaded) — an in-flight fetch isn't an error. */}
      {open && metaLoaded && !ep.ok && (
        <ErrorText>
          {ep.reason} Fix the control plane's public address (APP_BASE_URL)
          before enrolling a gateway.
        </ErrorText>
      )}
      {open && ep.ok && ep.usedFallback && metaError && (
        <p className="mt-2 text-xs text-amber-400">
          Couldn't confirm the control plane's public URL (metadata unavailable)
          so the command below uses this dashboard's origin. Verify the gateway
          can reach <span className="font-mono">{ep.apiURL}</span>.
        </p>
      )}

      {/* ⚠ THE ROUTE REPLACES THE BARE ERROR, never sits beside it — two renderings of one refusal read as
          two problems. The server's message is passed through verbatim: it already names the band, the
          ceiling, what is enrolled, and that nothing running is affected. */}
      {ceiling && error ? (
        <CeilingUpgrade message={error} kind={ceiling} />
      ) : (
        <ErrorText>{error}</ErrorText>
      )}

      {renderList && (
        <ul className="mt-3 space-y-2">
          {nodes.map((n) => (
            <li
              key={n.id}
              className="flex items-center justify-between rounded-lg border border-white/5 bg-ink-900 px-4 py-2.5"
            >
              <div>
                <span className="text-sm text-white">{n.name}</span>
                <span className="ml-2 font-mono text-xs text-slate-500">
                  {n.agent_version}
                </span>
                {n.status === "revoked" && (
                  <span className="ml-2 text-xs text-rose-400">revoked</span>
                )}
                {/* WF-S11-10: no health badge on a revoked gateway — `revoked` IS its state, and a degradation
                  badge beside it describes a gateway that is no longer meant to work. Matches the same
                  suppression Devices.tsx has always applied to device rows; this list never had it, which stayed
                  invisible only while the badges were vague ("degraded") rather than instructional. */}
                {/* S14.21: `n.status !== "revoked" &&` removed — policyHealthBadge now refuses a verdict
                  for a revoked node itself, so restating it here implied the callee does not. */}
                {(() => {
                  const b = policyHealthBadge(n);
                  return b ? (
                    <span className={`ml-2 text-xs ${badgeClass(b.tone)}`}>
                      {b.label}
                    </span>
                  ) : null;
                })()}
                {/* S9.1 4d: OpenVPN refuse-loudly surfaced (a different axis from policy health) — an
                  OVPN-enabled gateway missing its material/binary shows WHY, and keeps serving WireGuard. */}
                {n.ovpn_health && (
                  <span
                    className="ml-2 text-xs text-amber-400"
                    title="This gateway has OpenVPN enabled but is not serving it. Resolves on its own once the material, binary or config is corrected."
                  >
                    {n.ovpn_health === "ovpn_binary_absent"
                      ? "OpenVPN: binary missing"
                      : n.ovpn_health === "ovpn_transit_conflict"
                        ? "OpenVPN: address conflict"
                        : "OpenVPN: certs missing"}
                  </span>
                )}
                {n.egress_mode && (
                  <span
                    className={`ml-2 text-xs ${n.egress_mode === "dual_stack" ? "text-emerald-400" : n.egress_mode === "ipv4_only" ? "text-sky-300" : "text-slate-400"}`}
                    title={
                      n.egress_mode === "dual_stack"
                        ? "IPv4 and IPv6 egress verified; new full-tunnel profiles use both."
                        : n.egress_mode === "ipv4_only"
                          ? "IPv4 egress verified; IPv6 is blocked by the client kill-switch for full-tunnel profiles."
                          : "Waiting for the gateway to report egress capability."
                    }
                  >
                    {n.egress_mode === "dual_stack"
                      ? "Egress: dual-stack"
                      : n.egress_mode === "ipv4_only"
                        ? "Egress: IPv4-only"
                        : "Egress: checking"}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-500">
                  {n.last_seen_at
                    ? `last seen ${relativeAge(n.last_seen_at)}`
                    : "never connected"}
                </span>
                {/* WF-S11-9. Two-step, because this is irreversible AND wider than it looks: revoking a gateway
                  refuses its cert renewal, so every device homed there loses its tunnel and any site transit
                  through it stops. A one-click danger button next to a "last seen" label is a misclick away
                  from an outage. */}
                {n.status === "active" &&
                  (confirmRevoke === n.id ? (
                    <span className="flex items-center gap-2">
                      <span className="text-xs text-rose-300">
                        Revoke {n.name}? Devices homed here lose their tunnel.
                        This cannot be undone.
                      </span>
                      <Button
                        variant="danger"
                        onClick={() => revoke(n.id)}
                        disabled={revoking === n.id}
                      >
                        {revoking === n.id ? "Revoking…" : "Confirm revoke"}
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={() => setConfirmRevoke(null)}
                        disabled={revoking === n.id}
                      >
                        Cancel
                      </Button>
                    </span>
                  ) : (
                    <Button
                      variant="ghost"
                      onClick={() => setConfirmRevoke(n.id)}
                    >
                      Revoke
                    </Button>
                  ))}
                {/* S13.1 Slice 7 — only on a REVOKED gateway, because that is the only state whose devices are
                  stranded: re-key brings back a gateway that expired, and D3 refuses to re-key one that was
                  revoked. Withheld entirely when there is no live gateway to restore onto, rather than offered
                  and then refused. */}
                {n.status === "revoked" &&
                  liveGateways.length > 0 &&
                  (restoreFrom === n.id ? (
                    <span className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">
                        Restore its devices onto
                      </span>
                      <select
                        className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200"
                        value={restoreTarget}
                        onChange={(e) => setRestoreTarget(e.target.value)}
                        aria-label="Replacement gateway"
                      >
                        <option value="">Choose a gateway…</option>
                        {liveGateways.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name}
                          </option>
                        ))}
                      </select>
                      <Button
                        variant="primary"
                        onClick={() => restoreDevices(n.id)}
                        disabled={restoring || restoreTarget === ""}
                      >
                        {restoring ? "Restoring…" : "Restore devices"}
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={() => {
                          setRestoreFrom(null);
                          setRestoreTarget("");
                        }}
                        disabled={restoring}
                      >
                        Cancel
                      </Button>
                    </span>
                  ) : (
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setRestoreResult(null);
                        setRestoreFrom(n.id);
                      }}
                    >
                      Restore devices
                    </Button>
                  ))}
              </div>
            </li>
          ))}
          {restoreResult && (
            <li className="text-xs text-emerald-300" role="status">
              {restoreResult}
            </li>
          )}
          {nodes.length === 0 && (
            <li className="text-sm text-slate-500">
              No gateway enrolled yet. Enroll one to start serving WireGuard
              peers.
            </li>
          )}
        </ul>
      )}

      {/* One-time join-token CEREMONY — the token authenticates a new agent on its
          first connect and is shown exactly once (shared OneTimeSecretModal). The
          node itself only appears in the list above once the agent redeems the
          token on first connect. */}
      {token && ep.ok && (
        <OneTimeSecretModal
          title="Enroll your gateway: run this once"
          caption={
            <>
              Paste this <span className="font-semibold">single command</span>{" "}
              on the gateway VM (Docker installed) to bring it online. It pulls
              the agent and comes up on real WireGuard with{" "}
              <span className="font-semibold">no edits</span>. Shown{" "}
              <span className="font-semibold">exactly once</span>, single-use:
              copy it now.
              {pinnedName && (
                <>
                  {" "}
                  Pinned to the name{" "}
                  <span className="font-mono">{pinnedName}</span>. The agent
                  enrolls under exactly that or the server refuses it.
                </>
              )}
              {!pinnedEndpoint && (
                <>
                  {" "}
                  No public endpoint set → this gateway is treated as a{" "}
                  <span className="font-semibold">NAT'd spoke</span> (it dials
                  the hub; other peers can't dial it).
                </>
              )}{" "}
              (Installing on the SAME host as the control plane? See{" "}
              <span className="font-mono">docs/deploy-cloud-gateway.md</span>{" "}
              for the co-located compose form. It carries this same token.)
            </>
          }
          // D4: the ONE true remote-gateway docker run — single line, host networking + wgctrl baked in.
          // CP urls from the CP's own configured public base URL (review #1), not window.location.
          secret={remoteEnrollCommand({
            token,
            name: pinnedName,
            endpoint: pinnedEndpoint,
            apiURL: ep.apiURL,
            agentURL: ep.agentURL,
            serverName: ep.serverName,
            image:
              nodeAgentImage && nodeAgentImage.trim()
                ? nodeAgentImage.trim()
                : GATEWAY_IMAGE, // WF-2: CP-pinned, else default
          })}
          copyLabel="Copy command"
          onDismiss={() => {
            setToken(null);
            setPinnedName(null);
            setPinnedEndpoint(null);
          }}
        />
      )}
    </Card>
  );
}
