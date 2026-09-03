import { useCallback, useEffect, useState } from "react";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  type Org,
  type Meta,
} from "../lib/api";
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
export const DEFAULT_FLOW_LOG_GROUP = 100;

export interface RemoteEnrollOpts {
  token: string;
  name: string | null;
  endpoint: string | null; // public ip:port peers dial (D4a: admin-entered). null → NAT'd spoke, no endpoint.
  apiURL: string; // public CP REST origin (nginx), e.g. https://cp.example.com
  agentURL: string; // public CP agent TLS channel, e.g. https://cp.example.com:8443
  serverName: string; // CP cert SAN the agent pins, e.g. tunnex-control
  image: string; // WF-2: the agent image (CP-configured, digest-pinnable). One-truth over the artifact version.
  flowLogGroup?: number; // NFLOG group. Omit for the production default (100); set exactly 0 to disable.
}

// remoteEnrollCommand builds the ONE true `docker run` for a REMOTE cloud gateway (S8.2c D4) — a SINGLE
// LINE (D4b: a multi-line/compose line LOOKS copyable and got mis-pasted twice in the cross-cloud demo; a
// one-line docker run with every env inline cannot be). It bakes in EVERYTHING the demo needed by hand:
// `--network host` (so wg0 lives on the host + reaches real host LANs, not the bridge), `wgctrl` (real
// WireGuard, not the mem fake), `/dev/net/tun` + NET_ADMIN, the public CP URLs + servername, the token,
// the NFLOG collection group, and the optional public endpoint. Pasted verbatim on a clean VM it reaches
// agent_ready with ZERO edits.
// q shell-quotes an env VALUE (single charset, one rule for the whole command — review: an unquoted
// space/metachar in ANY operator-supplied value corrupts the zero-touch command). Applied uniformly to the
// name, endpoint AND the CP urls (the urls now come from operator config, not the browser origin).
const q = (s: string) => `"${s.replace(/(["\\$`])/g, "\\$1")}"`;

export function remoteEnrollCommand(o: RemoteEnrollOpts): string {
  const nameEnv = o.name ? ` -e TUNNEX_NODE_NAME=${q(o.name)}` : "";
  const endpointEnv = o.endpoint
    ? ` -e TUNNEX_NODE_ENDPOINT=${q(o.endpoint)}`
    : "";
  const requestedFlowLogGroup = o.flowLogGroup;
  const flowLogGroup =
    requestedFlowLogGroup !== undefined &&
    Number.isInteger(requestedFlowLogGroup) &&
    requestedFlowLogGroup >= 0 &&
    requestedFlowLogGroup <= 65535
      ? requestedFlowLogGroup
      : DEFAULT_FLOW_LOG_GROUP;
  return (
    `docker run -d --name tunnex-node --restart unless-stopped --network host ` +
    `--cap-add NET_ADMIN --device /dev/net/tun -v tunnex_node_state:/var/lib/tunnex-node ` +
    `-e TUNNEX_JOIN_TOKEN=${o.token}${nameEnv}${endpointEnv} ` +
    `-e TUNNEX_API_URL=${q(o.apiURL)} -e TUNNEX_AGENT_URL=${q(o.agentURL)} ` +
    `-e TUNNEX_AGENT_SERVERNAME=${q(o.serverName)} -e TUNNEX_WG_BACKEND=wgctrl ` +
    `-e TUNNEX_FLOWLOG_GROUP=${flowLogGroup} ${o.image}`
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

type GatewayEndpointAdminState =
  | "loading"
  | "authorized"
  | "restricted"
  | "error";

function controlEndpointHostname(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

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
  initiallyOpen = false,
  hideHeader = false,
  showGatewayEndpointSettings = true,
  onCancel,
  onEnrollmentAcknowledged,
}: {
  org: Org;
  /** Open the enrollment details immediately when the page owns the surrounding modal. */
  initiallyOpen?: boolean;
  /** Hide the legacy card heading/toggle when embedded in the S20 enrollment modal. */
  hideHeader?: boolean;
  /** Show the deployment-wide control endpoint status/editor in enrollment. */
  showGatewayEndpointSettings?: boolean;
  /** Cancel an enrollment owned by a surrounding dialog. */
  onCancel?: () => void;
  /** Close an embedding enrollment workspace after the one-time secret is acknowledged. */
  onEnrollmentAcknowledged?: () => void;
}) {
  const [open, setOpen] = useState(initiallyOpen);
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
  const [gatewayEndpointState, setGatewayEndpointState] =
    useState<GatewayEndpointAdminState>("loading");
  const [gatewayEndpointConfigured, setGatewayEndpointConfigured] = useState(false);
  const [gatewayEndpointEditing, setGatewayEndpointEditing] = useState(false);
  const [gatewayEndpointReadError, setGatewayEndpointReadError] = useState<string | null>(null);
  const [gatewayEndpointDraft, setGatewayEndpointDraft] = useState("");
  const [gatewayEndpointBusy, setGatewayEndpointBusy] = useState(false);
  useEffect(() => {
    api
      .GET("/api/v1/meta")
      .then(({ data }) => {
        setPublicBaseURL((data as Meta | undefined)?.public_base_url);
        const configuredGateway = (data as Meta | undefined)?.gateway_control_url?.trim() || "";
        if (configuredGateway) {
          setGatewayControlURL(configuredGateway);
          setGatewayEndpointDraft(configuredGateway);
        }
        setNodeAgentImage((data as Meta | undefined)?.node_agent_image);
        setMetaError(false);
      })
      .catch(() => setMetaError(true))
      .finally(() => setMetaLoaded(true));
  }, []);
  // ONE derivation of the CP urls (re-review budget-rule reduce). Recomputed each render — cheap + pure.
  const ep = cpEndpoints(publicBaseURL, window.location.origin, gatewayControlURL);

  const loadGatewayEndpoint = useCallback(async () => {
    if (!showGatewayEndpointSettings) return;
    setGatewayEndpointState("loading");
    setGatewayEndpointReadError(null);
    try {
      const { data, error: readError } = await api.GET(
        "/api/v1/admin/gateway-endpoint",
      );
      if (readError) {
        if (apiErrorCode(readError) === "gateway_endpoint_admin_required") {
          setGatewayEndpointState("restricted");
          return;
        }
        setGatewayEndpointState("error");
        setGatewayEndpointReadError(
          apiErrorMessage(
            readError,
            "Could not load the Gateway control endpoint.",
          ),
        );
        return;
      }
      if (!data) {
        setGatewayEndpointState("error");
        setGatewayEndpointReadError(
          "Could not load the Gateway control endpoint.",
        );
        return;
      }
      setGatewayEndpointState("authorized");
      setGatewayEndpointConfigured(data.configured);
      setGatewayEndpointDraft(data.url);
      setGatewayControlURL(data.configured ? data.url : undefined);
      setGatewayEndpointEditing(false);
    } catch {
      setGatewayEndpointState("error");
      setGatewayEndpointReadError("Could not reach the API.");
    }
  }, [showGatewayEndpointSettings]);

  useEffect(() => {
    void loadGatewayEndpoint();
  }, [loadGatewayEndpoint]);

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
      setGatewayEndpointDraft(data.url);
      setGatewayEndpointConfigured(true);
      setGatewayEndpointEditing(false);
      setGatewayEndpointState("authorized");
    } catch {
      setError("Could not reach the API.");
    } finally {
      setGatewayEndpointBusy(false);
    }
  }

  const gatewayEndpointSettled =
    !showGatewayEndpointSettings || gatewayEndpointState !== "loading";
  const gatewayEndpointReady =
    gatewayEndpointSettled &&
    ep.ok &&
    (gatewayEndpointState !== "restricted" || Boolean(gatewayControlURL));

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

  return (
    <Card variant={hideHeader ? "plain" : "glass"}>
      {!hideHeader && <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">Gateways</h2>
        <Button variant="ghost" onClick={() => setOpen((v) => !v)}>
          Enroll gateway
        </Button>
      </div>}

      {open && (
        <div className={`${hideHeader ? "" : "mt-3 border-t border-white/5 pt-3"}`}>
          <div className="mb-3">
            <h3 className="text-cell font-semibold text-ink-heading">Gateway</h3>
            <p className="mt-1 text-micro text-ink-tertiary">Name the host. Add a public endpoint only when peers can dial it directly.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Gateway name (optional)">
              <Input
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                placeholder="office-gw"
                maxLength={100}
              />
            </Field>
            <Field label="Public endpoint (optional)">
              <Input
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="203.0.113.7:51820"
                maxLength={100}
              />
            </Field>
          </div>
          {!hideHeader && <div className="mt-4 flex justify-end">
            <Button onClick={issue} disabled={busy || !metaLoaded || !gatewayEndpointReady}>
              {busy
                ? "Generating…"
                : !metaLoaded || !gatewayEndpointSettled
                  ? "Checking control plane…"
                  : "Generate join token"}
            </Button>
          </div>}
        </div>
      )}

      {open && showGatewayEndpointSettings && gatewayEndpointState === "loading" && (
        <p className="mt-3 text-micro text-ink-tertiary">Checking control connection…</p>
      )}
      {open && showGatewayEndpointSettings && gatewayEndpointState === "error" && (
        <div className="mt-3 flex items-center justify-between gap-3 rounded-md border border-danger/30 bg-danger/5 px-3 py-2">
          <ErrorText>{gatewayEndpointReadError}</ErrorText>
          <Button size="sm" variant="ghost" onClick={() => void loadGatewayEndpoint()}>Retry</Button>
        </div>
      )}
      {open && showGatewayEndpointSettings && gatewayEndpointState !== "loading" && gatewayEndpointState !== "error" && !gatewayEndpointEditing && (gatewayEndpointState === "authorized" || Boolean(gatewayControlURL)) && (
        <div className="mt-4 flex items-center justify-between gap-3 border-t border-white/[.08] pt-3">
          <div className="min-w-0">
            <p className="text-micro font-medium uppercase tracking-wide text-ink-faint">Control connection</p>
            <p className="mt-0.5 truncate text-cell text-ink-body">
              {gatewayControlURL ? controlEndpointHostname(gatewayControlURL) : "Automatic from control-plane URL"}
              <span className={`ml-2 text-micro ${gatewayControlURL ? "text-ok" : "text-ink-faint"}`}>
                {gatewayControlURL ? "Configured" : "Default"}
              </span>
            </p>
          </div>
          {gatewayEndpointState === "authorized" && (
            <Button size="sm" variant="ghost" onClick={() => setGatewayEndpointEditing(true)}>
              {gatewayControlURL ? "Change" : "Customize"}
            </Button>
          )}
        </div>
      )}
      {open && showGatewayEndpointSettings && gatewayEndpointState === "restricted" && !gatewayControlURL && (
        <div className="mt-3 rounded-md border border-amber-400/20 bg-amber-400/5 px-3 py-2 text-cell text-amber-200">
          A deployment admin must configure the control endpoint before enrollment.
        </div>
      )}
      {open && showGatewayEndpointSettings && gatewayEndpointState === "authorized" && gatewayEndpointEditing && (
        <div className="mt-4 rounded-md border border-white/10 bg-black/20 p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-cell font-semibold text-ink-heading">Custom control endpoint</div>
              <p className="mt-0.5 text-micro text-ink-tertiary">Advanced: override the raw mTLS endpoint with a DNS hostname on port 8443.</p>
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setGatewayEndpointDraft(gatewayControlURL ?? "");
                setGatewayEndpointEditing(false);
              }}
              disabled={gatewayEndpointBusy}
            >
              {gatewayEndpointConfigured ? "Keep current" : "Use automatic"}
            </Button>
          </div>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-end">
            <div className="flex-1">
              <Field label="Gateway control URL (DNS hostname)">
                <Input value={gatewayEndpointDraft} onChange={(e) => setGatewayEndpointDraft(e.target.value)} placeholder="https://agent.example.com:8443" maxLength={300} />
              </Field>
            </div>
            <Button onClick={saveGatewayEndpoint} disabled={gatewayEndpointBusy || gatewayEndpointDraft.trim() === ""}>
              {gatewayEndpointBusy ? "Saving…" : "Save endpoint"}
            </Button>
          </div>
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

      {open && hideHeader && (
        <div className="mt-5 flex items-center justify-end gap-2 border-t border-white/[.08] pt-4">
          {onCancel && <Button variant="ghost" onClick={onCancel}>Cancel</Button>}
          <Button onClick={issue} disabled={busy || !metaLoaded || !gatewayEndpointReady}>
            {busy
              ? "Generating…"
              : !metaLoaded || !gatewayEndpointSettled
                ? "Checking control plane…"
                : "Generate join token"}
          </Button>
        </div>
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
            onEnrollmentAcknowledged?.();
          }}
        />
      )}
    </Card>
  );
}
