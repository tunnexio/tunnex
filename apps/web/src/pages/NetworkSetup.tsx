import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useGatewayInventory } from "../lib/useGatewayInventory";
import { siteGate } from "../lib/sitesview";
import { siteLinkExposure, type EnforcementMode, type OtherNetwork } from "../lib/sitelinkview";
import { setupReturnPath } from "../lib/setuproute";
import { Gateways } from "../components/Gateways";
import "../resource-summary.css";
import { Button, Card, ErrorText, Field, Input, Loading, PageHeader, RefreshButton } from "../components/ui";
import "../network-setup.css";

type SetupOptions = { embedded?: boolean; onComplete?: () => void; onCancel?: () => void; onBusyChange?: (busy: boolean) => void };

export default function NetworkSetup(options: SetupOptions = {}) {
  const inventory = useGatewayInventory();
  const { state: auth } = useAuth();
  if (!inventory.org || inventory.state.kind === "loading") return <Loading />;
  if (inventory.state.kind === "error")
    return (
      <Card>
        <ErrorText>{inventory.state.error}</ErrorText>
        <Button onClick={inventory.reload}>Try again</Button>
      </Card>
    );
  const permitted = siteGate({
    role: inventory.state.role,
    emailVerified: auth.status === "authed" && auth.user.email_verified,
  }).canManage;
  if (!permitted)
    return (
      <Card>
        <h1>Network setup</h1>
        <p className="text-ink-secondary">
          A verified account with site management permission is required.
        </p>
        <Link to="/sites">View your network →</Link>
      </Card>
    );
  return <NetworkSetupWorkspace key={inventory.org.id} inventory={inventory} {...options} />;
}

function NetworkSetupWorkspace({
  inventory, embedded, onComplete, onCancel, onBusyChange,
}: {
  inventory: ReturnType<typeof useGatewayInventory>;
} & SetupOptions) {
  const { org, state, reload, canEnroll } = inventory;
  const [params] = useSearchParams();
  const fromGuide = params.get("from") === "setup";
  const guidePath = setupReturnPath("vpn", params.get("setupStep") ?? "2");
  const [step, setStep] = useState(0);
  const [nodeId, setNodeId] = useState("");
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  useEffect(() => { onBusyChange?.(busy || uncertain); }, [busy, uncertain, onBusyChange]);
  // SSI-4: what this range will be linked to, read when the operator reaches Review. `null` = still
  // reading; `error` = the other networks could not be listed, which is said out loud rather than read
  // as "there are none".
  const [linkContext, setLinkContext] = useState<{ mode: EnforcementMode; others: OtherNetwork[]; error: boolean } | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const orgId = org?.id;
  const nodes = state.nodes.filter(
    (node) =>
      node.status === "active" &&
      node.enrolled_kind === "gateway" && (!embedded || !node.site_id),
  );
  const selected = nodes.find((node) => node.id === nodeId);
  const existingSite = selected?.site_id;
  useEffect(() => {
    if (step !== 2 || !orgId) return;
    let current = true;
    setLinkContext(null);
    setAcknowledged(false);
    void (async () => {
      const [modeRes, sitesRes] = await Promise.all([
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", { params: { path: { orgId } } })),
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId } } })),
      ]);
      const read = modeRes.ok ? (modeRes.data as { mode?: string }).mode : undefined;
      const mode: EnforcementMode = read === "off" || read === "enforcing" ? read : "unknown";
      if (!sitesRes.ok) {
        if (current) setLinkContext({ mode, others: [], error: true });
        return;
      }
      const otherSites = (sitesRes.data as Array<{ id: string; name: string }>).filter((site) => site.id !== existingSite);
      const subnetResults = await Promise.all(otherSites.map((site) =>
        loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", { params: { path: { orgId, siteId: site.id } } })),
      ));
      if (!current) return;
      const others = otherSites.map((site, index) => {
        const result = subnetResults[index];
        const subnets = result.ok ? (result.data as Array<{ cidr: string; status: string }>) : [];
        return { name: site.name, ranges: subnets.filter((subnet) => subnet.status === "approved").map((subnet) => subnet.cidr) };
      });
      setLinkContext({ mode, others, error: subnetResults.some((result) => !result.ok) });
    })();
    return () => { current = false; };
  }, [step, orgId, existingSite]);
  const exposure = linkContext ? siteLinkExposure({ mode: linkContext.mode, newRange: cidr, others: linkContext.others }) : null;
  // Until the link context is read, and whenever it could not be read in full, the operator must
  // acknowledge: an unread list is not an empty one.
  const acknowledgement = !linkContext
    ? null
    : linkContext.error
      ? "I understand this may link to networks that could not be listed"
      : exposure?.acknowledgement ?? null;
  const awaitingAcknowledgement = step === 2 && (!linkContext || (acknowledgement !== null && !acknowledged));
  const siteName = existingSite ? state.siteNames?.[existingSite] || "Existing site" : name;
  if (!org) return null;
  async function apply() {
    if (!org || !selected || busy || uncertain) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.POST(
        "/api/v1/organizations/{orgId}/routed-lans",
        {
          params: { path: { orgId: org.id } },
          body: { node_id: nodeId, cidr: cidr.trim(), name: existingSite ? siteName : name.trim() },
        },
      );
      if (result.error) {
        setError(
          apiErrorMessage(result.error, "Could not create the network."),
        );
        return;
      }
      setDone(true);
    } catch {
      setUncertain(true);
      setError(
        "The response was interrupted. Check Sites before starting another setup; the network may already have been created.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="network-setup">
      {!embedded && <PageHeader
        title={done ? "Network created" : "Set up a network"}
        subtitle={org.name}
        actions={
          <Link className="text-sm text-ink-secondary" to={fromGuide ? guidePath : "/sites"}>
            {fromGuide ? "Back to setup guide →" : "Back to Sites →"}
          </Link>
        }
      />}
      {embedded && !done && <div><Button variant="ghost" disabled={busy || uncertain} onClick={onCancel}>Back to locations</Button></div>}
      {done ? (
        <Card>
          <div className="network-complete">
            <span className="network-complete-mark" aria-hidden="true">
              ✓
            </span>
            <h2>{siteName}</h2>
            <p>
              {cidr} through {selected?.name}
            </p>
          </div>
          <p className="text-sm text-ink-secondary">
            Your site and approved route are saved. Next, choose who can access
            it and verify the connection from a device.
          </p>
          <div className="network-actions">
            {embedded ? <Button onClick={onComplete}>Continue connection setup</Button> : <><Link to={fromGuide ? "/access?from=setup&purpose=vpn&setupStep=3" : "/access"} className="network-primary-link">
              Configure access →
            </Link>
            <Link to={fromGuide ? guidePath : "/sites"}>{fromGuide ? "Continue setup guide →" : "View network →"}</Link></>}
          </div>
        </Card>
      ) : (
        <>
          <nav className="network-steps" aria-label="Network setup steps">
            {["Gateway", "Network", "Review"].map((label, index) => (
              <button
                key={label}
                aria-current={step === index ? "step" : undefined}
                disabled={busy || uncertain || index > step}
                onClick={() => setStep(index)}
              >
                <span>{index + 1}</span>
                {label}
              </button>
            ))}
          </nav>
          <div className="network-workspace">
            <Card>
              {step === 0 && (
                <>
                  <h2>Where will this network connect?</h2>
                  <p className="network-hint">
                    {embedded ? "Choose an unassigned gateway for this location." : "Choose an active gateway. Gateways already connected to a site will add the private range to that site."}
                  </p>
                  <div
                    className="network-gateways"
                    role="group"
                    aria-label="Choose gateway"
                  >
                    {nodes.map((node) => (
                      <button
                        key={node.id}
                        aria-pressed={nodeId === node.id}
                        onClick={() => setNodeId(node.id)}
                      >
                        <span>
                          <strong>{node.name}</strong>
                          <small>
                            {node.site_id ? `Site: ${state.siteNames?.[node.site_id] || "Existing site"}` : "New site"} · {node.endpoint || "No public endpoint configured"}
                          </small>
                        </span>
                        <span aria-hidden="true">
                          {nodeId === node.id ? "●" : "○"}
                        </span>
                      </button>
                    ))}
                  </div>
                  {!nodes.length && (
                    <p className="network-hint">
                      {embedded ? "No unassigned gateways. Enroll one for this location, then refresh." : "No active gateways found. Enroll one here, then refresh when it has joined."}
                    </p>
                  )}
                  <div className="network-actions">
                    {canEnroll && (
                      <Button
                        variant="ghost"
                        onClick={() => setEnrolling(!enrolling)}
                      >
                        {enrolling ? "Close enrollment" : "Enroll a gateway"}
                      </Button>
                    )}
                    <RefreshButton label="Refresh gateways" onClick={reload} />
                  </div>
                  {enrolling && (
                    <Gateways
                      org={org}
                      initiallyOpen
                      hideHeader
                      onCancel={() => setEnrolling(false)}
                      onEnrollmentAcknowledged={() => {
                        setEnrolling(false);
                        void reload();
                      }}
                    />
                  )}
                </>
              )}
              {step === 1 && (
                <>
                  <h2>Give your network a home.</h2>
                  <p className="network-hint">
                    Enter the private address range reachable from{" "}
                    {selected?.name}.
                  </p>
                  <Field label={existingSite ? "Existing site" : "Network name"}>
                    <Input
                      value={existingSite ? siteName : name}
                      disabled={!!existingSite}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Sydney office"
                    />
                  </Field>
                  <Field label="Private range (CIDR)">
                    <Input
                      value={cidr}
                      onChange={(e) => setCidr(e.target.value)}
                      placeholder="10.20.0.0/24"
                    />
                  </Field>
                  <p className="network-hint">
                    The range must not overlap an existing site or device pool.
                    Tunnex validates it when you create the network.
                  </p>
                </>
              )}
              {step === 2 && (
                <>
                  <h2>Ready to create your network?</h2>
                  <p className="network-hint">
                    {existingSite ? "This adds the private range to the gateway’s existing site and approves it for distribution to devices." : "This creates a site, assigns the gateway, and approves the private route for distribution to devices."}
                  </p>
                  <dl className="network-review tnx-resource-facts">
                    <div>
                    <dt>Network</dt>
                    <dd>{siteName}</dd>
                    </div><div>
                    <dt>Gateway</dt>
                    <dd>{selected?.name || "Gateway no longer available"}</dd>
                    </div><div>
                    <dt>Private range</dt>
                    <dd>{cidr}</dd>
                    </div>
                  </dl>
                  {!linkContext && <p className="network-hint" role="status">Checking what this range will be linked to…</p>}
                  {linkContext?.error && <p role="status" className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-warn">Your other networks could not be listed, so Tunnex cannot say what this range will be linked to.</p>}
                  {exposure && (
                    <div role="status" data-testid="site-link-exposure" className={exposure.kind === "rules" ? "rounded-md border border-line px-3 py-2 text-xs text-ink-secondary" : "rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-warn"}>
                      <strong className="block text-sm">{exposure.heading}</strong>
                      <p className="mt-1">{exposure.body}</p>
                      <ul className="mt-2">
                        {exposure.networks.map((network) => <li key={network.name}><span>{network.name}</span> <span className="font-mono">{network.ranges.join(", ")}</span></li>)}
                      </ul>
                    </div>
                  )}
                  {acknowledgement && (
                    <label className="mt-3 flex items-start gap-2 text-sm">
                      <input type="checkbox" checked={acknowledged} disabled={busy || uncertain} onChange={(event) => setAcknowledged(event.target.checked)} />
                      <span>{acknowledgement}</span>
                    </label>
                  )}
                  <p className="network-hint">
                    {exposure || linkContext?.error ? "This step does not create access grants or verify reachability." : "Existing access policies still apply. This step does not create access grants or verify reachability."}
                  </p>
                </>
              )}
              <ErrorText>{error}</ErrorText>
              <div className="network-footer">
                {step > 0 && (
                  <Button
                    variant="ghost"
                    disabled={busy || uncertain}
                    onClick={() => {
                      setStep(step - 1);
                      setError(null);
                    }}
                  >
                    Back
                  </Button>
                )}
                {step < 2 ? (
                  <Button
                    disabled={
                      !selected ||
                      (step === 1 && ((!existingSite && !name.trim()) || !cidr.trim()))
                    }
                    onClick={() => setStep(step + 1)}
                  >
                    Continue →
                  </Button>
                ) : (
                  <Button
                    disabled={busy || !selected || uncertain || awaitingAcknowledgement}
                    onClick={apply}
                  >
                    {busy ? "Creating network…" : "Create network"}
                  </Button>
                )}
                {uncertain && <Link to="/sites">Check Sites →</Link>}
              </div>
            </Card>
            <aside className="network-preview" aria-label="Network preview">
              <span>Your network</span>
              <div className="network-preview-node">
                {siteName || "Private network"}
                <small>{cidr || "Private address range"}</small>
              </div>
              <div className="network-preview-connector" />
              <div className="network-preview-node">
                {selected?.name || "Choose a gateway"}
                <small>Tunnex gateway</small>
              </div>

            </aside>
          </div>
        </>
      )}
    </div>
  );
}
