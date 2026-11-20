import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useGatewayInventory } from "../lib/useGatewayInventory";
import { siteGate, lanEgressOptions, lanEgressOutboundNote, type LanEgress } from "../lib/sitesview";
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
  // SSI-9: how the new network sees traffic from other networks. Offered only where it means something
  // (there is a second side, the network is new, and its gateway can translate); Quick is the default.
  const [lanEgress, setLanEgress] = useState<LanEgress>("gateway_address");
  const [egressNote, setEgressNote] = useState<string | null>(null);
  // What is in force after creation: null = there is no second side, so nothing to say.
  const [appliedLanEgress, setAppliedLanEgress] = useState<LanEgress | null>(null);
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
  // A gateway that reports no ceiling counts as "cannot": the server would refuse the setting anyway.
  const canTranslate = (selected?.max_policy_version ?? 0) >= 15;
  const linksToOthers = Boolean(linkContext) && (exposure !== null || Boolean(linkContext?.error));
  const offerLanEgress = step === 2 && linksToOthers && !existingSite;
  const chosenLanEgress: LanEgress = offerLanEgress && canTranslate ? lanEgress : "preserve_source";
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
      // SSI-9: the network exists now. Applying the routing mode is a second write; if it fails the
      // network is NOT rolled back and is NOT reported as failed — the operator is told which mode is
      // actually in force and where to change it.
      if (chosenLanEgress === "gateway_address" && result.data?.id) {
        try {
          const egress = await api.PUT("/api/v1/organizations/{orgId}/sites/{siteId}/lan-egress", {
            params: { path: { orgId: org.id, siteId: result.data.id } },
            body: { lan_egress: "gateway_address" },
          });
          setEgressNote(egress.error
            ? `Servers on this network will see the original address: ${apiErrorMessage(egress.error, "the gateway address mode could not be set")}. Change it under Advanced.`
            : null);
          setAppliedLanEgress(egress.error ? "preserve_source" : "gateway_address");
        } catch {
          setEgressNote("The gateway address mode may not have been set. Check it under Advanced.");
          setAppliedLanEgress("preserve_source");
        }
      } else {
        setAppliedLanEgress(offerLanEgress || existingSite ? "preserve_source" : null);
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
      {embedded && !done && <div><Button variant="ghost" disabled={busy || uncertain} onClick={onCancel}>Start over</Button></div>}
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
            Your network and its range are saved. Next, choose who can access
            it and verify the connection from a device.
          </p>
          {egressNote && <p role="status" className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-warn">{egressNote}</p>}
          {appliedLanEgress === "gateway_address" && <p className="text-sm text-ink-secondary" data-testid="lan-egress-result">Servers on this network see the gateway's own address for traffic from other networks, so nothing needs setting up in this network's cloud for traffic that arrives here. {lanEgressOutboundNote}</p>}
          {appliedLanEgress === "preserve_source" && !existingSite && <div className="text-sm text-ink-secondary" data-testid="lan-egress-result"><p>Servers on this network see the remote machine's real address. Before traffic from other networks can be answered, in your cloud:</p><ol className="mt-1 list-decimal pl-5"><li>Route each other network's range to this gateway.</li><li>Allow the gateway to forward packets that are not addressed to it (on AWS, turn off the source/destination check; on Google Cloud and Azure, enable IP forwarding).</li></ol></div>}
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
                    {embedded ? "Choose the gateway that runs inside this network." : "Choose an active gateway. Gateways already connected to a site will add the private range to that site."}
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
                            {node.site_id ? `Network: ${state.siteNames?.[node.site_id] || "Existing network"}` : "New network"} · {node.endpoint || "No public endpoint configured"}
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
                      {embedded ? "No gateway is free. Enroll one in this network, then refresh." : "No active gateways found. Enroll one here, then refresh when it has joined."}
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
                    The range must not overlap another network or the device pool.
                    Tunnex validates it when you create the network.
                  </p>
                </>
              )}
              {step === 2 && (
                <>
                  <h2>Ready to create your network?</h2>
                  <p className="network-hint">
                    {existingSite ? "This adds the private range to the gateway’s existing network and approves it." : "This creates the network, assigns the gateway, and approves the private route for distribution to devices."}
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
                  {offerLanEgress && (canTranslate ? (
                    <fieldset className="mt-3">
                      <legend className="text-sm">Traffic from other networks arrives as</legend>
                      {lanEgressOptions.map((option) => (
                        <label key={option.value} className="mt-2 flex items-start gap-2 text-sm">
                          <input type="radio" name="lan-egress" value={option.value} checked={lanEgress === option.value} disabled={busy || uncertain} onChange={() => setLanEgress(option.value)} />
                          <span><strong>{option.label}</strong><span className="block text-ink-secondary">{option.sees} {option.needs}</span></span>
                        </label>
                      ))}
                      <p className="network-hint" data-testid="lan-egress-outbound-note">{lanEgressOutboundNote}</p>
                    </fieldset>
                  ) : (
                    <p className="network-hint" data-testid="lan-egress-unavailable">This gateway cannot translate traffic from other networks yet, so servers will see the remote machine's real address and your cloud must route the other networks' ranges to this gateway. Upgrade the gateway to remove that step.</p>
                  ))}
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
