import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage, type Org } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useGatewayInventory } from "../lib/useGatewayInventory";
import { ClientConnection } from "../components/ClientConnection";
import { toGatewayRow, gatewayOperationalLabel } from "../lib/gatewaysview";
import { relativeAge } from "../lib/format";
import { setupStep } from "../lib/setuproute";
import { can } from "../lib/rbac";
import { Gateways } from "../components/Gateways";
import { Icon, type IconName } from "../components/Icon";
import { Button, Card, ErrorText, Loading, PageHeader, RefreshButton } from "../components/ui";
import "../setup-guide.css";

const purposes = [
  { id: "vpn", title: "Company VPN", description: "Employees connect to private apps and servers.", icon: "laptop" },
  { id: "networks", title: "Site-to-site VPN", description: "Connect office and cloud networks.", icon: "network" },
  { id: "kubernetes", title: "Kubernetes access", description: "Reach private services inside your cluster.", icon: "boxes" },
] as const;

export function SetupChoices() {
  return <div className="space-y-4">
    <div><h2 className="text-lg font-semibold text-ink-heading">What do you want to connect?</h2><p className="mt-1 text-sm text-ink-secondary">Start with one. Add more later.</p></div>
    <div className="setup-purpose-grid">{purposes.map(purpose => <Link key={purpose.id} to={`/setup?purpose=${purpose.id}`} className="setup-purpose-card">
      <div className="setup-purpose-top"><Icon name={purpose.icon as IconName} size={22} /><span aria-hidden="true">→</span></div><strong>{purpose.title}</strong><span>{purpose.description}</span>
    </Link>)}</div>
    <p className="text-xs text-ink-tertiary">Need AI access? <Link className="text-accent-400 hover:underline" to="/ai-gateway">Open AI Gateway →</Link></p>
  </div>;
}

export default function Setup() {
  const inventory = useGatewayInventory();
  const { state: auth } = useAuth();
  const [params, setParams] = useSearchParams();
  const selected = purposes.find(purpose => purpose.id === params.get("purpose"));
  const step = setupStep(params.get("step"));
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [ranges, setRanges] = useState<{ orgId: string; values: string[]; error?: string } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const orgId = inventory.org?.id;
  const userId = auth.status === "authed" ? auth.user.id : "";
  const verified = auth.status === "authed" && auth.user.email_verified && !auth.user.must_change_password;

  useEffect(() => { setEnrolling(false); }, [orgId, userId, selected?.id, step]);
  useEffect(() => { headingRef.current?.focus({ preventScroll: true }); }, [step]);
  useEffect(() => {
    let current = true;
    setRanges(null);
    if (!orgId) return;
    void api.GET("/api/v1/organizations/{orgId}/routed-ranges", { params: { path: { orgId } } }).then(({ data, error }) => {
      if (current) setRanges({ orgId, values: data?.ranges ?? [], error: error || !data ? apiErrorMessage(error, "Could not load private networks.") : undefined });
    }).catch(() => {
      if (current) setRanges({ orgId, values: [], error: "Could not load private networks." });
    });
    return () => { current = false; };
  }, [orgId, userId, attempt]);

  const ready = inventory.state.kind === "ready" && inventory.state.orgId === orgId;
  const gateways = ready ? inventory.state.nodes.filter(node => node.status === "active" && node.enrolled_kind === "gateway") : [];
  const gatewayRows = gateways.map(node => toGatewayRow(node));
  const devices = inventory.state.devices?.filter(device => device.kind !== "agent") ?? null;
  const pending = devices?.filter(device => device.status === "pending") ?? [];
  const observed = devices?.filter(device => device.status === "active" && device.public_key && Number.isFinite(Date.parse(device.last_handshake_at ?? ""))) ?? [];
  const manage = verified && can(inventory.state.role, "site:manage");
  const currentRanges = ranges?.orgId === orgId ? ranges : null;
  const networkTask = selected?.id === "networks";
  const clusterTask = selected?.id === "kubernetes";
  const labels = ["Gateway", networkTask ? "Connection" : clusterTask ? "Cluster" : "Network", networkTask ? "Routing" : "Access", networkTask ? "Test" : "Connect"];
  const titles = [networkTask ? "Connect your locations" : "Connect a gateway", networkTask ? "Create a site-to-site connection" : clusterTask ? "Connect your cluster" : "Choose your private networks", networkTask ? "Review routes and forwarding" : "Review who can access it", networkTask ? "Test your connection" : "Make your first connection"];

  function goToStep(next: number) {
    if (!selected || enrolling) return;
    setParams({ purpose: selected.id, step: String(next) });
  }
  function destination(path: string) {
    return `${path}${path.includes("?") ? "&" : "?"}from=setup&purpose=${selected?.id ?? "vpn"}&setupStep=${step}`;
  }
  function refresh() { void inventory.reload(); setAttempt(value => value + 1); }

  return <div className="setup-guide space-y-5">
    <Link className="text-sm text-ink-secondary hover:text-ink-heading" to="/dashboard">← Overview</Link>
    <PageHeader title={selected?.title ?? "Set up Tunnex"} subtitle={inventory.org?.name ?? "Your first connection starts here."} actions={selected && <Button variant="ghost" disabled={enrolling} onClick={() => setParams({})}>Choose another task</Button>} />
    {inventory.state.kind === "error" ? <Card><ErrorText>{inventory.state.error}</ErrorText><Button onClick={refresh}>Retry setup</Button></Card>
      : !ready || !inventory.org ? <Loading label="Loading your setup…" />
      : !manage ? <Card><h2 className="font-semibold text-ink-heading">Ask your administrator to finish setup</h2><p className="mt-2 text-sm text-ink-secondary">Network setup requires a verified account with network management permission.</p><Link className="mt-4 inline-block text-accent-400" to="/connect">Connect your computer →</Link></Card>
      : !selected ? <Card><SetupChoices /></Card>
      : <div className="setup-wizard">
        <nav className="setup-progress" aria-label="Setup steps">
          {labels.map((label, index) => <button key={index} type="button" aria-label={`Step ${index + 1}: ${label}`} aria-current={step === index + 1 ? "step" : undefined} disabled={enrolling} onClick={() => goToStep(index + 1)}>
            <span aria-hidden="true">{index + 1}</span><strong>{label}</strong>
          </button>)}
        </nav>
        <section className="setup-panel" aria-labelledby="setup-step-title">
          <header className="setup-panel-heading">
            <p className="setup-eyebrow">STEP {step} OF 4</p>
            <h2 id="setup-step-title" ref={headingRef} tabIndex={-1}>{titles[step - 1]}</h2>
          </header>
          <div className="setup-panel-body" key={`${orgId}:${selected.id}:${step}`}>
            {step === 1 && <>
              {gateways.length ? <p>{gateways.length} gateway{gateways.length === 1 ? " is" : "s are"} already registered. No need to enroll again.</p> : <p>A gateway connects Tunnex to your private network. Use a Linux machine or VM that can reach your resources.</p>}
              {gatewayRows.map(row => <div className="setup-health" key={row.id}>
                <div><Link className="setup-text-link" to={destination(`/gateways/${row.id}`)}>{row.name} →</Link><p>{row.operationalState === "awaiting_first_connection" ? "Awaiting first connection" : gatewayOperationalLabel(row)}{row.lastSeenAt ? ` · Last report ${relativeAge(row.lastSeenAt)}` : ""}</p></div>
                {row.operationalState !== "healthy" && <Link className="setup-text-link" to={destination(`/gateways/${row.id}?tab=health`)}>Check gateway health</Link>}
              </div>)}
              {networkTask && <p>Use a gateway at each location, or a supported cloud VPN.</p>}
              <div className="setup-actions">
                {inventory.canEnroll && !enrolling && <Button variant={gateways.length ? "ghost" : "primary"} onClick={() => setEnrolling(true)}>{gateways.length ? "Add another gateway" : "Register a gateway"}</Button>}
                {!enrolling && <RefreshButton label="Refresh gateway status" onClick={refresh} />}
              </div>
              {enrolling && inventory.canEnroll && <Gateways key={orgId} org={inventory.org as Org} initiallyOpen hideHeader showGatewayEndpointSettings={false} onCancel={() => setEnrolling(false)} onEnrollmentAcknowledged={() => { setEnrolling(false); refresh(); }} />}
            </>}
            {step === 2 && <>
              {!networkTask && !clusterTask ? <>
                {currentRanges === null ? <p>Loading private networks…</p> : currentRanges.error ? <><ErrorText>{currentRanges.error}</ErrorText><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry private networks</Button></> : currentRanges.values.length ? <><p>Your configured private ranges:</p><div className="flex flex-wrap gap-2">{currentRanges.values.map(range => <span className="setup-range" key={range}>{range}</span>)}</div></> : <p>Add the private IP ranges employees need. Normal internet traffic stays on their own connection.</p>}
                {gateways.length ? <Link className="setup-primary-link" to={destination("/network/setup")}>Set up a private network →</Link> : <div className="setup-help"><p>Register a gateway before adding a private network.</p><Button variant="ghost" onClick={() => goToStep(1)}>Go to gateway step</Button></div>}
                <Link className="setup-text-link" to={destination("/routed-ranges")}>Review all routed ranges →</Link>
              </> : networkTask ? <><p>Choose the two locations and the private ranges to connect.</p><Link className="setup-primary-link" to={destination("/site-to-site")}>Open connection setup →</Link></> : <><p>Connect your cluster, then select the private services users can reach.</p><Link className="setup-primary-link" to={destination("/kubernetes")}>Open Kubernetes setup →</Link><p className="setup-note">Your Tunnex Server stays where it is.</p></>}
            </>}
            {step === 3 && <>
              {networkTask ? <><p>Check routes, gateway forwarding and cloud firewall rules on both sides.</p><Link className="setup-primary-link" to={destination("/site-to-site")}>Review connection settings →</Link></> : <>
                <p>Choose who can reach your private resources, then invite your users.</p>
                <div className="setup-actions"><Link className="setup-primary-link" to={destination("/access")}>Review access policies →</Link><Link className="setup-text-link" to={destination("/users")}>Invite users →</Link></div>
                <details className="setup-details"><summary>Email invitations</summary><p>If email delivery is off, share invitation links manually.</p>{auth.status === "authed" && auth.user.cp_admin && <Link className="setup-text-link" to={destination("/settings?section=email-delivery")}>Configure email delivery →</Link>}</details>
              </>}
            </>}
            {step === 4 && <>
              {networkTask ? <><p>From either network, open an allowed resource on the other side and verify the reply path.</p><p className="setup-note">Connection test pending. A tunnel handshake alone does not prove resource access.</p></> : <>
                <ClientConnection key={`${orgId}:${userId}`} organization={inventory.org.name} compact />
                {pending.length > 0 && <div className="setup-help"><p>{pending.length} device{pending.length === 1 ? "" : "s"} awaiting approval</p><Link className="setup-text-link" to={destination("/devices/approvals")}>Review device approvals →</Link></div>}
                <details className="setup-details"><summary>Connection status</summary>
                  {devices === null ? <p>Device status unavailable. Refresh to check again.</p> : observed.length ? <p>Handshake observed on {observed.length} active device{observed.length === 1 ? "" : "s"}. Latest observation: {relativeAge(observed.map(device => device.last_handshake_at!).sort().at(-1)!)}.</p> : <p>No client handshake observed yet.</p>}
                  <p>Private-resource access: not verified. Test an allowed resource from the connected client.</p>
                  <div className="setup-actions"><Link className="setup-text-link" to={destination("/devices")}>View devices and connection status →</Link><RefreshButton label="Refresh connection status" onClick={refresh} /></div>
                </details>
              </>}
            </>}
          </div>
          <footer className="setup-wizard-footer">
            <Button variant="ghost" disabled={enrolling} onClick={() => step === 1 ? setParams({}) : goToStep(step - 1)}>Back</Button>
            {step < 4 ? <Button disabled={enrolling} onClick={() => goToStep(step + 1)}>Continue</Button> : <Link className="setup-primary-link" to="/dashboard">Back to overview →</Link>}
          </footer>
        </section>
      </div>}
  </div>;
}
