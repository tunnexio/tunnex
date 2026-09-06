import { useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useGatewayInventory } from "../lib/useGatewayInventory";
import { siteGate } from "../lib/sitesview";
import { Gateways } from "../components/Gateways";
import {
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  Loading,
  PageHeader,
} from "../components/ui";
import "../network-setup.css";

export default function NetworkSetup() {
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
  return <NetworkSetupWorkspace key={inventory.org.id} inventory={inventory} />;
}

function NetworkSetupWorkspace({
  inventory,
}: {
  inventory: ReturnType<typeof useGatewayInventory>;
}) {
  const { org, state, reload, canEnroll } = inventory;
  const [step, setStep] = useState(0);
  const [nodeId, setNodeId] = useState("");
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [enrolling, setEnrolling] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const nodes = state.nodes.filter(
    (node) =>
      node.status === "active" &&
      !node.site_id &&
      node.enrolled_kind === "gateway",
  );
  const selected = nodes.find((node) => node.id === nodeId);
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
          body: { node_id: nodeId, cidr: cidr.trim(), name: name.trim() },
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
      <PageHeader
        title={done ? "Network created" : "Set up a network"}
        subtitle={org.name}
        actions={
          <Link className="text-sm text-ink-secondary" to="/sites">
            Back to Sites →
          </Link>
        }
      />
      {done ? (
        <Card>
          <div className="network-complete">
            <span className="network-complete-mark" aria-hidden="true">
              ✓
            </span>
            <h2>{name}</h2>
            <p>
              {cidr} through {selected?.name}
            </p>
          </div>
          <p className="text-sm text-ink-secondary">
            Your site and approved route are saved. Next, choose who can access
            it and verify the connection from a device.
          </p>
          <div className="network-actions">
            <Link to="/access" className="network-primary-link">
              Configure access →
            </Link>
            <Link to="/sites">View network →</Link>
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
                    Choose an active gateway that is not already assigned to a
                    site.
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
                            {node.endpoint || "No public endpoint configured"}
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
                      No available gateways. Enroll one here, then refresh when
                      it has joined.
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
                    <Button variant="ghost" onClick={reload}>
                      Refresh gateways
                    </Button>
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
                  <Field label="Network name">
                    <Input
                      value={name}
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
                    This creates a site, assigns the gateway, and approves the
                    private route for distribution to devices.
                  </p>
                  <dl className="network-review">
                    <dt>Network</dt>
                    <dd>{name}</dd>
                    <dt>Gateway</dt>
                    <dd>{selected?.name || "Gateway no longer available"}</dd>
                    <dt>Private range</dt>
                    <dd>{cidr}</dd>
                  </dl>
                  <p className="network-hint">
                    Existing access policies still apply. This step does not
                    create access grants or verify reachability.
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
                      (step === 1 && (!name.trim() || !cidr.trim()))
                    }
                    onClick={() => setStep(step + 1)}
                  >
                    Continue →
                  </Button>
                ) : (
                  <Button
                    disabled={busy || !selected || uncertain}
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
                {name || "Private network"}
                <small>{cidr || "Private address range"}</small>
              </div>
              <div className="network-preview-connector" />
              <div className="network-preview-node">
                {selected?.name || "Choose a gateway"}
                <small>Tunnex gateway</small>
              </div>
              <p>
                One gateway. One site.
                <br />A private route between them.
              </p>
            </aside>
          </div>
        </>
      )}
    </div>
  );
}
