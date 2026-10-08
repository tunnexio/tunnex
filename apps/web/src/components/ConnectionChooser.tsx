import { useEffect, useRef, useState } from "react";
import NetworkSetup from "../pages/NetworkSetup";
import { SitePairReview, SitePairDetails } from "./SitePairReview";
import { api, loadOne, type Site } from "../lib/api";
import { Button, Modal } from "./ui";

export function ConnectionChooser({ sites, orgId, onClose, onAWS }: {
  sites: Site[]; orgId?: string; onClose: () => void; onAWS: () => void;
}) {
  const [step, setStep] = useState<"method" | "ipsec" | "wireguard">("method");
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [networks, setNetworks] = useState(sites);
  const [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function reloadNetworks() {
    if (!orgId) return;
    setBusy(true); setError("");
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId } } }));
    if (!alive.current) return;
    setBusy(false);
    if (result.ok) { setNetworks(result.data); setAdding(false); }
    else setError("Could not refresh locations. Try again.");
  }
  return <Modal title={adding ? "Add location" : step === "method" ? "Create connection" : step === "ipsec" ? "Choose IPsec provider" : "Review WireGuard networks"} size={step === "wireguard" ? "workspace" : "wide"} onDismiss={busy ? () => {} : onClose} actions={adding ? undefined : <><Button disabled={busy} variant="ghost" onClick={step === "method" ? onClose : () => { setAdding(false); setStep("method"); }}>{step === "method" ? "Cancel" : "Back"}</Button></>}>
    <div className="sts-chooser">
    {!adding && <ol className="sts-chooser-steps" aria-label="Connection setup steps">
      <li aria-current={step === "method" ? "step" : undefined}><span aria-hidden="true">1</span>Connection type</li>
      <li aria-current={step !== "method" ? "step" : undefined}><span aria-hidden="true">2</span>{step === "wireguard" ? "Network pair" : "Provider"}</li>
    </ol>}
    {step === "method" && <div className="sts-chooser-choices">
      <button className="sts-chooser-choice" onClick={() => setStep("wireguard")}><span className="sts-chooser-choice-copy"><strong>Tunnex to Tunnex</strong><span>Review two networks with Tunnex gateways.</span></span><span className="sts-chooser-choice-meta">WireGuard</span></button>
      <button className="sts-chooser-choice" onClick={() => setStep("ipsec")}><span className="sts-chooser-choice-copy"><strong>Cloud VPN / Firewall</strong><span>Configure an external VPN endpoint.</span></span><span className="sts-chooser-choice-meta">IPsec</span></button>
    </div>}
    {step === "ipsec" && <div className="sts-chooser-choices">
      <button className="sts-chooser-choice" onClick={onAWS}><span className="sts-chooser-choice-copy"><strong>AWS</strong><span>Site-to-Site VPN · Static IPv4</span></span><span className="sts-chooser-choice-meta">Configure</span></button>
      {["Azure", "Google Cloud", "On-premises / Other"].map(provider => <button key={provider} disabled className="sts-chooser-choice"><span className="sts-chooser-choice-copy"><strong>{provider}</strong></span><span className="sts-chooser-choice-meta">Not available yet</span></button>)}
    </div>}
    {step === "wireguard" && <div className="sts-chooser-wireguard">
      {adding ? <NetworkSetup embedded onBusyChange={setBusy} onCancel={() => setAdding(false)} onComplete={() => void reloadNetworks()} /> : <>
        <div className="sts-chooser-wireguard-toolbar"><p>Each network needs a Tunnex gateway.</p><Button onClick={() => setAdding(true)}>Add location</Button></div>
        {networks.length < 2 ? <div className="sts-chooser-empty"><h3>{networks.length === 0 ? "Add two locations" : "Add a second location"}</h3>{networks.length === 1 && <p>Existing location: {networks[0].name}.</p>}</div> : orgId ? <SitePairReview sites={networks} renderDetails={(first, second) => <SitePairDetails orgId={orgId} first={first} second={second} />} /> : <p role="alert">Organization unavailable. Close and retry.</p>}
      </>}
      {error && <div role="alert"><p>{error}</p><Button disabled={busy} onClick={() => void reloadNetworks()}>Retry locations</Button></div>}
    </div>}
    </div>
  </Modal>;
}
