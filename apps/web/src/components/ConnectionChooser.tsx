import { useEffect, useRef, useState } from "react";
import NetworkSetup from "../pages/NetworkSetup";
import { SitePairReview, SitePairDetails } from "./SitePairReview";
import { api, loadOne, type Site } from "../lib/api";
import { Button, Modal } from "./ui";
import { ProviderMark } from "./ProviderMarks";
import "../connection-chooser.css";

// SSI-13 D3 — "Add a network" asks ONE question: what is on the other side. A Tunnex gateway goes straight
// to the existing network setup (it used to stop at a review of two networks, behind a button called
// "Create connection" that created nothing); a cloud VPN goes to the existing provider step, unchanged.
// `start="ipsec"` opens on the provider step for the Cloud VPN tab, where the question is already answered.
export function ConnectionChooser({ sites, orgId, onClose, onAWS, onGCP, onAzure, start = "method", onNetworkAdded }: {
  sites: Site[]; orgId?: string; onClose: () => void; onAWS: () => void; onGCP?: () => void; onAzure?: () => void;
  start?: "method" | "ipsec"; onNetworkAdded?: () => void;
}) {
  const [step, setStep] = useState<"method" | "ipsec" | "wireguard">(start);
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
    if (result.ok) { setNetworks(result.data); setAdding(false); onNetworkAdded?.(); }
    else setError("Could not refresh networks. Try again.");
  }
  return <Modal title={adding ? "Add a network" : step === "method" ? "Add a network" : step === "ipsec" ? "Choose your cloud VPN" : "Your networks"} size={step === "wireguard" ? "workspace" : "wide"} onDismiss={busy ? () => {} : onClose} actions={adding ? undefined : <><Button disabled={busy} variant="ghost" onClick={step === start ? onClose : () => { setAdding(false); setStep("method"); }}>{step === start ? "Cancel" : "Back"}</Button></>}>
    <div className="sts-chooser">
    {!adding && <ol className="sts-chooser-steps" aria-label="Connection setup steps">
      <li aria-current={step === "method" ? "step" : undefined}><span aria-hidden="true">1</span>Other side</li>
      <li aria-current={step !== "method" ? "step" : undefined}><span aria-hidden="true">2</span>{step === "wireguard" ? "Network" : "Provider"}</li>
    </ol>}
    {step === "method" && <div className="sts-chooser-choices">
      <p className="sts-chooser-question">What is on the other side?</p>
      <button className="sts-chooser-choice" onClick={() => { setStep("wireguard"); setAdding(true); }}><span className="sts-chooser-choice-copy"><strong>A machine where I can run a Tunnex gateway</strong><span>Any cloud, office or data center. The link forms by itself.</span></span><span className="sts-chooser-choice-meta">Tunnex link</span></button>
      <button className="sts-chooser-choice" onClick={() => setStep("ipsec")}><span className="sts-chooser-choice-copy"><strong>A cloud VPN gateway</strong><span>AWS, Google Cloud or Azure. You enter the tunnel details the provider gives you.</span></span><span className="sts-chooser-choice-meta">Cloud VPN · IPsec</span></button>
    </div>}
    {step === "ipsec" && <div className="sts-chooser-choices">
      <button className="sts-chooser-choice" onClick={onAWS}><span className="sts-chooser-provider-identity"><ProviderMark provider="aws" className="sts-chooser-provider-mark" /><span className="sts-chooser-choice-copy"><strong>AWS</strong><span>Site-to-Site VPN · Static / BGP IPv4</span></span></span><span className="sts-chooser-choice-meta">Configure</span></button>
      <button className="sts-chooser-choice" disabled={!onGCP} onClick={onGCP}><span className="sts-chooser-provider-identity"><ProviderMark provider="gcp" className="sts-chooser-provider-mark" /><span className="sts-chooser-choice-copy"><strong>Google Cloud</strong><span>HA VPN · BGP IPv4</span></span></span><span className="sts-chooser-choice-meta">{onGCP ? "Configure" : "Not available yet"}</span></button>
      <button className="sts-chooser-choice" disabled={!onAzure} onClick={onAzure}><span className="sts-chooser-provider-identity"><ProviderMark provider="azure" className="sts-chooser-provider-mark" /><span className="sts-chooser-choice-copy"><strong>Azure</strong><span>VPN Gateway · Static / BGP IPv4</span></span></span><span className="sts-chooser-choice-meta">Configure</span></button>
      {([
        { name: "On-premises / Other", mark: "self_managed" },
      ] as const).map(provider => <button key={provider.mark} disabled className="sts-chooser-choice"><span className="sts-chooser-provider-identity"><ProviderMark provider={provider.mark} className="sts-chooser-provider-mark" /><span className="sts-chooser-choice-copy"><strong>{provider.name}</strong></span></span><span className="sts-chooser-choice-meta">Not available yet</span></button>)}
    </div>}
    {step === "wireguard" && <div className="sts-chooser-wireguard">
      {adding ? <NetworkSetup embedded onBusyChange={setBusy} onCancel={() => setAdding(false)} onComplete={() => void reloadNetworks()} /> : <>
        <div className="sts-chooser-wireguard-toolbar"><p>Each network needs a Tunnex gateway.</p><Button onClick={() => setAdding(true)}>Add a network</Button></div>
        {networks.length < 2 ? <div className="sts-chooser-empty"><h3>{networks.length === 0 ? "Add two networks" : "Add a second network"}</h3>{networks.length === 1 && <p>Existing network: {networks[0].name}.</p>}</div> : orgId ? <SitePairReview sites={networks} renderDetails={(first, second) => <SitePairDetails orgId={orgId} first={first} second={second} />} /> : <p role="alert">Organization unavailable. Close and retry.</p>}
      </>}
      {error && <div role="alert"><p>{error}</p><Button disabled={busy} onClick={() => void reloadNetworks()}>Retry networks</Button></div>}
    </div>}
    </div>
  </Modal>;
}
