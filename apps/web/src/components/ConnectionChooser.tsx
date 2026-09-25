import { useEffect, useRef, useState } from "react";
import NetworkSetup from "../pages/NetworkSetup";
import { SitePairReview, SitePairDetails } from "./SitePairReview";
import { FaAws, FaNetworkWired, FaShieldAlt } from "react-icons/fa";
import { SiGooglecloud, SiWireguard } from "react-icons/si";
import { VscAzure } from "react-icons/vsc";
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
  const tile = "flex min-h-32 flex-col items-start gap-3 rounded-lg border border-line p-5 text-left hover:bg-white/5 focus-visible:outline focus-visible:outline-2 disabled:cursor-not-allowed disabled:opacity-60";
  return <Modal title={step === "method" ? "Create connection" : step === "ipsec" ? "Choose IPsec provider" : "Tunnex to Tunnex"} size={step === "wireguard" ? "workspace" : "wide"} onDismiss={busy ? () => {} : onClose} actions={<><Button disabled={busy} variant="ghost" onClick={step === "method" ? onClose : () => { setAdding(false); setStep("method"); }}>{step === "method" ? "Cancel" : "Back"}</Button></>}>
    {step === "method" && <div className="grid gap-3 sm:grid-cols-2">
      <button className={tile} onClick={() => setStep("wireguard")}><SiWireguard size={32} color="#ba2636" aria-hidden="true" /><strong>Tunnex to Tunnex</strong><span className="text-sm text-ink-secondary">WireGuard · Gateway at both ends</span></button>
      <button className={tile} onClick={() => setStep("ipsec")}><FaShieldAlt size={32} aria-hidden="true" /><strong>Cloud VPN / Firewall</strong><span className="text-sm text-ink-secondary">IPsec · External VPN endpoint</span></button>
    </div>}
    {step === "ipsec" && <div className="grid gap-3 sm:grid-cols-2">
      <button className={tile} onClick={onAWS}><FaAws size={34} color="#ff9900" aria-hidden="true" /><strong>AWS</strong><span className="text-sm text-ink-secondary">Site-to-Site VPN · Static IPv4</span></button>
      <button disabled className={tile}><VscAzure size={32} color="#0089d6" aria-hidden="true" /><strong>Azure</strong><span className="text-sm text-ink-secondary">Not available yet</span></button>
      <button disabled className={tile}><SiGooglecloud size={32} color="#4285f4" aria-hidden="true" /><strong>Google Cloud</strong><span className="text-sm text-ink-secondary">Not available yet</span></button>
      <button disabled className={tile}><FaNetworkWired size={32} aria-hidden="true" /><strong>On-premises / Other</strong><span className="text-sm text-ink-secondary">Not available yet</span></button>
    </div>}
    {step === "wireguard" && <div className="space-y-4">
      {adding ? <NetworkSetup embedded onBusyChange={setBusy} onCancel={() => setAdding(false)} onComplete={() => void reloadNetworks()} /> : <>
        <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-ink-secondary">Choose two locations. Tunnex manages the WireGuard links.</p><Button onClick={() => setAdding(true)}>Add location</Button></div>
        {networks.length < 2 ? <div className="rounded-lg border border-line p-4"><p className="font-medium">{networks.length === 0 ? "Add two locations" : "Add a second location"}</p>{networks.length === 1 && <p className="mt-1 text-sm text-ink-secondary">{networks[0].name} is ready to select.</p>}</div> : orgId ? <SitePairReview sites={networks} renderDetails={(first, second) => <SitePairDetails orgId={orgId} first={first} second={second} />} /> : <p role="alert">Organization unavailable. Close and retry.</p>}
      </>}
      {error && <div role="alert"><p>{error}</p><Button disabled={busy} onClick={() => void reloadNetworks()}>Retry locations</Button></div>}
    </div>}
  </Modal>;
}
