import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, loadOne } from "../lib/api";
import { Button } from "./ui";

type Report = components["schemas"]["IPsecConnectionStatus"];
type Tunnel = { outside_address: string; inside_cidr: string; customer_inside_address: string; cloud_inside_address: string };
const labels = { up: "Up", down: "Down", unknown: "Unknown" } as const;
const troubleshooting = {
  up: ["Encrypted tunnel established. Application access needs separate checks.", "Check access policies and return routes."],
  down: ["Check the remote VPN endpoint and IKE reachability (UDP 500/4500).", "Confirm matching PSK and IKE/IPsec proposals on both ends."],
  unknown: ["No fresh tunnel evidence yet.", "Refresh status and check gateway connectivity to the control plane."],
} as const;
type Mode = "ipv4-static" | "ipv4-bgp";
const peerLabels = { unknown: "Unknown", idle: "Idle", connect: "Connect", active: "Active", opensent: "OpenSent", openconfirm: "OpenConfirm", established: "Established" } as const;
const count = (value: unknown, maximum: number): value is number => Number.isSafeInteger(value) && typeof value === "number" && value >= 0 && value <= maximum;
function validBGP(report: Report, approved: string[]): boolean {
  if (report.recovery_version !== undefined || report.selection_sequence !== undefined || report.active_slot != null || report.tunnels.some(t => t.selected)) return false;
  if (report.bgp === undefined) return true;
  if (report.bgp === null || typeof report.bgp !== "object") return false;
  const bgp = report.bgp;
  const prefixes = new Set(approved);
  if (approved.length > 64 || prefixes.size !== approved.length || bgp.version !== 1 || !Number.isSafeInteger(bgp.sequence) || bgp.sequence <= 0 || !Array.isArray(bgp.peers) || bgp.peers.length !== 2 || !Array.isArray(bgp.routes) || bgp.routes.length > prefixes.size) return false;
  const installed = [0, 0];
  const seen = new Set<string>();
  for (const route of bgp.routes) {
    if (!route || typeof route !== "object" || typeof route.prefix !== "string" || !prefixes.has(route.prefix) || seen.has(route.prefix) || (route.slot !== 1 && route.slot !== 2)) return false;
    seen.add(route.prefix);
    installed[route.slot - 1]++;
  }
  return bgp.peers.every((peer, i) => peer && typeof peer === "object" && peer.slot === i + 1 && typeof peer.state === "string" && Object.prototype.hasOwnProperty.call(peerLabels, peer.state) && count(peer.accepted_prefixes, Math.min(64, prefixes.size)) && count(peer.installed_prefixes, peer.accepted_prefixes) && peer.installed_prefixes === installed[i] && (peer.rejected_prefixes === undefined || count(peer.rejected_prefixes, 1_000_000_000)) && (peer.state === "established" ? report.tunnels[i].status === "up" : peer.accepted_prefixes === 0 && peer.installed_prefixes === 0));
}
const colors = { up: "text-ok", down: "text-danger", unknown: "text-ink-secondary" } as const;

export function IPsecTunnelHealth({ orgId, connectionId, tunnels, mode = "ipv4-static", approvedRemotePrefixes = [] }: { orgId: string; connectionId: string; tunnels: Tunnel[]; mode?: Mode; approvedRemotePrefixes?: string[] }) {
  const [snapshot, setSnapshot] = useState<{ key: string; report: Report } | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [now, setNow] = useState(Date.now());
  const dynamic = mode === "ipv4-bgp";
  const key = `${orgId}:${connectionId}:${mode}:${JSON.stringify(approvedRemotePrefixes)}`;
  useEffect(() => {
    let cancelled = false;
    let pending = false;
    setSnapshot(null); setUnavailable(false);
    async function read() {
      if (pending || document.visibilityState === "hidden") return;
      pending = true;
      const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/status", { params: { path: { orgId, connectionId } } }));
      pending = false;
      if (cancelled) return;
      setNow(Date.now());
      const report = result.ok ? result.data : null;
      const valid = report && Array.isArray(report.tunnels) && report.tunnels.length === 2 && report.tunnels.every(t => t !== null && typeof t === "object" && typeof t.id === "string" && t.id.length > 0 && typeof t.selected === "boolean" && (t.status === "up" || t.status === "down" || t.status === "unknown")) && report.tunnels[0].slot === 1 && report.tunnels[1].slot === 2 && report.tunnels[0].id !== report.tunnels[1].id;
      const selectionValid = valid && report && (dynamic ? validBGP(report, approvedRemotePrefixes) : report.bgp == null && (report.recovery_version == null
        ? report.selection_sequence == null && report.active_slot == null
        : report.recovery_version === 1 && Number.isSafeInteger(report.selection_sequence) && report.selection_sequence! > 0 &&
          (report.active_slot == null || ((report.active_slot === 1 || report.active_slot === 2) && report.tunnels?.find(t => t?.slot === report.active_slot)?.status === "up"))));
      setSnapshot(valid && selectionValid ? { key, report } : null);
      setUnavailable(!valid || !selectionValid);
    }
    void read();
    const timer = window.setInterval(() => { setNow(Date.now()); void read(); }, 10_000);
    const visible = () => { setNow(Date.now()); void read(); };
    document.addEventListener("visibilitychange", visible);
    return () => { cancelled = true; window.clearInterval(timer); document.removeEventListener("visibilitychange", visible); };
  }, [orgId, connectionId, key, refresh]);
  const report = snapshot?.key === key ? snapshot.report : null;
  const observed = report?.observed_at ? Date.parse(report.observed_at) : NaN;
  const fresh = Number.isFinite(observed) && now - observed < 90_000 && observed <= now + 5_000;
  return <section aria-label="Tunnel status" className="space-y-3">
    <div className="flex items-center justify-between gap-3">
      <div><h4 className="font-medium text-ink-heading">Tunnel status</h4><p className="text-xs text-ink-secondary">{unavailable ? "Status unavailable" : fresh ? "Live gateway report · updates every 10s" : "Waiting for a fresh gateway report"}</p></div>
      <Button size="sm" variant="ghost" onClick={() => setRefresh(v => v + 1)}>Refresh tunnel status</Button>
    </div>
    <div className="overflow-x-auto rounded border border-line">
      <table className="w-full text-left text-sm" aria-label="IPsec tunnel state">
        <thead className="border-b border-line bg-surface-inset text-xs text-ink-secondary"><tr>{["Tunnel", "Outside IP address", "Inside IPv4 CIDR", dynamic ? "IPsec status" : "Status", ...(dynamic ? ["BGP peer", "Accepted prefixes", "Installed prefixes", "Rejected prefixes"] : ["Path"]), "Last observed"].map(label => <th key={label} scope="col" className="px-4 py-3 font-medium whitespace-nowrap">{label}</th>)}</tr></thead>
        <tbody>{tunnels.map((tunnel, i) => {
          const health = report?.tunnels.find(t => t.slot === i + 1);
          const status = fresh && health ? health.status : "unknown";
          const peer = fresh ? report?.bgp?.peers.find(p => p.slot === i + 1) : undefined;
          const peerKnown = peer && peer.state !== "unknown";
          return <tr key={`${connectionId}:${i}`} className="border-b border-line last:border-0">
            <th scope="row" className="px-4 py-4 font-medium text-ink-heading whitespace-nowrap">Tunnel {i + 1}</th>
            <td className="px-4 py-4 font-mono text-xs">{tunnel.outside_address}</td>
            <td className="px-4 py-4 font-mono text-xs">{tunnel.inside_cidr}</td>
            <td className="px-4 py-4"><span role="status" aria-label={`Tunnel ${i + 1} ${labels[status]}`} title={status === "up" ? "Encrypted tunnel established. Application reachability is separate." : status === "down" ? "Gateway reports the tunnel is not established." : "No current verified tunnel report."} className={`inline-flex items-center gap-2 font-medium ${colors[status]}`}><span aria-hidden="true" className="h-2 w-2 rounded-full bg-current" />{labels[status]}</span></td>
            {dynamic ? <>
              <td className="px-4 py-4"><span role="status" aria-label={`Tunnel ${i + 1} BGP ${peer ? peerLabels[peer.state] : "Unknown"}`} className={peer?.state === "established" ? "text-ok" : "text-ink-secondary"}>{peer ? peerLabels[peer.state] : "Unknown"}</span></td>
              <td className="px-4 py-4 tabular-nums">{peerKnown ? peer.accepted_prefixes : <span aria-label="No data">-</span>}</td>
              <td className="px-4 py-4 tabular-nums">{peerKnown ? peer.installed_prefixes : <span aria-label="No data">-</span>}</td>
              <td className="px-4 py-4 tabular-nums">{peerKnown && peer.rejected_prefixes !== undefined ? peer.rejected_prefixes : <span aria-label="No data">-</span>}</td>
            </> : <td className="px-4 py-4"><div className="flex flex-wrap gap-2">
              {fresh && report?.recovery_version === 1 && report.active_slot === i + 1 && status === "up" && <span title="Gateway verified this permitted outbound path. Application reachability remains separate." className="text-xs text-ok">Active path</span>}
              {health?.selected && <span title="Configured preference; the active path is reported separately." className="text-xs text-ink-secondary">Preferred path</span>}
              {!health?.selected && !(fresh && report?.active_slot === i + 1) && <span className="text-ink-secondary">Not selected</span>}
            </div></td>}
            <td className="px-4 py-4 text-xs text-ink-secondary whitespace-nowrap">{fresh ? new Date(observed).toLocaleTimeString() : <span aria-label="No data">-</span>}</td>
          </tr>;
        })}</tbody>
      </table>
    </div>
    {dynamic && <div className="space-y-2">
      <h4 className="font-medium text-ink-heading">Installed BGP routes</h4>
      <p className="text-xs text-ink-secondary">Routes are reported per approved prefix. IPsec health, BGP peer state, and application reachability are separate checks.</p>
      <div className="overflow-x-auto rounded border border-line"><table className="w-full text-left text-sm" aria-label="BGP routes">
        <thead className="border-b border-line bg-surface-inset text-xs text-ink-secondary"><tr>{["Approved remote prefix", "Installed via"].map(label => <th key={label} scope="col" className="px-4 py-3 font-medium whitespace-nowrap">{label}</th>)}</tr></thead>
        <tbody>{approvedRemotePrefixes.map(prefix => {
          const bgp = fresh ? report?.bgp : undefined;
          const route = bgp?.routes.find(r => r.prefix === prefix);
          return <tr key={prefix} className="border-b border-line last:border-0"><th scope="row" className="px-4 py-4 font-mono text-xs font-medium text-ink-heading">{prefix}</th><td className="px-4 py-4">{route ? `Tunnel ${route.slot}` : bgp && bgp.peers.every(p => p.state !== "unknown") ? "No installed route" : <span aria-label="No data">-</span>}</td></tr>;
        })}</tbody>
      </table></div>
    </div>}
    {tunnels.map((tunnel, i) => {
      const health = report?.tunnels.find(t => t.slot === i + 1);
      const status = fresh && health ? health.status : "unknown";
      return <details key={i} className="rounded border border-line text-sm">
        <summary aria-label={`Tunnel ${i + 1} troubleshooting`} className="cursor-pointer px-4 py-3 font-medium text-ink-heading focus-visible:outline focus-visible:outline-2">Tunnel {i + 1} details</summary>
        <div className="border-t border-line px-4 py-4">
          <dl className="grid grid-cols-2 gap-4"><div><dt className="text-xs text-ink-secondary">Customer inside IP</dt><dd className="mt-1 font-mono text-xs">{tunnel.customer_inside_address}</dd></div><div><dt className="text-xs text-ink-secondary">Cloud inside IP</dt><dd className="mt-1 font-mono text-xs">{tunnel.cloud_inside_address}</dd></div></dl>
          <ul className="mt-4 space-y-1 text-xs text-ink-secondary">{troubleshooting[status].map(check => <li key={check}>{check}</li>)}</ul>
          {dynamic && <p className="mt-3 text-xs text-ink-secondary">{fresh && report?.bgp && report.bgp.peers[i].state !== "unknown" ? report.bgp.peers[i].state === "established" ? "BGP peer established. Check each approved prefix above, access policies, and return routes." : "Check the configured local and remote ASNs, inside addresses, and remote BGP peer configuration." : "No fresh BGP peer or route evidence yet. Refresh status and check gateway connectivity."}</p>}
        </div>
      </details>;
    })}
  </section>;
}
