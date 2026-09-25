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
const colors = { up: "text-ok", down: "text-danger", unknown: "text-ink-secondary" } as const;

export function IPsecTunnelHealth({ orgId, connectionId, tunnels }: { orgId: string; connectionId: string; tunnels: Tunnel[] }) {
  const [snapshot, setSnapshot] = useState<{ key: string; report: Report } | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [now, setNow] = useState(Date.now());
  const key = `${orgId}:${connectionId}`;
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
      const selectionValid = valid && report && (report.recovery_version == null
        ? report.selection_sequence == null && report.active_slot == null
        : report.recovery_version === 1 && Number.isSafeInteger(report.selection_sequence) && report.selection_sequence! > 0 &&
          (report.active_slot == null || ((report.active_slot === 1 || report.active_slot === 2) && report.tunnels?.find(t => t?.slot === report.active_slot)?.status === "up")));
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
    <div className="grid grid-cols-2 gap-4">{tunnels.map((tunnel, i) => {
      const health = report?.tunnels.find(t => t.slot === i + 1);
      const status = fresh && health ? health.status : "unknown";
      return <div key={`${connectionId}:${i}`} className="rounded border border-line p-3 text-sm">
        <div className="mb-2 flex items-center justify-between gap-2"><h5 className="font-medium">Tunnel {i + 1}</h5><span role="status" aria-label={`Tunnel ${i + 1} ${labels[status]}`} title={status === "up" ? "Encrypted tunnel established. Application reachability is separate." : status === "down" ? "Gateway reports the tunnel is not established." : "No current verified tunnel report."} className={`inline-flex items-center gap-1.5 text-xs ${colors[status]}`}><span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-current" />{labels[status]}</span></div>
        {health?.selected && <span title="Configured preference; the active path is reported separately." className="mb-2 inline-block rounded border border-line px-1.5 py-0.5 text-xs text-ink-secondary">Preferred path</span>}
        {fresh && report?.recovery_version === 1 && report.active_slot === i + 1 && status === "up" && <span title="Gateway verified this permitted outbound path. Application reachability remains separate." className="mb-2 ml-2 inline-block rounded border border-line px-1.5 py-0.5 text-xs text-ok">Active path</span>}
        <dl className="space-y-1"><div><dt className="inline text-ink-secondary">Outside IP: </dt><dd className="inline">{tunnel.outside_address}</dd></div><div>Inside: {tunnel.inside_cidr}</div><div>Customer: {tunnel.customer_inside_address}</div><div>Cloud: {tunnel.cloud_inside_address}</div></dl>
        <details className="mt-3 border-t border-line pt-2 text-xs text-ink-secondary">
          <summary aria-label={`Tunnel ${i + 1} troubleshooting`} className="cursor-pointer select-none text-ink-heading focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2">Troubleshoot</summary>
          <ul className="mt-2 list-disc space-y-1 pl-4">{troubleshooting[status].map(check => <li key={check}>{check}</li>)}</ul>
        </details>
      </div>;
    })}</div>
  </section>;
}
