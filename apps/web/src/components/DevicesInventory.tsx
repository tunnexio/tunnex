import "../devices-management-workspace.css";
import { useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import type { Device, Node } from "../lib/api";
import {
  addressLabel,
  applyDeviceFilter,
  deviceFilterCounts,
  deviceProtocol,
  postureBadge,
  postureFailureSummary,
  posturePlatformSupported,
  type DeviceFilter,
} from "../lib/postureview";
import AppAccessEmptyState from "./AppAccessEmptyState";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessRowMenu from "./AppAccessRowMenu";
import { Button, Input, RefreshButton } from "./ui";

export type DevicesInventoryProps = {
  devices: Device[];
  nodes: Node[];
  ownerEmail: Map<string, string>;
  busy: boolean;
  canMutate?: boolean;
  lastSeenLabel: (device: Device) => string;
  onInspect: (id: string) => void;
  onRequestAction: (action: "revoke" | "remove", devices: Device[]) => void;
  onRefresh: () => void;
};

type SortKey = "name" | "connection" | "state" | "posture";

/** Presentation of an authoritative loaded inventory. The page owns reads and mutations. */
export default function DevicesInventory({ devices, nodes, ownerEmail, busy, canMutate = true, lastSeenLabel, onInspect, onRequestAction, onRefresh }: DevicesInventoryProps) {
  const location = useLocation();
  const gatewayId = new URLSearchParams(location.search).get("gateway") ?? "";
  const [filter, setFilter] = useState<DeviceFilter>("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean } | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const nodeById = useMemo(() => new Map(nodes.map(node => [node.id, node])), [nodes]);
  const gateway = nodeById.get(gatewayId);
  const scopedDevices = useMemo(() => gatewayId ? devices.filter(device => device.node_id === gatewayId) : devices, [devices, gatewayId]);
  const counts = deviceFilterCounts(scopedDevices);
  const pendingCount = scopedDevices.filter(device => device.status === "pending").length;
  const owner = (device: Device) => ownerEmail.get(device.user_id) ?? device.owner_email ?? "";
  const routing = (device: Device) => device.full_tunnel ? "Full tunnel" : "Split tunnel";
  const recency = (device: Device) => device.status !== "active" ? "" : deviceProtocol(device.public_key) === "OpenVPN" ? "liveness not reported" : lastSeenLabel(device);
  const posture = (device: Device) => {
    if (device.status === "revoked") return { label: "Not evaluated", tone: "unknown" as const };
    if (!posturePlatformSupported(device.platform)) return { label: "Not supported", tone: "unknown" as const };
    const badge = postureBadge(device);
    // An inactive credential must not look compliant or connected. Keep real
    // negative findings visible without presenting a saved pass as current access.
    if (device.status !== "active" && (!badge || badge.tone === "ok")) return { label: "Inactive device", tone: "unknown" as const };
    return badge ?? { label: "Not evaluated", tone: "unknown" as const };
  };
  const failure = (device: Device) => device.status === "revoked" ? null : postureFailureSummary(device.health_failed_checks);
  const reexport = (device: Device) => device.status !== "revoked" && device.needs_reexport === true;
  const connectionText = (device: Device) => [deviceProtocol(device.public_key), addressLabel(device.assigned_ip), routing(device), nodeById.get(device.node_id)?.name ?? ""].join(" ");
  const postureText = (device: Device) => [posture(device).label, failure(device), reexport(device) ? "re-export needed reexport" : ""].filter(Boolean).join(" ");
  const filteredDevices = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return applyDeviceFilter(scopedDevices, filter).filter(device => {
      const text = [device.name, owner(device), connectionText(device), device.status, device.platform ?? "", recency(device), postureText(device)].join(" ").toLowerCase();
      return terms.every(term => text.includes(term));
    });
  }, [scopedDevices, filter, query, ownerEmail, nodeById, lastSeenLabel]);
  const sortValue = (device: Device, key: SortKey) => {
    if (key === "name") return `${device.name} ${owner(device)}`;
    if (key === "connection") return connectionText(device);
    if (key === "state") return `${device.status} ${device.status === "active" && deviceProtocol(device.public_key) === "WireGuard" ? device.last_handshake_at ?? "" : ""}`;
    return postureText(device);
  };
  const orderedDevices = useMemo(() => sort ? [...filteredDevices].sort((a, b) => sortValue(a, sort.key).localeCompare(sortValue(b, sort.key), undefined, { numeric: true, sensitivity: "base" }) * (sort.descending ? -1 : 1)) : filteredDevices, [filteredDevices, sort, ownerEmail, nodeById]);
  const lastPage = Math.max(1, Math.ceil(orderedDevices.length / pageSize));
  const currentPage = Math.min(page, lastPage);
  const pageDevices = orderedDevices.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const selectedDevices = canMutate ? devices.filter(device => selection.has(device.id)) : [];
  const pageSelected = pageDevices.length > 0 && pageDevices.every(device => selection.has(device.id));
  const outsidePageCount = selectedDevices.filter(device => !pageDevices.some(visible => visible.id === device.id)).length;

  useEffect(() => { setPage(1); }, [gatewayId]);
  useEffect(() => { setPage(previous => Math.min(previous, lastPage)); }, [lastPage]);
  useEffect(() => { if (!canMutate) setSelection(new Set()); }, [canMutate]);
  useEffect(() => {
    setSelection(previous => {
      const next = new Set([...previous].filter(id => devices.some(device => device.id === id)));
      return previous.size === next.size ? previous : next;
    });
  }, [devices]);

  const unavailable = (device: Device, action: "revoke" | "remove") => {
    if (!canMutate) return "Verify your email to manage devices.";
    if (busy) return "Wait for the current device operation.";
    return action === "revoke"
      ? device.status === "active" ? null : `A ${device.status} device cannot be revoked.`
      : device.status === "revoked" ? null : "Only a revoked device can be removed. Revoke it first.";
  };
  const requestAction = (action: "revoke" | "remove", selected: Device[]) => {
    if (busy || !canMutate) return;
    const eligible = selected.map(device => devices.find(current => current.id === device.id)).filter((device): device is Device => !!device && !unavailable(device, action));
    if (eligible.length) onRequestAction(action, eligible);
  };
  const toggleSelection = (id: string, checked: boolean) => setSelection(previous => {
    const next = new Set(previous);
    if (checked) next.add(id); else next.delete(id);
    return next;
  });
  const sortColumn = (key: SortKey) => {
    setSort(previous => ({ key, descending: previous?.key === key ? !previous.descending : false }));
    setPage(1);
  };
  const sortIndicator = (key: SortKey) => sort?.key === key ? sort.descending ? " ↓" : " ↑" : "";
  const clearFilters = () => { setQuery(""); setFilter("all"); setPage(1); };
  const withoutGateway = new URLSearchParams(location.search);
  withoutGateway.delete("gateway");
  const clearGatewayTarget = { pathname: location.pathname, search: withoutGateway.size ? `?${withoutGateway}` : "", hash: location.hash };

  return <section className="devices-management-inventory" aria-label="Device inventory">
    {gatewayId && <div className="dm-gateway-context"><span>Gateway: <strong>{gateway?.name ?? "Gateway details unavailable"}</strong></span><Link to={clearGatewayTarget}>Show all gateways</Link></div>}
    <div className="dm-inventory-topbar">
      <nav className="dm-filter-tabs" aria-label="Device inventory filters">
        {([
          ["all", "All", counts.all],
          ["attention", "Needs attention", counts.attention],
          ["revoked", "Revoked", counts.revoked],
        ] as Array<[DeviceFilter, string, number]>).map(([key, label, count]) => <button key={key} type="button" aria-pressed={filter === key} onClick={() => { setFilter(key); setPage(1); }}>{label} <span>({count})</span></button>)}
      </nav>
      <RefreshButton label="Refresh devices" disabled={busy} onClick={onRefresh} />
    </div>
    <div className="dm-inventory-toolbar">
      <Input aria-label="Search devices" placeholder="Search devices…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} />
      {pendingCount > 0 && <Link className="dm-approvals-link" to="/devices/approvals" aria-label={`Review ${pendingCount} pending device${pendingCount === 1 ? "" : "s"}`}>Awaiting approval <span>{pendingCount}</span></Link>}
      <span className="dm-result-count">{query.trim() ? `${filteredDevices.length} matching` : `${filteredDevices.length} device${filteredDevices.length === 1 ? "" : "s"}`}</span>
    </div>
    {!canMutate && <p className="dm-mutation-note">Verify your email to manage devices.</p>}

    {selectedDevices.length > 0 && <div className="dm-selection" role="group" aria-label="Selected device actions">
      <div className="dm-selection-summary"><strong>{selectedDevices.length} selected</strong>{outsidePageCount > 0 && <span>{outsidePageCount} outside this page</span>}<Button size="sm" variant="ghost" onClick={() => setSelection(new Set())}>Clear</Button>{pageSelected && filteredDevices.length > pageDevices.length && <Button size="sm" variant="ghost" onClick={() => setSelection(new Set(filteredDevices.map(device => device.id)))}>Select all {filteredDevices.length} matching</Button>}</div>
      <div className="dm-selection-actions">{(["revoke", "remove"] as const).map(action => {
        const eligible = selectedDevices.filter(device => !unavailable(device, action));
        const reason = selectedDevices.map(device => unavailable(device, action)).find(Boolean);
        const partial = eligible.length > 0 && eligible.length < selectedDevices.length;
        return <div key={action}>{partial && <span>{eligible.length} of {selectedDevices.length}</span>}<Button size="sm" variant="ghost" disabled={busy || eligible.length === 0} title={reason ?? undefined} aria-describedby={reason ? `dm-bulk-${action}-reason` : undefined} onClick={() => requestAction(action, eligible)}>{action === "revoke" ? "Revoke" : "Remove"}</Button>{reason && <span id={`dm-bulk-${action}-reason`} className="sr-only">{partial ? `${eligible.length} of ${selectedDevices.length} selected devices are eligible. ` : ""}{reason}</span>}</div>;
      })}</div>
    </div>}

    {pageDevices.length > 0 ? <div className="dm-table-scroll"><table className="dm-devices-table"><caption className="sr-only">Devices</caption><thead><tr>
      {canMutate && <th className="dm-select"><input type="checkbox" aria-label={`Select all ${pageDevices.length} on this page`} checked={pageSelected} ref={element => { if (element) element.indeterminate = !pageSelected && pageDevices.some(device => selection.has(device.id)); }} onChange={event => { const checked = event.target.checked; setSelection(previous => { const next = new Set(previous); pageDevices.forEach(device => { if (checked) next.add(device.id); else next.delete(device.id); }); return next; }); }} /></th>}
      {([ ["name", "Device"], ["connection", "Connection"], ["state", "State"], ["posture", "Posture"] ] as Array<[SortKey, string]>).map(([key, label]) => <th key={key} data-column={key} scope="col" aria-sort={sort?.key === key ? sort.descending ? "descending" : "ascending" : "none"}><button type="button" onClick={() => sortColumn(key)}>{label}<span aria-hidden="true">{sortIndicator(key)}</span></button></th>)}
      <th className="dm-actions"><span className="sr-only">Actions</span></th>
    </tr></thead><tbody>{pageDevices.map(device => {
      const pb = posture(device);
      const failed = failure(device);
      const node = nodeById.get(device.node_id);
      return <tr key={device.id} data-selected={canMutate && selection.has(device.id) || undefined}>
        {canMutate && <td className="dm-select"><input type="checkbox" aria-label={`Select ${device.name}`} checked={selection.has(device.id)} onChange={event => toggleSelection(device.id, event.target.checked)} /></td>}
        <td data-column="name"><button type="button" className="dm-device-name" disabled={busy} onClick={() => onInspect(device.id)}>{device.name}</button>{owner(device) && <span className="dm-secondary dm-owner" title={owner(device)}>{owner(device)}</span>}</td>
        <td data-column="connection"><span className="dm-connection-primary"><span>{deviceProtocol(device.public_key)}</span><span className="dm-address">{addressLabel(device.assigned_ip)}</span></span><span className="dm-secondary">{routing(device)}{node && <> · {node.name}{node.status === "revoked" ? " (revoked)" : ""}</>}</span></td>
        <td data-column="state"><span className="dm-lifecycle" data-state={device.status}>{device.status}</span>{recency(device) && <span className="dm-secondary">{recency(device)}</span>}{reexport(device) && <span className="dm-reexport" title="This device's issued configuration no longer matches its address, gateway, or routed ranges. Replace and re-import the profile.">re-export needed</span>}</td>
        <td data-column="posture"><span className="dm-posture-label" data-tone={pb.tone}>{pb.label}</span>{failed && <span className="dm-secondary dm-posture-failure" data-posture-failure={device.id} title={failed}>{failed}</span>}</td>
        <td className="dm-actions"><AppAccessRowMenu label={`Device actions for ${device.name}`} actions={[
          { key: "inspect", label: "View details", disabledReason: busy ? "Wait for the current device operation." : null, onSelect: () => onInspect(device.id) },
          ...(device.status === "pending" ? [{ key: "approval", label: "Review approval", href: "/devices/approvals", disabledReason: busy ? "Wait for the current device operation." : null }] : []),
          ...(canMutate ? [
            { key: "revoke", label: "Revoke", danger: true, disabledReason: unavailable(device, "revoke"), onSelect: () => requestAction("revoke", [device]) },
            { key: "remove", label: "Remove", danger: true, disabledReason: unavailable(device, "remove"), onSelect: () => requestAction("remove", [device]) },
          ] : []),
        ]} /></td>
      </tr>;
    })}</tbody></table></div> : <AppAccessEmptyState icon={null} title={query.trim() ? "No devices match this search." : filter === "attention" ? "No devices need attention." : filter === "revoked" ? "No revoked devices." : gatewayId ? "No devices on this gateway." : "No devices yet."} description={query.trim() || filter !== "all" ? "Try a different search or view all devices." : gatewayId ? "Devices homed on this gateway will appear here." : "Enrolled devices will appear here."} action={query.trim() || filter !== "all" ? <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : undefined} />}
    <AppAccessPagination page={currentPage} pageSize={pageSize} count={pageDevices.length} hasNext={currentPage < lastPage} maxOffset={null} busy={busy} previousLabel="Previous devices page" nextLabel="Next devices page" onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} />
  </section>;
}
