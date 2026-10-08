import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage, loadOne, type Device, type DeviceApproval } from "../lib/api";
import { relativeAge } from "../lib/format";
import { NO_ADDRESS } from "../lib/postureview";
import { Button, DataTable, ErrorText, Input, Loading, Modal, Select } from "./ui";
import { ResourceSummary } from "./ResourceSummary";
import { LoadRetry } from "./LoadRetry";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessEmptyState from "./AppAccessEmptyState";
import "../devices-policy-workspace.css";

type Props = { orgId: string; canManage: boolean; renderNavigation?: (actions: ReactNode) => ReactNode };
export function DeviceApprovalSection(props: Props) { return <ApprovalWorkspace key={`${props.orgId}:${props.canManage}`} {...props} />; }

function ApprovalWorkspace({ orgId, canManage, renderNavigation }: Props) {
  const [mode, setMode] = useState<"off" | "on" | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);
  const [pending, setPending] = useState<Device[]>([]);
  const [pendingLoaded, setPendingLoaded] = useState(false);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<{ action: "approve" | "reject"; devices: Device[]; generation: number } | null>(null);
  const [viewing, setViewing] = useState<Device | null>(null);
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState(""), [sort, setSort] = useState("oldest");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const alive = useRef(true), request = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; request.current++; }; }, []);
  const load = useCallback(async () => {
    const sequence = ++request.current;
    setPendingLoaded(false); setPendingError(null); setMode(null); setModeError(null); setViewing(null);
    const [dr, pr] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/device-approval", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices/pending", { params: { path: { orgId } } })),
    ]);
    if (!alive.current || sequence !== request.current) return;
    const modeValid = dr.ok && dr.data != null && typeof dr.data === "object" && ((dr.data as DeviceApproval).mode === "on" || (dr.data as DeviceApproval).mode === "off");
    setModeError(!dr.ok ? dr.error : modeValid ? null : "The enrollment approval response was not valid. Retry to reload it.");
    if (modeValid) setMode((dr.data as DeviceApproval).mode);
    const pendingValid = pr.ok && Array.isArray(pr.data) && pr.data.every((device) => device && typeof device === "object" && typeof device.id === "string" && device.id.length > 0 && typeof device.name === "string" && typeof device.created_at === "string") && new Set(pr.data.map((device) => device.id)).size === pr.data.length;
    setPendingError(!pr.ok ? pr.error : pendingValid ? null : "The pending device response was not valid. Retry to reload it.");
    if (pendingValid) setPending(pr.data as Device[]);
    setPendingLoaded(true);
  }, [orgId]);
  useEffect(() => { void load(); }, [load]);

  function stage(action: "approve" | "reject", devices: Device[]) {
    if (!canManage || busy || !pendingLoaded || pendingError) return;
    const ids = new Set(devices.map((device) => device.id));
    const targets = pending.filter((device) => ids.has(device.id));
    if (!targets.length || targets.length !== ids.size) return;
    setViewing(null); setConfirmation({ action, devices: targets, generation: request.current });
  }
  async function decide() {
    if (!canManage || locked.current || !alive.current || !confirmation || !pendingLoaded || pendingError || confirmation.generation !== request.current) return;
    const { action, devices } = confirmation;
    if (!devices.every((device) => pending.some((row) => row.id === device.id))) return;
    locked.current = true; setBusy(true); setErr(null); setNotice(null);
    try {
      const results = await Promise.all(devices.map(async (device) => {
        const path = action === "approve" ? "/api/v1/organizations/{orgId}/devices/{deviceId}/approve" : "/api/v1/organizations/{orgId}/devices/{deviceId}/reject";
        try { const { error } = await api.POST(path, { params: { path: { orgId, deviceId: device.id } } }); return { device, error, uncertain: false }; }
        catch { return { device, error: { error: { message: "Decision was not confirmed. Reload request state before retrying." } }, uncertain: true }; }
      }));
      if (!alive.current) return;
      const failed = results.filter((result) => result.error), succeeded = results.length - failed.length;
      if (failed.length) setErr(`${succeeded} of ${results.length} devices ${results.some((result) => result.uncertain) ? "confirmed " : ""}${action === "approve" ? "approved" : "rejected"}. ${failed.map((result) => `${result.device.name}: ${apiErrorMessage(result.error, `Could not ${action} the device.`)}`).join(" ")}`);
      else setNotice(`${succeeded} device${succeeded === 1 ? "" : "s"} ${action === "approve" ? "approved" : "rejected"}.`);
      setConfirmation(null); await load();
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  const filtered = pending.filter((device) => `${device.name} ${device.owner_email ?? ""} ${device.assigned_ip ?? ""} ${device.platform ?? ""}`.toLowerCase().includes(query.trim().toLowerCase())).sort((a, b) => sort === "name" ? a.name.localeCompare(b.name) : (Date.parse(a.created_at) - Date.parse(b.created_at)) * (sort === "newest" ? -1 : 1));
  const current = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)));
  const visible = filtered.slice((current - 1) * pageSize, current * pageSize);
  const refresh = <Button variant="ghost" disabled={busy} onClick={() => { setPage(1); void load(); }}>Refresh requests</Button>;
  return <>{renderNavigation?.(refresh)}<div className="devices-policy-content">
    <div className="devices-policy-status"><span><strong>Enrollment approval: {mode === "on" ? "On" : mode === "off" ? "Off" : modeError ? "Unavailable" : "Loading"}</strong>{mode && <span> · {mode === "on" ? "New devices wait before connecting." : "New devices become active immediately."}</span>}</span><Link className="devices-policy-link" to="/settings?section=access-security">Manage setting</Link></div>
    {modeError && <LoadRetry error={modeError} onRetry={() => void load()} />}
    <ErrorText>{err}</ErrorText>{notice && <p role="status" className="devices-policy-notice">{notice}</p>}
    {!pendingLoaded ? <Loading label="Loading approval requests…" /> : pendingError ? <LoadRetry error={pendingError} onRetry={() => void load()} /> : pending.length === 0 ? <AppAccessEmptyState icon={null} title="No approvals waiting" description="New pending enrollment requests will appear here." /> : <>
      <div className="devices-policy-toolbar"><Input aria-label="Search approval requests" value={query} placeholder="Search device, owner, or address" onChange={(event) => { setQuery(event.target.value); setPage(1); }} /><div className="devices-policy-actions"><Select width="auto" aria-label="Sort approval requests" value={sort} onChange={(event) => { setSort(event.target.value); setPage(1); }}><option value="oldest">Oldest first</option><option value="newest">Newest first</option><option value="name">Device name</option></Select>{!renderNavigation && refresh}</div></div>
      <DataTable<Device> variant="flat" caption="Pending devices" rows={visible} rowKey={(device) => device.id} rowLabel={(device) => device.name} failed={false} filterable={false} pageSize={0} selectable={canManage} selectionBar="active" empty={<AppAccessEmptyState icon={null} title="No matching requests" description="Try another device, owner, or address." action={<Button variant="ghost" onClick={() => { setQuery(""); setPage(1); }}>Clear search</Button>} />} bulkActions={canManage ? (keys) => { const selected = new Set(keys); const targets = pending.filter((device) => selected.has(device.id)); return <><Button size="sm" variant="ghost" disabled={busy || !targets.length || targets.length !== selected.size} onClick={() => stage("approve", targets)}>Approve</Button><Button size="sm" variant="danger" disabled={busy || !targets.length || targets.length !== selected.size} onClick={() => stage("reject", targets)}>Reject</Button></>; } : undefined} columns={[
        { key: "name", header: "Device", cell: (device) => <div className="devices-policy-cell"><button className="devices-policy-name" onClick={() => setViewing(device)}>{device.name}</button><small>{device.platform || "Platform not reported"}</small></div> },
        { key: "owner", header: "Owner", cell: (device) => device.owner_email || "Owner unavailable" },
        { key: "address", header: "Address", cell: (device) => <span className="devices-policy-copy">{device.assigned_ip || NO_ADDRESS}</span> },
        { key: "waiting", header: "Waiting", cell: (device) => <span title={device.created_at}>{relativeAge(device.created_at)}</span> },
        { key: "actions", header: "Actions", cell: (device) => <AppAccessRowMenu label={`Actions for ${device.name}`} actions={[{ key: "view", label: "Review device", onSelect: () => setViewing(device) }, ...(canManage ? [{ key: "approve", label: "Approve", disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => stage("approve", [device]) }, { key: "reject", label: "Reject", danger: true, disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => stage("reject", [device]) }] : [])]} /> },
      ]} />
      <AppAccessPagination maxOffset={null} page={current} pageSize={pageSize} count={visible.length} hasNext={current * pageSize < filtered.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
    </>}
    {viewing && <Modal title={viewing.name} placement="right" size="enrollment" showClose onDismiss={() => !busy && setViewing(null)} actions={canManage ? <><Button variant="ghost" disabled={busy} onClick={() => stage("reject", [viewing])}>Reject</Button><Button disabled={busy} onClick={() => stage("approve", [viewing])}>Approve</Button></> : undefined}><div className="devices-policy-editor"><ResourceSummary title="Enrollment details"><dl className="devices-policy-facts tnx-resource-facts"><ApprovalFact label="Owner" value={viewing.owner_email || "Owner unavailable"} /><ApprovalFact label="Address" value={viewing.assigned_ip || NO_ADDRESS} /><ApprovalFact label="Platform" value={viewing.platform || "Not reported"} /><ApprovalFact label="Requested" value={relativeAge(viewing.created_at)} /><ApprovalFact label="Gateway identity" value={viewing.node_id || "Unavailable"} /><ApprovalFact label="Device identity" value={viewing.id} /></dl></ResourceSummary><p>These are enrollment facts. Review the device’s owner and source before approving connection.</p></div></Modal>}
    {confirmation && <Modal title={`${confirmation.action === "approve" ? "Approve" : "Reject"} pending device${confirmation.devices.length === 1 ? "" : "s"}?`} danger={confirmation.action === "reject"} showClose onDismiss={() => !busy && setConfirmation(null)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button variant={confirmation.action === "reject" ? "danger" : "primary"} disabled={busy} onClick={() => void decide()}>{busy ? "Applying…" : confirmation.action === "approve" ? "Approve device" : "Reject device"}</Button></>}><p className="devices-policy-copy">{confirmation.action === "approve" ? "Approval allows these pending devices to connect under the organization’s current policy. Recovery is revocation through Devices." : "Rejection keeps these devices from connecting. Recovery requires a fresh new enrollment request."}</p><ul className="devices-policy-confirm-list">{confirmation.devices.map((device) => <li key={device.id}><span>{device.name}</span><small>{device.owner_email || "Owner unavailable"} · {device.assigned_ip || "No assigned address"} · {device.platform || "Platform not reported"}</small></li>)}</ul><p className="devices-policy-copy">Successful bulk decisions remain applied. Failed or unconfirmed devices are reported individually after refresh.</p></Modal>}
  </div></>;
}

function ApprovalFact({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }
