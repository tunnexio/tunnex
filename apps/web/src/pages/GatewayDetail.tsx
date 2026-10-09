import "../gateway-workspace.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import {
  Badge,
  Button,
  ErrorText,
  Field,
  Input,
  Loading,
  Modal,
  RefreshButton,
  Select,
} from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { Icon } from "../components/Icon";
import { ResourceSummary } from "../components/ResourceSummary";
import { api, apiErrorMessage } from "../lib/api";
import { relativeAge } from "../lib/format";
import {
  gatewayEgressDetail,
  gatewayOperationalLabel,
  groupNotes,
  toGatewayRow,
} from "../lib/gatewaysview";
import { useGatewayInventory } from "../lib/useGatewayInventory";

type DetailTab = "overview" | "health" | "lifecycle";
type Dialog = "rename" | "transfer" | "revoke" | "restore" | "delete" | null;

const detailTab = (value: string | null): DetailTab =>
  value === "health" || value === "lifecycle" ? value : "overview";

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="gw-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function requiredImpactCount(data: unknown, field: string): number {
  if (typeof data === "object" && data !== null) {
    const value = (data as Record<string, unknown>)[field];
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  }
  throw new Error("The API returned an incomplete impact response. Refresh the gateway before retrying.");
}

export default function GatewayDetail() {
  const { gatewayId = "" } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = detailTab(params.get("tab"));
  const { org, state, reload, canManage, canTransfer, canRestore } = useGatewayInventory();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [draft, setDraft] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const mutationScope = `${org?.id ?? ""}:${gatewayId}`;
  const mutationScopeRef = useRef(mutationScope);
  mutationScopeRef.current = mutationScope;

  useEffect(() => {
    setDialog(null);
    setDraft("");
    setTarget("");
    setBusy(false);
    setError("");
    setNotice("");
  }, [gatewayId, org?.id]);

  const node = state.kind === "ready" ? state.nodes.find((item) => item.id === gatewayId) : undefined;
  const row = node ? toGatewayRow(node, state.siteNames) : null;
  const destinations = useMemo(
    () =>
      state.kind === "ready"
        ? state.nodes.filter((candidate) => candidate.id !== gatewayId && candidate.status === "active")
        : [],
    [gatewayId, state],
  );
  const homed = state.kind === "ready" && state.homedCounts !== null ? state.homedCounts[gatewayId] ?? 0 : null;
  const targetNode = destinations.find((candidate) => candidate.id === target);

  const selectTab = (next: DetailTab) => {
    const nextParams = new URLSearchParams(params);
    if (next === "overview") nextParams.delete("tab");
    else nextParams.set("tab", next);
    setParams(nextParams);
  };

  async function mutate(
    call: () => Promise<{ data?: unknown; error?: unknown }>,
    fallback: string,
    success: (data: unknown) => string,
  ) {
    const startedInScope = mutationScope;
    setBusy(true);
    setError("");
    try {
      const result = await call();
      if (mutationScopeRef.current !== startedInScope) return false;
      if (result.error) {
        setError(apiErrorMessage(result.error, fallback));
        return false;
      }
      try {
        setNotice(success(result.data));
      } catch (responseError) {
        setError(responseError instanceof Error ? responseError.message : fallback);
        return false;
      }
      setDialog(null);
      setTarget("");
      await reload();
      return true;
    } catch {
      if (mutationScopeRef.current !== startedInScope) return false;
      setError("Could not reach the API.");
      return false;
    } finally {
      setBusy(false);
    }
  }

  const rename = () =>
    mutate(
      () =>
        api.PATCH("/api/v1/organizations/{orgId}/nodes/{nodeId}", {
          params: { path: { orgId: org!.id, nodeId: gatewayId } },
          body: { name: draft.trim() },
        }),
      "Could not rename the gateway.",
      () => "Gateway name updated. Audit Log records the old and new labels.",
    );

  const openDialog = (next: Exclude<Dialog, null>) => {
    setError("");
    setDialog(next);
  };

  const breadcrumb = <nav className="gw-breadcrumb" aria-label="Gateway breadcrumb">
    <Link to="/gateways">Gateways</Link><Icon name="chevron-right" size={13} />
    <span aria-current="page">{node?.name ?? "Gateway details"}</span>
  </nav>;
  if (state.kind === "loading") return <div className="gateway-workspace gw-detail-workspace">{breadcrumb}<div className="gw-detail-state"><Loading label="Loading gateway workspace…" /></div></div>;
  if (state.kind === "error") return <div className="gateway-workspace gw-detail-workspace">{breadcrumb}<div className="gw-detail-state"><LoadRetry error={state.error ?? "Could not load gateways."} onRetry={reload} /></div></div>;
  if (!node || !row) return <div className="gateway-workspace gw-detail-workspace">{breadcrumb}<div className="gw-detail-state" role="status">
    <h1>Gateway not found</h1>
    <p>It may have been deleted or belong to another organization.</p>
    <Link className="gw-text-link" to="/gateways">Return to Gateways</Link>
  </div></div>;

  // The list contract is organization-scoped but Node intentionally carries no org_id.
  const activeOrgId = org?.id ?? "";
  const tabs: Array<{ id: DetailTab; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "health", label: "Health" },
    { id: "lifecycle", label: "Lifecycle" },
  ];
  const status = row.operationalState;
  const statusLabel = gatewayOperationalLabel(row);
  const canRevoke = node.status === "active" && canManage && homed === 0;
  const canRestoreRevoked = node.status === "revoked" && canRestore;
  const canDeleteRevoked = node.status === "revoked" && canManage;

  return (
    <div className="gateway-workspace gw-detail-workspace">
      {breadcrumb}
      <header className="gw-detail-header">
        <div className="gw-detail-identity"><h1>{node.name}</h1><p>{row.siteName ?? "No site assigned"}{row.address && <> · <span>{row.address}</span></>}</p></div>
        <div className="gw-detail-header-actions">
          <Badge tone={status === "healthy" ? "ok" : status === "degraded" ? "warn" : "neutral"}>{statusLabel}</Badge>
          <RefreshButton label="Refresh gateway" disabled={busy} onClick={() => void reload()} />
          {canManage && node.status !== "revoked" && <Button size="sm" variant="ghost" disabled={busy} onClick={() => { setDraft(node.name); openDialog("rename"); }}>Rename</Button>}
        </div>
      </header>
      {!dialog && <ErrorText>{error}</ErrorText>}
      {notice && <div role="status" className="gw-detail-notice">{notice}</div>}
      <div className="gw-detail-layout">
        <aside className="gw-detail-rail">
          <nav aria-label="Gateway detail sections" className="gw-detail-nav">
            {tabs.map(item => <button key={item.id} type="button" aria-current={tab === item.id ? "page" : undefined} onClick={() => selectTab(item.id)}>
              {item.label}
            </button>)}
          </nav>
          <p className="gw-detail-rail-note">{node.status === "revoked" ? "Revoked credentials cannot reconnect." : "Check health before making lifecycle changes."}</p>
        </aside>
        <section className="gw-detail-stage" aria-labelledby="gateway-stage-heading">
          <ResourceSummary title={tabs.find(item => item.id === tab)?.label ?? "Overview"} headingLevel={2} headingId="gateway-stage-heading" className="gw-detail-summary" footer={<>
            {tab !== "overview" ? <Button size="sm" variant="ghost" onClick={() => selectTab(tab === "health" ? "overview" : "health")}>{tab === "health" ? "Back to overview" : "Back to health"}</Button> : <span />}
            {tab !== "lifecycle" && <Button size="sm" onClick={() => selectTab(tab === "overview" ? "health" : "lifecycle")}>{tab === "overview" ? "View health" : "View lifecycle"}</Button>}
          </>}>
          {tab === "overview" && <>
            <dl className="gw-facts tnx-resource-facts tnx-resource-facts-three">
              <Fact label="Endpoint">{node.endpoint ?? "Not reported"}</Fact>
              <Fact label="Site">{row.siteName ?? "No site assigned"}</Fact>
              <Fact label="Credential"><Badge tone={node.status === "revoked" ? "neutral" : "ok"}>{node.status}</Badge></Fact>
              <Fact label="Agent version">{node.agent_version || "Not reported"}</Fact>
              <Fact label="Last seen">{node.last_seen_at ? <><span>{relativeAge(node.last_seen_at)}</span><small>{new Date(node.last_seen_at).toLocaleString()}</small></> : "Never connected"}</Fact>
              <Fact label="Enrolled">{node.enrolled_at ? new Date(node.enrolled_at).toLocaleString() : "Not reported"}</Fact>
            </dl>
            <div className="gw-related-links" aria-label="Related gateway resources">
              <Link to="/sites"><span>Site topology</span></Link>
              <Link to={`/devices?gateway=${gatewayId}`}><span>Homed devices{homed === null ? "" : ` (${homed})`}</span></Link>
              <Link to={`/audit?q=${encodeURIComponent(node.name)}`}><span>Audit evidence</span></Link>
            </div>
          </>}
          {tab === "health" && <>
            <div className="gw-health-list">
              <section className="gw-health-row"><div><h3>Connectivity</h3><p>{node.last_seen_at ? `Last control-plane observation ${relativeAge(node.last_seen_at)}.` : "This gateway has never reported a successful connection."}</p></div><span className="gw-health-value">{node.status === "revoked" ? "Historical" : !node.last_seen_at ? "Awaiting connection" : row.health?.label === "offline" ? "Offline" : "Reported"}</span></section>
              <section className="gw-health-row"><div><h3>Policy and transit</h3>{groupNotes([row]).map(note => <p key={note}>{note}</p>)}</div><Badge tone={node.status === "revoked" ? "neutral" : row.health?.tone ?? (!node.last_seen_at ? "neutral" : "ok")}>{node.status === "revoked" ? "not evaluated" : row.health?.label ?? (!node.last_seen_at ? "Awaiting first report" : "healthy")}</Badge></section>
              <section className="gw-health-row"><div><h3>OpenVPN</h3><p>{node.status === "revoked" ? "Not evaluated after revocation." : row.ovpnHealth ? row.ovpnHealth.replace(/^ovpn_/, "").replace(/_/g, " ") : "No OpenVPN failure reported."}</p></div>{row.ovpnHealth && <Badge tone="warn">Needs attention</Badge>}</section>
              <section className="gw-health-row"><div><h3>Egress</h3><p>{gatewayEgressDetail(row)}</p></div></section>
            </div>
            <details className="gw-detail-disclosure"><summary>How health is evaluated</summary><p>Active credentials do not confirm a recent connection. Policy health and OpenVPN are separate service signals; egress capabilities come from verified gateway reports.</p></details>
          </>}
          {tab === "lifecycle" && <>
            {node.status === "active" && <p className="gw-stage-context">Move dependent devices, then revoke this gateway.</p>}
            {node.status === "revoked" && <p className="gw-stage-context">This gateway cannot reconnect. Recover eligible devices on an active replacement.</p>}
            <div className="gw-lifecycle-steps">
              <section className="gw-lifecycle-step">
                <span className="gw-step-number" aria-hidden="true">1</span>
                <div className="gw-lifecycle-copy"><h3>Homed devices</h3><p>{homed === null ? "Impact count unavailable. Dependent actions are withheld." : homed === 0 ? "No active or pending devices depend on this gateway." : `${homed} active or pending device${homed === 1 ? " depends" : "s depend"} on this gateway.`}</p>
                  {homed !== null && homed > 0 && <Link className="gw-text-link" to={`/devices?gateway=${gatewayId}`}>View dependent devices</Link>}
                  {node.status === "active" && homed !== null && homed > 0 && canTransfer && !destinations.length && <p>No active replacement gateway is available. Enroll a replacement before moving devices.</p>}
                </div>
                <div className="gw-lifecycle-action">
                  {homed === 0 && <Badge tone="ok">No dependencies</Badge>}{homed === null && <RefreshButton label="Refresh impact" disabled={busy} onClick={() => void reload()} />}
                  {node.status === "active" && homed !== null && homed > 0 && canTransfer && <Button size="sm" disabled={busy || !destinations.length} onClick={() => openDialog("transfer")}>Move devices</Button>}
                </div>
              </section>
              {node.status === "active" && <section className="gw-lifecycle-step">
                <span className="gw-step-number" aria-hidden="true">2</span><div className="gw-lifecycle-copy"><h3>Revoke credential</h3><p>{homed === 0 ? "Permanently stop this gateway from authenticating again." : "Available after the authoritative homed-device count reaches zero."}</p></div>
                <div className="gw-lifecycle-action">{homed !== 0 && <Badge tone="neutral">Blocked</Badge>}{canRevoke && <Button size="sm" variant="danger" disabled={busy} onClick={() => openDialog("revoke")}>Revoke gateway</Button>}</div>
              </section>}
              {node.status === "revoked" && <>
                <section className="gw-lifecycle-step"><span className="gw-step-number" aria-hidden="true">2</span><div className="gw-lifecycle-copy"><h3>Restore cascaded devices</h3><p>Move eligible cascade-revoked devices to an active replacement. Deliberately revoked devices stay revoked.</p>{canRestoreRevoked && !destinations.length && <p>No active replacement gateway is available.</p>}</div><div className="gw-lifecycle-action">{canRestoreRevoked && destinations.length > 0 && <Button size="sm" disabled={busy} onClick={() => openDialog("restore")}>Restore cascaded devices</Button>}</div></section>
                <section className="gw-lifecycle-step gw-lifecycle-danger"><span className="gw-step-number" aria-hidden="true">3</span><div className="gw-lifecycle-copy"><h3>Delete gateway record</h3><p>Permanently remove the revoked record. Audit evidence remains.</p></div><div className="gw-lifecycle-action">{canDeleteRevoked && <Button size="sm" variant="danger" disabled={busy} onClick={() => openDialog("delete")}>Delete gateway record</Button>}</div></section>
              </>}
            </div>
            {!canManage && !canTransfer && !canRestore && <p className="gw-stage-context">You have read-only access to this gateway.</p>}
          </>}
          </ResourceSummary>
        </section>
      </div>

      {dialog === "rename" && (
        <Modal title="Rename gateway" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !draft.trim()} onClick={() => void rename()}>Save name</Button></>}>
          <ErrorText>{error}</ErrorText>
          <p className="mb-3 text-cell text-ink-tertiary">The name is display metadata. Endpoint and issued device configurations are unchanged.</p>
          <Field label="Gateway name"><Input autoFocus value={draft} onChange={(event) => setDraft(event.target.value)} /></Field>
        </Modal>
      )}

      {dialog === "transfer" && (
        <Modal title="Move homed devices" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !target} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/nodes/{nodeId}/transfer-devices", { params: { path: { orgId: activeOrgId, nodeId: gatewayId } }, body: { target_node_id: target } }), "Could not move the devices.", (data) => `${requiredImpactCount(data, "moved")} moved. ${requiredImpactCount(data, "needs_reissue")} require a configuration re-import. The old gateway remains active until you revoke it separately.`)}>Move devices</Button></>}>
          <ErrorText>{error}</ErrorText>
          <p className="mb-3 text-cell text-ink-tertiary">Move {homed} device{homed === 1 ? "" : "s"} before revocation. Addresses remain allocated; device owners must re-import new profiles before reconnecting. A different Site changes the policy context those devices inherit.</p>
          <Field label="Destination gateway"><Select value={target} onChange={(event) => setTarget(event.target.value)}><option value="">Choose an active gateway…</option>{destinations.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}{state.siteNames[candidate.site_id ?? ""] ? `, ${state.siteNames[candidate.site_id!]}` : ""}</option>)}</Select></Field>
          {targetNode && node.site_id && targetNode.site_id && node.site_id !== targetNode.site_id && <p className="mt-3 text-cell text-warn">Cross-site move: policy scope may grant or remove access. Review the device rules after transfer.</p>}
        </Modal>
      )}

      {dialog === "revoke" && (
        <Modal title="Revoke gateway permanently?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke", { params: { path: { orgId: activeOrgId, nodeId: gatewayId } } }), "Could not revoke the gateway.", () => "Gateway revoked. Its credential cannot renew and it cannot be reactivated; enroll a replacement to recover service.")}>Revoke gateway</Button></>}>
          <ErrorText>{error}</ErrorText>
          <p className="text-cell text-ink-tertiary">The bounded inventory reports zero homed active/pending devices. The server checks again transactionally. Revocation is permanent; recovery is a newly enrolled gateway.</p>
        </Modal>
      )}

      {dialog === "restore" && (
        <Modal title="Restore cascaded devices" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !target} onClick={() => void mutate(() => api.POST("/api/v1/organizations/{orgId}/nodes/{nodeId}/restore-devices", { params: { path: { orgId: activeOrgId, nodeId: gatewayId } }, body: { target_node_id: target } }), "Could not restore this gateway's devices.", (data) => `${requiredImpactCount(data, "restored")} cascade-revoked devices restored. ${requiredImpactCount(data, "readdressed")} require a new configuration because their original address was unavailable.`)}>Restore devices</Button></>}>
          <ErrorText>{error}</ErrorText>
          <p className="mb-3 text-cell text-ink-tertiary">Only devices revoked as a cascade from this gateway are eligible. Deliberately revoked devices stay revoked.</p>
          <Field label="Replacement gateway"><Select value={target} onChange={(event) => setTarget(event.target.value)}><option value="">Choose an active replacement…</option>{destinations.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}</option>)}</Select></Field>
        </Modal>
      )}

      {dialog === "delete" && (
        <Modal title="Delete revoked gateway record?" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void (async () => { const removed = await mutate(() => api.DELETE("/api/v1/organizations/{orgId}/nodes/{nodeId}", { params: { path: { orgId: activeOrgId, nodeId: gatewayId } } }), "Could not delete the gateway.", () => "Gateway deleted."); if (removed) navigate("/gateways", { replace: true }); })()}>Delete permanently</Button></>}>
          <ErrorText>{error}</ErrorText>
          <p className="text-cell text-ink-tertiary">This permanently removes {node.name}, its node telemetry and server credential records, and invalidates the enrollment token that created it. There is no recovery. Audit Log retains the gateway identity.</p>
        </Modal>
      )}
    </div>
  );
}
