import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorText,
  Field,
  Input,
  Loading,
  Modal,
  PageHeader,
  Select,
} from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
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
    <div>
      <dt className="text-micro uppercase tracking-wide text-ink-faint">{label}</dt>
      <dd className="mt-1 break-words text-cell text-ink-body">{children}</dd>
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

  if (state.kind === "loading") return <Card><Loading label="Loading gateway workspace…" /></Card>;
  if (state.kind === "error") return <LoadRetry error={state.error ?? "Could not load gateways."} onRetry={reload} />;
  if (!node || !row) {
    return (
      <div className="space-y-5">
        <PageHeader title="Gateway not found" subtitle="The authoritative Gateway inventory does not contain this identifier." />
        <Card><EmptyState action={<Link className="text-accent-400 hover:underline" to="/gateways">Return to Gateways</Link>}>It may have been deleted or belong to another organization.</EmptyState></Card>
      </div>
    );
  }

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
    <div className="space-y-5">
      <Link className="inline-flex text-cell text-ink-tertiary hover:text-ink-heading" to="/gateways">← Gateway inventory</Link>
      <PageHeader
        title={node.name}
        subtitle={`${row.siteName ?? "No site assigned"} · ${node.last_seen_at ? `seen ${relativeAge(node.last_seen_at)}` : "never connected"}`}
        actions={
          <div className="flex items-center gap-2">
            <Badge tone={status === "healthy" ? "ok" : status === "degraded" ? "warn" : "neutral"}>{statusLabel}</Badge>
            {canManage && node.status !== "revoked" && (
              <Button size="sm" variant="ghost" onClick={() => { setDraft(node.name); openDialog("rename"); }}>Rename</Button>
            )}
          </div>
        }
      />
      <nav aria-label="Gateway detail sections" className="border-b border-white/10">
        <div className="flex min-w-max gap-1 overflow-x-auto">
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={tab === item.id ? "page" : undefined}
              onClick={() => selectTab(item.id)}
              className={`min-h-10 border-b-2 px-3 py-2 text-sm ${tab === item.id ? "border-accent-400 text-ink-heading" : "border-transparent text-ink-tertiary hover:text-ink-heading"}`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </nav>
      {!dialog && <ErrorText>{error}</ErrorText>}
      {notice && <div role="status" className="rounded-card border border-ok/30 bg-ok/5 p-3 text-cell text-ink-body">{notice}</div>}

      {tab === "overview" && (
        <Card>
            <div>
              <h2 className="text-heading font-semibold text-ink-heading">Gateway overview</h2>
              <p className="mt-1 text-cell text-ink-tertiary">Identity, placement, and the latest reported runtime.</p>
            </div>
            <dl className="mt-4 grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Lifecycle"><Badge tone={node.status === "revoked" ? "neutral" : "ok"}>{node.status}</Badge></Fact>
              <Fact label="Site">{row.siteName ?? "No site assigned"}</Fact>
              <Fact label="Endpoint">{node.endpoint ?? "Not reported"}</Fact>
              <Fact label="Agent version">{node.agent_version || "Not reported"}</Fact>
              <Fact label="Enrolled">{node.enrolled_at ? new Date(node.enrolled_at).toLocaleString() : "Not reported"}</Fact>
              <Fact label="Last seen">{node.last_seen_at ? `${relativeAge(node.last_seen_at)} (${new Date(node.last_seen_at).toLocaleString()})` : "Never connected"}</Fact>
            </dl>
            <div className="mt-5 border-t border-white/[.08] pt-3">
              <h3 className="text-micro font-medium uppercase tracking-wide text-ink-faint">Related</h3>
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                <Link className="flex min-h-10 items-center justify-between rounded-md border border-white/[.08] px-3 text-cell text-ink-body hover:bg-white/[.04] hover:text-ink-heading" to="/sites"><span>Site topology</span><span aria-hidden="true">›</span></Link>
                <Link className="flex min-h-10 items-center justify-between rounded-md border border-white/[.08] px-3 text-cell text-ink-body hover:bg-white/[.04] hover:text-ink-heading" to={`/devices?gateway=${gatewayId}`}><span>Homed devices{homed === null ? "" : ` (${homed})`}</span><span aria-hidden="true">›</span></Link>
                <Link className="flex min-h-10 items-center justify-between rounded-md border border-white/[.08] px-3 text-cell text-ink-body hover:bg-white/[.04] hover:text-ink-heading" to={`/audit?q=${encodeURIComponent(node.name)}`}><span>Audit evidence</span><span aria-hidden="true">›</span></Link>
              </div>
            </div>
          </Card>
      )}

      {tab === "health" && (
        <Card className="overflow-hidden !p-0">
          <div className="grid gap-0 md:grid-cols-2">
          <section className="border-b border-white/[.08] p-4 md:border-r">
            <h2 className="text-heading font-semibold text-ink-heading">Connectivity</h2>
            <p className="mt-3 text-cell text-ink-body">{node.last_seen_at ? `Last control-plane observation ${relativeAge(node.last_seen_at)}.` : "This gateway has never reported a successful connection."}</p>
            <p className="mt-2 text-micro text-ink-tertiary">Lifecycle and connectivity are separate: an active credential does not prove a fresh handshake.</p>
          </section>
          <section className="border-b border-white/[.08] p-4">
            <h2 className="text-heading font-semibold text-ink-heading">Policy and transit</h2>
            <div className="mt-3"><Badge tone={row.health ? "warn" : node.status === "revoked" ? "neutral" : "ok"}>{row.health?.label ?? (node.status === "revoked" ? "not evaluated" : "healthy")}</Badge></div>
            {groupNotes([row]).map((note) => <p key={note} className="mt-2 text-cell text-ink-tertiary">{note}</p>)}
          </section>
          <section className="p-4 md:border-r md:border-white/[.08]">
            <h2 className="text-heading font-semibold text-ink-heading">OpenVPN</h2>
            <p className="mt-3 text-cell text-ink-body">{row.ovpnHealth ? row.ovpnHealth.replace(/^ovpn_/, "").replace(/_/g, " ") : "No OpenVPN failure reported."}</p>
            <p className="mt-2 text-micro text-ink-tertiary">A separate service axis from WireGuard policy health.</p>
          </section>
          <section className="border-t border-white/[.08] p-4 md:border-t-0">
            <h2 className="text-heading font-semibold text-ink-heading">Egress</h2>
            <p className="mt-3 text-cell text-ink-body">{gatewayEgressDetail(row)}</p>
          </section>
          </div>
        </Card>
      )}

      {tab === "lifecycle" && (
        <Card className="overflow-hidden !p-0">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[.08] px-4 py-3">
            <div>
              <h2 className="text-heading font-semibold text-ink-heading">Gateway lifecycle</h2>
              <p className="mt-1 text-cell text-ink-tertiary">Move dependent devices before permanently retiring this gateway.</p>
            </div>
            <Badge tone={node.status === "revoked" ? "neutral" : "ok"}>{node.status}</Badge>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/[.08] px-4 py-3">
            <div className="flex min-w-0 items-start gap-3">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-white/10 text-micro font-semibold text-ink-tertiary">1</span>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-cell font-semibold text-ink-heading">Homed devices</h3>
                  {homed === 0 && <Badge tone="ok">Complete</Badge>}
                  {homed === null && <Badge tone="neutral">Unavailable</Badge>}
                </div>
                <p className="mt-1 text-cell text-ink-tertiary">
                  {homed === null
                    ? "Impact count unavailable. Dependent actions are withheld."
                    : homed === 0
                      ? "No active or pending devices depend on this gateway."
                      : `${homed} active or pending device${homed === 1 ? " depends" : "s depend"} on this gateway.`}
                </p>
              </div>
            </div>
            {node.status === "active" && homed !== null && homed > 0 && canTransfer && (
              <Button size="sm" onClick={() => openDialog("transfer")}>Move devices</Button>
            )}
          </div>

          {node.status === "active" && (
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 px-4 py-3">
              <div className="flex min-w-0 items-start gap-3">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-white/10 text-micro font-semibold text-ink-tertiary">2</span>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-cell font-semibold text-ink-heading">Revoke credential</h3>
                    {homed !== 0 && <Badge tone="neutral">Blocked</Badge>}
                  </div>
                  <p className="mt-1 text-cell text-ink-tertiary">
                    {homed === 0
                      ? "Permanently stop this gateway from authenticating again."
                      : "Available after the authoritative homed-device count reaches zero."}
                  </p>
                </div>
              </div>
              {canRevoke && <Button size="sm" variant="danger" onClick={() => openDialog("revoke")}>Revoke gateway</Button>}
            </div>
          )}

          {node.status === "revoked" && (
            <>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/[.08] px-4 py-3">
                <div>
                  <h3 className="text-cell font-semibold text-ink-heading">Restore cascaded devices</h3>
                  <p className="mt-1 text-cell text-ink-tertiary">Move eligible cascade-revoked devices to a live replacement gateway.</p>
                </div>
                {canRestoreRevoked && destinations.length > 0 && <Button size="sm" onClick={() => openDialog("restore")}>Restore cascaded devices</Button>}
              </div>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 px-4 py-3">
                <div>
                  <h3 className="text-cell font-semibold text-danger">Delete gateway record</h3>
                  <p className="mt-1 text-cell text-ink-tertiary">Permanently remove the revoked record. Audit evidence remains.</p>
                </div>
                {canDeleteRevoked && <Button size="sm" variant="danger" onClick={() => openDialog("delete")}>Delete gateway record</Button>}
              </div>
            </>
          )}
        </Card>
      )}

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
          <p className="mb-3 text-cell text-ink-tertiary">Move {homed} device{homed === 1 ? "" : "s"} before revocation. Addresses remain allocated. A different Site changes the policy context those devices inherit.</p>
          <Field label="Destination gateway"><Select value={target} onChange={(event) => setTarget(event.target.value)}><option value="">Choose a live gateway…</option>{destinations.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}{state.siteNames[candidate.site_id ?? ""] ? ` — ${state.siteNames[candidate.site_id!]}` : ""}</option>)}</Select></Field>
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
          <Field label="Replacement gateway"><Select value={target} onChange={(event) => setTarget(event.target.value)}><option value="">Choose a live replacement…</option>{destinations.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}</option>)}</Select></Field>
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
