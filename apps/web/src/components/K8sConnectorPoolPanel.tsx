import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "../kubernetes-operations.css";
import "../resource-summary.css";

import {
  api,
  apiErrorCode,
  apiErrorMessage,
  type K8sConnectorPoolConfiguration,
  type Node,
  type Role,
} from "../lib/api";
import { can } from "../lib/rbac";
import { Badge, Button, ErrorText, Input, Modal } from "./ui";
import { NetworkDetailList } from "./NetworkDetailList";

type DraftMember = { selected: boolean; priority: number };
type ConnectorPoolCluster = { id: string; siteId: string; connectorNodeId: string | null };

type ConnectorPoolProps = {
  orgId: string;
  cluster: ConnectorPoolCluster;
  nodes: Node[] | null;
  role: Role | undefined;
  emailVerified: boolean;
  onChanged: () => Promise<void>;
};

export function K8sConnectorPoolPanel(props: ConnectorPoolProps) {
  return <ConnectorPoolForScope key={`${props.orgId}:${props.cluster.id}:${props.cluster.siteId}:${props.role ?? "unknown"}:${props.emailVerified}`} {...props} />;
}

function ConnectorPoolForScope({ orgId, cluster, nodes, role, emailVerified, onChanged }: ConnectorPoolProps) {
  const canView = can(role, "k8s_ha:view");
  const canManage = emailVerified && can(role, "k8s_ha:manage");
  const [configuration, setConfiguration] = useState<K8sConnectorPoolConfiguration | null>(null);
  const [state, setState] = useState<"loading" | "unconfigured" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<Record<string, DraftMember>>({});
  const alive = useRef(true);
  const requestSequence = useRef(0);
  const mutationBusy = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; requestSequence.current++; }; }, []);

  const candidates = useMemo(() => nodes?.filter((node) => node.status === "active" && node.site_id === cluster.siteId && node.endpoint?.trim()) ?? [], [cluster.siteId, nodes]);
  const initialConnectorID = cluster.connectorNodeId ?? configuration?.active_node_id ?? null;

  const load = useCallback(async () => {
    if (!canView || !alive.current) return;
    const request = ++requestSequence.current;
    setState("loading");
    setConfiguration(null);
    setError(null);
    try {
      const { data, error: readError } = await api.GET("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
        params: { path: { orgId, clusterId: cluster.id } },
      });
      if (!alive.current || request !== requestSequence.current) return;
      if (readError && apiErrorCode(readError) === "connector_pool_not_found") {
        setConfiguration(null);
        setState("unconfigured");
        return;
      }
      if (readError || data === undefined) {
        setState("error");
        setError(apiErrorMessage(readError, "Could not read connector-pool configuration. No pool state is inferred."));
        return;
      }
      setConfiguration(data);
      setState("ready");
    } catch {
      if (!alive.current || request !== requestSequence.current) return;
      setState("error");
      setError("Could not reach the API. Connector-pool configuration is unavailable.");
    }
  }, [canView, cluster.id, orgId]);

  useEffect(() => { void load(); }, [load]);

  function openEditor() {
    if (!canManage || busy || nodes === null || (state !== "ready" && state !== "unconfigured")) return;
    const memberByID = new Map(configuration?.members.map((member) => [member.node_id, member]) ?? []);
    const next: Record<string, DraftMember> = {};
    for (const node of candidates) {
      const member = memberByID.get(node.id);
      next[node.id] = { selected: member !== undefined || node.id === initialConnectorID, priority: member?.admin_priority ?? (node.id === initialConnectorID ? 100 : 90) };
    }
    setDraft(next);
    setError(null);
    setEditing(true);
  }

  async function save() {
    if (!alive.current || !canManage || mutationBusy.current || nodes === null || (state !== "ready" && state !== "unconfigured")) return;
    const members = Object.entries(draft)
      .filter(([, member]) => member.selected)
      .map(([node_id, member]) => ({ node_id, admin_priority: member.priority }));
    if (members.length === 0) return setError("Select the current connector and at least one eligible gateway.");
    if (members.some((member) => !Number.isInteger(member.admin_priority) || member.admin_priority < -2147483648 || member.admin_priority > 2147483647)) {
      return setError("Each priority must be a whole number in the supported range.");
    }
    mutationBusy.current = true;
    setBusy(true);
    setError(null);
    try {
      const { error: writeError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
        params: { path: { orgId, clusterId: cluster.id } },
        body: {
          members,
          ...(configuration?.membership_epoch_known && configuration.membership_epoch !== null ? { expected_membership_epoch: configuration.membership_epoch } : {}),
        },
      });
      if (!alive.current) return;
      if (writeError) return setError(apiErrorMessage(writeError, "Could not save the connector pool."));
      setEditing(false);
      await Promise.all([load(), onChanged()]);
    } catch {
      if (alive.current) setError("Could not save the connector pool. Refresh its configuration before retrying.");
    } finally {
      mutationBusy.current = false;
      if (alive.current) setBusy(false);
    }
  }

  if (!canView) return null;
  const configuredMembers = configuration?.members ?? [];
  const nameOf = (nodeId: string) => nodes?.find(node => node.id === nodeId)?.name ?? nodeId;

  return <section aria-labelledby="connector-pool-heading" className="k8s-operation-panel k8s-pool-panel">
    <header className="k8s-operation-heading"><h3 id="connector-pool-heading">Connector pool</h3><div className="k8s-operation-actions">{state === "ready" && <Badge tone="neutral">Configured</Badge>}{canManage && nodes !== null && state === "ready" && <Button size="sm" variant="ghost" disabled={busy} onClick={openEditor}>Edit connector pool</Button>}{canManage && nodes !== null && state === "unconfigured" && candidates.length > 0 && <Button size="sm" disabled={!initialConnectorID || busy} onClick={openEditor}>Configure connector pool</Button>}</div></header>
    {state === "loading" && <p role="status" className="k8s-operation-note">Reading connector-pool configuration…</p>}
    {state === "error" && <div className="k8s-operation-status"><span>Configuration unavailable</span><Button size="sm" variant="ghost" onClick={() => void load()}>Retry</Button></div>}
    {state === "unconfigured" && <p className="k8s-operation-note">{initialConnectorID ? "Direct connector. Configure membership before requesting fenced HA." : "Select a direct connector before configuring a pool."}</p>}
    {(state === "ready" || state === "unconfigured") && (nodes === null ? <p role="status" className="k8s-operation-warning">Gateway inventory is unavailable. Candidate selection is withheld.</p> : candidates.length === 0 && <p role="status" className="k8s-operation-warning">No active same-site gateways have a reported endpoint.</p>)}
    {state === "ready" && configuration && <>
      <dl className="k8s-operation-facts tnx-resource-facts"><div><dt>Active connector</dt><dd>{nameOf(configuration.active_node_id)}</dd></div><div><dt>Preferred connector</dt><dd>{nameOf(configuration.preferred_node_id)}</dd></div></dl>
      <NetworkDetailList label="Pool members" items={configuredMembers} searchText={member => `${nameOf(member.node_id)} ${member.admin_priority}`} renderItem={member => <li key={member.node_id} className="k8s-pool-member"><span>{nameOf(member.node_id)}</span><span className="k8s-operation-muted">Priority {member.admin_priority}</span></li>} />
      <details className="k8s-operation-disclosure"><summary>Membership details</summary><div><dl className="k8s-operation-facts tnx-resource-facts"><div><dt>Generation</dt><dd>{configuration.generation}</dd></div><div><dt>Membership epoch</dt><dd>{configuration.membership_epoch_known ? configuration.membership_epoch ?? "Unavailable" : "Unavailable"}</dd></div></dl><p>Priority affects later failover selection. Membership edits never move current ownership or enable fenced HA.</p></div></details>
    </>}
    {!editing && <ErrorText>{error}</ErrorText>}
    {editing && canManage && <Modal title="Configure connector pool" placement="right" size="wide" showClose onDismiss={busy ? () => {} : () => setEditing(false)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setEditing(false)}>Cancel</Button><Button disabled={busy || nodes === null} onClick={() => void save()}>{busy ? "Saving…" : "Save pool"}</Button></>}>
      <div className="k8s-pool-editor">
        <p className="k8s-operation-note">Keep the current connector and add same-site standbys. Saving membership does not move ownership or enable fenced HA.</p>
        <ErrorText>{error}</ErrorText>
        <div className="k8s-pool-candidate-columns" aria-hidden="true"><span>Gateway</span><span>Priority</span></div>
        <NetworkDetailList label="Connector candidates" items={candidates} searchText={node => `${node.name} ${node.id} ${draft[node.id]?.priority ?? ""}`} renderItem={node => {
            const member = draft[node.id] ?? { selected: false, priority: 90 };
            const required = node.id === initialConnectorID;
            return <li key={node.id} className="k8s-pool-candidate">
              <input type="checkbox" aria-label={`Include ${node.name}`} checked={member.selected} disabled={required || busy} onChange={(event) => setDraft((current) => ({ ...current, [node.id]: { ...member, selected: event.target.checked } }))} />
              <div className="k8s-pool-candidate-name"><strong>{node.name}</strong><span>{required ? "Current connector · required" : "Standby candidate"}</span></div>
              <Input aria-label={`${node.name} priority`} type="number" disabled={!member.selected || busy} value={member.priority} onChange={(event) => setDraft((current) => ({ ...current, [node.id]: { ...member, priority: Number(event.target.value) } }))} />
            </li>;
          }} />
        <details className="k8s-operation-disclosure"><summary>Selection and concurrency</summary><div><p>Only active same-site gateways with a reported endpoint are listed. The server validates their keys and endpoints.</p><p>No gateway is promoted by this form. A failed or concurrent save leaves the existing active owner unchanged.</p></div></details>
      </div>
    </Modal>}
  </section>;
}
