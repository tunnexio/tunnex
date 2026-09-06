import { useCallback, useEffect, useMemo, useState } from "react";

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

type DraftMember = { selected: boolean; priority: number };
type ConnectorPoolCluster = { id: string; siteId: string; connectorNodeId: string | null };

export function K8sConnectorPoolPanel({
  orgId,
  cluster,
  nodes,
  role,
  emailVerified,
  onChanged,
}: {
  orgId: string;
  cluster: ConnectorPoolCluster;
  nodes: Node[] | null;
  role: Role | undefined;
  emailVerified: boolean;
  onChanged: () => Promise<void>;
}) {
  const canView = can(role, "k8s_ha:view");
  const canManage = emailVerified && can(role, "k8s_ha:manage");
  const [configuration, setConfiguration] = useState<K8sConnectorPoolConfiguration | null>(null);
  const [state, setState] = useState<"loading" | "unconfigured" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<Record<string, DraftMember>>({});

  const candidates = useMemo(() => nodes?.filter((node) => node.status === "active" && node.site_id === cluster.siteId && node.endpoint?.trim()) ?? [], [cluster.siteId, nodes]);
  const initialConnectorID = cluster.connectorNodeId ?? configuration?.active_node_id ?? null;

  const load = useCallback(async () => {
    if (!canView) return;
    setState("loading");
    setError(null);
    const { data, error: readError } = await api.GET("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
      params: { path: { orgId, clusterId: cluster.id } },
    });
    if (readError) {
      if (apiErrorCode(readError) === "connector_pool_not_found") {
        setConfiguration(null);
        setState("unconfigured");
        return;
      }
      setConfiguration(null);
      setState("error");
      setError(apiErrorMessage(readError, "Could not read connector-pool configuration. No pool state is inferred."));
      return;
    }
    setConfiguration(data);
    setState("ready");
  }, [canView, cluster.id, orgId]);

  useEffect(() => { void load(); }, [load]);

  function openEditor() {
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
    const members = Object.entries(draft)
      .filter(([, member]) => member.selected)
      .map(([node_id, member]) => ({ node_id, admin_priority: member.priority }));
    if (members.length === 0) return setError("Select the current connector and at least one eligible gateway.");
    if (members.some((member) => !Number.isInteger(member.admin_priority) || member.admin_priority < -2147483648 || member.admin_priority > 2147483647)) {
      return setError("Each priority must be a whole number in the supported range.");
    }
    setBusy(true);
    try {
      const { error: writeError } = await api.PUT("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
        params: { path: { orgId, clusterId: cluster.id } },
        body: {
          members,
          ...(configuration?.membership_epoch_known && configuration.membership_epoch !== null ? { expected_membership_epoch: configuration.membership_epoch } : {}),
        },
      });
      if (writeError) return setError(apiErrorMessage(writeError, "Could not save the connector pool."));
      setEditing(false);
      await Promise.all([load(), onChanged()]);
    } finally {
      setBusy(false);
    }
  }

  if (!canView) return null;
  const configuredMembers = configuration?.members ?? [];

  return <section aria-labelledby="connector-pool-heading" className="border-t border-line pt-4">
    <div className="mb-3 flex items-center justify-between gap-3"><h3 id="connector-pool-heading" className="text-sm font-semibold text-ink-heading">Connector pool</h3>{state === "ready" && <Badge tone="neutral">configured</Badge>}</div>
    {error && <ErrorText>{error}</ErrorText>}
    {state === "loading" && <p className="text-micro text-ink-faint">Reading connector-pool configuration…</p>}
    {state === "error" && <Button size="sm" variant="ghost" onClick={() => void load()}>Retry</Button>}
    {state === "unconfigured" && <div className="space-y-2 text-micro text-ink-tertiary">
      <p>This cluster still has one direct connector. Configuring a pool keeps that connector active and preferred; it does not switch traffic or enable fenced HA.</p>
      {nodes === null ? <p className="text-amber-200">Gateway inventory is unavailable, so no candidate set is shown.</p> : candidates.length === 0 ? <p className="text-amber-200">No active same-site gateways are available for this cluster.</p> : canManage && <Button size="sm" variant="ghost" disabled={!initialConnectorID} onClick={openEditor}>Configure connector pool</Button>}
      {!initialConnectorID && <p className="text-amber-200">Select a direct connector before configuring a pool.</p>}
    </div>}
    {state === "ready" && configuration && <div className="space-y-2 text-micro text-ink-tertiary">
      <p>generation {configuration.generation} · active {configuration.active_node_id.slice(0, 8)} · preferred {configuration.preferred_node_id.slice(0, 8)}</p>
      <ul className="space-y-1 rounded-input border border-line bg-surface-inset p-2">
        {configuredMembers.map((member) => <li key={member.node_id} className="flex justify-between gap-3"><span>{nodes?.find((node) => node.id === member.node_id)?.name ?? member.node_id}</span><span className="font-mono text-ink-faint">priority {member.admin_priority}</span></li>)}
      </ul>
      <p>Membership epoch {configuration.membership_epoch_known ? configuration.membership_epoch : "unavailable"}. Priority affects a later failover selection only; it never moves current ownership.</p>
      {canManage && nodes !== null && <Button size="sm" variant="ghost" onClick={openEditor}>Edit connector pool</Button>}
    </div>}
    {editing && <Modal title="Configure connector pool" size="wide" onDismiss={busy ? () => {} : () => setEditing(false)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setEditing(false)}>Cancel</Button><Button disabled={busy} onClick={() => void save()}>{busy ? "Saving…" : "Save pool"}</Button></>}>
      <div className="space-y-4 text-sm text-ink-tertiary">
        <p>The current direct connector stays active and preferred. Add same-site gateways as standbys. This only changes desired membership; request fenced HA separately after the pool is configured.</p>
        <div className="space-y-2">
          {candidates.map((node) => {
            const member = draft[node.id] ?? { selected: false, priority: 90 };
            const required = node.id === initialConnectorID;
            return <div key={node.id} className="grid grid-cols-[auto_1fr_8rem] items-center gap-3 rounded-input border border-line p-3">
              <input type="checkbox" aria-label={`Include ${node.name}`} checked={member.selected} disabled={required || busy} onChange={(event) => setDraft((current) => ({ ...current, [node.id]: { ...member, selected: event.target.checked } }))} />
              <div><strong className="text-ink-heading">{node.name}</strong><p className="text-micro text-ink-faint">{required ? "Current active and preferred connector" : "Standby candidate; the server validates its key and endpoint"}</p></div>
              <Input aria-label={`${node.name} priority`} type="number" disabled={!member.selected || busy} value={member.priority} onChange={(event) => setDraft((current) => ({ ...current, [node.id]: { ...member, priority: Number(event.target.value) } }))} />
            </div>;
          })}
        </div>
        <p className="text-micro text-ink-faint">No gateway is promoted by this form. A failed or concurrent save leaves the existing active owner unchanged.</p>
      </div>
    </Modal>}
  </section>;
}
