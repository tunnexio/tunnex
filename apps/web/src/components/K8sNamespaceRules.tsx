import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import {
  namespaceIneligibleReason,
  namespaceRulePreview,
  namespaceRuleStatus,
  ruleableNamespaces,
  type K8sNamespaceRule,
  type ServiceRow,
} from "../lib/k8sview";
import { Badge, Button, ErrorText, Field, Input, Modal, Select } from "./ui";

// K8N-4 — "Expose every Service in a namespace…".
//
// A namespace rule exposes every Service of ONE namespace, now and as Services are added, and withdraws
// the exposures it made when their Service is gone. It never grants access. The consequences are stated
// in the dialog BEFORE the administrator confirms, in the dialog that removes a rule too.

type InventoryService = components["schemas"]["K8sInventoryService"];
type InventoryPage = components["schemas"]["K8sInventoryPage"];
type ExposedRow = Pick<ServiceRow, "namespace" | "name" | "protocol" | "ports">;

const RULES_PATH = "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/namespace-rules" as const;

export function K8sNamespaceRulesPanel({
  orgId,
  cluster,
  canManage,
  exposed,
  onChanged,
  fixtureInventory,
}: {
  orgId: string;
  cluster: { id: string; name: string; vipRange: string };
  canManage: boolean;
  exposed: ExposedRow[];
  /** Reload the page's Services after a rule was created or removed. */
  onChanged: () => void | Promise<void>;
  fixtureInventory?: InventoryPage;
}) {
  const [rules, setRules] = useState<K8sNamespaceRule[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<K8sNamespaceRule | null>(null);
  const epoch = useRef(0);

  const load = useCallback(async () => {
    const current = ++epoch.current;
    const result = await loadOne(() => api.GET(RULES_PATH, { params: { path: { orgId, clusterId: cluster.id } } }));
    if (current !== epoch.current) return;
    if (!result.ok) {
      setError(result.error || "Could not read this cluster's namespace rules.");
      return;
    }
    setError(null);
    setRules(Array.isArray(result.data) ? result.data : []);
  }, [orgId, cluster.id]);

  useEffect(() => {
    setRules(null);
    void load();
    return () => { epoch.current += 1; };
  }, [load]);

  async function changed() {
    await load();
    await onChanged();
  }

  return (
    <section className="kubernetes-namespace-rules" aria-label="Namespace rules">
      <div className="kubernetes-list-toolbar">
        <div className="kubernetes-cell-stack">
          <strong>Namespace rules</strong>
          <span className="kubernetes-muted">Expose every Service in a namespace, now and as Services are added. A rule never grants access.</span>
        </div>
        {canManage && <Button size="sm" variant="ghost" onClick={() => setCreating(true)}>Expose every Service in a namespace…</Button>}
      </div>
      {error && <div role="alert" className="kubernetes-read-warning"><span>{error}</span><Button variant="ghost" size="sm" onClick={() => void load()}>Retry</Button></div>}
      {rules !== null && rules.length === 0 && !error && <p className="kubernetes-muted">No namespace rule. Services in this cluster are exposed one at a time.</p>}
      {rules !== null && rules.length > 0 && (
        <ul className="kubernetes-namespace-rule-list">
          {rules.map((rule) => {
            const status = namespaceRuleStatus(rule);
            return (
              <li key={rule.id} data-status={rule.status}>
                <div className="kubernetes-cell-stack">
                  <span><strong>{rule.namespace}</strong> <Badge tone={status.tone}>{status.label}</Badge></span>
                  <span className="kubernetes-muted">
                    {rule.exposed_services} Service{rule.exposed_services === 1 ? "" : "s"} · {rule.exposed_ports} port{rule.exposed_ports === 1 ? "" : "s"} exposed by this rule
                    {rule.last_reconciled_at ? ` · last applied ${new Date(rule.last_reconciled_at).toLocaleString()}` : ""}
                  </span>
                  {status.message && <span className={status.tone === "ok" ? "kubernetes-muted" : "text-warn"} role={status.tone === "ok" ? undefined : "status"}>{status.message}</span>}
                </div>
                {canManage && <Button size="sm" variant="ghost" onClick={() => setRemoving(rule)}>Remove rule</Button>}
              </li>
            );
          })}
        </ul>
      )}
      {canManage && creating && (
        <ExposeNamespaceModal
          orgId={orgId}
          cluster={cluster}
          exposed={exposed}
          existingRules={rules ?? []}
          fixtureInventory={fixtureInventory}
          onClose={() => setCreating(false)}
          onDone={changed}
        />
      )}
      {canManage && removing && (
        <RemoveNamespaceRuleModal orgId={orgId} clusterId={cluster.id} rule={removing} onClose={() => setRemoving(null)} onDone={changed} />
      )}
    </section>
  );
}

export function ExposeNamespaceModal({
  orgId,
  cluster,
  exposed,
  existingRules,
  fixtureInventory,
  onClose,
  onDone,
}: {
  orgId: string;
  cluster: { id: string; name: string; vipRange: string };
  exposed: ExposedRow[];
  existingRules: Pick<K8sNamespaceRule, "namespace">[];
  fixtureInventory?: InventoryPage;
  onClose: () => void;
  onDone: () => void | Promise<void>;
}) {
  // null = still reading; "unavailable" = no current report (the rule can still be created: it waits).
  const [inventory, setInventory] = useState<InventoryService[] | "unavailable" | null>(fixtureInventory ? fixtureInventory.items : null);
  const [inventoryNote, setInventoryNote] = useState<string | null>(null);
  const [namespace, setNamespace] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (fixtureInventory) return;
    let live = true;
    void (async () => {
      const items: InventoryService[] = [];
      let cursor: string | undefined;
      // The report holds at most 500 Services, 100 a page.
      for (let page = 0; page < 6; page += 1) {
        const result = await loadOne(() => api.GET(
          "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/inventory",
          { params: { path: { orgId, clusterId: cluster.id }, query: { cursor, limit: 100 } } },
        ));
        if (!live) return;
        if (!result.ok || !result.data || !Array.isArray(result.data.items)) {
          setInventory("unavailable");
          setInventoryNote(result.ok ? null : result.error || null);
          return;
        }
        items.push(...result.data.items);
        if (!result.data.next_cursor) break;
        cursor = result.data.next_cursor;
      }
      setInventory(items);
    })();
    return () => { live = false; };
  }, [orgId, cluster.id, fixtureInventory]);

  const reported = inventory !== null && inventory !== "unavailable";
  const namespaces = useMemo(() => (reported ? ruleableNamespaces(inventory, existingRules) : []), [reported, inventory, existingRules]);
  const ns = namespace.trim();
  const taken = existingRules.some((rule) => rule.namespace === ns);
  const reason = ns === "" ? null : taken ? `This cluster already has a namespace rule for ${ns}.` : namespaceIneligibleReason(ns);
  const preview = reported && ns !== "" && reason === null ? namespaceRulePreview(inventory, exposed, ns) : null;
  const ready = ns !== "" && reason === null && understood && !busy && inventory !== null;

  async function submit() {
    if (!ready) return;
    setBusy(true);
    setErr(null);
    try {
      const { data, error } = await api.POST(RULES_PATH, { params: { path: { orgId, clusterId: cluster.id } }, body: { namespace: ns } });
      if (error || !data) return setErr(apiErrorMessage(error, "Could not create the namespace rule."));
      await onDone();
      const status = namespaceRuleStatus(data);
      // The rule exists either way. If its first pass did not apply, keep the dialog open and say why.
      if (data.status !== "applied" && status.message) return setErr(`The rule was created but is not applied yet. ${status.message}`);
      onClose();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      placement="right" showClose
      title={`Expose every Service in a namespace of ${cluster.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={!ready}>
            {busy ? "Creating rule…" : preview ? `Expose ${preview.servicesToExpose} Service${preview.servicesToExpose === 1 ? "" : "s"} and keep exposing` : "Create namespace rule"}
          </Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        {inventory === null && <p role="status">Reading the Services the cluster's gateway reported…</p>}
        {inventory === "unavailable" && (
          <p role="status" className="text-warn">
            There is no current Service report from this cluster's gateway{inventoryNote ? ` (${inventoryNote})` : ""}. You can still create the rule: nothing is exposed until the gateway reports.
          </p>
        )}
        {reported && namespaces.length > 0 ? (
          <Field label="Namespace">
            <Select value={namespace} onChange={(event) => { setNamespace(event.target.value); setUnderstood(false); }}>
              <option value="">Choose one namespace…</option>
              {namespaces.map((item) => <option key={item} value={item}>{item}</option>)}
            </Select>
          </Field>
        ) : inventory !== null && (
          <Field label="Namespace">
            <Input value={namespace} placeholder="for example shop" onChange={(event) => { setNamespace(event.target.value); setUnderstood(false); }} />
          </Field>
        )}
        {reported && namespaces.length === 0 && <p className="kubernetes-muted">The gateway reports no namespace that can take a new rule. You can name one that does not exist yet.</p>}
        <p className="kubernetes-muted">One namespace per rule. There is no all-namespaces rule; kube-system, kube-public, kube-node-lease and Tunnex's own namespaces cannot be chosen.</p>
        {reason && <ErrorText>{reason}</ErrorText>}

        {ns !== "" && reason === null && (
          <div className="kubernetes-action-impact" aria-label="What this rule will do">
            <p><strong>What happens when you confirm</strong></p>
            <ul>
              {preview ? (
                <li>
                  <strong>Now:</strong> {preview.portsToExpose} port{preview.portsToExpose === 1 ? "" : "s"} of {preview.servicesToExpose} Service{preview.servicesToExpose === 1 ? "" : "s"} in <strong>{ns}</strong> {preview.portsToExpose === 1 ? "is" : "are"} exposed, using {preview.newAddresses} new address{preview.newAddresses === 1 ? "" : "es"} from {cluster.vipRange}.
                  {preview.portsAlreadyExposed > 0 && ` ${preview.portsAlreadyExposed} port${preview.portsAlreadyExposed === 1 ? " is" : "s are"} already exposed and stay${preview.portsAlreadyExposed === 1 ? "s" : ""} exactly as ${preview.portsAlreadyExposed === 1 ? "it is" : "they are"}.`}
                  {preview.services === 0 && " The gateway reports no Service in this namespace yet."}
                </li>
              ) : (
                <li><strong>Now:</strong> nothing, until the gateway reports. Then every Service in <strong>{ns}</strong> is exposed.</li>
              )}
              <li><strong>From now on:</strong> every Service added to <strong>{ns}</strong> is exposed automatically, all of its TCP and UDP ports, within about a minute.</li>
              <li><strong>Nobody gains access.</strong> Exposure gives a Service an address and a name. Access rules still decide who can reach it; this creates none.</li>
              <li><strong>When a Service is deleted</strong> and stays gone for 10 minutes, its exposure is withdrawn. Access rules that pointed at it are kept but allow nothing, and they do not come back if the Service returns.</li>
              <li><strong>If the address range is full,</strong> nothing new is exposed and the rule says so here.</li>
              <li>Services exposed by hand or by the GitOps operator are never changed or removed by the rule.</li>
            </ul>
            <label className="kubernetes-confirm-check">
              <input type="checkbox" checked={understood} onChange={(event) => setUnderstood(event.target.checked)} />{" "}
              Expose every Service in {ns}, including Services added later
            </label>
          </div>
        )}
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

export function RemoveNamespaceRuleModal({
  orgId,
  clusterId,
  rule,
  onClose,
  onDone,
}: {
  orgId: string;
  clusterId: string;
  rule: K8sNamespaceRule;
  onClose: () => void;
  onDone: () => void | Promise<void>;
}) {
  const [choice, setChoice] = useState<"keep" | "withdraw" | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const count = `${rule.exposed_ports} exposed port${rule.exposed_ports === 1 ? "" : "s"} of ${rule.exposed_services} Service${rule.exposed_services === 1 ? "" : "s"}`;

  async function submit() {
    if (busy || choice === null) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.DELETE(
        "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/namespace-rules/{ruleId}",
        { params: { path: { orgId, clusterId, ruleId: rule.id }, query: { exposures: choice } } },
      );
      if (error) return setErr(apiErrorMessage(error, "Could not remove the namespace rule."));
      await onDone();
      onClose();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      placement="right" showClose
      title={`Remove the namespace rule for ${rule.namespace}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant={choice === "withdraw" ? "danger" : "primary"} onClick={() => void submit()} disabled={busy || choice === null}>
            {busy ? "Removing…" : choice === "withdraw" ? "Remove rule and withdraw exposures" : "Remove rule"}
          </Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        <p>Services added to <strong>{rule.namespace}</strong> will no longer be exposed automatically. Choose what happens to the {count} this rule created.</p>
        <fieldset className="kubernetes-choice-list">
          <legend className="sr-only">Exposures created by this rule</legend>
          <label>
            <input type="radio" name="namespace-rule-exposures" checked={choice === "keep"} onChange={() => setChoice("keep")} />{" "}
            <strong>Keep them exposed.</strong> They stay reachable under existing access rules and become ordinary exposures you unexpose one at a time.
          </label>
          <label>
            <input type="radio" name="namespace-rule-exposures" checked={choice === "withdraw"} onChange={() => setChoice("withdraw")} />{" "}
            <strong>Withdraw all of them.</strong> Their addresses and names stop working at once. Access rules that point at them are kept but allow nothing, and exposing the Services again later does not bring those rules back. If any one cannot be withdrawn, nothing is changed.
          </label>
        </fieldset>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}
