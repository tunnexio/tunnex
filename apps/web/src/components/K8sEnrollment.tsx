import { useMemo, useState } from "react";
import type { Node, Site } from "../lib/api";
import {
  EMPTY_ENROLLMENT_DRAFT,
  K8S_PROVIDER_CATALOG,
  catalogEntry,
  changeEnrollmentProvider,
  enrollmentComplete,
  enrollmentValidation,
  providerPlatformEntry,
  type EnrollmentDraft,
  type EnrollmentPlatform,
  type EnrollmentProvider,
} from "../lib/k8senrollment";
import { ProviderMark } from "./ProviderMarks";
import { Badge, Button, ErrorText, Field, Input, Modal, Select } from "./ui";

export type EnrollmentSubmitResult =
  | { ok: true; notice?: string }
  | { ok: false; error: string };

export function ProviderFirstEnrollmentModal({
  sites,
  nodes,
  sitesError,
  nodesError,
  initialDraft,
  initialAdvancedOpen = false,
  onDismiss,
  onSubmit,
  onDone,
}: {
  sites: Site[] | null;
  nodes: Node[] | null;
  sitesError?: string | null;
  nodesError?: string | null;
  initialDraft?: Partial<EnrollmentDraft>;
  initialAdvancedOpen?: boolean;
  onDismiss: () => void;
  onSubmit: (draft: EnrollmentDraft) => Promise<EnrollmentSubmitResult>;
  onDone: () => void;
}) {
  const [draft, setDraft] = useState<EnrollmentDraft>(() => ({
    ...EMPTY_ENROLLMENT_DRAFT,
    ...initialDraft,
  }));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(initialAdvancedOpen);

  const selectedCatalog = catalogEntry(draft.provider);
  const selectedSite = sites?.find((site) => site.id === draft.siteId) ?? null;
  const connectors = useMemo(
    () =>
      (nodes ?? []).filter(
        (node) =>
          node.status === "active" &&
          node.site_id === draft.siteId &&
          Boolean(node.endpoint),
      ),
    [draft.siteId, nodes],
  );
  const selectedConnector =
    connectors.find((node) => node.id === draft.connectorNodeId) ?? null;
  const complete = enrollmentComplete(draft);
  const validation = enrollmentValidation(draft);

  const update = <K extends keyof EnrollmentDraft>(key: K, value: EnrollmentDraft[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setError(null);
    setNotice(null);
  };

  const selectProvider = (provider: EnrollmentProvider) => {
    setDraft((current) => changeEnrollmentProvider(current, provider));
    setError(null);
    setNotice(null);
  };

  async function submit() {
    if (!complete || busy) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await onSubmit(draft);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      if (result.notice) setNotice(result.notice);
      onDone();
    } catch {
      setError("Could not reach the API. The cluster was not registered.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Enroll a Kubernetes cluster"
      size="wide"
      onDismiss={busy ? () => {} : onDismiss}
      actions={
        <>
          <Button variant="ghost" disabled={busy} onClick={onDismiss}>
            Cancel
          </Button>
          <Button disabled={busy || !complete} onClick={() => void submit()}>
            {busy ? "Enrolling…" : "Enroll cluster"}
          </Button>
        </>
      }
    >
      <p className="text-cell text-ink-tertiary">
        Choose the provider context first. This records installation and presentation context only; Tunnex does not discover or access a cloud account.
      </p>

      <ProviderCards value={draft.provider} onChange={selectProvider} disabled={busy} />

      <div className="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_14rem]">
        <div className="min-w-0 space-y-4">
          <section aria-labelledby="k8s-enrollment-connection" className="space-y-3 rounded-card border border-line bg-ink-900/30 p-3">
            <h3 id="k8s-enrollment-connection" className="text-sm font-semibold text-ink-heading">Connection</h3>
            <Field label="Kubernetes service">
              <Select
                value={draft.platform}
                disabled={!selectedCatalog}
                onChange={(event) => update("platform", event.target.value as EnrollmentPlatform | "")}
              >
                <option value="">{selectedCatalog ? "Select the supported service" : "Choose a provider first"}</option>
                {selectedCatalog && <option value={selectedCatalog.platform}>{selectedCatalog.platformLabel}</option>}
              </Select>
            </Field>
            {selectedCatalog && <p className="text-micro text-ink-faint">{selectedCatalog.guidance}</p>}

            <div className="grid gap-3 sm:grid-cols-2">
              <div><Field label="Fronting Site">
                <Select value={draft.siteId} disabled={!draft.platform || sites === null} aria-invalid={sitesError ? true : undefined} onChange={(event) => { setDraft((current) => ({ ...current, siteId: event.target.value, connectorNodeId: "" })); setError(null); setNotice(null); }}>
                  <option value="">{draft.platform ? "Select a Site" : "Select a service first"}</option>
                  {(sites ?? []).map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
                </Select>
              </Field>{sites === null && <p role={sitesError ? "alert" : "status"} className={`mt-1 text-micro ${sitesError ? "text-danger" : "text-ink-faint"}`}>{sitesError ? "Site inventory could not be loaded. No empty result is inferred." : "Loading Site inventory…"}</p>}</div>
              <div><Field label="In-cluster connector">
                <Select value={draft.connectorNodeId} disabled={!draft.siteId || nodes === null || connectors.length === 0} aria-invalid={nodesError ? true : undefined} onChange={(event) => update("connectorNodeId", event.target.value)}>
                  <option value="">{!draft.siteId ? "Select a Site first" : connectors.length === 0 ? "No active endpoint-bearing connector" : "Select a connector"}</option>
                  {connectors.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
                </Select>
              </Field>{nodes === null && <p role={nodesError ? "alert" : "status"} className={`mt-1 text-micro ${nodesError ? "text-danger" : "text-ink-faint"}`}>{nodesError ? "Node inventory could not be loaded. No zero-connector result is inferred." : "Loading Node inventory…"}</p>}</div>
            </div>
            <p className="text-micro text-ink-faint">
              The connector watches ready Kubernetes endpoints. Selecting it does not claim that the cluster or workloads are ready.
            </p>
            <div><Field label="Cluster name">
              <Input
                value={draft.name}
                disabled={!draft.connectorNodeId}
                aria-invalid={validation.name ? true : undefined}
                aria-describedby={validation.name ? "k8s-cluster-name-error" : undefined}
                onChange={(event) => update("name", event.target.value)}
                placeholder="e.g. prod-eks"
              />
            </Field>{validation.name && <div id="k8s-cluster-name-error"><ErrorText>{validation.name}</ErrorText></div>}</div>
          </section>

          <details
            open={advancedOpen}
            onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
            className="rounded-card border border-line bg-ink-900/30 p-3"
          >
            <summary className="cursor-pointer text-sm font-semibold text-ink-heading">Advanced network values</summary>
            <p className="mt-2 text-micro text-ink-faint">
              Enter every network value explicitly. Provider selection supplies no CIDR, VIP range, DNS zone, or cloud resource.
            </p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field label="Synthetic VIP range">
                <Input value={draft.vipRange} onChange={(event) => update("vipRange", event.target.value)} placeholder="e.g. 100.64.0.0/16" />
              </Field>
              <Field label="Kubernetes Service CIDR">
                <Input value={draft.serviceCidr} onChange={(event) => update("serviceCidr", event.target.value)} placeholder="e.g. 10.96.0.0/12" />
              </Field>
              <div className="sm:col-span-2">
                <Field label="DNS zone">
                  <Input value={draft.dnsZone} aria-invalid={validation.dnsZone ? true : undefined} aria-describedby={validation.dnsZone ? "k8s-dns-zone-error" : undefined} onChange={(event) => update("dnsZone", event.target.value)} placeholder="e.g. k8s.acme.com" />
                </Field>
                {validation.dnsZone && <div id="k8s-dns-zone-error"><ErrorText>{validation.dnsZone}</ErrorText></div>}
              </div>
            </div>
          </details>
        </div>

        <aside className="rounded-card border border-line bg-ink-900/50 p-3" aria-label="Enrollment context">
          <h3 className="text-sm font-semibold text-ink-heading">Enrollment context</h3>
          <div className="mt-3 flex items-center gap-2 border-b border-line pb-3">
            {draft.provider && <ProviderMark provider={draft.provider} className="h-8 w-9" />}
            <span className="text-xs font-semibold text-ink-body">{selectedCatalog?.providerLabel ?? "Provider not selected"}</span>
          </div>
          <dl className="divide-y divide-white/10 text-xs">
            <ContextRow label="Service" value={draft.platform ? selectedCatalog?.platformLabel ?? "Unavailable" : "Not selected"} />
            <ContextRow label="Site" value={selectedSite?.name ?? "Not selected"} />
            <ContextRow label="Connector" value={selectedConnector?.name ?? "Not selected"} />
            <ContextRow label="Cluster" value={draft.name.trim() || "Not entered"} />
            <ContextRow label="Network" value={draft.vipRange && draft.serviceCidr && draft.dnsZone ? "Explicit values entered" : "Incomplete"} />
          </dl>
          <div className="mt-3">
            <Badge tone={complete ? "ok" : "neutral"}>{complete ? "READY TO REGISTER" : "INCOMPLETE"}</Badge>
            <p className="mt-2 text-micro text-ink-faint">
              Registration records control-plane intent. Actual connector and workload state is reported separately.
            </p>
          </div>
        </aside>
      </div>

      <div className="mt-3 space-y-2">
        <ErrorText>{error}</ErrorText>
        {notice && <p role="status" className="text-xs text-ok">{notice}</p>}
      </div>
    </Modal>
  );
}

export function ProviderMetadataCorrectionModal({
  clusterName,
  initialProvider,
  initialPlatform,
  onDismiss,
  onSubmit,
  onDone,
}: {
  clusterName: string;
  initialProvider: string;
  initialPlatform: string;
  onDismiss: () => void;
  onSubmit: (
    provider: EnrollmentProvider,
    platform: EnrollmentPlatform,
  ) => Promise<EnrollmentSubmitResult>;
  onDone: () => void;
}) {
  const initial = providerPlatformEntry(initialProvider, initialPlatform);
  const [provider, setProvider] = useState<EnrollmentProvider | "">(
    initial?.provider ?? "",
  );
  const [platform, setPlatform] = useState<EnrollmentPlatform | "">(
    initial?.platform ?? "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selected = catalogEntry(provider);
  const complete = Boolean(selected && platform === selected.platform);

  async function submit() {
    if (!provider || !platform || !providerPlatformEntry(provider, platform) || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await onSubmit(provider, platform);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      onDone();
    } catch {
      setError("Could not reach the API. Provider metadata was not changed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Correct provider metadata for ${clusterName}`}
      size="wide"
      onDismiss={busy ? () => {} : onDismiss}
      actions={
        <>
          <Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button>
          <Button disabled={busy || !complete} onClick={() => void submit()}>
            {busy ? "Saving…" : "Save provider metadata"}
          </Button>
        </>
      }
    >
      <p className="text-cell text-ink-tertiary">
        This changes presentation and installation context only. It does not discover a cloud resource, move the connector, alter networking, or grant access.
      </p>
      {!initial && (
        <p role="status" className="mt-3 rounded-input border border-line bg-surface-inset p-2.5 text-micro text-ink-tertiary">
          Current metadata is unknown. No provider or platform was inferred from this legacy cluster.
        </p>
      )}
      <ProviderCards
        value={provider}
        disabled={busy}
        onChange={(next) => {
          setProvider(next);
          setPlatform("");
          setError(null);
        }}
      />
      <div className="mt-4">
        <Field label="Kubernetes service">
          <Select
            value={platform}
            disabled={!selected}
            onChange={(event) => {
              setPlatform(event.target.value as EnrollmentPlatform | "");
              setError(null);
            }}
          >
            <option value="">{selected ? "Select the supported service" : "Choose a provider first"}</option>
            {selected && <option value={selected.platform}>{selected.platformLabel}</option>}
          </Select>
        </Field>
      </div>
      <div className="mt-3"><ErrorText>{error}</ErrorText></div>
    </Modal>
  );
}

function ProviderCards({
  value,
  onChange,
  disabled = false,
}: {
  value: EnrollmentProvider | "";
  onChange: (provider: EnrollmentProvider) => void;
  disabled?: boolean;
}) {
  return (
    <fieldset className="mt-4">
      <legend className="text-sm font-semibold text-ink-heading">Cloud provider</legend>
      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {K8S_PROVIDER_CATALOG.map((entry) => {
          const selected = value === entry.provider;
          return (
            <label key={entry.provider} className="relative cursor-pointer">
              <input
                className="peer sr-only"
                type="radio"
                name="k8s-provider"
                value={entry.provider}
                checked={selected}
                disabled={disabled}
                onChange={() => onChange(entry.provider)}
              />
              <span className="flex min-h-[8.25rem] flex-col items-center justify-center rounded-card border border-line bg-ink-900/50 px-2 py-3 text-center transition-colors peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent-400 peer-checked:border-accent-400 peer-checked:bg-accent-400/5">
                <ProviderMark provider={entry.provider} className="h-10 w-12" />
                <strong className="mt-2 text-xs text-ink-heading">{entry.providerLabel}</strong>
                <span className="mt-1 text-micro text-ink-faint">{entry.platformLabel}</span>
                <span className={`mt-2 text-[10px] font-semibold uppercase tracking-wide ${selected ? "text-accent-400" : "text-transparent"}`} aria-hidden={!selected}>
                  {selected ? "Selected" : "Not selected"}
                </span>
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

function ContextRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[4.25rem_minmax(0,1fr)] gap-2 py-2">
      <dt className="text-ink-faint">{label}</dt>
      <dd className="break-words text-ink-body">{value}</dd>
    </div>
  );
}
