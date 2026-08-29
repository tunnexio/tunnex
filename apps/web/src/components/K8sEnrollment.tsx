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
        Choose where the cluster runs, then connect it to a Site and connector.
        <span className="sr-only"> Provider selection records context only; Tunnex does not discover or access a cloud account.</span>
      </p>

      <ProviderCards value={draft.provider} onChange={selectProvider} disabled={busy} />

      <div className="mt-4 min-w-0 space-y-4">
          <section aria-labelledby="k8s-enrollment-connection" className="space-y-3 border-t border-white/[0.08] pt-4">
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
            {selectedCatalog && <p className="sr-only">{selectedCatalog.guidance}</p>}

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
            className="border-t border-white/[0.08] pt-3"
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
        <div aria-label="Enrollment context" className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-input border border-white/[0.08] bg-white/[0.025] px-3 py-2.5 text-xs">
          {draft.provider && <ProviderMark provider={draft.provider} className="h-5 w-6 shrink-0" />}
          <strong className="text-ink-heading">{selectedCatalog?.providerLabel ?? "Choose a provider"}</strong>
          <span aria-hidden className="text-white/20">/</span>
          <span className="text-ink-tertiary">{selectedSite?.name ?? "Site not selected"}</span>
          <span aria-hidden className="text-white/20">/</span>
          <span className="text-ink-tertiary">{selectedConnector?.name ?? "Connector not selected"}</span>
          <span aria-hidden className="text-white/20">/</span>
          <span className="text-ink-tertiary">{draft.name.trim() || "Cluster unnamed"}</span>
          <span className="ml-auto"><Badge tone={complete ? "ok" : "neutral"}>{complete ? "READY" : "INCOMPLETE"}</Badge></span>
          <span className="sr-only">Registration records control-plane intent. Actual connector and workload state is reported separately.</span>
        </div>
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
                aria-label={entry.providerLabel}
                value={entry.provider}
                checked={selected}
                disabled={disabled}
                onChange={() => onChange(entry.provider)}
              />
              <span className="flex min-h-[4.5rem] items-center gap-2.5 rounded-card border border-line bg-ink-900/40 px-3 py-2 text-left transition-colors peer-focus-visible:outline peer-focus-visible:outline-1 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent-400 peer-checked:border-accent-400 peer-checked:bg-accent-400/5">
                <ProviderMark provider={entry.provider} className="h-6 w-7 shrink-0" />
                <span className="min-w-0">
                  <strong className="block truncate text-xs text-ink-heading">
                    {entry.provider === "aws" ? "AWS" : entry.provider === "azure" ? "Azure" : entry.providerLabel}
                  </strong>
                  <span className="mt-0.5 block text-micro text-ink-faint">{entry.platform === "gke_standard" ? "GKE" : entry.platform === "kubernetes" ? "K8s" : entry.platform.toUpperCase()}</span>
                </span>
                <span className={`ml-auto h-2 w-2 shrink-0 rounded-full ${selected ? "bg-accent-400" : "bg-transparent"}`} aria-hidden />
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
