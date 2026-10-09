import { useMemo, useRef, useState } from "react";
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
import { Button, ErrorText, Field, Input, Modal, Select } from "./ui";
import { ProviderMark } from "./ProviderMarks";
import "../kubernetes-enrollment.css";
import "../resource-summary.css";

export type EnrollmentSubmitResult =
  | { ok: true; notice?: string }
  | { ok: false; error: string };

const ENROLLMENT_STEPS = ["Provider", "Connection", "Network", "Review"] as const;

export function ProviderFirstEnrollmentModal({
  sites,
  nodes,
  sitesError,
  nodesError,
  initialDraft,
  onDismiss,
  onSubmit,
  onDone,
}: {
  sites: Site[] | null;
  nodes: Node[] | null;
  sitesError?: string | null;
  nodesError?: string | null;
  initialDraft?: Partial<EnrollmentDraft>;
  /** Retained for callers of the former form; network values are now a required step. */
  initialAdvancedOpen?: boolean;
  onDismiss: () => void;
  onSubmit: (draft: EnrollmentDraft) => Promise<EnrollmentSubmitResult>;
  onDone: () => void;
}) {
  const [draft, setDraft] = useState<EnrollmentDraft>(() => ({
    ...EMPTY_ENROLLMENT_DRAFT,
    ...initialDraft,
  }));
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
  const validation = enrollmentValidation(draft);
  const providerComplete = Boolean(selectedCatalog && draft.platform === selectedCatalog.platform);
  const connectionComplete = Boolean(selectedSite && selectedConnector && draft.name.trim() && !validation.name);
  const networkComplete = Boolean(draft.vipRange.trim() && draft.serviceCidr.trim() && draft.dnsZone.trim() && !validation.dnsZone);
  // Bind the draft to the current inventory, including its eligibility filters.
  // Failed or withdrawn reads must never be treated as a valid saved selection.
  const complete = enrollmentComplete(draft) && connectionComplete;
  const canContinue = [providerComplete, providerComplete && connectionComplete, complete][step] ?? false;

  const update = <K extends keyof EnrollmentDraft>(key: K, value: EnrollmentDraft[K]) => {
    if (submitting.current) return;
    setDraft((current) => ({ ...current, [key]: value }));
    setError(null);
    setNotice(null);
  };

  const selectProvider = (provider: EnrollmentProvider) => {
    if (submitting.current) return;
    setDraft((current) => changeEnrollmentProvider(current, provider));
    setError(null);
    setNotice(null);
  };

  const goTo = (next: number) => {
    if (!submitting.current) setStep(next);
  };

  async function submit() {
    if (!complete || submitting.current) return;
    submitting.current = true;
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
      setError("Could not confirm registration. Refresh the cluster list before trying again.");
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Enroll a Kubernetes cluster"
      size="enrollment"
      placement="right"
      onDismiss={() => { if (!submitting.current) onDismiss(); }}
      actions={
        <>
          {step > 0 && <Button className="k8s-enrollment-back" variant="ghost" disabled={busy} onClick={() => goTo(step - 1)}>Back</Button>}
          <Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button>
          {step < 3 ? (
            <Button disabled={busy || !canContinue} onClick={() => goTo(step + 1)}>Continue</Button>
          ) : (
            <Button disabled={busy || !complete} onClick={() => void submit()}>{busy ? "Enrolling…" : "Enroll cluster"}</Button>
          )}
        </>
      }
    >
      <div className="k8s-enrollment-flow">
        <nav className="k8s-enrollment-steps" aria-label="Enrollment steps">
          {ENROLLMENT_STEPS.map((label, index) => (
            <button type="button" key={label} disabled={busy} aria-current={step === index ? "step" : undefined} onClick={() => goTo(index)}>
              {index + 1}. {label}
            </button>
          ))}
        </nav>

        <section className="k8s-enrollment-stage" aria-labelledby="k8s-enrollment-step-heading">
          <h3 id="k8s-enrollment-step-heading" className="k8s-enrollment-step-heading">{ENROLLMENT_STEPS[step]}</h3>

          {step === 0 && <>
            <p className="k8s-enrollment-note">Choose where this cluster runs.</p>
            <ProviderOptions value={draft.provider} onChange={selectProvider} disabled={busy} />
            <div className="k8s-enrollment-fields">
              <Field label="Kubernetes service">
                <Select value={draft.platform} disabled={busy || !selectedCatalog} onChange={(event) => update("platform", event.target.value as EnrollmentPlatform | "")}>
                  <option value="">{selectedCatalog ? "Select the supported service" : "Choose a provider first"}</option>
                  {selectedCatalog && <option value={selectedCatalog.platform}>{selectedCatalog.platformLabel}</option>}
                </Select>
              </Field>
            </div>
            {selectedCatalog?.provider === "gcp" && <p className="k8s-enrollment-note">GKE Standard is supported. GKE Autopilot is not offered as qualified support.</p>}
            <p className="k8s-enrollment-note">Provider selection records context only; Tunnex does not discover or access a cloud account.</p>
          </>}

          {step === 1 && <>
            <p className="k8s-enrollment-note">Choose the Site and connector that reach this cluster.</p>
            <div className="k8s-enrollment-fields">
              <div>
                <Field label="Fronting Site">
                  <Select value={draft.siteId} disabled={busy || !providerComplete || sites === null} aria-invalid={sitesError ? true : undefined} onChange={(event) => {
                    if (submitting.current) return;
                    setDraft((current) => ({ ...current, siteId: event.target.value, connectorNodeId: "" }));
                    setError(null);
                    setNotice(null);
                  }}>
                    <option value="">{providerComplete ? sites === null ? "Site inventory unavailable" : "Select a Site" : "Select a service first"}</option>
                    {(sites ?? []).map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
                  </Select>
                </Field>
                {sites === null ? <p role={sitesError ? "alert" : "status"} className={`k8s-enrollment-note ${sitesError ? "text-danger" : ""}`}>
                  {sitesError ? "Site inventory unavailable. Close and refresh to retry." : "Loading Site inventory…"}
                </p> : sites.length === 0 && <p className="k8s-enrollment-note">No Sites are available for enrollment.</p>}
              </div>
              <div>
                <Field label="In-cluster connector">
                  <Select value={draft.connectorNodeId} disabled={busy || !selectedSite || nodes === null || connectors.length === 0} aria-invalid={nodesError ? true : undefined} onChange={(event) => update("connectorNodeId", event.target.value)}>
                    <option value="">{nodes === null ? "Connector inventory unavailable" : !selectedSite ? "Select a Site first" : connectors.length === 0 ? "No active endpoint-bearing connector" : "Select a connector"}</option>
                    {connectors.map((node) => <option key={node.id} value={node.id}>{node.name}</option>)}
                  </Select>
                </Field>
                {nodes === null ? <p role={nodesError ? "alert" : "status"} className={`k8s-enrollment-note ${nodesError ? "text-danger" : ""}`}>
                  {nodesError ? "Connector inventory unavailable. Close and refresh to retry." : "Loading Node inventory…"}
                </p> : selectedSite && connectors.length === 0 && <p className="k8s-enrollment-note">This Site needs an active connector with an endpoint.</p>}
              </div>
              <div>
                <Field label="Cluster name">
                  <Input value={draft.name} disabled={busy || !selectedConnector} aria-invalid={validation.name ? true : undefined} aria-describedby={validation.name ? "k8s-cluster-name-error" : undefined} onChange={(event) => update("name", event.target.value)} placeholder="e.g. prod-eks" />
                </Field>
                {validation.name && <div id="k8s-cluster-name-error"><ErrorText>{validation.name}</ErrorText></div>}
              </div>
            </div>
          </>}

          {step === 2 && <>
            <p className="k8s-enrollment-note">Enter the network values for this cluster. None are filled from the provider.</p>
            <div className="k8s-enrollment-fields">
              <Field label="Synthetic VIP range" help="Addresses assigned to exposed services.">
                <Input value={draft.vipRange} disabled={busy} onChange={(event) => update("vipRange", event.target.value)} placeholder="e.g. 100.64.0.0/16" />
              </Field>
              <Field label="Kubernetes Service CIDR" help="The Service network already configured in this cluster.">
                <Input value={draft.serviceCidr} disabled={busy} onChange={(event) => update("serviceCidr", event.target.value)} placeholder="e.g. 10.96.0.0/12" />
              </Field>
              <div>
                <Field label="DNS zone" help="Domain used for exposed services.">
                  <Input value={draft.dnsZone} disabled={busy} aria-invalid={validation.dnsZone ? true : undefined} aria-describedby={validation.dnsZone ? "k8s-dns-zone-error" : undefined} onChange={(event) => update("dnsZone", event.target.value)} placeholder="e.g. k8s.acme.com" />
                </Field>
                {validation.dnsZone && <div id="k8s-dns-zone-error"><ErrorText>{validation.dnsZone}</ErrorText></div>}
              </div>
            </div>
          </>}

          {step === 3 && <>
            <p className="k8s-enrollment-note">Register this cluster with the values below.</p>
            <dl className="k8s-enrollment-review tnx-resource-facts" aria-label="Enrollment context">
              <div><dt>Cluster</dt><dd>{draft.name.trim() || "Not entered"}</dd></div>
              <div><dt>Provider</dt><dd>{selectedCatalog?.providerLabel ?? "Not selected"}</dd></div>
              <div><dt>Kubernetes service</dt><dd>{providerComplete ? selectedCatalog?.platformLabel : "Not selected"}</dd></div>
              <div><dt>Fronting Site</dt><dd>{selectedSite?.name ?? (sites === null ? "Inventory unavailable" : "Not selected")}</dd></div>
              <div><dt>In-cluster connector</dt><dd>{selectedConnector?.name ?? (nodes === null ? "Inventory unavailable" : "Not selected")}</dd></div>
              <div><dt>Synthetic VIP range</dt><dd>{draft.vipRange.trim() || "Not entered"}</dd></div>
              <div><dt>Kubernetes Service CIDR</dt><dd>{draft.serviceCidr.trim() || "Not entered"}</dd></div>
              <div><dt>DNS zone</dt><dd>{draft.dnsZone.trim() || "Not entered"}</dd></div>
            </dl>
            {!complete && <p role="status" className="k8s-enrollment-note">{!providerComplete ? "Choose a supported provider and service in Provider." : !connectionComplete ? "Complete Connection with a valid name, Site and eligible connector." : !networkComplete ? "Complete all Network values with a valid DNS zone." : "Complete each step before enrollment."}</p>}
            <p className="k8s-enrollment-note">Registration records control-plane intent. Actual connector and workload state is reported separately.</p>
          </>}
        </section>
        <div className="k8s-enrollment-feedback">
          <ErrorText>{error}</ErrorText>
          {notice && <p role="status" className="text-xs text-ok">{notice}</p>}
        </div>
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
  onSubmit: (provider: EnrollmentProvider, platform: EnrollmentPlatform) => Promise<EnrollmentSubmitResult>;
  onDone: () => void;
}) {
  const initial = providerPlatformEntry(initialProvider, initialPlatform);
  const [provider, setProvider] = useState<EnrollmentProvider | "">(initial?.provider ?? "");
  const [platform, setPlatform] = useState<EnrollmentPlatform | "">(initial?.platform ?? "");
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const selected = catalogEntry(provider);
  const complete = Boolean(selected && platform === selected.platform);

  async function submit() {
    if (!provider || !platform || !providerPlatformEntry(provider, platform) || submitting.current) return;
    submitting.current = true;
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
      setError("Could not confirm the metadata update. Refresh the cluster list before trying again.");
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Correct provider metadata for ${clusterName}`}
      size="enrollment"
      placement="right"
      onDismiss={() => { if (!submitting.current) onDismiss(); }}
      actions={
        <>
          <Button variant="ghost" disabled={busy} onClick={onDismiss}>Cancel</Button>
          <Button disabled={busy || !complete} onClick={() => void submit()}>{busy ? "Saving…" : "Save provider metadata"}</Button>
        </>
      }
    >
      <div className="k8s-enrollment-flow k8s-metadata-correction">
        <p className="k8s-enrollment-note">Update the provider and service recorded for this cluster.</p>
        {!initial && <p role="status" className="k8s-enrollment-note">Current metadata is unknown. No provider or platform was inferred from this legacy cluster.</p>}
        <ProviderOptions value={provider} disabled={busy} onChange={(next) => {
          if (submitting.current) return;
          setProvider(next);
          setPlatform("");
          setError(null);
        }} />
        <div className="k8s-enrollment-fields">
          <Field label="Kubernetes service">
            <Select value={platform} disabled={busy || !selected} onChange={(event) => {
              if (submitting.current) return;
              setPlatform(event.target.value as EnrollmentPlatform | "");
              setError(null);
            }}>
              <option value="">{selected ? "Select the supported service" : "Choose a provider first"}</option>
              {selected && <option value={selected.platform}>{selected.platformLabel}</option>}
            </Select>
          </Field>
        </div>
        {selected?.provider === "gcp" && <p className="k8s-enrollment-note">GKE Standard is supported. GKE Autopilot is not offered as qualified support.</p>}
        <p className="k8s-enrollment-note k8s-metadata-scope">This changes presentation and installation context only. It does not discover a cloud resource, move the connector, alter networking, or grant access.</p>
        <ErrorText>{error}</ErrorText>
      </div>
    </Modal>
  );
}

function ProviderOptions({
  value,
  onChange,
  disabled = false,
}: {
  value: EnrollmentProvider | "";
  onChange: (provider: EnrollmentProvider) => void;
  disabled?: boolean;
}) {
  return (
    <fieldset className="k8s-provider-fieldset">
      <legend>Cloud provider</legend>
      <div className="k8s-provider-options">
        {K8S_PROVIDER_CATALOG.map((entry) => (
          <label key={entry.provider} className="k8s-provider-option">
            <input type="radio" name="k8s-provider" aria-label={entry.providerLabel} value={entry.provider} checked={value === entry.provider} disabled={disabled} onChange={() => onChange(entry.provider)} />
            <ProviderMark provider={entry.provider} className="k8s-provider-mark" />
            <span>
              <strong>{entry.provider === "aws" ? "AWS" : entry.provider === "azure" ? "Azure" : entry.providerLabel}</strong>
              <small>{entry.platform === "gke_standard" ? "GKE Standard" : entry.platform === "kubernetes" ? "Kubernetes" : entry.platform.toUpperCase()}</small>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
