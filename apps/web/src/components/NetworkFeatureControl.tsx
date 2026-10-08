import { useCallback, useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne, type Role } from "../lib/api";
import { can } from "../lib/rbac";
import { Button, ErrorText, Modal, SettingRow, SettingValue } from "./ui";
import { FQDNEnforcementSetting } from "./FQDNEnforcementSetting";
import { K8sHAActivationPanel } from "./K8sHAActivationPanel";
import { ModeSection } from "../pages/Access";

type Feature = "ipsec" | "fqdn" | "kubernetes-scopes" | "kubernetes-ha" | "zero-trust";
type Props = { feature: Feature; orgId: string; roles: readonly Role[]; canEdit: boolean };
type RevisionSettings = components["schemas"]["IPsecSettings"] | components["schemas"]["K8sClusterScopeSettings"];

export function NetworkFeatureControl(props: Props) {
  return <NetworkFeatureForScope key={`${props.feature}:${props.orgId}:${props.roles.join(",")}:${props.canEdit}`} {...props} />;
}

function NetworkFeatureForScope({ feature, orgId, roles, canEdit }: Props) {
  if (feature === "fqdn") return <FQDNEnforcementSetting orgId={orgId} role={roles} central canEdit={canEdit} />;
  if (feature === "kubernetes-ha") return <K8sHAActivationPanel orgId={orgId} role={roles} emailVerified={canEdit} central />;
  if (feature === "zero-trust") return can(roles, "policy:view") ? <ModeSection orgId={orgId} central canManage={canEdit && can(roles, "policy:manage")} onPolicyChange={() => {}} /> : null;
  return <RevisionFeature feature={feature} orgId={orgId} roles={roles} canEdit={canEdit} />;
}

function validSettings(value: unknown, feature: "ipsec" | "kubernetes-scopes"): value is RevisionSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  return typeof data.enabled === "boolean" && typeof data.revision === "number" && Number.isInteger(data.revision) && data.revision >= 0
    && (feature === "ipsec" || (typeof data.effective === "boolean" && typeof data.entitlement_unlocked === "boolean"));
}

function RevisionFeature({ feature, orgId, roles, canEdit }: Props & { feature: "ipsec" | "kubernetes-scopes" }) {
  const scopes = feature === "kubernetes-scopes";
  const permitted = scopes ? can(roles, "k8s_scope:view") && can(roles, "policy:view") : can(roles, "org:view");
  const manage = canEdit && can(roles, scopes ? "k8s_scope:manage" : "ipsec:manage");
  const [settings, setSettings] = useState<RevisionSettings | null>(null);
  const [loading, setLoading] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [review, setReview] = useState<boolean | null>(null);
  const alive = useRef(true), sequence = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; sequence.current++; }; }, []);
  const load = useCallback(async () => {
    if (!permitted) return;
    const request = ++sequence.current;
    setLoading(true); setSettings(null); setError(""); setReview(null);
    const result = scopes
      ? await loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/cluster-scope-settings", { params: { path: { orgId } } }))
      : await loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId } } }));
    if (!alive.current || request !== sequence.current) return;
    setLoading(false);
    if (!result.ok || !validSettings(result.data, feature)) { setError(result.ok ? "The server returned incomplete feature settings." : result.error); return; }
    setSettings(result.data);
  }, [feature, orgId, permitted, scopes]);
  useEffect(() => { void load(); }, [load]);
  async function save() {
    if (!alive.current || !manage || !settings || review === null || locked.current) return;
    if (review && scopes && !("entitlement_unlocked" in settings && settings.entitlement_unlocked)) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const body = { enabled: review, expected_revision: settings.revision };
      const result = scopes
        ? await api.PUT("/api/v1/organizations/{orgId}/k8s/cluster-scope-settings", { params: { path: { orgId } }, body })
        : await api.PUT("/api/v1/organizations/{orgId}/ipsec/settings", { params: { path: { orgId } }, body });
      if (!alive.current) return;
      if (result.error) {
        const message = apiErrorMessage(result.error, "The feature setting could not be saved.");
        const code = apiErrorCode(result.error);
        if (code?.includes("revision") || code?.includes("conflict")) { await load(); if (alive.current) setError(`${message} Review the current saved setting before retrying.`); }
        else setError(message);
        return;
      }
      if (!validSettings(result.data, feature)) { setSettings(null); setReview(null); setError("The server did not confirm the setting. Reload before another change."); return; }
      setSettings(result.data); setReview(null);
      setNotice(scopes ? result.data.enabled ? "Cluster scopes are enabled. Still-current approved children may grant access again." : "Cluster scopes are disabled. Derived access was withdrawn; decisions were preserved." : result.data.enabled ? "IPsec is enabled for this organization. Connections are configured separately." : "IPsec is disabled for this organization.");
    } catch {
      if (alive.current) { setSettings(null); setReview(null); setError("The change could not be confirmed. Reload the saved setting before retrying."); }
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  if (!permitted) return null;
  const unlocked = settings && "entitlement_unlocked" in settings ? settings.entitlement_unlocked : true;
  const label = scopes ? "Kubernetes cluster scopes" : "IPsec";
  return <>
    <SettingRow label={label} description={scopes ? "Allow approved, exact Kubernetes Service children to grant access." : "Allow cloud VPN connections to be configured for this organization."} error={review === null ? error : null}>
      <div className="features-control"><SettingValue>{loading ? "Loading…" : !settings ? "Unavailable" : scopes && "effective" in settings ? settings.effective ? "Effective" : settings.enabled ? "Unavailable" : "Off" : settings.enabled ? "Enabled" : "Off"}</SettingValue>
        {settings && manage && (unlocked || settings.enabled) && <Button variant="ghost" disabled={busy || loading} onClick={() => { setError(""); setReview(!settings.enabled); }}>{scopes ? settings.enabled ? "Disable for organization" : "Enable for organization" : settings.enabled ? "Disable IPsec" : "Enable IPsec"}</Button>}
        {!settings && !loading && <Button variant="ghost" disabled={busy} onClick={() => void load()}>Retry {label} settings</Button>}
      </div>
    </SettingRow>
      {settings && !unlocked && <p className="features-note">Not in the current plan. Saved settings and decisions remain preserved.</p>}
      {notice && <p role="status" className="features-note">{notice}</p>}
    {review !== null && settings && manage && <Modal placement="right" showClose title={scopes ? `${review ? "Enable" : "Disable"} cluster scopes for this organization?` : `${review ? "Enable" : "Disable"} IPsec for this organization?`} danger={!review} onDismiss={() => { if (!busy) setReview(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setReview(null)}>Cancel</Button><Button variant={review ? "primary" : "danger"} disabled={busy} onClick={() => void save()}>{busy ? "Saving…" : scopes ? review ? "Enable scopes" : "Disable and withdraw" : review ? "Confirm enable IPsec" : "Confirm disable IPsec"}</Button></>}>
      <div className="features-review"><p>{scopes ? review ? "Still-current, approved children become eligible to grant access again. This creates no scope and approves no pending child." : "Withdraw all scope-derived access. Scopes, decisions and audit evidence remain; enabling again can restore only still-current approvals." : review ? "Enable organization configuration. Each connection still requires a capable gateway and its own readiness and activation checks." : "Disable organization configuration after all enabled connections and pending cleanup are resolved. The server refuses this change while delivered state or retained guards require cleanup."}</p><p className="features-note">The server checks saved revision {settings.revision} before applying the change.</p><ErrorText>{error}</ErrorText></div>
    </Modal>}
  </>;
}
