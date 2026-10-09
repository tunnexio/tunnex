import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage, loadOne, type Loaded, type Role, type SandboxSetup } from "../lib/api";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import { useSandboxModuleState } from "../lib/deploymentMeta";
import { SANDBOX_PRODUCT_SHELVED } from "../lib/sandboxProduct";
import { aiGatewayPrerequisite } from "../lib/aiGatewayPrerequisite";
import { beamApi, type BeamPolicy, type BeamPolicyImpact } from "../lib/beam";
import { Button, Loading, Modal, SettingRow, Switch } from "./ui";

type Feature = "ai-gateway" | "server-access" | "local-sharing" | "sandboxes" | "alert-delivery";
type Props = { feature: Feature; orgId: string; roles: readonly Role[]; canEdit: boolean; serverAdmin: boolean };
const names: Record<Feature,string> = { "ai-gateway":"AI Gateway", "server-access":"Server Access", "local-sharing":"Local Sharing", sandboxes:"Sandboxes", "alert-delivery":"Alert delivery" };
const permissions: Record<Feature,string> = { "ai-gateway":"ai_gateway:manage", "server-access":"server_access:manage", "local-sharing":"beam:policy_manage", sandboxes:"sandbox:admin", "alert-delivery":"alerting:manage" };
const integer = (value: unknown, minimum = 0) => typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
const record = (value: unknown): value is Record<string,unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

/** Activation belongs to one actor, organization and current permission scope. */
export function WorkspaceFeatureControl(props: Props) {
  const { state } = useAuth();
  const moduleState = useSandboxModuleState();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}:${state.user.must_change_password}` : state.status;
  if (props.feature === "sandboxes" && (SANDBOX_PRODUCT_SHELVED || moduleState !== "enabled")) return <SettingRow label="Sandboxes" description={SANDBOX_PRODUCT_SHELVED ? "Unavailable in this product." : moduleState === "loading" ? "Reading server availability…" : "Unavailable until the server operator enables the sandbox module."}><span className="text-sm text-ink-secondary">Unavailable</span></SettingRow>;
  if (!can(props.roles,permissions[props.feature])) return <SettingRow label={names[props.feature]} description="Your current role cannot manage this feature."><span className="text-sm text-ink-secondary">Restricted</span></SettingRow>;
  const key = `${props.feature}:${props.orgId}:${actor}:${[...props.roles].sort().join(",")}:${props.canEdit}:${props.serverAdmin}`;
  const editable = props.canEdit && state.status === "authed" && state.user.email_verified && !state.user.must_change_password;
  switch (props.feature) {
    case "ai-gateway": return <AIFeature key={key} orgId={props.orgId} canEdit={editable} />;
    case "server-access": return <ServerFeature key={key} orgId={props.orgId} canEdit={editable} />;
    case "local-sharing": return <SharingFeature key={key} orgId={props.orgId} canEdit={editable} />;
    case "sandboxes": return <SandboxFeature key={key} orgId={props.orgId} canEdit={editable} />;
    case "alert-delivery": return <DeliveryFeature key={key} orgId={props.orgId} canEdit={editable} />;
  }
}

function useControl<T>(read: () => Promise<Loaded<T>>, valid: (value: T) => boolean) {
  const [data,setData] = useState<T | null>(null), [error,setError] = useState("");
  const [reading,setReading] = useState(true), [mutating,setMutating] = useState(false), [blocked,setBlocked] = useState(false);
  const alive = useRef(true), sequence = useRef(0), locked = useRef(false);
  const readRef = useRef(read), validRef = useRef(valid); readRef.current=read; validRef.current=valid;
  async function reload() {
    const request = ++sequence.current;
    setData(null); setError(""); setReading(true); setBlocked(false);
    const result = await readRef.current();
    if (!alive.current || request !== sequence.current) return;
    setReading(false);
    if (!result.ok || !validRef.current(result.data)) { setError(result.ok ? "The saved feature setting could not be read." : result.error); setBlocked(true); }
    else setData(result.data);
  }
  useEffect(() => { alive.current=true; void reload(); return () => { alive.current=false; sequence.current++; }; },[]);
  async function transact<R>(operation: () => Promise<Loaded<R>>, success: (value: R) => void | Promise<void>) {
    if (!alive.current || !data || reading || blocked || locked.current) return;
    locked.current=true; sequence.current++; setMutating(true); setError("");
    try {
      const result=await operation();
      if (!alive.current) return;
      if (!result.ok) { setBlocked(true); setError(`${result.error} Reload the saved setting before trying again.`); }
      else await success(result.data);
    } catch { if (alive.current) { setBlocked(true); setError("Could not confirm the change. Reload the saved setting before trying again."); } }
    finally { locked.current=false; if (alive.current) setMutating(false); }
  }
  function commit(value: T) {
    if (!validRef.current(value)) { setBlocked(true); setError("Could not confirm the saved setting. Reload before trying again."); return; }
    setData(value);
  }
  return { data,error,reading,busy:reading || mutating,blocked,reload,transact,commit };
}
type Control = { error:string; reading:boolean; busy:boolean; blocked:boolean; reload:()=>Promise<void> };
function FeatureRow({ name, description, enabled, canEdit, control, enableBlocked, onChange, children }: { name:string; description:string; enabled:boolean | undefined; canEdit:boolean; control:Control; enableBlocked?:boolean; onChange:(enabled:boolean)=>void; children?:React.ReactNode }) {
  return <div className="workspace-feature-control"><SettingRow label={name} description={description} error={control.error}>
    {control.reading ? <Loading size="inline" label={`Loading ${name} setting…`} /> : enabled !== undefined && !control.blocked ? <Switch label={name} checked={enabled} disabled={!canEdit || control.busy || !!enableBlocked} onChange={onChange} /> : <span className="text-sm text-ink-secondary">Unavailable</span>}
  </SettingRow>{control.blocked && enabled !== undefined && <p className="text-xs text-ink-secondary">Last reported: {enabled ? "Enabled" : "Disabled"}.</p>}{children}{control.error && <Button variant="ghost" disabled={control.busy} onClick={() => void control.reload()}>Reload {name} setting</Button>}</div>;
}
async function write<T>(operation: () => Promise<{ data?:T; error?:unknown }>): Promise<Loaded<T>> {
  const result=await operation();
  return result.error ? {ok:false,error:apiErrorMessage(result.error,"The setting could not be updated.")} : result.data === undefined ? {ok:false,error:"Could not confirm the setting change."} : {ok:true,data:result.data};
}

function AIFeature({ orgId,canEdit }: { orgId:string;canEdit:boolean }) {
  const control=useControl(() => loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway",{params:{path:{orgId}}})), value => !!value && typeof value.enabled === "boolean" && typeof value.available === "boolean" && integer(value.revision));
  const saved=control.data;
  function change(enabled:boolean) {
    if (!canEdit || !saved || enabled === saved.enabled || (enabled && !saved.available)) return;
    void control.transact(() => write(() => api.PUT("/api/v1/organizations/{orgId}/ai-gateway",{params:{path:{orgId}},body:{enabled}})),control.commit);
  }
  return <FeatureRow name="AI Gateway" description="Allow requests to configured models. Disabling blocks new requests; accepted requests may finish within 30 seconds." enabled={saved?.enabled} canEdit={canEdit} control={control} enableBlocked={!!saved && !saved.enabled && !saved.available} onChange={change}>{saved && !saved.available && <p className="text-sm text-ink-secondary">{aiGatewayPrerequisite(saved)}</p>}</FeatureRow>;
}

function ServerFeature({ orgId,canEdit }: { orgId:string;canEdit:boolean }) {
  const control=useControl(() => loadOne(() => api.GET("/api/v1/organizations/{orgId}/server-access",{params:{path:{orgId}}})), value => !!value && typeof value.enabled === "boolean" && typeof value.can_manage === "boolean" && integer(value.recording_retention_days,1) && integer(value.mfa_freshness_seconds,1) && integer(value.recording_max_session_bytes,1) && integer(value.recording_max_org_bytes,1));
  const saved=control.data;
  function change(enabled:boolean) {
    if (!canEdit || !saved?.can_manage || enabled === saved.enabled) return;
    void control.transact(() => write(() => api.PUT("/api/v1/organizations/{orgId}/server-access",{params:{path:{orgId}},body:{enabled,recording_retention_days:saved.recording_retention_days,mfa_freshness_seconds:saved.mfa_freshness_seconds,recording_max_session_bytes:saved.recording_max_session_bytes,recording_max_org_bytes:saved.recording_max_org_bytes}})),async () => { await control.reload(); });
  }
  return <FeatureRow name="Server Access" description="Allow server registration, account checks and new SSH or RDP sessions. Recording and security policies stay saved." enabled={saved?.enabled} canEdit={canEdit && !!saved?.can_manage} control={control} onChange={change} />;
}

function validPolicy(value: BeamPolicy) {
  return !!value && typeof value.enabled === "boolean" && integer(value.version,1) && typeof value.domain_ready === "boolean" && typeof value.can_manage_policy === "boolean"
    && typeof value.require_mfa === "boolean" && integer(value.max_duration_seconds,60) && value.max_duration_seconds <= 86400 && integer(value.max_shares,1) && value.max_shares <= 25
    && (value.open_for_all_users === undefined || typeof value.open_for_all_users === "boolean")
    && [value.publisher_group_ids,value.reviewer_user_ids,value.reviewer_group_ids].every(ids => Array.isArray(ids) && ids.every(id => typeof id === "string" && id.length > 0));
}
function SharingFeature({ orgId,canEdit }: { orgId:string;canEdit:boolean }) {
  const control=useControl(() => beamApi.policy(orgId),validPolicy);
  const [review,setReview]=useState<{policy:BeamPolicy;impact:BeamPolicyImpact} | null>(null), [confirmed,setConfirmed]=useState(false);
  const saved=control.data;
  function change(enabled:boolean) {
    if (!canEdit || !saved?.can_manage_policy || enabled === saved.enabled || (enabled && !saved.domain_ready)) return;
    const policy={...saved,enabled};
    void control.transact(async () => {
      const result=await beamApi.policyImpact(orgId,policy);
      if (!result.ok) return result;
      const impact=result.data;
      return impact.policy_version !== saved.version || typeof impact.requires_confirmation !== "boolean" || ![impact.active_share_count,impact.affected_share_count,impact.affected_reviewer_session_count].every(value => integer(value))
        ? {ok:false as const,error:"Sharing policy or its impact changed. Review the saved policy."} : result;
    },impact => { setConfirmed(false); setReview({policy,impact}); });
  }
  function save() {
    if (!canEdit || !saved?.can_manage_policy || !review || (review.impact.requires_confirmation && !confirmed)) return;
    void control.transact(() => beamApi.savePolicy(orgId,review.policy,confirmed),value => { setReview(null); control.commit(value); });
  }
  return <><FeatureRow name="Local Sharing" description="Allow local app publishing under the saved sharing policy. Policy limits and audiences stay saved." enabled={saved?.enabled} canEdit={canEdit && !!saved?.can_manage_policy} control={control} enableBlocked={!!review || (!!saved && !saved.enabled && !saved.domain_ready)} onChange={change}>{saved && !saved.domain_ready && <p className="text-sm text-ink-secondary">Installation serving setup must be qualified before enabling publishing.</p>}<Link to="/settings?section=beam" className="text-sm text-brand">Review sharing policy</Link></FeatureRow>
    {review && <Modal title="Review Local Sharing activation" placement="right" showClose onDismiss={() => { if (!control.busy) setReview(null); }} actions={<><Button variant="ghost" disabled={control.busy} onClick={() => setReview(null)}>Cancel</Button><Button disabled={!canEdit || control.busy || control.blocked || (review.impact.requires_confirmation && !confirmed)} onClick={save}>Confirm Local Sharing change</Button></>}>
      <p>{review.policy.enabled ? "Enable Local Sharing for this organization." : "Disable Local Sharing for this organization."}</p><p>{review.impact.active_share_count} active shares; {review.impact.affected_share_count} shares and {review.impact.affected_reviewer_session_count} current reviewer sessions affected.</p><p className="text-sm text-ink-secondary">The saved policy version and current impact are checked again before applying the change.</p>{review.impact.requires_confirmation && <label className="flex items-center gap-3"><input type="checkbox" disabled={control.busy} checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>End active shares affected by this policy change</span></label>}{control.error && <p role="alert" className="text-danger">{control.error}</p>}
    </Modal>}
  </>;
}

type SandboxRead = { setup:SandboxSetup; runnerConfirmed:boolean };
function validSandbox(value: SandboxRead) {
  const setup=value?.setup;
  return !!setup && record(setup.settings) && typeof setup.settings.enabled === "boolean" && integer(setup.settings.max_per_user,1) && integer(setup.settings.max_total,1)
    && record(setup.creation_status) && typeof setup.creation_status.can_admin === "boolean" && typeof setup.creation_status.runtime_ready === "boolean"
    && Array.isArray(setup.creation_status.blocked_reasons) && setup.creation_status.blocked_reasons.every(reason => typeof reason === "string")
    && typeof setup.policy_mode === "string" && Array.isArray(setup.catalog) && setup.catalog.every(entry => record(entry) && typeof entry.enabled === "boolean" && typeof entry.runtime_compatible === "boolean");
}
function SandboxFeature({ orgId,canEdit }: { orgId:string;canEdit:boolean }) {
  async function read(): Promise<Loaded<SandboxRead>> {
    const result=await loadOne(() => api.GET("/api/v1/organizations/{orgId}/sandbox-setup",{params:{path:{orgId}}}));
    if (!result.ok) return result;
    const required=result.data?.creation_status?.runner_enrollment_required === true;
    if (!required) return {ok:true,data:{setup:result.data,runnerConfirmed:true}};
    const runners=await loadOne(() => api.GET("/api/v1/organizations/{orgId}/sandbox-runner-enrollments",{params:{path:{orgId}}}));
    return {ok:true,data:{setup:result.data,runnerConfirmed:runners.ok && Array.isArray(runners.data.enrollments) && runners.data.enrollments.some(enrollment => enrollment?.state === "ready")}};
  }
  const control=useControl(read,validSandbox), saved=control.data?.setup;
  const canActivate=!!saved && control.data?.runnerConfirmed === true && saved.creation_status.runtime_ready && !saved.creation_status.blocked_reasons.includes("historical_reservation_invalid") && saved.policy_mode === "enforcing" && saved.catalog.some(entry => entry.enabled && entry.runtime_compatible);
  function change(enabled:boolean) {
    if (!canEdit || !saved?.creation_status.can_admin || enabled === saved.settings.enabled || (enabled && !canActivate)) return;
    void control.transact(() => write(() => api.PUT("/api/v1/organizations/{orgId}/sandbox-setup",{params:{path:{orgId}},body:{expected:saved.settings,settings:{...saved.settings,enabled}}})),async () => { await control.reload(); });
  }
  return <FeatureRow name="Sandboxes" description="Allow sandbox creation. Turning this off withdraws workspace access; retained limits and catalog settings stay saved." enabled={saved?.settings.enabled} canEdit={canEdit && !!saved?.creation_status.can_admin} control={control} enableBlocked={!!saved && !saved.settings.enabled && !canActivate} onChange={change}>{saved && !saved.settings.enabled && !canActivate && <p className="text-sm text-ink-secondary">Activation requires enforcing network policy, a qualified runtime and a compatible published configuration.</p>}<Link to="/sandboxes/setup" className="text-sm text-brand">Review sandbox setup</Link></FeatureRow>;
}

function DeliveryFeature({ orgId,canEdit }: { orgId:string;canEdit:boolean }) {
  const control=useControl(() => loadOne(() => api.GET("/api/v1/organizations/{orgId}/alerting-settings",{params:{path:{orgId}}})),value => !!value && typeof value.enabled === "boolean");
  const saved=control.data;
  function change(enabled:boolean) {
    if (!canEdit || !saved || enabled === saved.enabled) return;
    void control.transact(() => write(() => api.PUT("/api/v1/organizations/{orgId}/alerting-settings",{params:{path:{orgId}},body:{enabled}})),control.commit);
  }
  return <FeatureRow name="Alert delivery" description="Deliver alerts through routing policies. Pausing delivery keeps conditions and delivery history recorded." enabled={saved?.enabled} canEdit={canEdit} control={control} onChange={change} />;
}
