import "../network-workspaces.css";
import "../devices-workspace.css";
import "../devices-policy-workspace.css";
import { useEffect, useState } from "react";
import { PostureChecksSection } from "../components/DevicePostureSection";
import { DevicesTabRail } from "../components/DevicesTabRail";
import { PageHeader, Loading } from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { api, loadOne, type Member } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can } from "../lib/rbac";

export default function DevicePosture() {
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? `${state.user.id}:${state.user.email_verified}` : state.status;
  return <DevicePolicyPage key={`${org?.id ?? ""}:${actor}`} />;
}

function DevicePolicyPage() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [canManage, setCanManage] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [manages, setManages] = useState(false);
  const verified = state.status === "authed" && state.user.email_verified;
  useEffect(() => {
    setCanManage(null); setError("");
    if (!org || state.status !== "authed") { setCanManage(false); return; }
    let stale = false;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (stale) return;
      if (!result.ok) { setError(result.error); return; }
      if (!Array.isArray(result.data) || !result.data.every((member) => member && typeof member === "object" && typeof member.user_id === "string" && typeof member.role === "string")) { setError("The permission response was not valid. Retry to reload it."); return; }
      const mine = (result.data as Member[]).find((member) => member.user_id === state.user.id);
      const roles = mine ? mine.roles ?? [mine.role] : [];
      // RBAC-1: posture checks are readable with device_health:view (the auditor); changing them is manage.
      setCanManage(can(roles, "device_health:manage") || can(roles, "device_health:view"));
      setManages(can(roles, "device_health:manage"));
    });
    return () => { stale = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : "", state.status === "authed" ? state.user.email_verified : false, attempt]);
  return <div className="network-management devices-workspace devices-policy-workspace space-y-5"><PageHeader navigationTitle title="Device posture" />
    {canManage === true && org ? <PostureChecksSection orgId={org.id} canManage={verified && manages} renderNavigation={(actions) => <><DevicesTabRail actions={actions} />{!manages ? <p role="status" className="devices-policy-copy">Only owners, admins and network admins can change posture checks.</p> : !verified && <p role="status" className="devices-policy-copy">Verify your email to manage device posture.</p>}</>} /> : <><DevicesTabRail />{error ? <LoadRetry error={`Could not check posture permission: ${error}`} onRetry={() => setAttempt((value) => value + 1)} /> : !org || canManage === null ? <Loading label="Checking posture permission…" /> : <p role="alert" className="devices-policy-copy">You do not have permission to manage device posture.</p>}</>}
  </div>;
}
