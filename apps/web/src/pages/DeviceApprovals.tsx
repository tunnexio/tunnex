import "../network-workspaces.css";
import "../devices-workspace.css";
import "../devices-policy-workspace.css";
import { useEffect, useState } from "react";
import { DeviceApprovalSection } from "../components/DeviceApprovalSection";
import { DevicesTabRail } from "../components/DevicesTabRail";
import { PageHeader, Loading } from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { api, loadOne, type Device, type Member } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { can, HELPDESK_CEILING_REASON, helpdeskCeilingApplies, isAdminGrade } from "../lib/rbac";

export default function DeviceApprovals() {
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
  const [blockedReason, setBlockedReason] = useState<(device: Device) => string | null>(() => () => null);
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
      setCanManage(can(roles, "device:approve"));
      // RBAC-1 Helpdesk ceiling, mirrored so a Helpdesk person never meets a button the server refuses.
      const ceiling = helpdeskCeilingApplies(roles, "device:approve");
      const byUser = new Map((result.data as Member[]).map((member) => [member.user_id, member.roles ?? [member.role]]));
      setBlockedReason(() => (device: Device) => ceiling && isAdminGrade(byUser.get(device.user_id) ?? []) ? HELPDESK_CEILING_REASON : null);
    });
    return () => { stale = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : "", state.status === "authed" ? state.user.email_verified : false, attempt]);
  return <div className="network-management devices-workspace devices-policy-workspace space-y-5"><PageHeader navigationTitle title="Device approvals" />
    {canManage === true && org ? <DeviceApprovalSection orgId={org.id} canManage={verified} blockedReason={blockedReason} renderNavigation={(actions) => <><DevicesTabRail actions={actions} />{!verified && <p role="status" className="devices-policy-copy">Verify your email to manage device approvals.</p>}</>} /> : <><DevicesTabRail />{error ? <LoadRetry error={`Could not check device approval permission: ${error}`} onRetry={() => setAttempt((value) => value + 1)} /> : !org || canManage === null ? <Loading label="Checking device approval permission…" /> : <p role="alert" className="devices-policy-copy">You do not have permission to manage device approvals.</p>}</>}
  </div>;
}
