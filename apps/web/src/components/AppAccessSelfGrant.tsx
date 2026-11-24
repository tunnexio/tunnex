import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { SelfGrant } from "./SelfGrant";

// SA-UX-2 AA-4: a grant manager who has no access to this application can grant themself time-limited access with
// the ordinary grant endpoint (same validation and audit). The public app hostname stays uniform (anti-enumeration);
// this lives only in the dashboard.
export function AppAccessSelfGrant({ orgId, appId, userId, appName, onGranted }: { orgId: string; appId: string; userId: string; appName: string; onGranted?: () => void }) {
  const [missing, setMissing] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let live = true;
    void api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/effective-access", { params: { path: { orgId, appId } }, body: { user_id: userId } })
      .then(result => { if (live) setMissing(!!result.data && !result.data.grant_match); })
      .catch(() => { if (live) setMissing(false); });
    return () => { live = false; };
  }, [orgId, appId, userId, refresh]);
  if (!missing) return null;
  return <SelfGrant what={appName || "this application"} canGrant askWho="an organization administrator" maxHours={168} onDismiss={() => setMissing(false)} onGrant={async hours => {
    const now = Date.now();
    const result = await api.POST("/api/v1/organizations/{orgId}/app-access/grants", { params: { path: { orgId } }, body: { app_id: appId, subject_kind: "user", subject_id: userId, enabled: true, starts_at: new Date(now).toISOString(), expires_at: new Date(now + hours * 3600000).toISOString() } }).catch(() => null);
    if (!result) return "Could not reach the control plane.";
    if (result.error || !result.data) return apiErrorMessage(result.error, "The grant was not created.");
    setRefresh(value => value + 1); onGranted?.();
    return undefined;
  }} />;
}
