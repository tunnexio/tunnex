import { useEffect, useState } from "react";
import { api } from "../lib/api";
import AppAccessWorkspaceTabs from "./AppAccessWorkspaceTabs";
import { Loading } from "./ui";

type Navigation = { orgId: string; viewApplications: boolean; grantAccess: boolean; manageAssigned: boolean; pending: number };
export default function AppAccessMemberTabs({ orgId }: { orgId: string }) {
  const [navigation, setNavigation] = useState<Navigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [settledOrg, setSettledOrg] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false; let generation = 0;
    const refresh = async () => {
      const current = ++generation;
      setNavigation(null); setLoading(true);
      try {
        // The server returns current global capabilities and only safely scoped app summaries.
        // An org role label or an App admin assignment does not imply configuration authority.
        const apps = await api.GET("/api/v1/organizations/{orgId}/app-access/managed-apps", { params: { path: { orgId }, query: { limit: 1, offset: 0 } } });
        if (cancelled || generation !== current) return;
        if (apps.error || !apps.data) return;
        const state: Navigation = { orgId, viewApplications: apps.data.can_view_applications === true, grantAccess: apps.data.can_manage_grants === true, manageAssigned: apps.data.items.length > 0, pending: 0 };
        if (state.grantAccess || state.manageAssigned) {
          const requests = await api.GET("/api/v1/organizations/{orgId}/app-access/access-requests", { params: { path: { orgId }, query: { scope: "managed", status: "pending", limit: 1, offset: 0 } } });
          if (cancelled || generation !== current) return;
          if (requests.error || !requests.data) return;
          state.pending = requests.data.pending_count;
        }
        setNavigation(state);
      } catch {
        // A failed refresh leaves management controls hidden, never the last successful role.
        if (!cancelled && generation === current) setNavigation(null);
      } finally {
        if (!cancelled && generation === current) { setSettledOrg(orgId); setLoading(false); }
      }
    };
    void refresh();
    const onRefresh = () => { void refresh(); };
    window.addEventListener("focus", onRefresh);
    window.addEventListener("app-access-requests-changed", onRefresh);
    return () => { cancelled = true; window.removeEventListener("focus", onRefresh); window.removeEventListener("app-access-requests-changed", onRefresh); };
  }, [orgId]);
  const current = navigation?.orgId === orgId ? navigation : null;
  if (loading || settledOrg !== orgId) return <Loading label="Loading application navigation…" />;
  return <AppAccessWorkspaceTabs viewApplications={current?.viewApplications === true} manageGrants={current?.grantAccess === true} manageAssigned={current?.manageAssigned === true} pending={current?.pending ?? 0} />;
}
