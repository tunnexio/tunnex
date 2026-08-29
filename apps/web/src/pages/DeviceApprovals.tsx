import { useEffect, useState } from "react";
import { DeviceApprovalSection } from "../components/DeviceApprovalSection";
import { DevicesTabRail } from "../components/DevicesTabRail";
import { PageHeader, Card, ErrorText, Loading } from "../components/ui";
import { api, loadOne, type Member } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

/** Device lifecycle owns approval configuration and the pending-device queue. */
export default function DeviceApprovals() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [canManage, setCanManage] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!org || state.status !== "authed") { setCanManage(false); return; }
    let stale = false;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })).then((result) => {
      if (stale) return;
      if (!result.ok) { setError(result.error); setCanManage(false); return; }
      const mine = (result.data as Member[]).find((m) => m.user_id === state.user.id);
      setCanManage(mine?.role === "owner" || mine?.role === "admin");
    });
    return () => { stale = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  return <div className="space-y-5"><PageHeader title="Devices" subtitle="Review new enrollment requests before they connect." /><DevicesTabRail />
    {!org || canManage === null ? <Card><Loading label="Checking device approval permission…" /></Card> : !canManage ? <Card><p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage device approvals.</p><ErrorText>{error}</ErrorText></Card> : <DeviceApprovalSection orgId={org.id} canManage />}
  </div>;
}
