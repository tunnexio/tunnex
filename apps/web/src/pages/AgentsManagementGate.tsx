import { useEffect, useState, type ReactNode } from "react";
import { Loading } from "../components/ui";
import { api, type Member } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

export function AgentsManagementGate({ children }: { children: (orgId: string) => ReactNode }) {
  const { org } = useOrg();
  const { state } = useAuth();
  const [allowed, setAllowed] = useState<boolean | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") { setAllowed(false); return; }
    setAllowed(null);
    void api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } }).then(({ data, error }) => {
      if (cancelled) return;
      const member = !error && data ? (data as Member[]).find((value) => value.user_id === state.user.id) : undefined;
      setAllowed(member?.role === "owner" || member?.role === "admin");
    });
    return () => { cancelled = true; };
  }, [org?.id, state.status, state.status === "authed" ? state.user.id : ""]);
  if (!org) return <Loading label="Loading organization…" />;
  if (allowed === null) return <Loading label="Checking AI Agents management permissions…" />;
  if (!allowed) return <p role="alert" className="text-cell text-ink-tertiary">You do not have permission to manage AI Agent groups or policy templates.</p>;
  return <>{children(org.id)}</>;
}
