import { useEffect, useState, type ReactNode } from "react";
import { Button, Loading } from "../components/ui";
import { api, type Member } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

export function AgentsManagementGate({
  children,
}: {
  children: (orgId: string) => ReactNode;
}) {
  const { org } = useOrg();
  const { state } = useAuth();
  const userId = state.status === "authed" ? state.user.id : "";
  const scope = `${org?.id ?? ""}/${userId}`;
  const [result, setResult] = useState<{
    scope: string;
    status: "allowed" | "denied" | "error";
  } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setResult(null);
    if (!org || !userId) return;
    void api
      .GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: org.id } },
      })
      .then(({ data, error }) => {
        if (cancelled) return;
        if (error || !data) {
          setResult({ scope, status: "error" });
          return;
        }
        const member = (data as Member[]).find(
          (value) => value.user_id === userId,
        );
        setResult({
          scope,
          status:
            member?.role === "owner" || member?.role === "admin"
              ? "allowed"
              : "denied",
        });
      })
      .catch(() => {
        if (!cancelled) setResult({ scope, status: "error" });
      });
    return () => {
      cancelled = true;
    };
  }, [org?.id, userId, scope, attempt]);
  if (!org) return <Loading label="Loading organization…" />;
  if (!userId)
    return (
      <p role="alert" className="text-cell text-ink-tertiary">
        You do not have permission to manage AI Agent groups or policy
        templates.
      </p>
    );
  // Do not render children with the previous organization's permission while a
  // new effect is pending. Scope is checked during render, not only on response.
  if (!result || result.scope !== scope)
    return <Loading label="Checking AI Agents management permissions…" />;
  if (result.status === "error")
    return (
      <div className="space-y-2">
        <p role="alert" className="text-cell text-ink-tertiary">
          Could not check AI Agents management permissions.
        </p>
        <Button
          onClick={() => {
            setResult(null);
            setAttempt((value) => value + 1);
          }}
        >
          Retry permissions
        </Button>
      </div>
    );
  if (result.status !== "allowed")
    return (
      <p role="alert" className="text-cell text-ink-tertiary">
        You do not have permission to manage AI Agent groups or policy
        templates.
      </p>
    );
  return <>{children(org.id)}</>;
}
