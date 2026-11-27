import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import { useMyOrgRoles } from "../lib/navaccess";
import { useOrganizationFeatureMirror, type AgentFeatureKey, type AgentFeatures } from "../lib/agentFeatures";
import { Button, SettingRow, SettingValue, Switch } from "./ui";

type Copy = { label: string; sentence: string; permission: string; inUse?: string };

/** One sentence per switch: what turning it on does, and what it does not do. */
export const AGENT_FEATURE_COPY: Record<AgentFeatureKey, Copy> = {
  runtime_sync: {
    label: "Runtime synchronization",
    sentence: "Lets Tunnex install agents on your hosts and keep their settings up to date. It gives an agent no access by itself.",
    permission: "agent_runtime:manage",
  },
  agent_groups: {
    label: "Agent groups & policy templates",
    sentence: "Lets you put agents in groups and give a whole group the same rules. Nothing changes for an agent until you add it to a group.",
    permission: "agent_template:manage",
    inUse: "Agent groups are still in use. Remove the policy templates assigned to your agent groups, then turn this off.",
  },
  mcp: {
    label: "MCP",
    sentence: "Lets agents use MCP servers through the gateway. Every tool stays off until you allow it.",
    permission: "mcp:manage",
    inUse: "MCP is still in use. Remove the MCP servers from your agents and agent groups, then turn this off.",
  },
  agent_jit: {
    label: "Just-in-time agent access",
    sentence: "Lets an agent ask for temporary access that a person approves. Each approval creates one rule that expires.",
    permission: "agent_access:approve",
  },
};

export function planName(plan: string | null | undefined): string {
  const name = (plan ?? "").trim();
  return name ? name[0].toUpperCase() + name.slice(1) : "";
}

async function save(orgId: string, key: AgentFeatureKey, enabled: boolean) {
  const options = { params: { path: { orgId } }, body: { enabled } };
  if (key === "runtime_sync") return api.PUT("/api/v1/organizations/{orgId}/agent-runtime-settings", options);
  if (key === "agent_groups") return api.PUT("/api/v1/organizations/{orgId}/agent-policy-template-settings", options);
  if (key === "mcp") return api.PUT("/api/v1/organizations/{orgId}/mcp-settings", options);
  return api.PUT("/api/v1/organizations/{orgId}/agent-jit-access-settings", options);
}

/** The signed-in person may change this switch. An unreadable role withholds nothing: the server decides. */
function useMayChange(permission: string): boolean {
  let mine: ReturnType<typeof useMyOrgRoles> = { state: "failed" };
  // Also rendered in dialogs and specimens outside the organization provider: no roles to ask about there.
  try { mine = useMyOrgRoles(); } catch { mine = { state: "failed" }; }
  let verified = true;
  try {
    const { state } = useAuth();
    verified = state.status === "authed" && state.user.email_verified && !state.user.must_change_password;
  } catch { verified = true; }
  if (mine.state === "loading") return false;
  return verified && (mine.state === "failed" || can(mine.roles, permission));
}

/**
 * A feature's switch, wherever the feature is needed: what it does in one sentence, and the switch itself.
 * On a plan that does not include the feature the switch is disabled and names the plan that does, so
 * nobody clicks a switch that then fails.
 */
export function FeatureEnableInline({ orgId, feature, features, variant = "inline", canEdit, onChanged }: {
  orgId: string;
  feature: AgentFeatureKey;
  features: AgentFeatures;
  /** `row` is the Settings layout; `inline` sits on the page that needs the feature. */
  variant?: "inline" | "row";
  /** Settings passes its own answer. Elsewhere the component works it out from the person's roles. */
  canEdit?: boolean;
  onChanged?: (enabled: boolean) => void | Promise<void>;
}) {
  const copy = AGENT_FEATURE_COPY[feature];
  const derived = useMayChange(copy.permission);
  const mayChange = canEdit ?? derived;
  const mirror = useOrganizationFeatureMirror(orgId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true), locked = useRef(false), allowed = useRef(mayChange);
  allowed.current = mayChange;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { setError(null); }, [orgId, feature]);

  const current = features.get(feature);
  const plan = planName(current?.required_plan);
  const unavailable = current !== null && !current.available;

  async function toggle(next: boolean) {
    if (!current || unavailable || !allowed.current || locked.current || next === current.enabled) return;
    locked.current = true; setBusy(true); setError(null);
    try {
      const result = await save(orgId, feature, next);
      if (!alive.current || !allowed.current) return;
      const saved = (result.data as { enabled?: unknown } | undefined)?.enabled;
      if (result.error || typeof saved !== "boolean") {
        const code = apiErrorCode(result.error);
        if (code === "feature_required" || code === "edition_required") { setError(`Your plan does not include ${copy.label}.`); features.reload(); }
        else if ((code === "mcp_in_use" || code === "conflict") && copy.inUse) setError(copy.inUse);
        else setError(apiErrorMessage(result.error, `Could not turn ${copy.label} ${next ? "on" : "off"}. Try again.`));
        return;
      }
      features.apply(feature, saved);
      mirror(feature, saved);
      await onChanged?.(saved);
    } catch {
      if (alive.current) setError("Could not reach the API. The setting was not changed.");
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }

  const planNote = unavailable ? <span>{plan ? `Included in the ${plan} plan.` : "Not included in your plan."} <Link className="underline" to="/settings?section=licence">See your plan</Link></span> : null;
  const control = features.state.kind === "loading"
    ? <SettingValue>Checking…</SettingValue>
    : !current
      ? <Button variant="ghost" size="sm" onClick={features.reload}>Check again</Button>
      : <Switch label={copy.label} checked={current.enabled && !unavailable} disabled={busy || unavailable || !mayChange} onChange={(next) => void toggle(next)} />;
  const readError = features.state.kind === "error" ? `Could not check whether ${copy.label} is on: ${features.state.message}` : features.state.kind === "ready" && !current ? `The server did not say whether ${copy.label} is on.` : null;
  const permissionNote = current && !unavailable && !mayChange && features.state.kind === "ready" ? "Ask an owner or administrator to change this." : null;

  if (variant === "row") return <div data-testid={`agent-feature-${feature}`}>
    <SettingRow label={copy.label} description={copy.sentence} error={error ?? readError}>{control}</SettingRow>
    {planNote && <p className="feature-control-note">{planNote}</p>}
  </div>;

  return <div data-testid={`agent-feature-${feature}`} role="group" aria-label={copy.label} className="min-w-0 rounded-lg border border-line bg-surface p-4">
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-ink-heading">{current?.enabled && !unavailable ? `${copy.label} is on` : `Turn on ${copy.label}`}</h3>
        <p className="mt-1 text-sm text-ink-tertiary">{copy.sentence}</p>
      </div>
      <div className="shrink-0 pt-0.5">{control}</div>
    </div>
    {planNote && <p className="mt-2 text-sm text-ink-secondary">{planNote}</p>}
    {permissionNote && <p className="mt-2 text-sm text-ink-secondary">{permissionNote}</p>}
    {(error ?? readError) && <p role="alert" className="mt-2 text-sm text-danger">{error ?? readError}</p>}
  </div>;
}
