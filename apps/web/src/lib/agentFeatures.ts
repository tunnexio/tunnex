import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, type Org } from "./api";
import { useOrg } from "./useOrg";

export type AgentFeature = components["schemas"]["AgentFeature"];
export type AgentFeatureKey = AgentFeature["key"];

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: AgentFeature[] };

export type AgentFeatures = {
  state: State;
  /** The feature as the server reports it; null while loading, after a failed read, or when it is not reported. */
  get: (key: AgentFeatureKey) => AgentFeature | null;
  /** True or false once known; null while it is not. A page must not treat null as "off". */
  enabled: (key: AgentFeatureKey) => boolean | null;
  reload: () => void;
  /** Record a switch the server just confirmed, without another read. */
  apply: (key: AgentFeatureKey, enabled: boolean) => void;
};

function isFeature(value: unknown): value is AgentFeature {
  const item = value as Partial<AgentFeature> | null;
  return !!item && typeof item === "object" && typeof item.key === "string" && typeof item.enabled === "boolean" && typeof item.available === "boolean";
}

/**
 * What the organization row itself says, for a control plane that does not answer the feature list.
 * MCP follows the agent-groups switch there, which is what it depended on before it had its own.
 */
function fromOrganization(org: Org | null): AgentFeature[] | null {
  if (!org) return null;
  const items: AgentFeature[] = [];
  if (typeof org.managed_agent_runtime_enabled === "boolean") items.push({ key: "runtime_sync", enabled: org.managed_agent_runtime_enabled, available: true });
  if (typeof org.agent_policy_templates_enabled === "boolean") {
    items.push({ key: "agent_groups", enabled: org.agent_policy_templates_enabled, available: true });
    items.push({ key: "mcp", enabled: org.agent_policy_templates_enabled, available: true });
  }
  return items;
}

/** The organization seam is optional here: dialogs and specimens also render outside its provider. */
function useOptionalOrg(): { org: Org | null; updateOrg?: (org: Org) => void } {
  try { return useOrg(); } catch { return { org: null }; }
}

/** Which agent features are on, and which this plan includes. One read per page; every switch shares it. */
export function useAgentFeatures(orgId: string | undefined): AgentFeatures {
  const { org } = useOptionalOrg();
  const [state, setState] = useState<State>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  const orgRow = useRef<Org | null>(null);
  orgRow.current = org && org.id === orgId ? org : null;
  useEffect(() => {
    if (!orgId) return;
    let cancelled = false;
    setState({ kind: "loading" });
    void (async () => {
      let next: State;
      try {
        const result = await api.GET("/api/v1/organizations/{orgId}/agent-features", { params: { path: { orgId } } });
        const items = (result.data as { items?: unknown } | undefined)?.items;
        if (!result.error && Array.isArray(items) && items.every(isFeature)) next = { kind: "ready", items };
        else {
          const code = apiErrorCode(result.error);
          const fallback = !result.error || code === "agent_ux_not_implemented" || code === "not_found" ? fromOrganization(orgRow.current) : null;
          next = fallback ? { kind: "ready", items: fallback } : { kind: "error", message: apiErrorMessage(result.error, "Could not check which agent features are on.") };
        }
      } catch {
        next = { kind: "error", message: "Could not reach the API." };
      }
      if (!cancelled) setState(next);
    })();
    return () => { cancelled = true; };
  }, [orgId, attempt]);
  const reload = useCallback(() => setAttempt((value) => value + 1), []);
  const apply = useCallback((key: AgentFeatureKey, enabled: boolean) => setState((current) => current.kind !== "ready" ? current : {
    kind: "ready",
    items: current.items.some((item) => item.key === key) ? current.items.map((item) => item.key === key ? { ...item, enabled } : item) : [...current.items, { key, enabled, available: true }],
  }), []);
  return useMemo(() => {
    const get = (key: AgentFeatureKey) => state.kind === "ready" ? state.items.find((item) => item.key === key) ?? null : null;
    return { state, get, enabled: (key) => get(key)?.enabled ?? null, reload, apply };
  }, [state, reload, apply]);
}

/** Keep the organization row in step with a switch that mirrors one of its fields. */
export function useOrganizationFeatureMirror(orgId: string): (key: AgentFeatureKey, enabled: boolean) => void {
  const { org, updateOrg } = useOptionalOrg();
  return (key, enabled) => {
    if (!org || org.id !== orgId || !updateOrg) return;
    if (key === "runtime_sync") updateOrg({ ...org, managed_agent_runtime_enabled: enabled });
    if (key === "agent_groups") updateOrg({ ...org, agent_policy_templates_enabled: enabled });
    if (key === "agent_jit") updateOrg({ ...org, agent_jit_access_enabled: enabled });
  };
}
