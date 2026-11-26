import { useEffect, useState } from "react";
import { api, type Role } from "./api";
import { can } from "./rbac";
import { useAuth } from "./auth";
import { useOrg } from "./useOrg";

// LS-UX-2: role-aware navigation. ⛔ UX ONLY. Every API keeps its own permission check; hiding a
// destination here grants and denies nothing. A destination with no rule is shown to everyone.
//
// Rules are ANY-OF permission lists, read from the generated grant table (rbac-policy.json), so a
// role that gains a permission in Go gains the destination without touching this file.
export const NAV_PERMISSIONS: Record<string, readonly string[]> = {
  "/gateways": ["org:update", "site:manage"],
  "/sites": ["site:manage", "ipsec:manage"],
  "/kubernetes": ["k8s:manage", "k8s_scope:view", "k8s_ha:view"],
  "/sandboxes": ["sandbox:view"],
  "/ai-gateway": ["ai_model:use", "ai_gateway:view"],
  "/agents": ["agent:manage", "agent:enroll", "agent:grant_access", "agent_access:request"],
  "/mcp": ["agent_template:manage"],
  "/access": ["policy:view"],
  "/users": ["member:manage", "member:invite"],
  "/app-access": ["app_access:use", "app_access:view"],
  "/browser-access/terminal": ["server_access:use", "server_access:view"],
  "/beam": ["beam:use"],
  "/vault": ["vault:use"],
  "/alerts": ["alerting:manage"],
  "/access-events": ["policy:view", "app_access:event_view", "beam:audit_view"],
  // Not sidebar destinations: sub-pages and tabs gated the same way (AdminOnlyRoute, tab rails).
  "/devices/approvals": ["device:approve"],
  "/devices/posture": ["device:approve", "device_health:manage"],
  "/users/groups": ["policy:view"],
  "/users/invitations": ["member:invite"],
};

/** Organization-wide audit (everyone else reads only their own actions). Mirrors audit_handlers.go. */
export function seesOrgAudit(roles: readonly Role[]): boolean { return roles.includes("owner") || roles.includes("admin"); }
/** The fleet overview is for people who administer the network; everyone else gets their workspace. */
export function administersNetwork(roles: readonly Role[]): boolean { return can(roles, "org:update") || can(roles, "policy:view"); }

export type MyRoles = { state: "loading" } | { state: "failed" } | { state: "ready"; roles: Role[] };

/**
 * Should this destination be offered? While roles load, gated destinations wait; when the role read
 * FAILS every destination is offered — a failed read must never remove a destination (the server decides).
 */
export function navAllows(to: string, mine: MyRoles): boolean {
  const rule = NAV_PERMISSIONS[to];
  if (!rule) return true;
  if (mine.state === "failed") return true;
  if (mine.state === "loading") return false;
  return rule.some(permission => can(mine.roles, permission));
}

const cache = new Map<string, Promise<Role[] | null>>();
function readRoles(orgId: string, userId: string): Promise<Role[] | null> {
  const key = `${orgId}:${userId}`;
  let pending = cache.get(key);
  if (!pending) {
    pending = api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } }).then(({ data }) => {
      const rows = Array.isArray(data) ? data : [];
      const me = rows.find(member => member && member.user_id === userId);
      if (!me || typeof me.role !== "string") return null;
      return Array.isArray(me.roles) && me.roles.length ? me.roles : [me.role];
    }).catch(() => null);
    // In-flight sharing only: a settled answer is never reused, so a role change shows on the next page.
    void pending.finally(() => cache.delete(key));
    cache.set(key, pending);
  }
  return pending;
}
/** Test seam: forget cached role reads. */
export function resetMyOrgRolesCache() { cache.clear(); }

/** The signed-in person's roles in the current organization (`roles ?? [role]`, so multi-role users are right). */
export function useMyOrgRoles(): MyRoles {
  const { org } = useOrg();
  // Shared chrome also renders outside the auth provider (palette, isolated pages): no person, no gate.
  let auth: ReturnType<typeof useAuth> | null = null;
  try { auth = useAuth(); } catch { auth = null; }
  const userId = auth?.state.status === "authed" ? auth.state.user.id : "";
  const orgId = org?.id ?? "";
  const [mine, setMine] = useState<MyRoles & { key?: string }>({ state: "loading" });
  const key = `${orgId}:${userId}`;
  useEffect(() => {
    if (!orgId || !userId) return;
    let live = true;
    void readRoles(orgId, userId).then(roles => { if (live) setMine(roles ? { state: "ready", roles, key } : { state: "failed", key }); });
    return () => { live = false; };
  }, [orgId, userId, key]);
  // No signed-in person or organization to ask about: unknown, so nothing is withheld.
  if (!orgId || !userId) return { state: "failed" };
  if (mine.key !== key) return { state: "loading" };
  return mine;
}
