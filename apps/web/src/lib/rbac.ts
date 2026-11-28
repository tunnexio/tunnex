import type { Role } from "./api";
import rbacPolicy from "./rbac-policy.json";

// Client-side MIRROR of the server RBAC policy. This gates what CONTROLS render
// — it is UX, never enforcement. Every action is still authorized server-side;
// the UI simply must not offer what the server forbids (S4.4 watch-item a).
//
// The grant table is NOT hand-copied: rbac-policy.json is GENERATED from the Go
// source of truth (rbac.Policy, via `make generate-rbac`) and `make
// generate-check` fails the build if it drifts. So adding/moving a permission in
// rbac.go can no longer silently desync this mirror. (canManageMembership's
// relational rules below are logic, not data, and are still mirrored by hand.)
const grants: Record<string, Set<string>> = Object.fromEntries(
  Object.entries(rbacPolicy as Record<string, string[]>).map(
    ([role, perms]) => [role, new Set(perms)],
  ),
);

export function can(role: Role | readonly Role[] | undefined, perm: string): boolean {
  const roles = Array.isArray(role) ? role : role ? [role] : [];
  return roles.some((r) => grants[r]?.has(perm) ?? false);
}

// Assignable human roles in picker order: the most powerful first, then the RBAC-1 roles below admin, then
// the AI Gateway roles, then member. Machine roles (operator, agent) are never offered.
export const HUMAN_ROLES: Role[] = ["owner", "admin", "network-admin", "agents-admin", "auditor", "helpdesk", "ai-admin", "ai-view", "member"];

/** What a person reads for a role. Stored values never change (ai-admin is shown as AI Gateway admin). */
export const ROLE_LABELS: Record<Role, string> = {
  owner: "Owner",
  admin: "Admin",
  "network-admin": "Network admin",
  "agents-admin": "AI Agents admin",
  auditor: "Auditor",
  helpdesk: "Helpdesk",
  "ai-admin": "AI Gateway admin",
  "ai-view": "AI Gateway viewer",
  member: "Member",
};

/** One plain sentence per role, shown wherever a role is chosen. */
export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  owner: "Owns the organization and can do everything, including deleting it.",
  admin: "Manages people, access and infrastructure, everything except ownership.",
  "network-admin": "Runs gateways, sites, IPsec, Kubernetes, resources, access rules and devices.",
  "agents-admin": "Runs AI agents and MCP servers, including access rules for agents.",
  auditor: "Sees everything an admin sees, including the full audit log, and cannot change anything.",
  helpdesk: "Approves and restores devices and resets two-factor authentication for people without an admin role.",
  "ai-admin": "Manages AI Gateway models, provider credentials and model access.",
  "ai-view": "Sees AI Gateway configuration and usage.",
  member: "Uses the resources that access rules allow.",
};

export function roleLabel(role: string): string {
  return (ROLE_LABELS as Record<string, string>)[role] ?? role;
}

export function roleListLabel(roles: readonly string[]): string {
  return roles.map(roleLabel).join(" + ");
}

// Mirrors rbac.adminGradeRoles / HelpdeskCeilingApplies in Go (RBAC-1): Helpdesk may not reset MFA for, or act
// on devices of, a person holding any of these. The server enforces it; this decides what to offer.
export const ADMIN_GRADE_ROLES: readonly Role[] = ["owner", "admin", "network-admin", "agents-admin", "auditor", "ai-admin"];

export function isAdminGrade(roles: readonly string[]): boolean {
  return roles.some(role => (ADMIN_GRADE_ROLES as readonly string[]).includes(role));
}

/** True when the actor holds perm ONLY through Helpdesk, so admin-grade people are out of reach. */
export function helpdeskCeilingApplies(actorRoles: readonly Role[], perm: string): boolean {
  let viaHelpdesk = false;
  for (const role of actorRoles) {
    if (!can(role, perm)) continue;
    if (role !== "helpdesk") return false;
    viaHelpdesk = true;
  }
  return viaHelpdesk;
}

/** A role as a noun in a sentence: "owner", "network admins", "AI Gateway admin", "Helpdesk" never pluralised. */
export function roleNoun(role: Role, plural: boolean): string {
  const label = ROLE_LABELS[role];
  const lower = label.startsWith("AI") || role === "helpdesk" ? label : label.charAt(0).toLowerCase() + label.slice(1);
  return plural && role !== "helpdesk" ? lower + "s" : lower;
}
const pluralLabel = (role: Role) => roleNoun(role, true);

/** "owners, admins and network admins": who holds perm, read from the generated grant table. */
export function rolesWhoCan(perm: string): string {
  const labels = HUMAN_ROLES.filter((role) => can(role, perm)).map(pluralLabel);
  if (labels.length === 0) return "nobody in this organization";
  return labels.length === 1 ? labels[0] : `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

export const HELPDESK_CEILING_REASON = "Helpdesk cannot do this for a person with an administrator role. Ask an owner or admin.";

// NOTE: the drift guard covers the GRANT TABLE above (generated from Go) but NOT
// the relational logic below — canManageMembership is control flow, not data, so
// it can't be a fixture. It is the one surface still mirrored BY HAND; if you
// change rbac.CanManageMembership in Go, change it here too (no build will catch
// it). Keep the two in lockstep manually.
//
// canManageMembership mirrors rbac.CanManageMembership: the actor needs
// member:manage, only an owner may manage another owner, and only an owner may
// promote someone TO owner. newRole "" means removal/deactivation (no promotion).
export function canManageMembership(
  actorRole: Role | undefined,
  targetRole: Role,
  newRole: Role | "",
): boolean {
  if (!can(actorRole, "member:manage")) return false;
  if (targetRole === "owner" && actorRole !== "owner") return false;
  if (newRole === "owner" && actorRole !== "owner") return false;
  return true;
}
