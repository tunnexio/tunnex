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

export function can(role: Role | undefined, perm: string): boolean {
  return role ? (grants[role]?.has(perm) ?? false) : false;
}

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
