import { describe, expect, it } from "vitest";
import type { Member, Role } from "../src/lib/api";
import { navAllows, NAV_PERMISSIONS, seesOrgAudit, administersNetwork } from "../src/lib/navaccess";
import {
  ADMIN_GRADE_ROLES, can, canManageMembership, HELPDESK_CEILING_REASON, helpdeskCeilingApplies, HUMAN_ROLES, isAdminGrade,
  ROLE_DESCRIPTIONS, ROLE_LABELS, roleLabel, roleListLabel, roleNoun, rolesWhoCan,
} from "../src/lib/rbac";
import { accountActionBlocked, deviceCountFor, roleTallyLabel } from "../src/lib/usersview";
import sharedFixture from "../../api/internal/rbac/testdata/can_manage_membership.json";

// RBAC-1 (docs/RBAC-1-roles.md): four new human roles, the AI Gateway renames, and permission checks in place of
// role-name checks. The grant table itself is generated from Go (rbac-policy.json) and drift-guarded there.

describe("RBAC-1 role labels and descriptions", () => {
  it("offers every human role, most powerful first, and never a machine role", () => {
    expect(HUMAN_ROLES).toEqual(["owner", "admin", "network-admin", "agents-admin", "auditor", "helpdesk", "ai-admin", "ai-view", "member"]);
    expect(HUMAN_ROLES).not.toContain("operator");
    expect(HUMAN_ROLES).not.toContain("agent");
  });

  it("labels every role in plain words, with the AI Gateway renames and unchanged stored values", () => {
    expect(ROLE_LABELS).toEqual({
      owner: "Owner", admin: "Admin", "network-admin": "Network admin", "agents-admin": "AI Agents admin",
      auditor: "Auditor", helpdesk: "Helpdesk", "ai-admin": "AI Gateway admin", "ai-view": "AI Gateway viewer", member: "Member",
    });
    expect(roleListLabel(["owner", "ai-admin"])).toBe("Owner + AI Gateway admin");
    expect(roleLabel("operator")).toBe("operator");
  });

  it("gives every human role exactly one plain sentence", () => {
    for (const role of HUMAN_ROLES) {
      const sentence = ROLE_DESCRIPTIONS[role];
      expect(sentence, role).toMatch(/^[A-Z][^.]*\.$/);
    }
    expect(ROLE_DESCRIPTIONS.auditor).toBe("Sees everything an admin sees, including the full audit log, and cannot change anything.");
  });

  it("names roles as nouns in sentences", () => {
    expect(roleNoun("owner", true)).toBe("owners");
    expect(roleNoun("network-admin", false)).toBe("network admin");
    expect(roleNoun("helpdesk", true)).toBe("Helpdesk");
    expect(roleNoun("ai-admin", true)).toBe("AI Gateway admins");
    expect(roleTallyLabel({ role: "auditor", n: 2, deactivated: 0 })).toBe("2 auditors");
    expect(rolesWhoCan("ipsec:manage")).toBe("owners, admins and network admins");
    expect(rolesWhoCan("audit:view_all")).toBe("owners, admins and auditors");
  });
});

describe("RBAC-1 canManageMembership mirrors Go against one shared table", () => {
  const fixture = sharedFixture as unknown as { cases: Array<{ actor: Role; target: Role; new_role: Role | ""; allowed: boolean }> };
  it("agrees with every case Go is tested against", () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(81);
    for (const c of fixture.cases) expect(canManageMembership(c.actor, c.target, c.new_role), `${c.actor} ${c.target} ${c.new_role}`).toBe(c.allowed);
  });
  it("no new role invites, assigns roles or changes the organization", () => {
    for (const role of ["auditor", "agents-admin", "network-admin", "helpdesk"] as Role[]) {
      for (const perm of ["member:invite", "member:manage", "org:update", "org:delete", "license:manage", "machine:manage"]) expect(can(role, perm), `${role} ${perm}`).toBe(false);
    }
  });
});

describe("RBAC-1 navigation per role", () => {
  const ready = (...roles: Role[]) => ({ state: "ready" as const, roles });
  const visible = (...roles: Role[]) => Object.keys(NAV_PERMISSIONS).filter((to) => navAllows(to, ready(...roles))).sort();

  it("auditor sees what an admin reads, and the organization audit log", () => {
    // Founder, 2026-11-28: the auditor also reads the admin lists (alerts, device approvals and posture, MCP,
    // invitations, gateways and sites), read-only.
    expect(visible("auditor")).toEqual(["/access", "/access-events", "/agents", "/ai-gateway", "/alerts", "/app-access", "/devices/approvals", "/devices/posture", "/gateways", "/kubernetes", "/mcp", "/sandboxes", "/sites", "/users", "/users/groups", "/users/invitations"].sort());
    expect(seesOrgAudit(["auditor"])).toBe(true);
  });
  it("helpdesk sees people and device approvals only", () => {
    expect(visible("helpdesk")).toEqual(["/devices/approvals", "/users"]);
    expect(seesOrgAudit(["helpdesk"])).toBe(false);
  });
  it("AI Agents admin sees agents, MCP, approvals and the rules it reads", () => {
    expect(visible("agents-admin")).toEqual(["/access", "/access-events", "/agents", "/approvals", "/mcp", "/users/groups"].sort());
    expect(seesOrgAudit(["agents-admin"])).toBe(false);
  });
  it("network admin sees the network and devices, not people, AI or agents", () => {
    expect(visible("network-admin")).toEqual(["/access", "/access-events", "/devices/approvals", "/devices/posture", "/gateways", "/kubernetes", "/sites", "/users/groups"].sort());
    expect(administersNetwork(["network-admin"])).toBe(true);
    expect(seesOrgAudit(["network-admin"])).toBe(false);
  });
  it("the AI Gateway roles keep their pages", () => {
    expect(visible("ai-view")).toContain("/ai-gateway");
    expect(visible("ai-view")).not.toContain("/agents");
  });
});

describe("RBAC-1 Helpdesk ceiling and people actions", () => {
  const person = (roles: Role[], extra: Partial<Member> = {}): Member => ({ user_id: "target", email: "t@example.test", name: "T", role: roles[0], roles, status: "active", email_verified: true, ...extra }) as Member;
  const ctx = (actorRoles: Role[]) => ({ actorId: "me", actorRole: actorRoles[0], actorRoles, emailVerified: true, activeOwners: 2 });

  it("knows the admin-grade roles", () => {
    expect([...ADMIN_GRADE_ROLES].sort()).toEqual(["admin", "agents-admin", "ai-admin", "auditor", "network-admin", "owner"]);
    expect(isAdminGrade(["member", "helpdesk", "ai-view"])).toBe(false);
  });
  it("applies only when Helpdesk is the actor's only qualifying role", () => {
    expect(helpdeskCeilingApplies(["helpdesk"], "mfa:reset")).toBe(true);
    expect(helpdeskCeilingApplies(["helpdesk", "network-admin"], "mfa:reset")).toBe(true);
    expect(helpdeskCeilingApplies(["helpdesk", "network-admin"], "device:approve")).toBe(false);
    expect(helpdeskCeilingApplies(["helpdesk", "admin"], "mfa:reset")).toBe(false);
    expect(helpdeskCeilingApplies(["member"], "mfa:reset")).toBe(false);
  });
  it("Helpdesk resets 2FA for ordinary people and says who can for administrators", () => {
    expect(accountActionBlocked(person(["member"]), "reset", ctx(["helpdesk"]))).toBeNull();
    expect(accountActionBlocked(person(["ai-view", "member"]), "reset", ctx(["helpdesk"]))).toBeNull();
    for (const grade of ["admin", "network-admin", "agents-admin", "auditor", "ai-admin"] as Role[]) {
      expect(accountActionBlocked(person([grade, "member"]), "reset", ctx(["helpdesk"])), grade).toBe(HELPDESK_CEILING_REASON);
    }
    expect(accountActionBlocked(person(["owner"]), "reset", ctx(["helpdesk"]))).toBe("Only an owner can reset an owner's 2FA.");
    expect(accountActionBlocked(person(["network-admin"]), "reset", ctx(["admin", "helpdesk"]))).toBeNull();
  });
  it("Helpdesk cannot deactivate anyone, and the reason says who can", () => {
    expect(accountActionBlocked(person(["member"]), "deactivate", ctx(["helpdesk"]))).toBe("Only an owner or an admin can deactivate or reactivate people.");
    expect(accountActionBlocked(person(["member"]), "reset", ctx(["network-admin"]))).toBe("Only an owner, an admin or Helpdesk can reset 2FA.");
    expect(accountActionBlocked(person(["member"]), "reset", ctx(["auditor"]))).toBe("Only an owner, an admin or Helpdesk can reset 2FA.");
  });
  it("device counts follow device:view, not people management", () => {
    const devices = [{ id: "d1", user_id: "target" }] as never;
    for (const role of ["helpdesk", "auditor", "network-admin"] as Role[]) expect(deviceCountFor({ role: [role], devices, userId: "target" })).toEqual({ kind: "count", n: 1 });
    expect(deviceCountFor({ role: ["agents-admin"], devices, userId: "target" })).toEqual({ kind: "hidden" });
  });
});
