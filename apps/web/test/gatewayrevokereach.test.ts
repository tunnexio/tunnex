import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { stripJsComments } from "./support/source";

/**
 * ⛔ THE SIXTH INSTANCE OF THE CLASS: A LAYOUT DECISION SILENTLY DELETED A CAPABILITY.
 *
 * `POST /nodes/{nodeId}/revoke` has existed since S11, with a two-step confirm, inside `EnrolCeremony`'s
 * own list. The Gateways page renders that component with `renderList={false}` — it owns the list itself —
 * so the action went off WITH the list, and the tables that replaced it never grew one.
 *
 * ⚠ NOTHING WENT RED. The component still exists, its own tests still pass, and the endpoint is still
 * wired. What broke is REACHABILITY, which no component-scoped test asks about.
 *
 * > ## ⛔ **THE GUARD MUST BE ABOUT THE ACTION BEING REACHABLE, NOT ABOUT A COMPONENT EXISTING** — the
 * > ## component existing is exactly what was true the whole time the control was gone.
 *
 * ⚠ SO IT READS THE PAGE, and it reads it for the CALL rather than for a label: a button wired to nothing
 * would pass a text search. And it survives whatever `renderList` does, because the page's own column is
 * what it asserts.
 */
// ⛔ COMMENTS STRIPPED, AND A CENSUS-OF-CENSUSES CAUGHT THAT I HAD NOT. The doc comment above CONTAINS the
// endpoint path this test hunts for, so a raw read would have matched its own prose — reporting the action
// present because I had described it. The guard would have passed with the button deleted.
const index = stripJsComments(readFileSync("src/pages/Gateways.tsx", "utf8"));
const detail = stripJsComments(readFileSync("src/pages/GatewayDetail.tsx", "utf8"));

describe("revoking a gateway is reachable from the active Gateway workspace", () => {
  it("the inventory opens a stable detail route and the detail owns the revoke call", () => {
    expect(index).toContain("`/gateways/${row.id}`");
    expect(
      detail.includes("/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke"),
      "The stable detail workspace is the active lifecycle owner; the enrollment component's hidden list is not.",
    ).toBe(true);
  });

  it("offers revocation for any active gateway only after the homed count is authoritative zero", () => {
    expect(detail).toMatch(/node\.status === "active" && canManage && homed === 0/);
    expect(detail).toMatch(/server checks again transactionally/i);
    expect(detail).toContain("Move devices");
  });

  it("⚠ an already-revoked gateway is not offered a revoke — there is no un-revoke", () => {
    expect(detail).toMatch(/node\.status === "revoked" && canRestore/);
    expect(detail).toMatch(/node\.status === "revoked" && canManage/);
    expect(detail).not.toMatch(/node\.status === "revoked"[^\n]+setDialog\("revoke"\)/);
    expect(detail).toContain("cannot be reactivated");
  });
});

describe("S20 Gateway mutation-to-rendered-caller census", () => {
  const enrollment = stripJsComments(
    readFileSync("src/components/Gateways.tsx", "utf8"),
  );
  const callers = [
    ["PUT", "/api/v1/admin/gateway-endpoint", enrollment],
    ["POST", "/api/v1/organizations/{orgId}/nodes/join-token", enrollment],
    ["PATCH", "/api/v1/organizations/{orgId}/nodes/{nodeId}", detail],
    ["POST", "/api/v1/organizations/{orgId}/nodes/{nodeId}/transfer-devices", detail],
    ["POST", "/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke", detail],
    ["POST", "/api/v1/organizations/{orgId}/nodes/{nodeId}/restore-devices", detail],
    ["DELETE", "/api/v1/organizations/{orgId}/nodes/{nodeId}", detail],
  ] as const;

  for (const [method, path, owner] of callers) {
    it(`${method} ${path} has an active Gateway owner`, () => {
      const escapedPath = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      expect(owner).toMatch(new RegExp(`api\\.${method}\\(\\s*"${escapedPath}"`));
    });
  }

  it("the enrollment component no longer carries hidden lifecycle callers", () => {
    expect(enrollment).not.toContain("/revoke");
    expect(enrollment).not.toContain("/restore-devices");
  });
});
