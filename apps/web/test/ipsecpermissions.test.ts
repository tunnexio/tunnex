import { expect, it } from "vitest";
import type { Role } from "../src/lib/api";
import { can } from "../src/lib/rbac";

it.each(["owner", "admin"] as const)("allows %s to manage IPsec through the generated policy", role => {
  expect(can(role, "ipsec:manage")).toBe(true);
});

it.each(["member", "ai-admin", "ai-view", "operator", "agent", "unknown", undefined])("refuses IPsec management for %s", role => {
  expect(can(role as Role | undefined, "ipsec:manage")).toBe(false);
});

it("unions human roles without promoting combined read and AI authority", () => {
  expect(can(["member", "ai-admin", "ai-view"], "ipsec:manage")).toBe(false);
  expect(can(["member", "admin"], "ipsec:manage")).toBe(true);
  expect(can(["ai-admin", "owner"], "ipsec:manage")).toBe(true);
});
