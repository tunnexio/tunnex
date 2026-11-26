import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";

// VAULT-UX-2 W1: "Vault activity" is every vault.* action, whatever its target type.
afterEach(cleanup);
const queries: Array<Record<string, unknown>> = [];

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string, opts?: { params?: { query?: Record<string, unknown> } }) => {
        if (path === "/api/v1/auth/me") return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/organizations") return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members")) return { data: [{ user_id: "u1", email: "a@b.c", name: "Ada", role: "owner", roles: ["owner"], status: "active", email_verified: true, joined_at: "2026-01-01T00:00:00Z" }] };
        if (path.endsWith("/audit-logs")) {
          queries.push(opts?.params?.query ?? {});
          return { data: [{ id: "01900000-0000-7000-8000-000000000001", action: "vault.service_created", created_at: "2026-08-01T10:00:00Z", actor_id: "u1", target_type: "vault_service", target_id: "01900000-0000-7000-8000-000000000002", details: { service: "Payments" } }] };
        }
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { MemoryRouter } from "react-router-dom";
import { OrgProvider } from "../src/lib/useOrg";
import { AuthProvider } from "../src/lib/auth";
import AuditLog from "../src/pages/AuditLog";
import { VAULT_AUDIT_ACTIONS, auditActionLabel } from "../src/lib/auditview";

function show() {
  return render(<MemoryRouter initialEntries={["/audit"]}><AuthProvider><OrgProvider><AuditLog /></OrgProvider></AuthProvider></MemoryRouter>);
}
beforeEach(() => { queries.length = 0; });

describe("Audit Log — Vault activity", () => {
  it("asks for the whole vault.* family, not one target type", async () => {
    show(); await screen.findByRole("table", { name: "Audit events" });
    fireEvent.click(screen.getByRole("button", { name: "Vault activity" }));
    await waitFor(() => expect(queries.at(-1)).toMatchObject({ action_prefix: "vault." }));
    expect(queries.at(-1)?.target_type).toBeUndefined();
    expect(queries.at(-1)?.action).toBeUndefined();
    expect((screen.getByLabelText("Action") as HTMLInputElement).value).toBe("vault.*");
  });

  it("treats a typed family.* action as the same family filter", async () => {
    show(); await screen.findByRole("table", { name: "Audit events" });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "vault.*" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(queries.at(-1)).toMatchObject({ action_prefix: "vault." }));
    expect(queries.at(-1)?.action).toBeUndefined();
  });

  it("still sends an exact action unchanged", async () => {
    show(); await screen.findByRole("table", { name: "Audit events" });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "vault.service_created" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(queries.at(-1)).toMatchObject({ action: "vault.service_created" }));
    expect(queries.at(-1)?.action_prefix).toBeUndefined();
  });

  it("labels the family suggestion", () => {
    expect(auditActionLabel("vault.*")).toBe("All Vault activity");
  });
});

describe("Vault audit labels cover every action the API writes", () => {
  it("has a label for each vault.* action in the API and its migrations", () => {
    const api = join(__dirname, "..", "..", "api");
    const sources = [
      ...readdirSync(join(api, "internal", "vault")).filter(name => name.endsWith(".go") && !name.endsWith("_test.go")).map(name => join(api, "internal", "vault", name)),
      ...readdirSync(join(api, "db", "migrations")).filter(name => name.endsWith(".up.sql")).map(name => join(api, "db", "migrations", name)),
    ];
    const written = new Set<string>();
    for (const file of sources) {
      const raw = readFileSync(file, "utf8");
      // Go comments are C-style; SQL comments are "--" lines. Neither may count as a written action.
      const text = file.endsWith(".go") ? stripJsComments(raw) : raw.replace(/--.*$/gm, "");
      // Literal actions ("vault.service_created", migration SQL) and the entry helper's suffixes:
      // audit(ctx, tx, org, user, entry, "created", …) and Reveal's action := "revealed" / "copied".
      for (const match of text.matchAll(/["'`](vault\.[a-z_]+)["'`]/g)) written.add(match[1]);
      for (const match of text.matchAll(/\baudit\(ctx, tx, org, \w+, \w+, "([a-z_]+)"/g)) written.add(`vault.${match[1]}`);
      for (const match of text.matchAll(/\baction :?= "([a-z_]+)"/g)) written.add(`vault.${match[1]}`);
    }
    expect(written.size).toBeGreaterThanOrEqual(10);
    for (const action of written) expect(VAULT_AUDIT_ACTIONS).toContain(action);
    for (const action of VAULT_AUDIT_ACTIONS) expect(action.startsWith("vault.")).toBe(true);
  });
});
