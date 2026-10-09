vi.mock("../src/components/TerminalReplay", () => ({ TerminalReplay: () => null }));
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  fireEvent,
  cleanup,
  within,
} from "@testing-library/react";

// SLICE 8 — AuditLog, and the last of the tier's accountable screens.
//
// IT NEARLY DID NOT EARN A TEST. The tier's definition is "the decision the user gets", and a read-only log
// that only displays would have been an honest EXEMPTION rather than a test asserting that data appears — the
// same judgement that exempted Dashboard. It earns one because it holds a real decision, stated in the
// product's own comment:
//
//   `filters` is the EDITING state; `applied` is the set that produced the current list — "Load more" must page
//   with `applied`, NEVER mid-edit `filters`, or the keyset cursor (from the applied list) mixes with a
//   different filter set.
//
// THE CONSEQUENCE: paging with mid-edit filters APPENDS A PAGE FROM A DIFFERENT QUERY to the current list.
// Not an error — WRONG DATA, silently, in the surface whose entire value is being trustworthy. An audit log
// that quietly interleaves two filter sets is worse than one that fails, because it is still legible.
//
// QUERY RULES 1-5 BIND.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

// Every audit-log request, captured at the NETWORK boundary — the query is the assertion target.
const queries: Array<Record<string, unknown>> = [];
let logFail = false;
let emptyLaterPage = false;
let viewerRoles = ["owner"];

// ⛔ `actor_id`, NOT `actor_user_id`. The mock sent a field the spec does not have — and ActivityEntry is
// `additionalProperties: false`, so the server can NEVER send it. The page reads `a.actor_id`, so every row
// in every audit-log test rendered the "system" FALLBACK and no test ever saw an actor name.
//
// MEASURED on the live API before changing this: 34 of 78 rows carry a populated `actor_id`, and its value
// is the acting user's uuid. THE PAGE WAS RIGHT; THE MOCK WAS WRONG.
//
//   A FALLBACK THAT IS NEVER EXERCISED DELIBERATELY IS A FALLBACK THAT IS ALWAYS EXERCISED ACCIDENTALLY.
const ENTRY = (id: string) => ({
  id: `01900000-0000-7000-8000-${Number(id).toString().padStart(12, "0")}`,
  action: "device.created",
  created_at: new Date(Date.UTC(2026, 7, 1, 10) - Number(id) * 1000).toISOString(),
  actor_id: "u1",
  target_type: "device",
  target_id: "d1",
});

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(
        async (
          path: string,
          opts?: { params?: { query?: Record<string, unknown> } },
        ) => {
          if (path === "/api/v1/auth/me")
            return { data: { id: "u1", email: "a@b.c", email_verified: true } };
          if (path === "/api/v1/organizations")
            return { data: [{ id: "org-1", name: "Acme" }] };
          if (path.endsWith("/members"))
            return {
              data: [
                {
                  user_id: "u1",
                  email: "a@b.c",
                  name: "Ada Auditor",
                  role: viewerRoles[0],
                  roles: viewerRoles,
                  status: "active",
                  email_verified: true,
                  joined_at: "2026-01-01T00:00:00Z",
                },
              ],
            };
          if (path.endsWith("/audit-logs")) {
            queries.push(opts?.params?.query ?? {});
            if (logFail)
              return {
                data: undefined,
                error: { error: { code: "boom", message: "nope" } },
              };
            // Honor the real keyset and size probe, including the undisplayed probe on the next page.
            const query = opts?.params?.query ?? {};
            if (query.cursor_id && emptyLaterPage) return { data: [] };
            const first = query.cursor_id ? Number(String(query.cursor_id).slice(-12)) + 1 : 0;
            return { data: Array.from({ length: 53 }, (_, i) => ENTRY(String(i))).slice(first, first + Number(query.limit ?? 21)) };
          }
          return { data: [] };
        },
      ),
      POST: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { MemoryRouter } from "react-router-dom";
import { OrgProvider } from "../src/lib/useOrg";
import AuditLog from "../src/pages/AuditLog";
import { AuthProvider } from "../src/lib/auth";

const withAuth = (ui: React.ReactElement, initialEntry = "/audit") =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <MemoryRouter initialEntries={[initialEntry]}><AuthProvider>
      <OrgProvider>{ui}</OrgProvider>
    </AuthProvider></MemoryRouter>,
  );

beforeEach(() => {
  queries.length = 0;
  logFail = false;
  emptyLaterPage = false;
  viewerRoles = ["owner"];
});

describe("AuditLog — AI roles keep a self-activity view", () => {
  it.each([["member"], ["ai-view"], ["ai-admin"], ["ai-admin", "member"], ["ai-view", "member"]])("scopes %j to the signed-in user's activity", async (...roles) => {
    viewerRoles = roles;
    withAuth(<AuditLog />);
    await screen.findByText("Showing your activity only. Organization-wide activity is visible to admins and owners.");
    expect((screen.getByRole("combobox", { name: "Actor" }) as HTMLSelectElement).disabled).toBe(true);
  });
  it.each([["admin", "ai-view"], ["owner", "ai-admin"]])("retains organization audit access for %j", async (...roles) => {
    viewerRoles = roles;
    withAuth(<AuditLog />);
    await screen.findByRole("table", { name: "Audit events" });
    expect(screen.queryByText("Showing your activity only. Organization-wide activity is visible to admins and owners.")).toBeNull();
    expect((screen.getByRole("combobox", { name: "Actor" }) as HTMLSelectElement).disabled).toBe(false);
  });
});

describe("AuditLog — wiring: paging must use the APPLIED filter set, not the one being edited", () => {
  it("pages with applied filters while a draft filter is edited", async () => {
    withAuth(<AuditLog />);

    const loadMore = await waitFor(() =>
      screen.getByRole("button", { name: "Next audit events" }),
    );
    expect(queries.at(-1)?.action).toBeUndefined(); // the initial page: no filters applied

    // Edit a filter WITHOUT applying it. This is the mid-edit state the comment warns about.
    fireEvent.change(screen.getByRole("combobox", { name: "Action" }), {
      target: { value: "policy.rule_enabled" },
    });

    fireEvent.click(loadMore);

    // THE DECISION: the next page must carry the APPLIED filter set (empty), plus a cursor. Carrying the
    // mid-edit `action` would append rows from a DIFFERENT query onto the current list — and the cursor,
    // which came from the applied list, would be meaningless against it.
    await waitFor(() => expect(queries.length).toBeGreaterThan(1));
    const paged = queries.at(-1)!;
    expect(paged.action).toBeUndefined();
    expect(paged.cursor_id).toBeDefined();
  });
});

describe("AuditLog — failure path", () => {
  // D1(b). An empty audit log reads as "nothing happened" — which on a compliance surface is a claim, not an
  // absence of data. A failed load has no standing to make it.
  it("a failed load is surfaced rather than rendering as an empty history", async () => {
    logFail = true;
    withAuth(<AuditLog />);

    await waitFor(() => screen.getByText(/Could not load the audit log\./));
  });
});

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE ACTOR COLUMN — asserting a NAME, never the fallback.
//
// ⛔ WHY THIS TEST EXISTS AND DID NOT BEFORE. The mock sent `actor_user_id`; the page reads `actor_id`; the
// suite passed. Every row rendered "system", and no assertion ever looked at the actor column — so the only
// branch ever exercised was the one nobody wanted.
//
//   THE MOCK AND THE PAGE DISAGREED, THE TEST PASSED, AND THE PASSING BRANCH WAS THE ONE NOBODY WANTED.
//   A FALLBACK THAT IS NEVER EXERCISED DELIBERATELY IS A FALLBACK THAT IS ALWAYS EXERCISED ACCIDENTALLY.
//
// This is the audit surface, where mis-attributing a human act to the system is the exact failure the feature
// exists to prevent. So the assertion is on the NAME.
// ══════════════════════════════════════════════════════════════════════════════════════════════════════════

describe("AuditLog — the actor column names the human", () => {
  it("⛔ renders the ACTOR'S NAME for a human-actor row, not 'system'", async () => {
    withAuth(<AuditLog />);
    const table = await waitFor(() =>
      screen.getByRole("table", { name: /audit|activity/i }),
    );
    // The roster resolves u1 -> "Ada Auditor". If `actor_id` is ever renamed or dropped from the mock again,
    // this goes red instead of silently falling back.
    await waitFor(() =>
      expect(within(table).getAllByText("Ada Auditor").length).toBeGreaterThan(
        0,
      ),
    );

    // AND the fallback must NOT be what these rows render. Both halves: a name present, the fallback absent.
    const firstRow = within(table)
      .getAllByRole("row")
      .find((r) => r.textContent?.includes("Ada Auditor"))!;
    expect(firstRow.textContent).not.toMatch(/\bsystem\b/);

    fireEvent.click(
      within(firstRow).getByRole("button", {
        name: "Inspect device.created audit event",
      }),
    );
    const dialog = screen.getByRole("region", { name: "Audit evidence" });
    expect(dialog).toBeTruthy();
    expect(within(dialog).getByText("device · d1")).toBeTruthy();
  });
});

describe("AuditLog — bounded server pages", () => {
  it("shows exactly the requested page and advances from its final displayed row", async () => {
    withAuth(<AuditLog />);
    const table = await screen.findByRole("table", { name: "Audit events" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    expect(queries[0]?.limit).toBe(21);
    fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
    await waitFor(() => expect(queries).toHaveLength(2));
    expect(queries[1]).toMatchObject({ cursor_id: ENTRY("19").id, cursor_ts: ENTRY("19").created_at, limit: 21 });
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Audit events" })).getAllByRole("row")).toHaveLength(21));
    const requests = queries.length;
    fireEvent.click(screen.getByRole("button", { name: "Previous audit events" }));
    expect(queries).toHaveLength(requests);
    expect(within(screen.getByRole("table", { name: "Audit events" })).getAllByRole("row")).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
    expect(queries).toHaveLength(requests);
    fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
    await waitFor(() => expect(queries).toHaveLength(3));
    expect(queries[2]).toMatchObject({ cursor_id: ENTRY("39").id, cursor_ts: ENTRY("39").created_at });
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Audit events" })).getAllByRole("row")).toHaveLength(14));
    expect((screen.getByRole("button", { name: "Next audit events" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Previous audit events" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("changes the real server limit and resets the cursor when the page size changes", async () => {
    withAuth(<AuditLog />);
    await screen.findByRole("table", { name: "Audit events" });
    fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
    await waitFor(() => expect(queries).toHaveLength(2));
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    await waitFor(() => expect(queries).toHaveLength(3));
    expect(queries[2].limit).toBe(11);
    expect(queries[2].cursor_id).toBeUndefined();
    expect(queries[2].cursor_ts).toBeUndefined();
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Audit events" })).getAllByRole("row")).toHaveLength(11));
  });
});


it("application audit links scope the initial query and preserve that scope while paging", async () => {
  const appId = "11111111-1111-4111-8111-111111111111";
  withAuth(<AuditLog />, `/audit?target_type=app_access&target_id=${appId}`);
  await screen.findByRole("table", { name: "Audit events" });
  expect(queries[0]).toMatchObject({ target_type: "app_access", target_id: appId });
  fireEvent.change(screen.getByLabelText("Target UUID"), { target: { value: "22222222-2222-4222-8222-222222222222" } });
  fireEvent.click(await screen.findByRole("button", { name: "Next audit events" }));
  await waitFor(() => expect(queries.length).toBe(2));
  expect(queries[1]).toMatchObject({ target_type: "app_access", target_id: appId, cursor_id: expect.any(String) });
});

it("an invalid deep-link target refuses an audit read until corrected", async () => {
  withAuth(<AuditLog />, "/audit?target_type=app_access&target_id=invalid");
  await screen.findByText("Choose a valid target UUID.");
  expect(queries).toHaveLength(0);
  fireEvent.change(screen.getByLabelText("Target UUID"), { target: { value: "11111111-1111-4111-8111-111111111111" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(queries).toHaveLength(1));
});


it("retries the failed audit keyset unchanged and preserves Previous when the later page is empty", async () => {
  withAuth(<AuditLog />); await screen.findByRole("table", { name: "Audit events" });
  logFail = true;
  fireEvent.click(screen.getByRole("button", { name: "Next audit events" }));
  await screen.findByText(/Could not load the audit log\./);
  const failed = queries[1];
  logFail = false; emptyLaterPage = true;
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await screen.findByText("No events on this page");
  expect(queries[2]).toEqual(failed);
  expect(screen.getByText("0 results")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Previous audit events" }));
  expect(within(screen.getByRole("table", { name: "Audit events" })).getAllByRole("row")).toHaveLength(21);
  expect(queries).toHaveLength(3);
});
