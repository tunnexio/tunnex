import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
  within,
} from "@testing-library/react";

// SLICE 2 — Devices. It is the REFERENCE IMPLEMENTATION for revoked-suppression: the surface that always had
// the guard (`d.status !== "revoked" && …`) while Gateways.tsx lacked it (WF-S11-10) and Sites.tsx still lacked
// it until this branch. So its wiring test is also HALF OF D4's three-way assertion, and the sibling file reads
// from the same production functions rather than restating the rule — a fixture that restates production tests
// the restatement, which is WF-S13-3's class.
//
// QUERY STRATEGY (docs/UI-REDESIGN-registration.md consequence 2): role + accessible name for anything that
// carries a role; mocking at the NETWORK boundary (api.GET / api.POST), never the component boundary, because
// that layer does not change in a redesign. getByText appears only for content with NO role today — status
// badges and empty states are <span>/<li> — and each such use is a MARKER that the element should gain
// role="status"/role="alert" in the redesign, not an exemption.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let devicesFail = false;
// ⛔ RECONCILED TO THE FIXTURE (S14.10). Every device below now EXISTS in `make seed-fixtures`, and every
// state asserted here is one the seeded stack can actually render. Before this the mock asserted three states
// the fixture could not produce, which is the inversion that let 522 tests pass while the POSTURE column
// rendered blank:
//
//   health_blocked: true   -> ZERO blocked devices were seeded. `posture blocked` — the DANGER tone, the
//                             highest-severity posture state — HAD NEVER RENDERED ON LOCALHOST, and the device
//                             named `blocked-device` was not blocked. It is unreachable from SQL (see the
//                             register): the seeder now POSTs a real health report for it.
//   needs_reexport: true   -> asserted twice, ONE static device seeded. Now two.
//   revoked + posture      -> `old-laptop` is revoked and had NO health row, so the suppression this file
//                             exists to pin could never be observed on the screen.
//
// `thinkpad-erin` was the one device here with no seeded counterpart at all. It is now `thinkpad-erin`, which
// carries the same shape (active + noncompliant) and is a real fixture row.
const DEVICES = [
  // REVOKED and posture-bearing: the row whose badges must be suppressed. This is the shape Gateways got wrong.
  // ⛔ THIS SHAPE IS NOW SEEDED (S14.10): `old-laptop` has a real device_health row, so the suppression is
  // observable on localhost instead of only here. It also has assigned_ip NULL on the wire — the revoked sweep
  // frees the pool IP — so the ADDRESS cell's placeholder is exercised by the same row.
  {
    id: "d-revoked",
    name: "old-laptop",
    status: "revoked",
    assigned_ip: "10.99.0.9",
    health_state: "noncompliant",
    health_blocked: true,
    needs_reexport: true,
  },
  {
    // Was `thinkpad-erin`, which the fixture could not produce. `thinkpad-erin` is seeded active+noncompliant.
    // health_blocked stays FALSE here: only ONE seeded device is blocked, and that is deliberate — a loop that
    // blocked every device destroyed the fixture's posture spread once already, and the spread is the only
    // thing that makes this column reviewable.
    id: "d-active",
    name: "thinkpad-erin",
    status: "active",
    assigned_ip: "10.99.0.12",
    health_state: "noncompliant",
    health_blocked: false,
    needs_reexport: false,
  },
  {
    // THE BLOCKED ROW, and it is its own device because exactly one seeded device is blocked. Reachable only
    // through ReportHealth — the seeder registers it through the product.
    id: "d-blocked",
    name: "blocked-device",
    status: "active",
    assigned_ip: "10.99.0.18",
    health_state: "noncompliant",
    health_blocked: true,
    needs_reexport: true,
  },
  {
    id: "d-pending",
    name: "unapproved-phone",
    status: "pending",
    assigned_ip: "10.99.0.15",
  },
  {
    id: "d-stale-reexport",
    name: "stale-laptop",
    status: "active",
    assigned_ip: "10.99.0.16",
    needs_reexport: true,
  },
  {
    id: "d-ovpn",
    name: "ovpn-contractor",
    status: "active",
    public_key: "",
    assigned_ip: "10.99.0.17",
  },
  {
    id: "d-stale-posture",
    name: "stale-device",
    status: "active",
    assigned_ip: "10.99.0.19",
    health_state: "unknown",
    health_reported_at: "2026-07-16T00:00:00Z",
  },
  {
    id: "d-blocked",
    name: "blocked-device",
    status: "active",
    assigned_ip: "10.99.0.18",
    health_state: "noncompliant",
    health_blocked: true,
  },
];

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, fallback: string) => fallback,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/devices")) {
          // THE FAILURE PATH under test: the load REFUSES. The page must not render this as "no devices".
          if (devicesFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: DEVICES };
        }
        if (path.endsWith("/nodes"))
          return {
            data: [
              {
                id: "n-1",
                name: "gw",
                status: "active",
                agent_version: "0.1.0",
              },
            ],
          };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import Devices, { lastSeen } from "../src/pages/Devices";

beforeEach(() => {
  devicesFail = false;
});

// ⚠ RE-POINTED AT ROLES IN S14.3 SLICE A, and the re-pointing is half the slice.
//
// These assertions used to match device names as FREE TEXT, because until slice A there was no `<table>`
// anywhere in the app and therefore no `role="row"` or `role="cell"` to ask for. The primitive's absence had
// made the TESTS weaker, not only the UI — and a primitive that ships while its consumers keep the workaround
// has only half landed (docs/laws.md).
//
// What changes materially: `getByText("old-laptop")` passes if that string appears ANYWHERE — a heading, a
// tooltip, a modal, a toast. `within(row).getByText(...)` passes only if it is in THAT DEVICE'S ROW. The old
// query could not tell "the revoked device shows a posture badge" from "a posture badge exists on the page".

/** The row for a device, found by its name — the query that was impossible before slice A. */
function rowFor(name: string): HTMLElement {
  const table = screen.getByRole("table", { name: "Devices" });
  const row = within(table)
    .getAllByRole("row")
    .find((r) => within(r).queryByText(name));
  if (!row) throw new Error(`no row for device "${name}"`);
  return row;
}

describe("Devices — wiring", () => {
  it("a REVOKED device carries no posture badge and no re-export instruction; an active one carries both", async () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByRole("table", { name: "Devices" })).toBeTruthy(),
    );

    // Two devices are posture-blocked and both need re-export. Only the ACTIVE one may say so — the revoked
    // row's badges would describe a device that is no longer meant to work, and "re-export needed" would be an
    // instruction to act on a device that cannot come back.
    //
    // ASSERTED PER ROW, which is the upgrade. The old page-wide count would have passed even if both badges
    // sat on the WRONG device, as long as there was one of each.
    // ⛔ THE CARRIER IS `blocked-device`, NOT `thinkpad-erin`. Reconciling the mock to the fixture SPLIT these
    // roles: exactly one seeded device is blocked, so the blocked+needs-reexport shape became its own row and
    // `thinkpad-erin` is active+noncompliant only. A blanket rename pointed this assertion at the device that
    // no longer carries the badges — the test caught it, which is the point of asserting PER ROW.
    expect(
      within(rowFor("blocked-device")).queryByText("posture blocked"),
    ).toBeTruthy();
    expect(
      within(rowFor("blocked-device")).queryByText("re-export needed"),
    ).toBeTruthy();
    expect(
      within(rowFor("old-laptop")).queryByText("posture blocked"),
    ).toBeNull();
    expect(
      within(rowFor("old-laptop")).queryByText("re-export needed"),
    ).toBeNull();
  });

  it("both devices are listed — suppression hides BADGES, never the row itself", async () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    const table = await waitFor(() =>
      screen.getByRole("table", { name: "Devices" }),
    );
    // The distinction matters: an operator must still see a revoked device exists. Suppressing the row would
    // trade a wrong badge for a missing fact.
    //
    // 9 rows = 1 header + 8 devices (old-laptop, thinkpad-erin, unapproved-phone, stale-laptop,
    // ovpn-contractor, stale-device, blocked-device, and the blocked row that is now its own device).
    //
    // ⛔ THE NUMBER MOVED IN A REVIEWED EDIT, WHICH IS THE CENSUS WORKING. It went 8 -> 9 because the mock was
    // reconciled to the fixture: `thinkpad-erin` did not exist in `seed-fixtures`, and the BLOCKED shape had to
    // become its own row because exactly one seeded device is blocked. Counting rows is a stronger claim than
    // "these strings appear" — it also fails if an unexpected device were rendered.
    expect(within(table).getAllByRole("row")).toHaveLength(9);
    // The address, pending status, and posture blocked label are asserted ON THEIR OWN DEVICE'S ROW.
    expect(within(rowFor("old-laptop")).getByText("10.99.0.9")).toBeTruthy();
    expect(
      within(rowFor("unapproved-phone")).getByText("pending"),
    ).toBeTruthy();
    expect(
      within(rowFor("blocked-device")).getByText("posture blocked"),
    ).toBeTruthy();
  });

  it("the table names its columns — a cell with no header is a value nobody can identify", async () => {
    expect(lastSeen(undefined, false)).toBe("liveness not reported");
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByRole("table", { name: "Devices" })).toBeTruthy(),
    );
    // ⚠ "Actions" left this list because the verbs left the ROWS — Approve / Reject / Revoke now live in
    // the selection bar. The claim is unchanged (every column a reader sees is named); the affordance it
    // used to head is asserted below, where it now lives.
    for (const h of ["Device", "Address", "State", "Posture"]) {
      expect(screen.getByRole("columnheader", { name: h }), h).toBeTruthy();
    }
    expect(screen.getAllByRole("checkbox").length).toBeGreaterThan(0);
  });
});

describe("Devices — failure path", () => {
  // D1(b). The loadOne law's violation mode is a REASSURING EMPTY STATE: the screen renders perfectly and tells
  // the user nothing. `loadDevices` sets the error and returns EARLY, so `devices` stays empty and the page
  // shows both the error and "No devices yet." — the error is what must never go missing.
  it("a failed device load is SURFACED, never swallowed into 'no devices'", async () => {
    devicesFail = true;
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByText("Could not load devices.")).toBeTruthy(),
    );
  });

  it("an empty-but-successful load says so in words", async () => {
    devicesFail = false;
    DEVICES.length = 0; // an org with no devices — a FACT, not a failure
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No devices yet.")).toBeTruthy(),
    );
    // And with no failure, no error line is present — the two states must stay distinguishable.
    expect(screen.queryByText("Could not load devices.")).toBeNull();
    DEVICES.push(
      {
        id: "d-revoked",
        name: "old-laptop",
        status: "revoked",
        assigned_ip: "10.99.0.9",
        health_state: "noncompliant",
        health_blocked: true,
        needs_reexport: true,
      },
      {
        id: "d-active",
        name: "thinkpad-erin",
        status: "active",
        assigned_ip: "10.99.0.3",
        health_state: "noncompliant",
        health_blocked: true,
        needs_reexport: true,
      },
    );
  });
});

/**
 * ⛔ A STATE A SURFACE DISPLAYS AND CANNOT ACT ON IS A DEAD END.
 *
 * This page listed a device with a `pending` badge and rendered its Actions cell `null` — Revoke was offered
 * for `active` only. Approve and Reject existed, and their sole call site was the Device-approval card on
 * ACCESS POLICIES, so an operator looking straight at a pending device had to already know it was governed
 * from a different screen. Found by the founder, on the screen where it is most obvious.
 */
describe("Devices — a pending device can be acted on HERE", () => {
  // ⚠ `DEVICES` is a SHARED, MUTATED array — an earlier test in this file empties and refills it, so an
  // appended test inherits whatever ran before. Set it explicitly rather than depending on order.
  const seed = (rows: unknown[]) => {
    DEVICES.length = 0;
    (DEVICES as unknown[]).push(...rows);
  };

  it("⛔ APPROVE IS OFFERED ON A PENDING DEVICE — the verb that had no call site on this screen", async () => {
    seed([
      {
        id: "d-p",
        name: "unapproved-phone",
        status: "pending",
        assigned_ip: "10.99.0.15",
      },
    ]);
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByRole("table", { name: "Devices" })).toBeTruthy(),
    );
    fireEvent.click(
      await screen.findByRole("checkbox", { name: /^Select unapproved-phone/ }),
    );

    expect(
      screen.getByRole("button", { name: "Approve" }).hasAttribute("disabled"),
    ).toBe(false);
    expect(
      screen.getByRole("button", { name: "Reject" }).hasAttribute("disabled"),
    ).toBe(false);

    // ⛔ AND REVOKE IS *NOT* OFFERED FOR IT, with the reason. A pending device is REJECTED, not revoked —
    // two different decisions — and revoking one would be a no-op the server reports as success.
    const revoke = screen.getByRole("button", { name: "Revoke" });
    expect(revoke.hasAttribute("disabled")).toBe(true);
    expect(revoke.getAttribute("title")).toMatch(
      /pending device cannot be revoked/,
    );
  });

  it("⚠ …AND THE CONVERSE, so 'always enabled' cannot pass: an ACTIVE device revokes and cannot be approved", async () => {
    seed([
      {
        id: "d-a",
        name: "live-laptop",
        status: "active",
        assigned_ip: "10.99.0.20",
      },
    ]);
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByRole("table", { name: "Devices" })).toBeTruthy(),
    );
    fireEvent.click(
      await screen.findByRole("checkbox", { name: /^Select live-laptop/ }),
    );

    expect(
      screen.getByRole("button", { name: "Revoke" }).hasAttribute("disabled"),
    ).toBe(false);
    expect(
      screen.getByRole("button", { name: "Approve" }).hasAttribute("disabled"),
    ).toBe(true);
  });
});
