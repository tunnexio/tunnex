import { describe, expect, it, vi, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  cleanup,
  within,
  fireEvent,
  act,
} from "@testing-library/react";

// S14.2 LAYER 3 — THE RESPONSIVE CONTRACT.
//
// The assertions that actually protect users, and the reason the capability is INJECTED rather than measured:
// jsdom has no layout engine, so `window.innerWidth = 375` would change a number nothing reads. Injecting the
// capability is not a shortcut around the real check — it IS the real check, because the capability is what the
// product branches on. Width is only ever an input to `layoutIntent`, and that is gated in layout.test.ts.
//
// QUERY RULES 1-5 BIND. Rule 4 in particular: no assertion below assumes a viewport. They assume a CAPABILITY,
// which is a value.

afterEach(cleanup); // no globals/setup file, so auto-cleanup never registers (docs/laws.md)

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: "admin", email_verified: true }],
          };
        if (path.endsWith("/zero-trust-mode"))
          return { data: { mode: "enforcing" } };
        if (path.endsWith("/groups"))
          return { data: [{ id: "g1", name: "Everyone" }] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { MemoryRouter } from "react-router-dom";
import { OrgProvider } from "../src/lib/useOrg";
import { AppShell, NAV_DESTINATIONS } from "../src/components/AppShell";
import { LayoutCapabilityProvider } from "../src/components/ComposeGate";
import { capabilityFor, type LayoutIntent } from "../src/lib/layout";
import { AuthProvider } from "../src/lib/auth";
import Access from "../src/pages/Access";

const INTENTS: LayoutIntent[] = ["triage", "compose", "operate", "wide", "max"];

function renderShell(intent: LayoutIntent) {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <LayoutCapabilityProvider value={capabilityFor(intent)}>
        <AuthProvider>
          <OrgProvider>
            <AppShell />
          </OrgProvider>
        </AuthProvider>
      </LayoutCapabilityProvider>
    </MemoryRouter>,
  );
}

/** The destination set of the MAIN nav landmark, opening the drawer first if the shell put one there. */
async function mainNavHrefs(): Promise<string[]> {
  // fireEvent, not user-event: a single click on a button needs no typing/pointer simulation, and the phantom
  // dependency this tier already shipped once is reason enough not to add a package for it.
  const menu = screen.queryByRole("button", { name: /menu/i });
  if (menu) act(() => fireEvent.click(menu));
  const nav = await screen.findByRole("navigation", { name: "Main" });
  return within(nav)
    .getAllByRole("link")
    .map((a) => a.getAttribute("href")!)
    .sort();
}

describe("RESPONSIVE MAY RE-ARRANGE, NEVER REMOVE", () => {
  // The invariant, stated as the founder ruled it: PERMISSION IS A RENDER DECISION; WIDTH NEVER IS. A
  // destination that exists for a laptop user and not for a phone user is a navigation surface decided by
  // viewport, which is a decision nobody made.
  const expected = NAV_DESTINATIONS.map((d) => d.to).sort();

  for (const intent of INTENTS) {
    it(`[${intent}] the main nav carries EVERY destination`, async () => {
      renderShell(intent);
      await waitFor(async () => expect(await mainNavHrefs()).toEqual(expected));
    });
  }

  it("the destination list is non-trivial — parity over an empty nav would hold vacuously", () => {
    // Without this, deleting NAV_GROUPS entirely would make all five assertions above compare [] to [] and
    // pass. The parity check compares the render to the source, so the source has to be asserted too.
    expect(expected.length).toBeGreaterThanOrEqual(8);
  });

  it("[triage] the drawer is BEHIND a menu button, and its links are absent until it is opened", async () => {
    // The one honest concession, and it is deliberate: an off-canvas panel whose links stay in the accessible
    // tree is a keyboard trap — tab order walks destinations the user cannot see. So the closed drawer is
    // genuinely absent, and the invariant it satisfies is that OPENING it yields the full set (asserted above).
    renderShell("triage");
    expect(screen.getByRole("button", { name: /menu/i })).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
  });

  it("[operate] there is no menu button — the rail is already open", async () => {
    renderShell("operate");
    expect(screen.queryByRole("button", { name: /menu/i })).toBeNull();
    expect(
      await screen.findByRole("navigation", { name: "Main" }),
    ).toBeTruthy();
  });

  it("[triage] the triage bar carries a SUBSET of the real destinations, never a destination of its own", async () => {
    renderShell("triage");
    const bar = await screen.findByRole("navigation", { name: "Triage" });
    const hrefs = within(bar)
      .getAllByRole("link")
      .map((a) => a.getAttribute("href")!);
    expect(hrefs.length).toBeGreaterThan(0);
    for (const h of hrefs)
      expect(expected, `${h} is not a real destination`).toContain(h);
  });

  it("the triage bar exists ONLY at triage — a second nav surface on a laptop is duplication, not redundancy", async () => {
    renderShell("operate");
    await screen.findByRole("navigation", { name: "Main" });
    expect(screen.queryByRole("navigation", { name: "Triage" })).toBeNull();
  });
});

describe("COMPOSITION IS ABSENT BELOW THE FLOOR — asserted BY ROLE, so `display:none` FAILS", () => {
  // This is the assertion the whole gate exists for, and its FORM is the point.
  //
  // ⚠ `hidden: true` IS LOAD-BEARING, AND IT IS THERE BECAUSE THE MUTATION PROOF CAUGHT ITS ABSENCE.
  //
  // The first version of this test used a plain `queryByRole`, with a comment claiming it "finds a hidden
  // element, so a display:none implementation fails". THAT CLAIM IS FALSE. testing-library defaults to
  // `hidden: false` and runs `isInaccessible`, which jsdom evaluates against inline styles — so an element
  // with `display:none` is EXCLUDED from the query, `queryByRole` returns null, and the assertion passes.
  //
  // Mutation 1 (implement the gate as `display:none`) PASSED under that assertion. The test asserted
  // "not in the accessible tree" while its comment claimed "not in the DOM" — and those two differ on exactly
  // the failure mode being guarded against. It is the same family the repo already has a law for: an
  // assertion that checks a different event than the one it claims to check.
  //
  // With `hidden: true` the query searches the whole DOM regardless of visibility, so ABSENCE is what is
  // asserted, the mutation goes red, and the test finally distinguishes HIDDEN from ABSENT — which is the
  // whole point, since a control that grants access, present to a keyboard and gone only to a sighted mouse
  // user, is a security-adjacent surface failing open (docs/laws.md — INVISIBLE IS NOT ABSENT).
  function renderAccess(intent: LayoutIntent) {
    return render(
      <MemoryRouter>
        <OrgProvider>
        <LayoutCapabilityProvider value={capabilityFor(intent)}>
          <AuthProvider>
            <Access />
          </AuthProvider>
        </LayoutCapabilityProvider>
      </OrgProvider>
      </MemoryRouter>,
    );
  }

  it("[operate] an admin gets the rule builder", async () => {
    renderAccess("operate");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /add rule/i })).toBeTruthy(),
    );
  });

  it("[triage] the rule builder is NOT IN THE DOM", async () => {
    renderAccess("triage");
    // Wait on the surface being loaded before asserting an absence — asserting "not there" against a screen
    // that has not finished loading passes for the wrong reason (docs/laws.md, the vacuous-check family).
    await waitFor(() => expect(screen.getByText(/Allow rules:/)).toBeTruthy());
    expect(
      screen.queryByRole("button", { name: /add rule/i, hidden: true }),
    ).toBeNull();
  });

  it("[triage] the honest line stands WHERE the builder was — never a blank space", async () => {
    renderAccess("triage");
    const note = await screen.findByRole("note");
    expect(note.textContent).toMatch(
      /Access rules are read-only on this screen size/,
    );
    expect(note.textContent).toMatch(/laptop or tablet/);
  });

  it("[operate] the honest line is absent when the builder is present — never both", async () => {
    renderAccess("operate");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /add rule/i })).toBeTruthy(),
    );
    expect(screen.queryByRole("note")).toBeNull();
  });
});
