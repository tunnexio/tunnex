import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";

// SLICE 5 — Sites. First of the two SHEDDERS, and the shedder constraint drives how these are written.
//
// ⚠ THE REDESIGN SPLITS THIS SCREEN. `Sites.tsx` keeps `sites` and sheds ROUTED RANGES to a NEW `subnets`
// screen (docs/UI-REDESIGN-registration.md — the wireframe declares `subnets` in the main nav). So every
// assertion below is written against the DECISION and NAMES ITS DESTINATION:
//
//   "a routed range that is PENDING must not read as ROUTED"  -> travels to `subnets`
//   "the Sites page shows a routed-range list"                -> does NOT travel, and would be throwaway work
//
// The decision under test is what the user is told about REACHABILITY. A pending subnet is advertised but NOT
// yet routed; presenting it as routed tells an admin a LAN is reachable when it is not, and the inverse hides
// one that is. Neither is a rendering preference.
//
// QUERY RULES 1-4 BIND: role + accessible name; NETWORK-boundary mocks; decisions not rendering; and no
// assertion may assume a viewport — nothing here depends on layout, column order, or width-conditional
// visibility.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let sitesFail = false;

const SITES = [{ id: "s1", name: "aws-site" }];
const SUBNETS = [
  {
    id: "sub-approved",
    site_id: "s1",
    cidr: "172.31.0.0/16",
    status: "approved",
  },
  { id: "sub-pending", site_id: "s1", cidr: "10.50.0.0/16", status: "pending" },
];

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
        if (path === "/api/v1/meta")
          return { data: { edition: "enterprise", protocol_version: 5 } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: "admin", email_verified: true }],
          };
        if (path.endsWith("/sites")) {
          if (sitesFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: SITES };
        }
        if (path.endsWith("/nodes")) return { data: [] };
        if (path.includes("/subnets")) return { data: SUBNETS };
        if (path.endsWith("/site-subnets/pending")) return { data: [] };
        if (path.endsWith("/hub-set")) return { data: null };
        if (path.endsWith("/dns-forwards")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import Sites from "../src/pages/Sites";
import { AuthProvider } from "../src/lib/auth";
import { crossesMultiSiteThreshold } from "../src/lib/sitesview";

// The REAL AuthProvider — stubbing the context puts the TEST's role gate under assertion, not the PRODUCT's.
const withAuth = (ui: React.ReactElement) =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <AuthProvider>
      <OrgProvider>{ui}</OrgProvider>
    </AuthProvider>,
  );

beforeEach(() => {
  sitesFail = false;
});

describe("Sites — wiring: a routed range must not lie about REACHABILITY (destination: `subnets`)", () => {
  it("a PENDING range is marked pending; an APPROVED one is not — the two must stay distinguishable", async () => {
    withAuth(<Sites />);
    // WAIT ON THE THING BEING ASSERTED. The first draft waited on the CIDR text and then queried the title —
    // which raced a partially-rendered tree and passed locally while failing in the gate's container. A
    // waitFor whose condition is weaker than the assertion is not synchronisation, it is luck.
    // Timeout raised above waitFor's 1s default: the FIRST test in a file pays module-init + the page's
    // multi-request load chain, and the gate's container is slower than a dev machine. Evidence it is latency
    // and not absence: the next test asserts the SAME element and passes. A default that works locally and
    // times out in CI is the local-equivalent trap one layer down.
    // WAIT FOR BOTH, then assert. Waiting on only one let the test proceed while the other had not rendered:
    // pending appears BEFORE approved, so test 1 raced ahead and failed on the approved chip while test 2 —
    // which happened to wait on the LATER one — passed. Two tests over the same elements disagreeing is the
    // tell. The rule generalises: a waitFor must cover EVERY element the assertions touch, not the first one
    // that happens to appear.
    const [pendingEl, approvedEl] = await waitFor(
      () => [
        screen.getByRole("listitem", {
          name: /Pending approval, not yet routed/,
        }),
        screen.getByRole("listitem", { name: /Approved, routed/ }),
      ],
      { timeout: 5000 },
    );

    // The decision: pending means ADVERTISED BUT NOT ROUTED. If both rendered identically an admin would read
    // an unapproved LAN as reachable — or, inverted, treat a routed one as still waiting.
    //
    // Queried BY TITLE (the accessible name), not by a regex spanning sibling text nodes. The first draft did
    // the latter and passed locally while FAILING IN THE GATE'S CONTAINER: `{s.cidr}` and `" · pending"` are
    // separate JSX children, so matching across them depends on how a given @testing-library/dom build
    // normalizes whitespace between nodes. That is a DOM-STRUCTURE dependency, which query rule 1 forbids —
    // and the gate caught it, which is the argument for running the gate's own command.
    expect(pendingEl.textContent).toContain("10.50.0.0/16");
    expect(pendingEl.textContent).toContain("pending");

    expect(approvedEl.textContent).toContain("172.31.0.0/16");
    expect(approvedEl.textContent).not.toContain("pending");
  });

  // ⛔ QUERIED BY ROLE + ACCESSIBLE NAME (query rule 1), not by `title`.
  //
  // These asserted `getByTitle`, which is neither a role nor an accessible name — and the chip it queried was
  // a role-less <span> whose `title` a screen reader does not reliably announce. So the test was BOTH a rule-1
  // violation AND evidence of a real defect: the reachability claim, load-bearing in two assertions, was not
  // announced to anyone using assistive tech.
  //
  // THE FIX WAS THE CHIP, NOT THE QUERY. It is now role="listitem" inside role="list", with an aria-label
  // carrying the range AND its state. Fixing the query alone would have kept the test green over a chip that
  // still said nothing.
  it("the reachability claim is carried in the accessible name, not by colour alone", async () => {
    withAuth(<Sites />);
    // ⛔ THE WAITFOR COVERS BOTH TITLES, AND IT DID NOT UNTIL S14.5.
    //
    // It waited for "Approved, routed" alone and then asserted on the PENDING one — the exact defect the test
    // directly above documents in its own comment, one test down, unnoticed. It passed for months because
    // both chips render in the same commit; it started failing only when the FULL suite ran slower than the
    // file alone, which is the definition of a race that was always there.
    //
    // SAME SHAPE AS THE MISSING-PRIMITIVE LAW: a lesson written at one call site does not reach the call site
    // beside it. Writing the rule in a comment is not applying it.
    const [approvedEl, pendingEl] = await waitFor(
      () => [
        screen.getByRole("listitem", { name: /Approved, routed/ }),
        screen.getByRole("listitem", {
          name: /Pending approval, not yet routed/,
        }),
      ],
      { timeout: 5000 },
    );
    // The pending counterpart must say the opposite in words. Colour-only differentiation would fail both a
    // screen reader and the accessibility gate the redesign now carries (registration consequence 1).
    expect(approvedEl).toBeTruthy();
    expect(pendingEl).toBeTruthy();
  });

  // The CW crossing decision, asserted through the production function rather than restated. It travels with
  // routed ranges to `subnets`: approving a range that makes the org multi-site routable for the FIRST time is
  // the moment that needs a confirm, and it is a property of the ranges, not of the page.
  it("crossing into multi-site routability is detected only on the FIRST crossing", () => {
    // The approving site contributes nothing yet and exactly one OTHER site does -> this approval crosses.
    expect(crossesMultiSiteThreshold("s2", { s1: 1 })).toBe(true);
    // Already contributing -> not a crossing.
    expect(crossesMultiSiteThreshold("s1", { s1: 1 })).toBe(false);
    // Nobody else routes yet -> still single-site.
    expect(crossesMultiSiteThreshold("s2", {})).toBe(false);
    // Already multi-site -> the crossing happened earlier; do not re-confirm.
    expect(crossesMultiSiteThreshold("s3", { s1: 1, s2: 1 })).toBe(false);
  });
});

describe("Sites — failure path", () => {
  // D1(b). On this surface an empty topology reads as "this org has no sites" — a statement about the network
  // that a failed load has no standing to make.
  it("a failed sites load renders a retry, not an empty topology", async () => {
    sitesFail = true;
    withAuth(<Sites />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy(),
    );
  });
});
