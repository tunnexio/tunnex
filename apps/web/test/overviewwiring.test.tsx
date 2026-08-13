import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  cleanup,
  within,
} from "@testing-library/react";

// S14.4 — OVERVIEW. THE FAILURE PATHS ARE THE TEST; the happy path is the easy half.
//
// This screen's whole thesis is that "we have not learned this" and "the answer is zero" are different
// statements. Every assertion below is about which one gets rendered.

afterEach(cleanup);

let overviewFail = false;
let sitesFail = false;
let nodesFail = false;
let empty = false;
let edition: string | null = "enterprise";

const OV = () => ({
  members: empty ? 0 : 4,
  devices: empty ? 0 : 7,
  nodes: empty ? 0 : 2,
  online: empty ? 0 : 1,
  recent_activity: empty
    ? []
    : [{ action: "device.created", created_at: new Date().toISOString() }],
});

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  const err = { error: { code: "boom", message: "nope" } };
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta")
          return edition === null
            ? { data: undefined, ...err }
            : { data: { edition } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/overview"))
          return overviewFail ? { data: undefined, ...err } : { data: OV() };
        if (path.endsWith("/sites"))
          return sitesFail
            ? { data: undefined, ...err }
            : { data: empty ? [] : [{ id: "s1" }] };
        if (path.endsWith("/devices/pending")) return { data: [] };
        if (path.endsWith("/devices")) return { data: [] };
        // The hub-set endpoint returns an OBJECT, not a list. The catch-all `{ data: [] }` below fed an array
        // into hubSetView and threw — which surfaced as "cannot find Members", i.e. the whole page failing to
        // render. A catch-all mock is a fixture that answers questions it was never asked.
        if (path.endsWith("/hub-set"))
          return {
            data: {
              generation: 1,
              members: [{ node_id: "gw-a", role: "primary", hub_priority: 1 }],
            },
          };
        if (path.endsWith("/nodes"))
          return nodesFail
            ? { data: undefined, ...err }
            : {
                data: empty
                  ? []
                  : [
                      {
                        id: "n1",
                        name: "gw-a",
                        policy_degraded: true,
                        policy_degraded_kind: "silent_desync",
                      },
                    ],
              };
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
import Dashboard from "../src/pages/Dashboard";
import { AuthProvider } from "../src/lib/auth";

// MemoryRouter is required: the get-started panel links to /devices, and a bare render throws
// "Cannot destructure property 'basename'" — which surfaced as an UNHANDLED ERROR rather than a clean
// failure, so the visible symptom ("could not find Get started") pointed away from the cause.
const show = () =>
  render(
    <MemoryRouter>
      <OrgProvider>
        <AuthProvider>
          <Dashboard />
        </AuthProvider>
      </OrgProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  overviewFail = false;
  edition = "enterprise";
  sitesFail = false;
  nodesFail = false;
  empty = false;
});

describe("the six cards resolve INDEPENDENTLY — one failure degrades one card", () => {
  it("a failed /sites leaves the other five intact and marks only Sites unavailable", async () => {
    // The argument against an aggregated endpoint, asserted rather than argued: an API change driven by a
    // layout would convert three independent failures into one blast radius.
    sitesFail = true;
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.getByText("4")).toBeTruthy(); // members still resolved
    expect(screen.getByText("7")).toBeTruthy(); // devices still resolved
    expect(screen.getAllByText("could not load").length).toBe(1); // exactly one card degraded
  });
});

describe("⛔ A FAILED COUNT NEVER RENDERS AS ZERO", () => {
  it("a failed /sites shows 'unavailable', and no card shows 0", async () => {
    sitesFail = true;
    show();
    await waitFor(() => expect(screen.getByText("Sites")).toBeTruthy());
    await waitFor(() =>
      expect(screen.getByText("could not load")).toBeTruthy(),
    );

    // ⚠ THE ASSERTION HAD TO BE SHARPENED, AND THE FIRST VERSION WAS WRONG IN AN INSTRUCTIVE WAY.
    //
    // It was `expect(screen.queryByText("0")).toBeNull()` — "no card shows 0" — and it failed, correctly:
    // /devices/pending returned [] and the Pending-approvals card rendered a TRUE ZERO. We DID learn there
    // are none. That zero is honest and must render.
    //
    // The rule is not "never show 0". It is "NEVER SHOW 0 FOR SOMETHING WE DID NOT LEARN" — and a page-wide
    // text query cannot tell those apart, because on screen they are the same character. So the assertion is
    // scoped to the FAILED card, which is the only place the distinction lives.
    const sitesCard = screen.getByText("Sites").closest("div")!.parentElement!;
    // (copy changed with the design pass; the ASSERTION is unchanged — a failed card must not show a number)
    expect(within(sitesCard).queryByText("0")).toBeNull();
  });

  it("a failed /overview does not render six zeroes", async () => {
    overviewFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Could not load the overview.")).toBeTruthy(),
    );
    expect(screen.queryByText("0")).toBeNull();
  });
});

describe("the gateway health list uses the ONE health interpreter", () => {
  it("renders the badge policyHealthBadge produces, not a second vocabulary", async () => {
    show();
    const list = await waitFor(() =>
      screen.getByRole("list", { name: "Gateway health" }),
    );
    // `silent_desync` -> "silent desync" comes from lib/healthview.ts. If this screen grew its own mapping,
    // the two would drift and BOTH would still render — which is why there is exactly one interpreter.
    expect(within(list).getByText("silent desync")).toBeTruthy();
  });

  it("a failed /nodes says unavailable — never an empty 'all healthy' list", async () => {
    // "Nothing is wrong" and "we could not check" are opposite claims about a fleet.
    nodesFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Gateway health is unavailable.")).toBeTruthy(),
    );
    expect(screen.queryByRole("list", { name: "Gateway health" })).toBeNull();
  });
});

describe("the get-started state appears only when the org is KNOWN to be empty", () => {
  it("a fresh org shows ONE get-started panel", async () => {
    empty = true;
    show();
    await waitFor(() => expect(screen.getByText("Get started")).toBeTruthy());
    expect(screen.getByText(/Enroll a tunnex-node agent/)).toBeTruthy();
  });

  it("a POPULATED org shows no get-started panel", async () => {
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.queryByText("Get started")).toBeNull();
  });

  it("a FAILED overview shows no get-started panel — a failure is not an empty org", async () => {
    // Showing onboarding because a fetch failed would tell a founder with a working fleet that they have
    // nothing: the reassuring-empty defect wearing an onboarding hat.
    overviewFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Could not load the overview.")).toBeTruthy(),
    );
    expect(screen.queryByText("Get started")).toBeNull();
  });
});

describe("the CUT panels are ABSENT, not hidden", () => {
  it("no throughput chart, no fleet-risk plot, no date picker", async () => {
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    // `hidden: true` searches the whole DOM regardless of visibility — the S14.2 lesson: a plain query would
    // pass against a `display:none` implementation and certify absence it never checked.
    expect(
      screen.queryByRole("figure", { name: /throughput/i, hidden: true }),
    ).toBeNull();
    expect(
      screen.queryByRole("figure", { name: /fleet risk/i, hidden: true }),
    ).toBeNull();
    expect(
      screen.queryByRole("textbox", { name: /date/i, hidden: true }),
    ).toBeNull();
  });

  it("⛔ THE FORBIDDEN LIVENESS LABEL APPEARS NOWHERE IN THE APP — the ruling outlived its card", () => {
    // A render-floor violation in a WORD: `online` is last-handshake RECENCY, not a live session, and the
    // wireframe's own caption says "never green-while-dead" under a label claiming exactly that. The
    // founder ruled the qualification belongs IN THE LABEL, and this test guarded the one card that
    // carried it — "Seen in last 3 min".
    //
    // ⛔ THAT CARD WAS REMOVED (replaced by AI Agents), WHICH LEFT THE GUARD WITH NO SUBJECT. Deleting it
    // would have retired a founder ruling as a side effect of a layout change — the ruling was about how
    // liveness may be NAMED, not about which card names it, and liveness still renders (Peer Connection
    // Status, and the Devices surfaces).
    //
    // So it is re-pointed at the whole source tree instead of one card, which is STRICTER than what it
    // replaced: the old version could only see a label on a screen the test happened to render.
    const src = join(process.cwd(), "src");
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (/\.tsx?$/.test(e.name)) {
          const body = stripJsComments(readFileSync(full, "utf8"));
          if (/online\s+peers/i.test(body)) offenders.push(full);
        }
      }
    };
    walk(src);
    expect(offenders).toEqual([]);
  });
});

describe("⛔ EDITION IS A FOURTH STATE — an enterprise-only card is ABSENT, never an error", () => {
  // The defect this fixes: `/devices/pending` is enterprise-only, so the OPEN edition gets
  // `403 edition_required` — a SUCCESSFUL REFUSAL. Read through loadOne alone it became `failed`, and the
  // card rendered a red "could not load" for a feature the org was never sold.
  //
  // A design that carefully enumerates states pushes the danger onto the state nobody enumerated, and it gets
  // absorbed by whichever existing state is nearest — which is almost never the harmless one.
  it("[open edition] the Pending-approvals card is not rendered at all", async () => {
    edition = "open";
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.queryByText("Pending approvals")).toBeNull();
    // And no error treatment anywhere in its place.
    expect(screen.queryByText("could not load")).toBeNull();
  });

  it("[enterprise] the card IS rendered", async () => {
    edition = "enterprise";
    show();
    await waitFor(() =>
      expect(screen.getByText("Pending approvals")).toBeTruthy(),
    );
  });

  it("[edition still unknown] the card is absent — absent-until-known, never a flash", async () => {
    // A slow /meta must not briefly render an enterprise surface to an open-edition org.
    edition = null;
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.queryByText("Pending approvals")).toBeNull();
  });
});

describe("HA Hub Set un-reporting member rendering", () => {
  it("renders 'not reporting' for a member without metrics (Query Rule One listitem role + exact count)", async () => {
    show();
    await waitFor(() => expect(screen.getByText("HA Hub Set")).toBeTruthy());
    // Query Rule One: Query listitem by role and single-truth accessible name
    const listItems = screen.getAllByRole("listitem", {
      name: /not reporting/i,
    });
    expect(listItems.length).toEqual(1);
    expect(
      screen.getByRole("listitem", {
        name: /gw-a \(primary\): not reporting/i,
      }),
    ).toBeTruthy();
    // Absence assertion: paired with positive role query above
    expect(
      screen.queryByRole("listitem", { name: /gw-a \(primary\): hs n\/a/i }),
    ).toBeNull();
  });
});
