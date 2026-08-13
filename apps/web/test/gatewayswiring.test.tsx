import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";

// QUERY STRATEGY (ruled 2026-08-01, docs/UI-REDESIGN-registration.md consequence 2). Every interactive control
// is queried BY ROLE + ACCESSIBLE NAME — never a test-id, a class name, or DOM structure. That is the most
// rewrite-resistant selector there is: it survives any markup change that preserves semantics, and a redesign
// that breaks it has broken accessibility too, which is a finding rather than test debt. Mocking is at the
// NETWORK boundary (api.GET/api.POST) for the same reason — that layer does not change in a redesign.
//
// getByText appears below ONLY for content that carries no role today: status badges and empty states are
// <span>s, so they are unreachable by role. Each such use is a MARKER, not an exemption — those elements should
// gain role="status" / role="alert" in the redesign, at which point these queries convert and the tier gets
// stricter for free. (The redesign was ruled a RE-ARCHITECTURE on evidence including 0 aria- attributes and one
// <button> among 1,015 divs; this file is one of the reasons semantic markup is now a hard requirement.)
//
// EXPLICIT CLEANUP, and it is a tier convention rather than boilerplate. vitest.config.ts sets no
// `globals: true` and no setup file, so @testing-library's automatic afterEach cleanup NEVER REGISTERS —
// renders accumulate in one document across tests in a file. The S13.1 foothold never hit this because it
// renders exactly once. The first multi-render file did, immediately: three assertions failed with "Found
// multiple elements with the role button and name Revoke", including one that was asserting a button's
// ABSENCE — i.e. a leaked render can turn a real absence into a false presence, and the reverse.
afterEach(cleanup);

// SLICE 1 of the component test tier (docs/web-component-tests-commit-one.md). Gateways is first because
// THREE of the four web-side EPIC 11 walk findings landed on this surface:
//
//   WF-S11-9   the revoke endpoint existed in the API and never in the UI
//   WF-S11-10  a REVOKED gateway was badged "certificate expired — re-enroll this gateway", because this
//              list never suppressed health badges for revoked rows the way Devices.tsx always has
//   WF-S11-10b the same concept counted wrong one layer over (kinds summing to 4 on a fleet of 3)
//
// What they share is the reason this tier exists: NONE is a rendering bug. Every one is a surface
// DISAGREEING WITH THE BACKEND about what exists or what counts. So "covered" here means the WIRING — the
// decision the user actually gets — plus the FAILURE PATH, never that the component renders.

const posts: Array<{ path: string; nodeId?: string }> = [];
let revokeFails = false;

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, fallback: string) => fallback,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/meta")
          return { data: { public_base_url: "https://cp.example.com" } };
        return { data: undefined, error: undefined };
      }),
      POST: vi.fn(
        async (
          path: string,
          opts: { params?: { path?: Record<string, string> } },
        ) => {
          posts.push({ path, nodeId: opts?.params?.path?.nodeId });
          if (path.endsWith("/revoke") && revokeFails)
            return { error: { error: { code: "boom", message: "nope" } } };
          return { data: {}, error: undefined };
        },
      ),
    },
  };
});

import { Gateways } from "../src/components/Gateways";

const org = { id: "org-1", name: "Acme" } as never;

// A fleet with the EPIC 11 shape: one revoked gateway that is ALSO degraded, and one healthy active one.
// The revoked row is the whole point — it is the row WF-S11-10 rendered a confident wrong instruction beside.
const NODES = [
  {
    id: "gw-revoked",
    name: "aws-gw-1",
    status: "revoked",
    agent_version: "0.1.0",
    policy_degraded: true,
    policy_degraded_kind: "cert_expired_cannot_reconnect",
  },
  {
    id: "gw-live",
    name: "aws-gw-2",
    status: "active",
    agent_version: "0.1.0",
    policy_degraded: false,
  },
] as never[];

beforeEach(() => {
  posts.length = 0;
  revokeFails = false;
});

describe("Gateways — wiring", () => {
  // WF-S11-10. The defect was NOT that the badge looked wrong; it was that this surface disagreed with the
  // backend about whether a revoked gateway's health still counts. A pure test of policyHealthBadge passes
  // either way — it is the RULE, not the USE. This asserts the use.
  it("renders NO health badge on a revoked gateway, while still badging an active degraded one", () => {
    render(<Gateways org={org} nodes={NODES} />);

    // The revoked row says "revoked" and nothing instructional beside it.
    expect(screen.getByText("revoked")).toBeTruthy();
    // The kind that WF-S11-10 rendered on a revoked row must not appear anywhere.
    expect(screen.queryByText(/re-enroll this gateway/i)).toBeNull();
    expect(screen.queryByText(/certificate expired/i)).toBeNull();
  });

  // WF-S11-9. The endpoint existed for five stories with no way to call it. This asserts the call is REACHABLE
  // and carries the right node — not that a button exists.
  it("revoke POSTs the ACTIVE gateway's id, and only after the second step", async () => {
    render(<Gateways org={org} nodes={NODES} />);

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    // Two-step: the first click must NOT have called anything. A one-click danger control next to a
    // "last seen" label is a misclick away from an outage.
    expect(posts.filter((p) => p.path.endsWith("/revoke"))).toHaveLength(0);
    expect(
      screen.getByText(/Devices homed here lose their tunnel/),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() =>
      expect(posts.filter((p) => p.path.endsWith("/revoke"))).toHaveLength(1),
    );
    expect(posts.at(-1)!.nodeId).toBe("gw-live");
  });

  // The revoke control is offered ONLY where it can succeed. A revoked node has nothing to revoke, and
  // offering it would be the same active-vs-usable confusion one control over.
  it("offers no revoke control on an already-revoked gateway", () => {
    render(<Gateways org={org} nodes={[NODES[0]]} />);
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });
});

describe("Gateways — failure path", () => {
  // THE CLAUSE THAT MAKES THIS TIER WORTH GATING (commit-one D1(b)). The loadOne law is web-specific and its
  // violation mode is a REASSURING result: the screen renders perfectly and tells the user nothing. A wiring
  // test that only walks the happy path passes on a component that swallows every error.
  it("a failed revoke is surfaced, never swallowed into a silent no-op", async () => {
    revokeFails = true;
    render(<Gateways org={org} nodes={NODES} />);

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));

    await waitFor(() =>
      expect(screen.getByText("Could not revoke the gateway.")).toBeTruthy(),
    );
    // And the row must NOT have quietly re-rendered as though it worked.
    expect(screen.getByText("aws-gw-2")).toBeTruthy();
  });

  // An empty fleet must say so in words. "No rows" and "the load failed" are different facts and the
  // no-false-empty discipline exists because they render identically if nobody asserts otherwise.
  it("an empty fleet renders a named empty state, not blankness", () => {
    render(<Gateways org={org} nodes={[]} />);
    expect(screen.getByText(/No gateway enrolled yet/i)).toBeTruthy();
  });
});
