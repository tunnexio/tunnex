import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";

// SLICE 3 — Kubernetes. Ranked above Access by the stated criterion: both survive the redesign intact, but this
// screen CARRIES ONE OF THE FOUR WALK FINDINGS while Access's case is consequence-based.
//
// WF-S11-7 was an UNRENDERED HEALTH KIND — `k8s_endpoints_unavailable` shipped in the Go enum and the metrics
// and reached neither the spec nor the renderer, so it fell through to a generic badge and its named remedy was
// invisible. It is the canonical producer-without-consumer instance this repo cites everywhere.
//
// So the wiring test for this screen is a MIRROR CENSUS, not a page assertion: every kind the API can emit must
// reach a renderer. That is the same shape as the server-side TestEveryHealthKindReachesItsMirrorSurfaces, and
// it is the check that would have caught WF-S11-7 the day it shipped.
//
// QUERY STRATEGY (docs/UI-REDESIGN-registration.md consequence 2): role + accessible name; mocked at the
// NETWORK boundary; getByText only where no role exists today, each use a marker for the redesign.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let clustersFail = false;
const CLUSTERS = [
  { id: "c1", name: "prod-cluster", site_id: "s1", managed_by_operator: true },
];
const SERVICES = [
  {
    id: "sv1",
    cluster_id: "c1",
    namespace: "default",
    name: "api",
    managed_by_operator: true,
    vip: "100.64.0.5",
  },
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
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: "admin", email_verified: true }],
          };
        if (path.endsWith("/k8s/clusters")) {
          if (clustersFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: CLUSTERS };
        }
        if (path.endsWith("/k8s/services")) return { data: SERVICES };
        if (path.endsWith("/sites"))
          return { data: [{ id: "s1", name: "prod-site" }] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import { policyHealthBadge } from "../src/lib/healthview";
import Kubernetes from "../src/pages/Kubernetes";
import { AuthProvider } from "../src/lib/auth";

// The REAL AuthProvider, not a stub. Kubernetes reads `useAuth()` for its role/verification gate, and stubbing
// the context would put the test's copy of the gate under assertion instead of the product's — the
// fixture-restates-production trap this branch already caught once (docs/laws.md).
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
  clustersFail = false;
});

// EVERY kind the OpenAPI contract allows. Kept as a literal on purpose: it is a MIRROR of the generated
// `policy_degraded_kind` union in packages/shared/src/api.d.ts, and a mirror that silently tracked its source
// would prove nothing — the whole point is that the two are maintained separately and must be shown to agree.
// When the contract gains a kind, this list is edited deliberately and the test below names what is missing.
const CONTRACT_KINDS = [
  "apply_failing",
  "stuck_enforcing",
  "converging",
  "silent_desync",
  "desync_unknown",
  "unsupported_policy_version",
  "site_hub_down",
  "site_link_down",
  "site_subnet_unreachable",
  "conntrack_flush_unavailable",
  "hub_forwarding_not_reconciling",
  "k8s_endpoints_unavailable",
  "cert_expired_cannot_reconnect",
] as const;

describe("health-kind mirror census — WF-S11-7's own check", () => {
  it("EVERY degraded kind the contract can emit reaches a renderer with a non-empty label", () => {
    const unrendered = CONTRACT_KINDS.filter(
      (k) =>
        policyHealthBadge({
          policy_degraded: true,
          policy_degraded_kind: k,
        } as never) === null,
    );
    expect(
      unrendered,
      `kinds the API can emit that render NOTHING (WF-S11-7's exact defect): ${unrendered.join(", ")}`,
    ).toEqual([]);
  });

  it("`healthy` renders no badge — absence of degradation is not a badge", () => {
    // The negative half. Without it the census above is satisfiable by returning a badge for everything,
    // which would put a "degraded" label on healthy gateways — the inverse defect, equally wrong.
    expect(
      policyHealthBadge({
        policy_degraded: false,
        policy_degraded_kind: "healthy",
      } as never),
    ).toBeNull();
  });
});

describe("Kubernetes — wiring", () => {
  it("names an unassigned connector instead of implying a same-site gateway can serve the cluster", async () => {
    withAuth(<Kubernetes />);

    await waitFor(() =>
      expect(screen.getByText("connector: not selected")).toBeTruthy(),
    );
    expect(
      screen.getByText(/no in-cluster connector is selected/i),
    ).toBeTruthy();
  });

  // S10.2's WITHHELD DESTRUCTIVE CONTROL. An operator-managed object must NOT offer Deregister/Unexpose: a
  // dashboard edit would be silently reverted on the next reconcile, so the product refuses and says where the
  // real control lives. `objectControls` is unit-pinned; this asserts the SCREEN honours it.
  it("an operator-managed object withholds its destructive control and names the CR instead", async () => {
    withAuth(<Kubernetes />);

    // Queried by ACCESSIBLE NAME (the aria-label carries the full guidance), not by the visible fragment.
    // The first draft used getAllByText("edit the CR") and raced the render — it passed locally and failed in
    // the gate's container. Rule 1 asked for the accessible name anyway; the gate is what made me use it.
    await waitFor(() =>
      screen.getAllByLabelText(/managed by the GitOps operator/i),
    );

    // The control is absent BY ROLE — the strongest form of this assertion.
    expect(screen.queryByRole("button", { name: "Unexpose" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Deregister/i })).toBeNull();
  });
});

describe("Kubernetes — failure path", () => {
  // D1(b). This screen uses loadOne + LoadRetry, so the triad exists — the test asserts it is REACHED, because
  // a triad that is never rendered is the reassuring-empty-state defect with extra steps.
  it("a failed cluster load renders the retry affordance, not an empty cluster list", async () => {
    clustersFail = true;
    withAuth(<Kubernetes />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy(),
    );
  });
});
