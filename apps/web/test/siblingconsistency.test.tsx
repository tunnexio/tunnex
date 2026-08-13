import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

// D4 — SIBLING CONSISTENCY. The check the per-screen census CANNOT SEE, by construction.
//
// WF-S11-10's root was `Gateways.tsx` never suppressing health badges on revoked rows THE WAY `Devices.tsx`
// ALWAYS HAS. Two components disagreeing with each other about one backend concept — and a per-screen wiring
// test passes on BOTH while they disagree, because each is internally consistent and neither test has any
// reason to mention the other.
//
// THE ENUMERATION FOUND A THIRD SURFACE STILL CARRYING THE DEFECT. `Sites.tsx`'s GatewayRow rendered
// `{g.health && …}` with no revoked guard, so a revoked degraded gateway read "revoked" beside "certificate
// expired — re-enroll this gateway" — the same two-labels-contradicting-each-other shape, on the surface the
// fix never reached. It was STRUCTURALLY PRESENT and UNCONFIRMED ON THE WIRE when found: not a sighting.
//
// FOUND BY ASKING WHO ELSE RENDERS THIS CONCEPT, NOT BY WALKING THE UI. That is the argument for D4 in one
// sentence, and it is why this file asserts the rule across all three surfaces rather than screen by screen.
//
// SCOPE: the concepts that ALREADY exist on more than one surface. Not a framework. The other candidates were
// enumerated and dispositioned — `relativeAge` is one shared pure function (no room to disagree), the
// failed-load-triad asymmetry is a census question (D3), and edition gating is the redesign's one-seam item.

afterEach(cleanup); // see docs/laws.md — no globals/setup file, so auto-cleanup never registers

// Mocked at the NETWORK boundary (consequence 2), so the Devices page below mounts as the real component.
const POSTURE_FLEET = [
  {
    id: "dr",
    name: "dev-revoked",
    status: "revoked",
    assigned_ip: "10.99.0.9",
    health_state: "noncompliant",
    health_blocked: true,
  },
  {
    id: "da",
    name: "dev-active",
    status: "active",
    assigned_ip: "10.99.0.3",
    health_state: "noncompliant",
    health_blocked: true,
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
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/devices")) return { data: POSTURE_FLEET };
        if (path.endsWith("/nodes")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import { Gateways } from "../src/components/Gateways";
import { GatewayRow } from "../src/pages/Sites";
import Devices from "../src/pages/Devices";
import { policyHealthBadge } from "../src/lib/healthview";
import { postureBadge } from "../src/lib/postureview";

const org = { id: "org-1", name: "Acme" } as never;

// ONE degraded+revoked fixture, rendered through every surface that draws this concept. The kind is the one
// WF-S11-10 actually put on screen — an instruction to undo a deliberate security action.
const DEGRADED_KIND = "cert_expired_cannot_reconnect";

describe("sibling consistency — revoked rows carry NO health/instruction badge, on EVERY surface that renders one", () => {
  // The badge these surfaces would draw if unguarded. Asserting against the real label keeps this test honest:
  // if the vocabulary changes, this fails rather than silently checking for a string nobody renders any more.
  const badge = policyHealthBadge({
    policy_degraded: true,
    policy_degraded_kind: DEGRADED_KIND,
  } as never);

  it("the fixture is genuinely degraded — otherwise every assertion below is vacuous", () => {
    // WITHOUT THIS the whole file passes on a fixture that produces no badge at all, which is the
    // could-this-check-have-failed trap one level up from what it is testing.
    expect(badge).not.toBeNull();
    expect(badge!.label.length).toBeGreaterThan(0);
  });

  it("Gateways: a revoked gateway shows no health badge; an active one still does", () => {
    render(
      <Gateways
        org={org}
        nodes={
          [
            {
              id: "a",
              name: "gw-revoked",
              status: "revoked",
              agent_version: "0.1.0",
              policy_degraded: true,
              policy_degraded_kind: DEGRADED_KIND,
            },
            {
              id: "b",
              name: "gw-active",
              status: "active",
              agent_version: "0.1.0",
              policy_degraded: true,
              policy_degraded_kind: DEGRADED_KIND,
            },
          ] as never[]
        }
      />,
    );
    // Exactly one badge for two degraded gateways — the active one. The revoked one is suppressed.
    expect(screen.getAllByText(badge!.label)).toHaveLength(1);
  });

  it("Sites (GatewayRow): a revoked gateway shows no health badge — THE SURFACE THE FIX HAD NOT REACHED", () => {
    render(
      <ul>
        <GatewayRow
          g={
            {
              id: "a",
              name: "gw-revoked",
              status: "revoked",
              isHub: false,
              lastSeenAt: null,
              health: badge,
              siteLinkNote: null,
            } as never
          }
        />
      </ul>,
    );
    expect(screen.getByText("revoked")).toBeTruthy();
    expect(screen.queryByText(badge!.label)).toBeNull();
  });

  it("Sites (GatewayRow): an ACTIVE gateway still shows it — suppression must not become blanket removal", () => {
    render(
      <ul>
        <GatewayRow
          g={
            {
              id: "b",
              name: "gw-active",
              status: "active",
              isHub: false,
              lastSeenAt: null,
              health: badge,
              siteLinkNote: null,
            } as never
          }
        />
      </ul>,
    );
    expect(screen.getByText(badge!.label)).toBeTruthy();
  });

  // THE THIRD PARTY, AND THE REFERENCE IMPLEMENTATION. Devices has ALWAYS carried this guard — it is the
  // surface Gateways was measured against when WF-S11-10 was diagnosed, and the one Sites was measured against
  // on this branch. Its badge producer is DIFFERENT (postureBadge, not policyHealthBadge), which is precisely
  // why the concept has to be asserted rather than the label: the rule is "a revoked row carries no
  // health/status/instruction badge", and it holds across surfaces that compute their badges differently.
  //
  // READ FROM THE SAME SOURCE OF TRUTH, NOT RESTATED. The expected label comes from postureBadge() itself — the
  // function the component calls — so a fixture cannot drift from production. A hardcoded "posture blocked"
  // would test the restatement, which is WF-S13-3's class exactly.
  it("Devices: the rule holds on the surface that always had it, via a DIFFERENT badge producer", async () => {
    const posture = postureBadge({
      health_state: "noncompliant",
      health_blocked: true,
    } as never);
    expect(
      posture,
      "fixture must genuinely produce a badge, or the assertion below is vacuous",
    ).not.toBeNull();

    // THE REAL PAGE, not a stand-in. The first draft of this test rendered a three-line `DeviceRowProbe` that
    // re-encoded `status !== "revoked" && <badge>` — which would have PASSED FOREVER even if Devices.tsx lost
    // its guard, because the assertion would have been reading the test's own copy of the rule. That is
    // fixture-restates-production (WF-S13-3's class) inside the very check written to prevent it. Caught before
    // it was committed; recorded here because the near-miss is the lesson.
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    await screen.findByText("dev-revoked");

    // One badge for two posture-blocked devices: the active one. Same arithmetic as the Gateways case above —
    // one rule, three surfaces, asserted identically, each against its own real component.
    expect(screen.getAllByText(posture!.label)).toHaveLength(1);
  });
});
