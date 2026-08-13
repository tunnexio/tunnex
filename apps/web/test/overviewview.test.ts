import { describe, expect, it } from "vitest";
import {
  isFreshOrg,
  sortGateways,
  statFrom,
  statText,
  peerSlices,
  postureSplit,
  type GatewayRow,
} from "../src/lib/overviewview";
import { FAILED, LOADING, ok } from "../src/lib/navcounts";

// S14.4 — the Overview's PURE decisions.
//
// ⚠ THIS FILE EXISTS BECAUSE TWO MUTATIONS PASSED. `sortGateways`'s ordering and `isFreshOrg`'s
// known-empty requirement were both asserted only INDIRECTLY, through a screen test that happened to hold
// while the decision was wrong. Indirect coverage is coverage of the path, not of the decision.

describe("sortGateways — UNHEALTHY FIRST", () => {
  const rows: GatewayRow[] = [
    { id: "1", name: "b-healthy", label: "healthy", tone: "ok" },
    { id: "2", name: "a-broken", label: "silent desync", tone: "danger" },
    { id: "3", name: "c-syncing", label: "syncing…", tone: "warn" },
    { id: "4", name: "d-unknown", label: "health unknown", tone: "neutral" },
  ];

  it("orders danger, warn, neutral, ok", () => {
    // The list shows ALL gateways, so ORDER is what makes it useful. A broken gateway sorted below three
    // healthy ones is a broken gateway below the fold — present, and not seen.
    expect(sortGateways(rows).map((r) => r.name)).toEqual([
      "a-broken",
      "c-syncing",
      "d-unknown",
      "b-healthy",
    ]);
  });

  it("breaks ties by name, so the order is stable across renders", () => {
    const tie: GatewayRow[] = [
      { id: "1", name: "zed", label: "healthy", tone: "ok" },
      { id: "2", name: "alpha", label: "healthy", tone: "ok" },
    ];
    expect(sortGateways(tie).map((r) => r.name)).toEqual(["alpha", "zed"]);
  });

  it("does not mutate its input", () => {
    const before = rows.map((r) => r.name);
    sortGateways(rows);
    expect(rows.map((r) => r.name)).toEqual(before);
  });
});

describe("isFreshOrg — onboarding only when the org is KNOWN to be empty", () => {
  // ⚠ AND THIS IS BELT-AND-BRACES, WHICH IS WORTH SAYING RATHER THAN OVERSTATING. On the screen today the
  // primary protection is that a failed `/overview` leaves `data` null, so the whole block is unrendered —
  // the screen test passes for THAT reason, not because of these checks. Gating the decision directly means
  // the guard survives a refactor that changes how the screen handles a null `data`.
  it("all zero and all KNOWN -> fresh", () => {
    expect(isFreshOrg(ok(0), ok(0), ok(0))).toBe(true);
  });

  it("a FAILED count is NOT fresh — a failure is not an empty org", () => {
    // Showing onboarding because a fetch failed would tell a founder with a working fleet that they have
    // nothing: the reassuring-empty defect wearing an onboarding hat.
    expect(isFreshOrg(FAILED, ok(0), ok(0))).toBe(false);
    expect(isFreshOrg(ok(0), FAILED, ok(0))).toBe(false);
    expect(isFreshOrg(ok(0), ok(0), FAILED)).toBe(false);
  });

  it("a LOADING count is NOT fresh — the answer has not arrived", () => {
    expect(isFreshOrg(LOADING, ok(0), ok(0))).toBe(false);
  });

  it("a populated org is not fresh", () => {
    expect(isFreshOrg(ok(2), ok(0), ok(1))).toBe(false);
    expect(isFreshOrg(ok(0), ok(5), ok(1))).toBe(false);
  });
});

describe("statFrom / statText", () => {
  it("null (not yet fetched) is LOADING and renders nothing", () => {
    expect(statText(statFrom(null, () => 1))).toBeNull();
  });
  it("a failed load renders nothing", () => {
    expect(statText(statFrom({ ok: false, error: "x" }, () => 1))).toBeNull();
  });
  it("a true zero renders '0'", () => {
    expect(
      statText(statFrom({ ok: true, data: [] }, (a: number[]) => a.length)),
    ).toBe("0");
  });
});

describe("peerSlices — the donut counts DEVICES, and the buckets are disjoint", () => {
  // ⚠ The first build counted GATEWAYS. The panel is "Peer Connection Status" and peers are devices — a
  // different, larger population. A chart can be perfectly honest about the wrong denominator.
  const D = (o: Partial<Record<string, unknown>>) => o as never;

  it("every device lands in exactly one bucket", () => {
    const devices = [
      D({ status: "active", online: true }),
      D({ status: "active", online: false }),
      D({ status: "active", online: true, health_blocked: true }),
      D({ status: "revoked", online: false }),
    ];
    const s = peerSlices(devices);
    expect(s.reduce((t, x) => t + x.value, 0)).toBe(devices.length);
    expect(s.map((x) => [x.label, x.value])).toEqual([
      ["Connected", 1],
      ["Idle", 1],
      ["Posture-blocked", 1],
      ["Revoked / offline", 1],
    ]);
  });

  it("precedence: a revoked device is NOT idle, and a blocked device is NOT connected", () => {
    // Both would otherwise be double-counted into the reassuring bucket.
    expect(peerSlices([D({ status: "revoked", online: true })])[0]!.value).toBe(
      0,
    );
    expect(
      peerSlices([
        D({ status: "active", online: true, health_blocked: true }),
      ])[0]!.value,
    ).toBe(0);
  });
});

describe("postureSplit — UNKNOWN is its own state and is excluded from the percentage", () => {
  const D = (o: Partial<Record<string, unknown>>) => o as never;

  it("never-reported devices are unknown, not compliant", () => {
    // Counting them compliant is the reassuring-empty defect with a denominator. The design says it too:
    // "Absence ≠ compliance — unknown is its own state."
    const s = postureSplit([
      D({ status: "active" }),
      D({ status: "active", health_state: "ok" }),
    ]);
    expect(s.unknown).toBe(1);
    expect(s.compliant).toBe(1);
    expect(s.percent).toBe(100); // 1 of 1 REPORTED, not 1 of 2 total
  });

  it("percent is null when nothing has reported — not 0, and not 100", () => {
    // 0% would claim total non-compliance; 100% would claim the opposite. Neither was measured.
    expect(postureSplit([D({ status: "active" })]).percent).toBeNull();
  });

  it("revoked devices are excluded entirely", () => {
    expect(
      postureSplit([D({ status: "revoked", health_state: "ok" })]),
    ).toEqual({
      compliant: 0,
      blocked: 0,
      unknown: 0,
      percent: null,
    });
  });
});
