import { describe, expect, it } from "vitest";
import {
  badgeText,
  countFrom,
  gatewayTotalFrom,
  gatewayBadgeText,
  FAILED,
  LOADING,
  ok,
  INITIAL_NAV_COUNTS,
  NAV_COUNT_REFRESH_MS,
} from "../src/lib/navcounts";

// S14.4 — THE STRICTEST DATA SURFACE IN THE PRODUCT.
//
//   A WRONG COUNT ON A PAGE THE USER *OPENED* IS A BUG THEY MIGHT NOTICE.
//   A WRONG COUNT IN *PERMANENT CHROME* IS FURNITURE.
//
// The user did not navigate to the nav, did not ask it a question, and has no moment of expectation against
// which to check its answer. That is why absent-never-zero is stricter here than anywhere else.

describe("badgeText — absent until loaded, absent on failure, never 0", () => {
  it("loading renders NOTHING", () => expect(badgeText(LOADING)).toBeNull());
  it("failed renders NOTHING", () => expect(badgeText(FAILED)).toBeNull());
  it("a known zero DOES render — a true zero is honest", () => {
    // The distinction the whole type exists for: "there are none" is a fact worth showing. "We could not find
    // out" is not. They are the same character on screen and different claims about the world.
    expect(badgeText(ok(0))).toBe("0");
  });
  it("a known number renders", () => expect(badgeText(ok(7))).toBe("7"));
});

describe("gatewayBadgeText — a PARTIAL answer is worse than none", () => {
  it("both known renders n/m", () =>
    expect(gatewayBadgeText(ok(3), ok(7))).toBe("3/7"));
  it("online unknown renders NOTHING — not ?/7", () =>
    expect(gatewayBadgeText(FAILED, ok(7))).toBeNull());
  it("total unknown renders NOTHING — not 3/?", () =>
    expect(gatewayBadgeText(ok(3), FAILED)).toBeNull());
  it("either still loading renders NOTHING", () =>
    expect(gatewayBadgeText(LOADING, ok(7))).toBeNull());
  // `3/?` asserts one half as fact while implying the other is momentarily missing — and the reader has no
  // way to know which half is real, which is strictly worse than an absent badge.
});

describe("the initial state cannot leak a zero", () => {
  it("every count starts UNKNOWN, not 0", () => {
    for (const [k, v] of Object.entries(INITIAL_NAV_COUNTS)) {
      expect(v.state, k).toBe("loading");
      expect(badgeText(v), k).toBeNull();
    }
  });
});

describe("the refresh cadence is slow on purpose", () => {
  it("is a minute, not a few seconds", () => {
    // A static count goes stale the moment anything changes and becomes a remembered number wearing a live
    // badge. A fast poll is four requests on a timer for a number the user glances at. Route-change covers
    // the case that actually matters.
    expect(NAV_COUNT_REFRESH_MS).toBeGreaterThanOrEqual(30_000);
  });
});

describe("countFrom — the Loaded<T> mapping, gated after a mutation exposed it as unguarded", () => {
  // ⚠ THIS BLOCK EXISTS BECAUSE A MUTATION PASSED. Rewriting the hook's mapping to
  // `ok(res.ok ? len : 0)` — a failed fetch degrading to a length of zero — went GREEN, because every
  // assertion above tested the PURE layer and nothing tested the WIRING that produces its input.
  //
  // The decision was living in a useEffect. This project's own three-layer shape says a decision must be pure
  // and unit-tested; the mapping IS the decision.
  it("a successful load projects the number", () => {
    expect(countFrom({ ok: true, data: [1, 2, 3] }, (a) => a.length)).toEqual({
      state: "ok",
      value: 3,
    });
  });
  it("a FAILED load is FAILED — never a zero-length degradation", () => {
    expect(countFrom({ ok: false }, (a: number[]) => a.length)).toEqual({
      state: "failed",
    });
  });
  it("a successful load of an EMPTY list is a true zero", () => {
    expect(
      countFrom({ ok: true, data: [] }, (a: number[]) => a.length),
    ).toEqual({ state: "ok", value: 0 });
  });
});

describe("gatewayTotalFrom — sidebar agrees with the Gateways page", () => {
  it("counts the current org gateway rows, including a truthful empty zero", () => {
    expect(gatewayTotalFrom({ ok: true, data: [] })).toEqual({ state: "ok", value: 0 });
    expect(gatewayTotalFrom({ ok: true, data: [{ id: "gateway-1" }] })).toEqual({ state: "ok", value: 1 });
  });

  it("does not invent a count when the gateway list failed", () => {
    expect(gatewayTotalFrom({ ok: false })).toEqual({ state: "failed" });
  });
});

// ⛔ THE GATEWAY BADGE IS USED/CEILING (founder-ruled), AND EVERY CASE HERE IS ONE A REAL DEPLOYMENT SITS IN.
//
// It used to be online/total. `1/6` sat beside a licence card reading 20, and the two looked like one fact
// disagreeing with itself — they were two different facts wearing the same shape.
describe("the gateway badge is headroom, not liveness", () => {
  const ok = (value: number) => ({ state: "ok" as const, value });
  const failed = { state: "failed" as const };

  it("renders used over ceiling", () => {
    expect(gatewayBadgeText(ok(6), ok(20))).toBe("6/20");
  });

  // ⭐ UNLIMITED IS `∞` — never the word, never a blank. A blank denominator reads as a loading state and
  // the reader waits for a number that is never coming.
  it("renders ∞ for an unlimited ceiling", () => {
    expect(gatewayBadgeText(ok(37), null)).toBe("37/∞");
  });

  // ⛔ COMMUNITY'S STEADY STATE. `1/1` is the expected condition of every free deployment — using the one
  // gateway it has. It is TRUE, and it must render plainly rather than be softened, hidden, or alarmed.
  it("renders 1/1 on Community without hiding or softening it", () => {
    expect(gatewayBadgeText(ok(1), ok(1))).toBe("1/1");
  });

  // ⛔ NO CLAMP, NO ERROR. A deployment sits ABOVE its band whenever a licence lapses or a tier is
  // downgraded — running gateways are never stopped, so exceeding the ceiling is a NORMAL state. Clamping
  // to 20/20 would hide the one number the operator needs to act on.
  it("renders an over-ceiling deployment truthfully", () => {
    expect(gatewayBadgeText(ok(24), ok(20))).toBe("24/20");
  });

  // ⛔ EITHER SIDE UNKNOWN => NO BADGE. `6/?` asserts one half as fact while implying the other is merely
  // late, when the reader cannot tell which half is real.
  it("renders nothing when either side is unknown", () => {
    expect(gatewayBadgeText(failed, ok(20))).toBeNull();
    expect(gatewayBadgeText(ok(6), failed)).toBeNull();
  });

  // ⚠ AND ZERO IS A NUMBER. A deployment with no gateways yet renders 0/1, not an absent badge — the
  // empty state is information, and hiding it is how "you have none" becomes indistinguishable from
  // "we could not tell".
  it("renders zero used", () => {
    expect(gatewayBadgeText(ok(0), ok(1))).toBe("0/1");
  });
});
