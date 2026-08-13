import { describe, expect, it } from "vitest";
import {
  BREAKPOINTS,
  capabilityFor,
  layoutIntent,
  readOnlyByWidthMessage,
} from "../src/lib/layout";

// S14.2 LAYER 1 — the breakpoint decision, tested as a PURE FUNCTION with no DOM at all.
//
// This is the only layer that can meaningfully assert a width, because it is the only layer where a width is a
// value rather than a rendering. jsdom has no layout engine: it evaluates no media query and lays nothing out,
// so a test that rendered components and asserted "the layout is narrow" would assert nothing and pass at every
// width (docs/laws.md). Extracting the decision is what makes it testable at all.

describe("layoutIntent — boundaries on BOTH sides of every threshold", () => {
  // Boundary values, not midpoints. A threshold implemented with `>` instead of `>=` renders correctly at 800
  // and wrongly at exactly 768, and only the boundary case can tell them apart.
  const cases: Array<[number, string]> = [
    [0, "triage"],
    [320, "triage"],
    [767, "triage"],
    [768, "compose"],
    [1023, "compose"],
    [1024, "operate"],
    [1439, "operate"],
    [1440, "wide"],
    [1919, "wide"],
    [1920, "max"],
    [3840, "max"],
  ];
  for (const [width, expected] of cases) {
    it(`${width}px -> ${expected}`, () =>
      expect(layoutIntent(width)).toBe(expected));
  }
});

describe("the 768 boundary is where a SECURITY CAPABILITY turns on", () => {
  // Singled out from the table above deliberately. The other breakpoints are taste and may be re-tuned; this
  // one is a ruled floor — below it the access-rule builder is not rendered, because a rule builder on a phone
  // is a surface where a MIS-TAP GRANTS ACCESS, and a bad one is worse than none.
  it("767 cannot compose; 768 can", () => {
    expect(capabilityFor(layoutIntent(767)).canCompose).toBe(false);
    expect(capabilityFor(layoutIntent(768)).canCompose).toBe(true);
  });

  it("the floor's VALUE is pinned, so moving it is a visible edit rather than a drifting number", () => {
    expect(BREAKPOINTS.compose).toBe(768);
  });
});

describe("capabilityFor — every intent yields a complete capability", () => {
  const intents = ["triage", "compose", "operate", "wide", "max"] as const;

  it("no intent returns undefined — a missing case would make canCompose read as falsy and gate correctly BY ACCIDENT", () => {
    // The dangerous direction is the safe-looking one: an unhandled intent returning undefined would throw on
    // destructure, but a partial object would silently read canCompose === undefined and fail CLOSED, hiding
    // the bug behind an outcome that looks right.
    for (const i of intents) {
      const c = capabilityFor(i);
      expect(typeof c.canCompose, i).toBe("boolean");
      expect(["drawer", "rail", "full"], i).toContain(c.navMode);
      expect([1, 2, 3, 4], i).toContain(c.columns);
    }
  });

  it("only triage forbids composition", () => {
    expect(intents.filter((i) => !capabilityFor(i).canCompose)).toEqual([
      "triage",
    ]);
  });

  it("columns never decrease as width grows, and CLAMP rather than stretch at max", () => {
    const cols = intents.map((i) => capabilityFor(i).columns);
    expect(cols).toEqual([...cols].sort((a, b) => a - b));
    expect(capabilityFor("max").columns).toBe(capabilityFor("wide").columns);
  });
});

describe("readOnlyByWidthMessage — ONE wording, parameterised", () => {
  it("names the surface and says what to do about it", () => {
    const msg = readOnlyByWidthMessage("Access rules");
    expect(msg).toContain("Access rules");
    expect(msg).toMatch(/read-only/i);
    // It must tell the user the way out. "Read-only" without "open it on a laptop" is a dead end, not an
    // explanation — the user is left to guess whether the restriction is their role or their window.
    expect(msg).toMatch(/laptop|tablet/i);
  });
});
