// S14.2 — THE LAYOUT DECISION, AS A PURE FUNCTION.
//
// WIDTH -> INTENT -> CAPABILITY -> RENDER DECISION. Never width -> CSS visibility.
//
// WHY PURE, AND WHY THIS SHAPE. jsdom HAS NO LAYOUT ENGINE: it does not evaluate media queries, compute widths,
// or lay anything out. A "responsive test" that rendered components in vitest and asserted layout would assert
// NOTHING and pass at every width — a check that cannot fail (docs/laws.md, the detector's fourth prospective
// catch, caught before the test was written). Extracting the decision means the boundaries are unit-testable
// with no DOM at all, and the component tier never has to ask jsdom a question jsdom cannot answer.
//
// Breakpoints are named by WHAT THE USER CAN DO at that width, not by device. A pixel value is an
// implementation detail; the capability is the decision.

export type LayoutIntent = "triage" | "compose" | "operate" | "wide" | "max";

/**
 * The breakpoints.
 *
 * `compose` (768) IS THE LOAD-BEARING ONE and the only value that is ruled rather than tuned: it is where a
 * SECURITY CAPABILITY turns on. Below it the access-rule builder is not rendered at all. It is a FLOOR, not a
 * guess about tablets — 768px is the narrowest width at which a source/destination/port/expiry form fits
 * without collapsing fields into an order that invites a mis-tap, and a bad rule builder is worse than none.
 *
 * The others may be re-tuned freely.
 */
export const BREAKPOINTS = {
  triage: 0,
  compose: 768,
  operate: 1024,
  wide: 1440,
  max: 1920,
} as const;

/** Pure: viewport width -> layout intent. */
export function layoutIntent(width: number): LayoutIntent {
  if (width >= BREAKPOINTS.max) return "max";
  if (width >= BREAKPOINTS.wide) return "wide";
  if (width >= BREAKPOINTS.operate) return "operate";
  if (width >= BREAKPOINTS.compose) return "compose";
  return "triage";
}

export type NavMode = "drawer" | "rail" | "full";

export interface LayoutCapability {
  /**
   * MAY THE USER COMPOSE A POLICY HERE? Mobile is a TRIAGE SUBSET (founder-ruled): read state, act on queues,
   * approve, revoke. Everything that COMPOSES a policy is desktop-and-tablet only, and below the floor it
   * renders READ-ONLY with an honest line — never a degraded editor.
   */
  canCompose: boolean;
  navMode: NavMode;
  /** Column budget for the dashboard grid. `max` clamps rather than stretching. */
  columns: 1 | 2 | 3 | 4;
}

export function capabilityFor(intent: LayoutIntent): LayoutCapability {
  switch (intent) {
    case "triage":
      return { canCompose: false, navMode: "drawer", columns: 1 };
    case "compose":
      return { canCompose: true, navMode: "rail", columns: 2 };
    case "operate":
      return { canCompose: true, navMode: "full", columns: 3 };
    case "wide":
    case "max":
      return { canCompose: true, navMode: "full", columns: 4 };
  }
}

/**
 * The ONE wording for every composition surface gated by width, parameterised by surface name.
 *
 * One sentence, not fourteen slightly different ones: a message duplicated per screen drifts, and the drift is
 * invisible because each copy still reads fine on its own.
 */
export function readOnlyByWidthMessage(surface: string): string {
  return `${surface} are read-only on this screen size. Open Tunnex on a laptop or tablet to edit them.`;
}
