// S14.4 — THE LIVE NAV COUNTS. THE STRICTEST DATA SURFACE IN THE PRODUCT, AND HERE IS WHY.
//
//   A WRONG COUNT ON A PAGE THE USER *OPENED* IS A BUG THEY MIGHT NOTICE.
//   A WRONG COUNT IN *PERMANENT CHROME* IS FURNITURE.
//
// The user did not navigate to the nav, did not ask it a question, and has no moment of expectation against
// which to check its answer. It is simply always there, and always believed — on every screen, all day. That
// is why absent-never-zero is STRICTER here than anywhere else in the app.
//
//   ABSENT UNTIL LOADED. ABSENT ON FAILURE. NEVER `0`. NEVER A REMEMBERED NUMBER.
//
// A nav badge reading `0 DOWN` because a fetch failed is the reassuring-empty defect in the one place every
// user looks.

/**
 * A count that may be UNKNOWN, and the type makes the unknown unavoidable.
 *
 * `number | null` would let a caller write `count ?? 0` — the exact defect — in one keystroke, and the result
 * would typecheck and look reasonable. A tagged state forces the caller to say what it renders when the answer
 * is not a number, which is the decision this whole surface is about.
 */
export type NavCount =
  { state: "loading" } | { state: "failed" } | { state: "ok"; value: number };

export const LOADING: NavCount = { state: "loading" };
export const FAILED: NavCount = { state: "failed" };
export const ok = (value: number): NavCount => ({ state: "ok", value });

/**
 * What a nav badge renders for a count. `null` means RENDER NOTHING — not "render an empty string", not
 * "render a dash", and certainly not zero.
 *
 * The DESTINATION is never affected: S14.2's rule still binds, so the link and its label are always present.
 * Only the badge is conditional.
 */
export function badgeText(c: NavCount): string | null {
  return c.state === "ok" ? String(c.value) : null;
}

/**
 * The gateway badge — `6/20` — is USED over CEILING (founder-ruled).
 *
 * ⛔ IT USED TO BE ONLINE OVER TOTAL, AND THAT WAS THE DEFECT. `1/6` sat in the sidebar beside a licence card
 * reading `20 gateways`, and the two looked like one fact disagreeing with itself. They were two different
 * facts wearing the same shape, and the reading it invited — "6 of my 20" — was wrong in BOTH numbers.
 *
 * ⭐ HEADROOM IS WHAT A DENOMINATOR MEANS. A reader seeing `x/y` asks "how much of my allowance is gone",
 * not "how many are awake" — so the badge now answers the question it was always being asked. Liveness is
 * still on the Gateways page, where a reader is looking at gateways rather than glancing at a nav.
 *
 * ⛔ IF EITHER SIDE IS UNKNOWN THE WHOLE BADGE IS ABSENT. Rendering `?/20` or `6/?` would be worse than
 * nothing: it asserts one half as fact while implying the other is momentarily missing, when the reader has
 * no way to know which half is real.
 */
export function gatewayBadgeText(
  used: NavCount,
  ceiling: NavCount | null,
): string | null {
  if (used.state !== "ok") return null;
  // ⭐ UNLIMITED IS `∞`, NOT "unlimited" AND NOT A BLANK (founder-ruled).
  //
  // A blank denominator reads as a loading state — the reader waits for a number that is never coming. The
  // word "unlimited" does not fit a nav badge and forces the numerator to shrink. `∞` is the only rendering
  // that stays the same SHAPE as every other badge, so the eye compares it to `6/20` without re-reading.
  if (ceiling === null) return `${used.value}/∞`;
  if (ceiling.state !== "ok") return null;
  // ⛔ NO CLAMP. `24/20` RENDERS AS `24/20`.
  //
  // A deployment sits above its band whenever a licence lapses or a tier is downgraded — running gateways
  // are never stopped, by ruling, so exceeding the ceiling is a NORMAL state and not an error. Clamping to
  // `20/20` would hide the one number the operator needs to act on, and erroring would put a fault on a
  // deployment that is behaving exactly as designed.
  //
  // ⚠ `1/1` ON COMMUNITY IS THE SAME KIND OF TRUTH AND MUST NOT LOOK LIKE AN ALARM. It says "you are using
  // the gateway you have", which is the expected steady state of every free deployment — not a warning, not
  // red, and not something to soften into `1` or hide. The badge states it and the refusal explains it if
  // the operator ever tries to add another.
  return `${used.value}/${ceiling.value}`;
}

/**
 * ⛔ THE Loaded<T> -> NavCount MAPPING, EXTRACTED SO IT CAN BE TESTED.
 *
 * FOUND BY A MUTATION THAT PASSED. The pure `badgeText`/`gatewayBadgeText` layer was gated and the WIRING was
 * not: rewriting `sites.ok ? ok(len) : FAILED` into `ok(sites.ok ? len : 0)` — the classic route to a false
 * count — went green, because no test looked at the hook that performs the mapping.
 *
 * The three-layer shape this project already uses says the DECISION must be pure and unit-tested, and the
 * component must only render it. This mapping WAS the decision, and it was living in a `useEffect`.
 */
export function countFrom<T>(
  res: { ok: true; data: T } | { ok: false },
  project: (t: T) => number,
): NavCount {
  // `.data` is unreachable without narrowing `.ok`, so there is no branch in which a failure can produce a
  // number — the Loaded<T> contract doing its job one layer further out.
  return res.ok ? ok(project(res.data)) : FAILED;
}

/** The Gateways page and its sidebar must agree: count the current org's node rows, never licence metadata. */
export function gatewayTotalFrom<T extends readonly unknown[]>(
  res: { ok: true; data: T } | { ok: false },
): NavCount {
  return countFrom(res, (rows) => rows.length);
}

/** Every count starts unknown. There is no zero-valued initial state to leak. */
export interface NavCounts {
  gatewaysOnline: NavCount;
  gatewaysTotal: NavCount;
  // ⚠ null means UNLIMITED (Scale), which is a real answer — distinct from a NavCount that failed to load.
  gatewayCeiling: NavCount | null;
  sites: NavCount;
  devices: NavCount;
}

export const INITIAL_NAV_COUNTS: NavCounts = {
  gatewaysOnline: LOADING,
  gatewaysTotal: LOADING,
  gatewayCeiling: LOADING,
  sites: LOADING,
  devices: LOADING,
};

/**
 * How often the counts refresh, in ms.
 *
 * Ruled: refresh on ROUTE CHANGE plus a SLOW interval. A static count goes stale the moment anything changes
 * and becomes a remembered number wearing a live badge; a fast poll is four requests on a timer for a number
 * the user glances at. Sixty seconds is the compromise, and route-change covers the case that actually matters
 * — the user just did something and navigated.
 */
export const NAV_COUNT_REFRESH_MS = 60_000;
