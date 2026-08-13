// S14.3 SLICE B — MOTION, AS A DECISION RATHER THAN A STYLE.
//
// ⛔ `prefers-reduced-motion` IS A GATE, NOT A COURTESY (founder-ruled). Vestibular disorders make large or
// fast motion physically unpleasant; honouring the preference is an accessibility obligation, not a polish
// item, so it is asserted and PROVEN TO REJECT rather than reviewed.
//
// ⚠ WHY THIS IS A PURE FUNCTION, AND IT IS THE SAME REASON S14.2's `layoutIntent` IS ONE: jsdom DOES NOT
// IMPLEMENT `window.matchMedia`. A test that rendered a component and asked whether reduced motion was
// honoured would THROW, or — worse, if someone stubbed it carelessly — silently no-op and pass at every
// setting. That is the detector's FIFTH prospective catch, found BEFORE this gate was written rather than
// after it silently passed (docs/laws.md).
//
// THE SHAPE: preference read ONCE at the app edge -> a boolean -> a pure decision -> a render decision.
// Never a component asking the media query itself.

/**
 * The whole decision. Pure, total, and trivially testable in both directions.
 *
 * It is deliberately not `!prefersReducedMotion` inlined at call sites: a named function is a place to hang
 * the reason, and it is the single point a mutation can attack to prove the gate is load-bearing.
 */
export function motionAllowed(prefersReducedMotion: boolean): boolean {
  return !prefersReducedMotion;
}

/**
 * The media query string, exported so the app and its tests refer to the SAME literal.
 *
 * A typo here fails OPEN — `matchMedia` returns `matches: false` for a query it cannot parse, which reads as
 * "the user has no preference" and animates for someone who asked not to be animated. So the string is named
 * once and asserted, never retyped.
 */
export const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

/**
 * Reads the preference from the platform. THE ONLY PLACE IN THE PRODUCT THAT MAY TOUCH `matchMedia`.
 *
 * Defaults to REDUCED (`true`) when the platform cannot answer — an old browser, a test environment, an
 * embedded webview. FAIL TOWARDS LESS MOTION: the cost of not animating for someone who would have enjoyed it
 * is nothing; the cost of animating for someone who cannot tolerate it is a person feeling ill.
 */
export function readsReducedMotionPreference(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function")
    return true;
  try {
    return window.matchMedia(REDUCED_MOTION_QUERY).matches;
  } catch {
    return true;
  }
}
