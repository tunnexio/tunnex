// The user-controlled sidebar collapse.
//
// ⛔ WE BUILT THE RESPONSIVE COLLAPSE AND NEVER THE USER-CONTROLLED ONE. `navMode` narrows the rail
// when the VIEWPORT is small; nothing let an operator narrow it on a wide screen and keep it that
// way. That is the state the design specifies and persists.
//
// ⚠ AND THE KEY IS DOCUMENTED, WHICH I PREVIOUSLY SAID IT WAS NOT. It is in the wireframe's own JS,
// not in our README — which is the only place I grepped:
//
//     localStorage.setItem('tnx-nav', c ? 'closed' : 'open')
//
// So the key AND its two values are the designer's, transcribed rather than chosen. **"Not in our
// README" is not the same as "not documented", and I reported the first as the second.**
//
// The rest of the state model, verbatim from the same object:
//
//     sbWidth  closed ? 64px  : 228px
//     wmDisp   closed ? none  : block     the wordmark
//     hdDisp   closed ? none  : block     the section headers
//     navPad   closed ? 9px 0 : 7px 12px
//     navJus   closed ? center: flex-start
//     title    closed ? "Expand sidebar" : "Collapse sidebar"

export const NAV_STORAGE_KEY = "tnx-nav";

export type NavCollapse = "open" | "closed";

/**
 * Read the persisted state.
 *
 * ⛔ DEFAULTS OPEN, AND AN UNREADABLE STORE IS NOT "CLOSED". A user in private mode, or with
 * storage disabled, gets the full sidebar rather than a mystery icon rail they never chose — the
 * same absent-until-known rule the nav counts and the edition seam follow.
 */
export function readNavCollapse(
  store: Pick<Storage, "getItem"> | null,
): NavCollapse {
  try {
    return store?.getItem(NAV_STORAGE_KEY) === "closed" ? "closed" : "open";
  } catch {
    // Access itself can throw (Safari private mode). Absence is not a preference.
    return "open";
  }
}

/** Persist, defensively: a failed write must not break the toggle the user just clicked. */
export function writeNavCollapse(
  store: Pick<Storage, "setItem"> | null,
  next: NavCollapse,
): void {
  try {
    store?.setItem(NAV_STORAGE_KEY, next);
  } catch {
    /* the preference is lost on reload; the current session still honours it */
  }
}

export function toggleNavCollapse(current: NavCollapse): NavCollapse {
  return current === "closed" ? "open" : "closed";
}

/** The design's own values, so a reader can check them against the handoff rather than trust me. */
export const NAV_WIDTH = { open: "228px", closed: "64px" } as const;

export function navToggleTitle(c: NavCollapse): string {
  return c === "closed" ? "Expand sidebar" : "Collapse sidebar";
}

/**
 * ⛔ WHAT COLLAPSING HIDES — and what it must NOT.
 *
 * The wordmark and the SECTION HEADERS go; the destinations and their badges stay. A rail that
 * dropped a destination would make it unreachable rather than compact, and the badges are the
 * reason to glance at the rail at all ("1 DOWN", "3/7").
 */
export function navShows(c: NavCollapse): {
  wordmark: boolean;
  sectionHeaders: boolean;
  labels: boolean;
} {
  const open = c === "open";
  return { wordmark: open, sectionHeaders: open, labels: open };
}
