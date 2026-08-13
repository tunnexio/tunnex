// The renderer's entry URL — ONE constant, because there is more than one place that loads it.
//
// ⛔ STEP 3 WAS REPORTED AS A ONE-LINE FLIP. IT WAS TWO LINES, AND THE ONE I MISSED IS THE ONE A
// NEW USER HITS FIRST.
//
// `index.ts` loads the renderer when a server URL is already configured. `ipc.ts` loads it again in
// `config:setServerUrl` on the wasUnset branch — the FIRST RUN path, where a plain `reload()` cannot
// work because it would re-load the setup `data:` URL and cannot change origin. So a fresh install
// went: setup screen → server URL → **the web dashboard**, and only a second launch reached the
// client. The flip's own commit message called that line "the whole migration".
//
// > **A CONSTANT WITH TWO CALL SITES WRITTEN AS TWO LITERALS IS TWO CONSTANTS**, and they only agree
// > until someone changes one of them. Nothing about the second site was subtle — it was simply not
// > searched for, because the change was believed to be one line before it was measured.
//
// ⚠ The census that was supposed to catch this read `index.ts` ALONE. It asserted the entry is
// loaded SOMEWHERE, which was true, and never asked whether anything loads a DIFFERENT one — a
// ledger sees only the shape it is keyed on. It now scans every file in this directory for any
// `app://tunnex/*.html` and holds the set to exactly this value.
export const CLIENT_ENTRY = "app://tunnex/client.html";

/**
 * What to do with the window after `config:setServerUrl` accepts a URL.
 *
 * ⛔ EXTRACTED BECAUSE THE BUG LIVED ON A BRANCH NO TEST COULD REACH. `ipc.ts` imports `electron` at
 * module scope, and client tests must import no Electron at runtime — so `config:setServerUrl` has
 * never been executed by a test, and the wrong entry survived a whole merge cycle there. A source
 * census caught it the second time; a source census is the same instrument class that missed it the
 * first time. **The decision is a pure function so it can be RUN, not scanned.**
 *
 * `wasUnset` is the first-run transition (no server configured → configured). It must LOAD: a plain
 * `reload()` would re-load the setup `data:` URL, which cannot change origin.
 */
export type PostServerUrlAction =
  | { kind: "load"; url: string }
  | { kind: "reload" };

export function postServerUrlAction(wasUnset: boolean): PostServerUrlAction {
  return wasUnset ? { kind: "load", url: CLIENT_ENTRY } : { kind: "reload" };
}
