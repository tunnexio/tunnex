// What the client can honestly say about updates — the PURE half, so it can be tested.
//
// ⛔ "WE HAVE THE ROLLOUT DONE, JUST WIRE IT UP" — AND THE MEASUREMENT SAYS TWO PIECES ARE MISSING,
// NOT ONE.
//
//   · `AUTOUPDATE_ENABLED` is `false`, and `security.test.ts` PINS it false on purpose: macOS
//     auto-update (Squirrel.Mac) cannot function on an unsigned app, and shipping an unsigned
//     auto-updater is a security anti-pattern — it is a remote-code-execution channel with no
//     signature check on the far end.
//   · `package.json` has **`build.publish: null`**. There is no feed. Even with signing, there is
//     nowhere to check.
//
// > **A SCAFFOLD IS NOT A ROLLOUT.** `updater.ts` imports `electron-updater`, sets a logger and
// > returns — which is enough to look finished from the outside and enough to log a line every
// > launch, which is exactly what made it look wired.
//
// ⛔ SO THE BUTTON IS NOT WIRED TO A CHECK THAT CANNOT RUN. This repo has already shipped that
// defect twice today (Connect while signed out; the entry that 404s), and the state model's own
// rule is that a null action means NO BUTTON rather than a control that can only fail. What ships
// instead is the VERSION — which is real, is the thing a user is actually asked for in a support
// conversation — and one sentence naming what is missing.

export type UpdateStatus =
  | { kind: "disabled"; reason: string; detail: string }
  | { kind: "no_feed"; reason: string; detail: string }
  | { kind: "ready" };

/**
 * Decide what the client may claim about updating itself.
 *
 * Both inputs are build-time facts, so this is total and has no I/O — the point is that the
 * ANSWER is checkable in a unit test rather than discovered by pressing a button in a packaged app.
 */
export function updateStatus(enabled: boolean, feedConfigured: boolean): UpdateStatus {
  if (!enabled) {
    return {
      kind: "disabled",
      reason: "Automatic updates are off in this build.",
      detail:
        "The app is not code-signed or notarized yet, and an unsigned auto-updater would install code without verifying who produced it. Update by downloading a new build.",
    };
  }
  if (!feedConfigured) {
    return {
      kind: "no_feed",
      reason: "No update feed is configured for this build.",
      detail:
        "The updater is enabled but has no release channel to query, so a check would have nowhere to look.",
    };
  }
  return { kind: "ready" };
}

/** Is there anything a "Check for updates" button could actually do? */
export function canCheckForUpdates(s: UpdateStatus): boolean {
  return s.kind === "ready";
}
