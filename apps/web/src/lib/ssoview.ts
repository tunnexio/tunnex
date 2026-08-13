// SSO form — what a control is allowed to ASSERT.
//
// ⛔ A CONTROL WHOSE DEFAULT READS AS A FACT.
//
// Found on the review stack: Google SSO showed **"Enabled" CHECKED** and a **dotted secret field**
// on a provider the server answers `404 sso_not_configured` for. Microsoft showed the identical
// checked box and identical dots — and IS configured. The two were visually indistinguishable, and
// one of them was asserting something false.
//
// MEASURED, all three halves:
//   · `GET /sso/google`   -> 404 sso_not_configured   (nothing is stored)
//   · `useState(true)`    -> the box is checked BEFORE any load, and an unconfigured provider never
//                            calls `setEnabled`, so it simply stays checked
//   · `placeholder="••••••••"` renders unconditionally, with no relation to whether a secret exists
//
// An admin reading that screen concludes Google SSO is enabled with a stored secret. **Neither is
// true.** This is the S14.11 collapse one field over: there the failure was a FAILED READ rendering
// as "not configured"; here it is a FORM DEFAULT rendering as "configured".

/**
 * What the toggle MEANS depends on the arm, so the label must too.
 *
 * Configured  -> it reflects STORED STATE. "Enabled" is a statement about the server.
 * Unconfigured -> nothing is stored, so it can only be an INTENT about the config being created.
 *                 Calling that "Enabled" states a fact that does not exist yet.
 */
export function enabledLabel(configured: boolean): string {
  return configured ? "Enabled" : "Enable when saved";
}

/**
 * ⛔ THE DOTS ARE A CLAIM THAT A SECRET IS STORED, so they may only render when one is.
 *
 * On the configured arm the dots sit above a real `secret_fingerprint` — proof of storage. On the
 * unconfigured arm they sat above nothing and meant nothing, while looking exactly the same.
 */
export function secretPlaceholder(configured: boolean): string {
  return configured ? "••••••••" : "";
}

/**
 * Whether the panel may show the toggle as reflecting server state at all.
 *
 * Kept as its own predicate rather than inlined, because the assertion that matters is the
 * NEGATIVE one — and a boolean that is always true cannot be told from one that is correctly true.
 */
export function toggleReflectsServer(configured: boolean): boolean {
  return configured;
}
