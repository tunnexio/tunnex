// The MFA-enrollment gate's CLIENT routing decision (S7.5.5 D8), extracted as a pure function so the
// release journey is table-testable without a DOM/component harness (web test convention: the
// consequential decisions live as pure view-models in src/lib, tested in node without jsdom).
// RequireAuth calls this for an already-AUTHENTICATED user.
//
// WF-3 (UI walk): the gate needs BOTH directions. The original code only routed TO /enroll-mfa, which
// trapped a user whose gate had CLEARED (enrollment confirmed, or a stale flag) on the ceremony page
// with no way back into the app — the ForcedEnroll comment claimed a release the code never performed.
// The release branch below is that missing exit, symmetric with the confinement branch.

export const ENROLL_MFA_PATH = "/enroll-mfa";
export const APP_HOME_PATH = "/dashboard";

// resolveMfaGateRoute returns the path to redirect an authenticated user to, or null to render the
// current route. `gated` is the user's mfa_enrollment_required flag.
export function resolveMfaGateRoute(
  gated: boolean,
  pathname: string,
): string | null {
  // Confine a gated user to the enrollment ceremony until they set up 2FA.
  if (gated && pathname !== ENROLL_MFA_PATH) return ENROLL_MFA_PATH;
  // Release a NON-gated user off the ceremony (WF-3): once the gate clears, back to the app.
  if (!gated && pathname === ENROLL_MFA_PATH) return APP_HOME_PATH;
  return null;
}
