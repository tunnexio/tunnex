import { apiErrorCode } from "../lib/api";

export function mfaRequiresSignIn(error: unknown): boolean {
  return ["unauthenticated", "session_required", "mfa_session_invalid"].includes(apiErrorCode(error) ?? "");
}

export function MfaSignInAgain({ next }: { next: string }) {
  // A full navigation discards stale in-memory authentication. An expired parent cannot be
  // logged out reliably; do not require that request before allowing a fresh sign-in.
  return <a className="text-sm font-medium underline underline-offset-4" href={'/login?next=' + encodeURIComponent(next)}>Sign in again</a>;
}
