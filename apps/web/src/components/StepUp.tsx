import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useOptionalAuth } from "../lib/auth";
import { Field, Input } from "./ui";

// RBAC-0 D9 — step-up for people-management actions (role changes, deactivation, 2FA reset, machine
// credentials). The server decides; /auth/me says what it will ask for, so the password is asked for up
// front and a stale MFA is handled inline with InlineTerminalMfa rather than surfacing a raw error.

export type StepUpNeeds = { password: boolean; mfa: boolean; available: boolean };

export function useStepUpNeeds(): StepUpNeeds | undefined {
  const auth = useOptionalAuth();
  return useResolvedStepUpNeeds(auth?.state.status === "authed" ? auth.state.user.reauthentication : undefined, auth?.state.status === "authed");
}

/**
 * The sign-in response does not carry `reauthentication` (it is session-derived and only /auth/me reports
 * it), so a freshly signed-in page reads it once from /auth/me rather than guessing.
 */
export function useResolvedStepUpNeeds(known: StepUpNeeds | undefined, authed: boolean): StepUpNeeds | undefined {
  const [fetched, setFetched] = useState<StepUpNeeds | undefined>(undefined);
  useEffect(() => {
    if (known || !authed) return;
    let alive = true;
    void Promise.resolve(api.GET("/api/v1/auth/me")).then(result => {
      const value = (result as { data?: { reauthentication?: StepUpNeeds } } | undefined)?.data?.reauthentication;
      if (alive && value && typeof value.password === "boolean") setFetched(value);
    }).catch(() => {});
    return () => { alive = false; };
  }, [known, authed]);
  return known ?? fetched;
}

/** The error codes that mean "confirm it is you", as opposed to a refusal of the action itself. */
export const STEP_UP_MFA = "mfa_step_up_required";
const STEP_UP_CODES = new Set([
  STEP_UP_MFA,
  "current_password_required",
  "invalid_credentials",
  "reauthentication_rate_limited",
  "reauthentication_unavailable",
  "human_session_required",
]);

export function isStepUpCode(code: string | undefined): boolean {
  return !!code && STEP_UP_CODES.has(code);
}

export function stepUpBody(needs: StepUpNeeds | undefined, password: string): { current_password?: string } {
  return needs?.password && password ? { current_password: password } : {};
}

export function StepUpPassword({ needs, value, onChange, disabled, action }: { needs: StepUpNeeds | undefined; value: string; onChange: (value: string) => void; disabled?: boolean; action: string }) {
  if (needs && !needs.available) {
    return <p role="note" className="user-stage-meta">To {action}, set up an authenticator app (two-factor authentication) in your account settings first.</p>;
  }
  if (!needs?.password) return needs?.mfa ? <p className="user-stage-meta">You may be asked for a two-factor code to confirm it is you.</p> : null;
  return <Field label="Your current password">
    <Input type="password" autoComplete="current-password" value={value} disabled={disabled} onChange={event => onChange(event.target.value)} />
  </Field>;
}
