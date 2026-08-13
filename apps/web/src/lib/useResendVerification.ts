import { useState } from "react";
import { api } from "./api";

export type ResendState = "idle" | "busy" | "sent" | "error";

/**
 * useResendVerification wraps POST /auth/verify-email/resend with one load-bearing
 * rule: report "sent" ONLY on a real success. A failed or errored request must not
 * show a confirmation — that would hide the retry affordance and mislead the user
 * into thinking a link is on the way. Shared by the shell banner and the
 * verify-pending onboarding page so the two can't disagree.
 */
export function useResendVerification() {
  const [state, setState] = useState<ResendState>("idle");
  async function resend() {
    setState("busy");
    try {
      const { error } = await api.POST("/api/v1/auth/verify-email/resend", {});
      setState(error ? "error" : "sent");
    } catch {
      setState("error");
    }
  }
  return { state, resend };
}
