import { useState } from "react";
import { useOptionalAuth } from "../lib/auth";
import { MfaSettings } from "./MfaSettings";

// SA-UX-2 item 3: managers learn before any action that setting up and connecting to servers needs two-factor
// verification, and can set it up here. Shown only when the signed-in account has no confirmed factor.
export function ServerAccessMfaNotice() {
  const auth = useOptionalAuth();
  const [open, setOpen] = useState(false), [done, setDone] = useState(false);
  if (done || auth?.state.status !== "authed" || typeof auth.state.user.recovery_codes_remaining === "number") return null;
  return <section aria-label="Two-factor verification required" className="rounded-lg border border-white/10 p-3 text-sm space-y-2">
    <p className="text-ink-heading">Server setup and server connections need two-factor verification, and your account has none yet.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary className="cursor-pointer">Set up two-factor verification</summary>{open && <MfaSettings setupLabel="Set up two-factor" onEnrolled={() => setDone(true)} signInReturnTo="/browser-access/terminal" />}</details>
  </section>;
}
