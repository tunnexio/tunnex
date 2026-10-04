import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { Button, Card, ErrorText, Field, Input } from "./ui";
import { MfaSettings } from "./MfaSettings";
import { mfaRequiresSignIn, MfaSignInAgain } from "./MfaSessionRequired";

export default function AppAccessMfaChallenge({ setupRequired, onVerified }: {
  setupRequired: boolean; onVerified: () => void;
}) {
  const [setup, setSetup] = useState(setupRequired);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sessionRequired, setSessionRequired] = useState(false);
  const active = useRef(true);
  const locked = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  async function verify(event: FormEvent) {
    event.preventDefault();
    if (!code.trim() || locked.current) return;
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/auth/mfa/step-up", { body: { code: code.trim() } });
      if (!active.current) return;
      setCode("");
      if (result.error || !result.data) {
        if (mfaRequiresSignIn(result.error)) setSessionRequired(true);
        else if (["mfa_setup_required", "app_mfa_setup_required"].includes(apiErrorCode(result.error) ?? "")) setSetup(true);
        else setError(apiErrorMessage(result.error, "Could not verify your code. Try a fresh authenticator code or an unused recovery code."));
        return;
      }
      onVerified();
    } catch { if (active.current) { setCode(""); setError("Could not confirm verification. Try a fresh authenticator code."); } }
    finally { locked.current = false; if (active.current) setBusy(false); }
  }
  if (sessionRequired) return <Card className="space-y-4">
    <h2 className="text-lg font-semibold">Sign in again to verify MFA</h2>
    <p className="text-sm text-ink-secondary">Your sign-in session is no longer valid. Sign in again, then reopen the application from My Applications.</p>
    <MfaSignInAgain next="/app-access/my-applications" />
  </Card>;
  return <Card className="space-y-4">
    <div className="space-y-2"><h2 className="text-lg font-semibold">{setup ? "Set up MFA to open this application" : "Verify MFA to open this application"}</h2>
      <p className="text-sm text-ink-secondary">{setup ? "This app requires recent multi-factor verification. Set up your account authenticator once; the same factor works for your account and other protected apps." : "Use your existing account authenticator or an unused recovery code. A recent verified check can be reused by other protected apps."}</p>
      <p className="text-sm text-ink-secondary">This requirement also applies when you sign in with SSO. Only verified recent MFA can satisfy it.</p>
    </div>
    {setup ? <><MfaSettings setupLabel="Set up MFA" onEnrolled={onVerified} signInReturnTo="/app-access/my-applications" /><Button variant="ghost" onClick={() => setSetup(false)}>Use an existing authenticator</Button></> : <form onSubmit={verify} className="space-y-4">
      <Field label="Authenticator or recovery code"><Input value={code} onChange={event => setCode(event.target.value)} required maxLength={128} autoComplete="one-time-code" autoFocus disabled={busy} /></Field>
      <Button type="submit" disabled={busy || !code.trim()}>{busy ? "Verifying…" : "Verify MFA"}</Button>
    </form>}
    <ErrorText>{error}</ErrorText>
  </Card>;
}
