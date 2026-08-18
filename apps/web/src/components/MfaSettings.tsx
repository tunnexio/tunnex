import { useEffect, useState, type FormEvent } from "react";
import { QRCodeSVG } from "qrcode.react";
import { api, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  Button,
  Field,
  Input,
  Modal,
  SettingRow,
  SettingValue,
} from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";

/**
 * MfaSettings — self-service TOTP (OPEN, all editions, S7.5.5). Verify-before-arm ceremony:
 * a secret is provisioned unconfirmed, the QR/manual key is shown ONCE, and MFA only arms on a
 * valid code. Recovery codes are a one-time-secret-class display. An abandoned ceremony leaves
 * the user unenrolled (the secret is unconfirmed) and is fully restartable — starting again
 * replaces the pending secret. Enrolled state carries the D11 low-remaining warning.
 */
export function MfaSettings() {
  const [enrolled, setEnrolled] = useState<boolean | null>(null); // null = loading
  const [remaining, setRemaining] = useState<number | undefined>(undefined);
  const [phase, setPhase] = useState<"idle" | "enrolling">("idle");
  // The manage dialog is separate from `phase`: enrolment and management are different transactions.
  const [managing, setManaging] = useState(false);
  const [otpauth, setOtpauth] = useState("");
  const [manualKey, setManualKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { setUser } = useAuth();

  async function refresh() {
    const { data } = await api.GET("/api/v1/auth/me");
    if (data) {
      // Update the GLOBAL auth user too: confirming here clears mfa_enrollment_required, which
      // lifts the RequireAuth enrollment gate without a re-login.
      setUser(data);
      const rem = data.recovery_codes_remaining;
      setEnrolled(rem !== undefined && rem !== null);
      setRemaining(rem ?? undefined);
    } else {
      setEnrolled(false);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);

  async function start() {
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/mfa/enroll", {});
    setBusy(false);
    if (error || !data) {
      setError(apiErrorMessage(error, "Could not start two-factor setup."));
      return;
    }
    setOtpauth(data.otpauth_uri);
    setManualKey(data.secret);
    setShowKey(false);
    setCode("");
    setPhase("enrolling");
  }

  async function confirm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/mfa/enroll/confirm", {
      body: { code },
    });
    setBusy(false);
    if (error || !data) {
      setError(
        apiErrorMessage(
          error,
          "That code is not valid — check your authenticator app and try again.",
        ),
      );
      return;
    }
    setRecovery(data.recovery_codes);
    setPhase("idle");
    setCode("");
    // WF-5: do NOT refresh()/clear the gate here. On the forced-enroll path clearing
    // mfa_enrollment_required fires RequireAuth's release-to-app redirect, which would unmount this
    // component and DESTROY the one-time recovery-codes modal before the user can save them. The gate
    // clears only when the user acknowledges the codes (modal onDismiss → refresh), so the recovery
    // codes always survive the ceremony.
  }

  async function disable() {
    setBusy(true);
    setError(null);
    const { error } = await api.DELETE("/api/v1/auth/mfa", {});
    setBusy(false);
    setConfirmDisable(false);
    if (error) {
      setError(
        apiErrorMessage(error, "Could not turn off two-factor authentication."),
      );
      return;
    }
    void refresh();
  }

  return (
    // ⛔ THE ROW STATES WHETHER 2FA IS ON; THE WIZARD LIVES IN A DIALOG. This was a bordered card sitting
    // among rows, permanently showing a setup flow most visits are not here to run. `enrolled === null` is
    // "not read yet", NOT "off" — rendering "Off" for an unknown value would tell someone their account is
    // unprotected when it may not be.
    <SettingRow
      label="Two-factor authentication"
      description="Require a code from an authenticator app when signing in."
      error={error}
    >
      <div className="flex items-center gap-3">
        {enrolled === null ? (
          <span className="text-cell text-ink-tertiary">…</span>
        ) : (
          <SettingValue tone={enrolled ? "live" : "muted"}>
            {enrolled ? "On" : "Off"}
          </SettingValue>
        )}
        {enrolled === false && (
          <Button variant="ghost" onClick={start} disabled={busy}>
            {busy ? "Starting…" : "Set up"}
          </Button>
        )}
        {enrolled === true && (
          <Button
            variant="ghost"
            onClick={() => setManaging(true)}
            disabled={busy}
          >
            Manage
          </Button>
        )}
      </div>

      {phase === "enrolling" && (
        <Modal
          title="Set up two-factor authentication"
          onDismiss={() => setPhase("idle")}
          actions={
            <Button variant="ghost" onClick={() => setPhase("idle")}>
              Cancel
            </Button>
          }
        >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Scan this with your authenticator app, then enter the 6-digit code
            it shows to finish.
          </p>
          <div className="inline-block rounded-lg bg-white p-3">
            <QRCodeSVG value={otpauth} size={168} />
          </div>
          <div>
            <button
              type="button"
              className="text-xs text-slate-400 underline hover:text-slate-200"
              onClick={() => setShowKey((v) => !v)}
            >
              {showKey ? "Hide manual key" : "Can’t scan? Enter a key manually"}
            </button>
            {showKey && (
              <pre className="mt-2 select-all rounded-md bg-ink-950 p-2 font-mono text-xs text-slate-300">
                {manualKey}
              </pre>
            )}
          </div>
          <form onSubmit={confirm} className="flex items-end gap-2">
            <Field label="6-digit code">
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                autoComplete="one-time-code"
                inputMode="numeric"
              />
            </Field>
            <Button type="submit" disabled={busy}>
              {busy ? "Verifying…" : "Verify & turn on"}
            </Button>
          </form>
        </div>
        </Modal>
      )}

      {enrolled === true && phase === "idle" && managing && (
        <Modal
          title="Two-factor authentication"
          onDismiss={() => {
            setManaging(false);
            setConfirmDisable(false);
          }}
          actions={
            <Button
              variant="ghost"
              onClick={() => {
                setManaging(false);
                setConfirmDisable(false);
              }}
            >
              Close
            </Button>
          }
        >
        <div className="space-y-3">
          <p className="text-xs text-emerald-400">
            Two-factor authentication is on.
          </p>
          {remaining !== undefined && remaining <= 3 && (
            <p className="text-xs text-warn">
              {remaining === 0
                ? "You have no recovery codes left. Turn 2FA off and on again to generate a new set before you lose access to your authenticator."
                : `Only ${remaining} recovery code${remaining === 1 ? "" : "s"} left — turn 2FA off and on again to generate a fresh set.`}
            </p>
          )}
          {!confirmDisable ? (
            <Button variant="ghost" onClick={() => setConfirmDisable(true)}>
              Turn off two-factor authentication
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">
                Turn off 2FA? Your account will rely on your password alone.
              </span>
              <Button variant="ghost" onClick={disable} disabled={busy}>
                {busy ? "Turning off…" : "Confirm"}
              </Button>
              <Button variant="ghost" onClick={() => setConfirmDisable(false)}>
                Keep it on
              </Button>
            </div>
          )}
        </div>
        </Modal>
      )}

      {recovery && (
        <OneTimeSecretModal
          requireAck="I have saved my recovery codes somewhere I can reach without this device."
          title="Save your recovery codes"
          caption="Each code works once, in place of your authenticator. Store them somewhere safe — they are shown only now and let you sign in if you lose your device."
          secret={recovery.join("\n")}
          copyLabel="Copy codes"
          downloadFilename="tunnex-recovery-codes.txt"
          onDismiss={() => {
            setRecovery(null);
            // WF-5: clear the gate ONLY now (after the codes are acknowledged). On the forced-enroll
            // path this is what releases the user to the app (RequireAuth), so the recovery modal is
            // never skipped; on the Settings path it just refreshes the enrolled/remaining state.
            void refresh();
          }}
        />
      )}
    </SettingRow>
  );
}
