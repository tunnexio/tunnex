import { useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { useResendVerification } from "../lib/useResendVerification";
import { AuthLayout } from "../components/AuthLayout";
import { Button } from "../components/ui";

/**
 * VerifyPending is the onboarding landing for an authenticated user who has not
 * verified their email AND has no organization yet (S4.7). Creating an org is
 * verified-gated server-side, so instead of routing them to the create-org step
 * (which would 403), RequireOrg sends them here to finish verification first.
 *
 * An unverified user who already belongs to an org is NOT sent here — they reach
 * the shell, where VerifyEmailBanner nudges them without blocking navigation.
 */
export default function VerifyPending() {
  const { state, logout } = useAuth();
  const navigate = useNavigate();
  const { state: resend, resend: onResend } = useResendVerification();
  const email = state.status === "authed" ? state.user.email : "";

  async function onLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">Verify your email</h1>
      <p className="mt-2 text-sm text-slate-400">
        We sent a verification link to{" "}
        <span className="text-slate-200">{email}</span>. Follow it to finish
        setting up your account, then you can create your organization.
      </p>
      {/* Success feedback uses the accent, not green: green is reserved for
          liveness, not "the action worked" (S4.4 decision f). */}
      {resend === "sent" && (
        <p className="mt-3 text-xs text-accent-400">Sent — check your inbox.</p>
      )}
      {resend === "error" && (
        <p className="mt-3 text-xs text-danger">
          Couldn&rsquo;t send — try again.
        </p>
      )}
      <div className="mt-5 flex items-center justify-between">
        {resend !== "sent" ? (
          <Button
            variant="ghost"
            onClick={onResend}
            disabled={resend === "busy"}
          >
            {resend === "busy" ? "Sending…" : "Resend link"}
          </Button>
        ) : (
          <span />
        )}
        <button
          onClick={onLogout}
          className="text-xs text-slate-400 hover:text-slate-200"
        >
          Sign in as someone else
        </button>
      </div>
    </AuthLayout>
  );
}
