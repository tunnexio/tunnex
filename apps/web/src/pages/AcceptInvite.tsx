import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";
import { CLIENT_DOWNLOAD_URL } from "../components/ClientConnection";

/**
 * AcceptInvite is the landing page for the invitation link
 * (/accept-invite?token=…). WITHOUT it the link fell through to `*` → /dashboard →
 * /login and the token was dropped, so an invited user signed up fresh with no org
 * and got bounced into create-org onboarding instead of joining the inviting org.
 *
 * Accepting provisions/links the user and adds the membership. It does NOT auto-login
 * (the link is admin-visible in the dashboard, so a session must never be minted from
 * it): the invitee sets a password here, then signs in explicitly and lands in the
 * org (RequireOrg passes — the membership now exists).
 *
 * RBAC-0 D1: when the invited address ALREADY has an account, the token alone is not
 * enough — the invitee must be signed in as that account. The page keeps the token in
 * this tab's sessionStorage (never the URL), sends them to sign in, and brings them back
 * here to accept with one button.
 */
const PENDING_INVITE_KEY = "tunnex.pendingInvite";

function readPendingInvite(): { token: string; signIn: boolean } | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_INVITE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { token?: unknown; signIn?: unknown };
    return typeof parsed.token === "string" && parsed.token ? { token: parsed.token, signIn: parsed.signIn === true } : null;
  } catch {
    return null;
  }
}

function writePendingInvite(value: { token: string; signIn: boolean } | null) {
  try {
    if (value) window.sessionStorage.setItem(PENDING_INVITE_KEY, JSON.stringify(value));
    else window.sessionStorage.removeItem(PENDING_INVITE_KEY);
  } catch {
    // Storage unavailable: the person can open the invitation link again after signing in.
  }
}
export default function AcceptInvite() {
  const [params] = useSearchParams();
  // Capture the token ONCE, then strip it from the URL so the secret doesn't linger
  // in browser history / leak via the Referer header (same hygiene as ResetPassword).
  const [pending] = useState(() => {
    const fromUrl = params.get("token");
    if (fromUrl) return { token: fromUrl, signIn: false };
    return readPendingInvite() ?? { token: "", signIn: false };
  });
  const token = pending.token;
  const { state: auth } = useAuth();
  const [needsSignIn, setNeedsSignIn] = useState(false);
  // Came back from signing in for an existing account: accept with one button.
  const existingAccount = pending.signIn && auth.status === "authed";
  useEffect(() => {
    if (params.get("token"))
      window.history.replaceState(null, "", window.location.pathname);
  }, [params]);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNeedsSignIn(false);
    const { error } = await api.POST("/api/v1/auth/invitations/accept", {
      body: existingAccount ? { token } : { token, name, password },
    });
    setBusy(false);
    if (error) {
      const code = apiErrorCode(error);
      if (code === "sign_in_required") {
        writePendingInvite({ token, signIn: true });
        setNeedsSignIn(true);
      }
      setError(
        apiErrorMessage(error, "This invitation is invalid or has expired."),
      );
      return;
    }
    writePendingInvite(null);
    setDone(true);
  }

  if (!token) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Invalid invitation link
        </h1>
        <p className="mt-2 text-sm text-slate-400">
          This link is missing its token. Ask your administrator to resend the
          invitation.
        </p>
        <Link
          to="/login"
          className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
        >
          Go to sign in
        </Link>
      </AuthLayout>
    );
  }

  if (done) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">You're in</h1>
        <p className="mt-2 text-sm text-slate-400">
          Your account is ready. Download the Tunnex client, then sign in to see your server address and connection steps.
        </p>
        <Link
          to="/login?next=%2Fconnect"
          className="mt-5 inline-block text-xs text-accent-400 hover:text-accent-500"
        >
          Sign in and connect
        </Link>
        <a href={CLIENT_DOWNLOAD_URL} target="_blank" rel="noreferrer" className="mt-4 block text-sm text-accent-400 hover:underline">Download Client</a>
      </AuthLayout>
    );
  }

  if (existingAccount && auth.status === "authed") {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Accept your invitation
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          You're signed in as {auth.user.email}. Accept to join the organization that invited you. Your roles in other organizations don't change.
        </p>
        <form onSubmit={submit} className="mt-5 space-y-4">
          <ErrorText>{error}</ErrorText>
          <Button type="submit" disabled={busy} className="w-full">
            {busy ? "Joining…" : "Accept invitation"}
          </Button>
        </form>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">
        Accept your invitation
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Set up your account to join your organization.
      </p>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Your name">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
          />
        </Field>
        <Field label="Password">
          <Input
            type="password"
            name="new-password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        {needsSignIn && (
          <Link
            to="/login?next=%2Faccept-invite"
            className="block text-center text-sm text-accent-400 hover:underline"
          >
            Sign in to accept
          </Link>
        )}
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Joining…" : "Accept invitation"}
        </Button>
      </form>
    </AuthLayout>
  );
}
