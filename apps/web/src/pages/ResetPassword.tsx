import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";

export default function ResetPassword() {
  const [params] = useSearchParams();
  // Capture the token ONCE, then strip it from the URL so the secret doesn't
  // linger in browser history / leak via the Referer header. Captured in state so
  // later re-renders (typing) don't lose it after the URL is scrubbed.
  const [token] = useState(() => params.get("token") ?? "");
  useEffect(() => {
    if (params.get("token"))
      window.history.replaceState(null, "", window.location.pathname);
  }, [params]);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { error } = await api.POST("/api/v1/auth/password-reset/confirm", {
      body: { token, password },
    });
    setBusy(false);
    if (error) {
      setError(
        apiErrorMessage(error, "This reset link is invalid or has expired."),
      );
      return;
    }
    setDone(true);
  }

  if (!token) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">Invalid reset link</h1>
        <p className="mt-2 text-sm text-slate-400">
          This link is missing its token. Request a new one.
        </p>
        <Link
          to="/forgot-password"
          className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
        >
          Request a reset link
        </Link>
      </AuthLayout>
    );
  }

  if (done) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">Password updated</h1>
        <p className="mt-2 text-sm text-slate-400">
          You can now sign in with your new password.
        </p>
        <Link
          to="/login"
          className="mt-5 inline-block text-xs text-accent-400 hover:text-accent-500"
        >
          Go to sign in
        </Link>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">Set a new password</h1>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="New password">
          <Input
            type="password"
            name="new-password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
            autoFocus
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Updating…" : "Update password"}
        </Button>
      </form>
    </AuthLayout>
  );
}
