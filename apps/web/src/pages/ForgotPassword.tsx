import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { AuthLayout } from "../components/AuthLayout";
import { Button, Field, Input } from "../components/ui";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    // Reset-request is enumeration-resistant server-side (always accepted); we
    // show the same confirmation regardless of whether the email exists.
    await api.POST("/api/v1/auth/password-reset", { body: { email } });
    setBusy(false);
    setDone(true);
  }

  if (done) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">Check your email</h1>
        <p className="mt-2 text-sm text-slate-400">
          If an account exists for that email, we&rsquo;ve sent a link to reset
          your password.
        </p>
        <Link
          to="/login"
          className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
        >
          Back to sign in
        </Link>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">Reset your password</h1>
      <p className="mt-1 text-sm text-slate-400">
        We&rsquo;ll email you a link to set a new password.
      </p>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Email">
          <Input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
        </Field>
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Sending…" : "Send reset link"}
        </Button>
      </form>
      <Link
        to="/login"
        className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
      >
        Back to sign in
      </Link>
    </AuthLayout>
  );
}
