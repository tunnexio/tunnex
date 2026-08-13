import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { PRODUCT_NAME } from "../brand";
import { api, apiErrorMessage } from "../lib/api";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";

export default function Signup() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { error } = await api.POST("/api/v1/auth/signup", {
      body: { name, email, password },
    });
    setBusy(false);
    // Signup returns 202 identically whether the email is new or already
    // registered (enumeration resistance) — we ONLY branch on a validation error
    // (e.g. weak_password), never on account existence.
    if (error) {
      setError(apiErrorMessage(error, "Could not create the account."));
      return;
    }
    setDone(true);
  }

  if (done) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">Check your email</h1>
        <p className="mt-2 text-sm text-slate-400">
          If that email can be registered, we&rsquo;ve sent a verification link.
          Follow it to finish setting up your account.
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
      <h1 className="text-xl font-semibold text-white">Create your account</h1>
      <p className="mt-1 text-sm text-slate-400">
        Set up a {PRODUCT_NAME} account to manage your devices.
      </p>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Name">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="Email">
          <Input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
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
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Creating…" : "Create account"}
        </Button>
      </form>
      <Link
        to="/login"
        className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
      >
        Already have an account? Sign in
      </Link>
    </AuthLayout>
  );
}
