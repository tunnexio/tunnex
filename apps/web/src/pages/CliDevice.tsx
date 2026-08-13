import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";

// CliDevice is the device-code approval page (S5.1 browserless fallback). The
// human enters the user_code the CLI printed; on approve the polling CLI
// receives its credential. The user_code is DISPLAYED (flag-1) — prefilled from
// the query when the CLI links here, but always visible and editable so the
// human confirms exactly what they are approving.
export default function CliDevice() {
  const { state: auth } = useAuth();
  const [params] = useSearchParams();
  const [userCode, setUserCode] = useState(params.get("user_code") ?? "");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/cli/device/approve", {
      body: { user_code: userCode.trim() },
    });
    setBusy(false);
    if (error || !data)
      return setError(apiErrorMessage(error, "Could not approve that code."));
    setDone(true);
  }

  const email = auth.status === "authed" ? auth.user.email : "";

  if (done) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">CLI approved</h1>
        <p className="mt-2 text-sm text-slate-400">
          Return to your terminal — the Tunnex CLI now has its credential. You
          can close this page.
        </p>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">
        Approve a CLI sign-in
      </h1>
      <p className="mt-2 text-sm text-slate-400">
        Signed in as <span className="text-slate-200">{email}</span>. Enter the
        code shown by <span className="font-mono">tunnex login --device</span>{" "}
        to grant it a credential.
      </p>
      {/* Anti-phishing (device-flow's inherent risk): approving binds a credential
          to YOUR identity for whoever is polling that code. */}
      <p className="mt-3 rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-xs text-slate-300">
        Only enter a code you started yourself on this or another of your
        machines. If someone asked you to enter a code here, stop — approving it
        would give <span className="font-semibold">them</span> access to your
        account.
      </p>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Device code">
          <Input
            value={userCode}
            onChange={(e) => setUserCode(e.target.value.toUpperCase())}
            placeholder="XXXX-XXXX"
            required
            autoFocus
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button
          type="submit"
          disabled={busy || !userCode.trim()}
          className="w-full"
        >
          {busy ? "Approving…" : "Approve this device"}
        </Button>
      </form>
    </AuthLayout>
  );
}
