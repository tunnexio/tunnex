import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";
import { api, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";

/**
 * ChangePassword is the forced first-login password change.
 *
 * ⛔ THE SERVER WALL EXISTED BEFORE THIS SCREEN DID, AND THAT COMBINATION IS ITS OWN DEFECT. Every route
 * returned `403 password_change_required` and the client had nowhere to send anyone — so the operator
 * signed in with the credential the logs printed, landed on the create-org form, and read a red error under
 * a button that could never work. Correct refusal, no route: the same dead-end shape as a ceiling with no
 * upgrade path.
 *
 * ⭐ A WALL IS ONLY HONEST IF IT HAS A DOOR IN IT.
 *
 * ⚠ THE BOOTSTRAP CREDENTIAL IS PRINTED TO `docker compose logs` — shipped, aggregated, searchable — so it
 * is treated as compromised from the moment it works. This screen is how it stops being.
 */
export function ChangePassword() {
  const { state, setUser } = useAuth();
  const navigate = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    // ⚠ CHECKED HERE, NOT ON THE SERVER. A typo in a password nobody can read back would lock the operator
    // out of a deployment whose only other recovery is destroying the database.
    if (next !== confirm) {
      return setError("The two new passwords do not match.");
    }
    setBusy(true);
    setError(null);
    try {
      const { error: err } = await api.POST("/api/v1/auth/password", {
        body: { current_password: current, new_password: next },
      });
      if (err) {
        setError(apiErrorMessage(err, "Could not change the password."));
        return;
      }
      // ⛔ THE FLAG IS CLEARED LOCALLY TOO, or the guard that routed us here routes us here again — a loop
      // whose only exit is closing the tab, which this product has already shipped once.
      if (state.status === "authed") {
        setUser({ ...state.user, must_change_password: false });
      }
      navigate("/dashboard", { replace: true });
    } catch {
      setError("Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">Set a new password</h1>
      <p className="mt-2 text-sm text-slate-400">
        This account is using the one-time password printed in the server logs.
        Anyone who can read those logs can read it, so choose a new one before
        going any further.
      </p>

      <form onSubmit={submit} className="mt-5 space-y-3">
        <Field label="Current password">
          <Input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </Field>
        <Field label="New password">
          <Input
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </Field>
        <Field label="Confirm new password">
          <Input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Saving…" : "Set password"}
        </Button>
      </form>
    </AuthLayout>
  );
}

export default ChangePassword;
