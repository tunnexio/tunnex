import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage } from "../lib/api";
import { AuthLayout } from "../components/AuthLayout";

type State =
  | { status: "verifying" }
  | { status: "ok" }
  | { status: "error"; message: string };

/** VerifyEmail consumes the ?token= from the emailed link on mount. */
export default function VerifyEmail() {
  const [params] = useSearchParams();
  const [token] = useState(() => params.get("token") ?? "");
  const [state, setState] = useState<State>({ status: "verifying" });

  useEffect(() => {
    if (!token) {
      setState({
        status: "error",
        message: "This verification link is missing its token.",
      });
      return;
    }
    // Strip the secret token from the URL/history after capture.
    window.history.replaceState(null, "", window.location.pathname);
    let cancelled = false;
    api
      .POST("/api/v1/auth/verify-email", { body: { token } })
      .then(({ error }) => {
        if (cancelled) return;
        setState(
          error
            ? {
                status: "error",
                message: apiErrorMessage(
                  error,
                  "This link is invalid or has expired.",
                ),
              }
            : { status: "ok" },
        );
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <AuthLayout>
      {state.status === "verifying" && (
        <h1 className="text-xl font-semibold text-white">
          Verifying your email…
        </h1>
      )}
      {state.status === "ok" && (
        <>
          <h1 className="text-xl font-semibold text-white">Email verified</h1>
          <p className="mt-2 text-sm text-slate-400">
            Your email is confirmed. You can now sign in.
          </p>
          <Link
            to="/login"
            className="mt-5 inline-block text-xs text-accent-400 hover:text-accent-500"
          >
            Go to sign in
          </Link>
        </>
      )}
      {state.status === "error" && (
        <>
          <h1 className="text-xl font-semibold text-white">
            Verification failed
          </h1>
          <p className="mt-2 text-sm text-danger">{state.message}</p>
          <Link
            to="/login"
            className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
          >
            Back to sign in
          </Link>
        </>
      )}
    </AuthLayout>
  );
}
