import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage, type Meta } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AuthLayout } from "../components/AuthLayout";
import { recoveryCountLabel, recoveryWarning } from "../lib/authhero";
import { Button, ErrorText, Field, Input } from "../components/ui";

// Human-readable text for SSO callback reject codes (watch-item d) — the server
// redirects failures to /login?sso_error=<code> instead of a raw error body.
const SSO_ERRORS: Record<string, string> = {
  unverified_local_exists:
    "An account with this email already exists. Sign in with your password first, then link SSO from settings.",
  idp_email_unverified:
    "Your identity provider hasn't verified this email address. Verify it there and try again.",
  edition_required: "SSO is not enabled on this deployment.",
};
function ssoErrorText(code: string): string {
  return (
    SSO_ERRORS[code] ??
    "Single sign-on failed. Please try again or sign in with your password."
  );
}

export default function Login() {
  // ⛔ THE DESKTOP ARM IS GONE (S14.20 step 4). This page is the BROWSER login and nothing else:
  // the desktop client loads `client.html`, which mounts no router and never reaches this file.
  // The browser-based sign-in it used to trigger still exists — it lives in the client's own
  // surface now, behind `auth.login()`, which is where the "never an in-app password field" rule
  // is actually enforced.
  return <BrowserLogin />;
}

function BrowserLogin() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(
    params.get("sso_error") ? ssoErrorText(params.get("sso_error")!) : null,
  );
  const [busy, setBusy] = useState(false);
  const [meta, setMeta] = useState<Meta | null>(null);
  // S7.5.5: an MFA-pending login carries a challenge token (NOT a session) — the code step
  // completes at /auth/mfa/verify. (Slice 3 polishes this UI; slice 1 keeps the flow working.)
  const [challenge, setChallenge] = useState<string | null>(null);
  // Cardinality only, and only if the server sent it — undefined means "not told", which must not
  // render as a number. Populated from the login response's challenge payload where present.
  const [remaining, setRemaining] = useState<number | undefined>(undefined);
  const [code, setCode] = useState("");

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/meta")
      .then(({ data }) => {
        if (!cancelled) setMeta(data ?? null);
      })
      .catch(() => {
        /* meta unavailable — SSO section simply stays hidden */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/login", {
      body: { email, password },
    });
    setBusy(false);
    if (error || !data) {
      // The server keeps invalid-credentials generic and account_deactivated
      // distinct; we render its message verbatim (no client-side enumeration tell).
      setError(apiErrorMessage(error, "Invalid email or password."));
      return;
    }
    if (data.mfa_required) {
      setChallenge(data.challenge ?? null);
      setRemaining(
        (data as { recovery_codes_remaining?: number })
          .recovery_codes_remaining,
      );
      return; // NO session yet — the second step mints it
    }
    if (data.user) {
      setUser(data.user);
      finish();
    }
  }

  // Honor a `next` from RequireAuth, but ONLY a local path (leading single slash) so it
  // can never become an open redirect to another origin.
  function finish() {
    const next = params.get("next");
    const dest =
      next && next.startsWith("/") && !next.startsWith("//")
        ? next
        : "/dashboard";
    navigate(dest, { replace: true });
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/mfa/verify", {
      body: { challenge, code },
    });
    setBusy(false);
    if (error || !data) {
      // Legibility (loadOne): each failure is a distinct, named state — never a blank or a
      // reassuring default. A capped-out or burned/expired challenge is DEAD (D7's cap is
      // per-challenge), so route back to the password step; a wrong code stays on the code form.
      const code = (error as { error?: { code?: string } } | undefined)?.error
        ?.code;
      if (code === "mfa_challenge_exhausted") {
        setChallenge(null);
        setCode("");
        setError("Too many incorrect codes. Please sign in again.");
        return;
      }
      if (code === "mfa_challenge_invalid") {
        setChallenge(null);
        setCode("");
        setError("This sign-in has expired. Please sign in again.");
        return;
      }
      setError(
        apiErrorMessage(
          error,
          "That code is not valid — check your authenticator app or use a recovery code.",
        ),
      );
      return;
    }
    setUser(data);
    finish();
  }

  if (challenge) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Two-factor authentication
        </h1>
        {/* ⛔ THE PENDING STATE IS A CHALLENGE TOKEN, NOT A SESSION (D6). Saying so stops a reader
            concluding the password alone got them in — the wireframe's "Password accepted — no
            session yet" is a correct description of the server's state machine, not flavour. */}
        <p className="mt-1 text-sm text-slate-400">
          Password accepted — no session yet. Enter the 6-digit code from your
          authenticator app, or a recovery code.
        </p>
        <form onSubmit={verify} className="mt-5 space-y-4">
          <Field label="Code">
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              autoFocus
              autoComplete="one-time-code"
            />
          </Field>
          {/* ⛔ CARDINALITY ONLY. `recovery_codes_remaining` is documented in the schema as
              "never the codes (nothing recoverable)", so the count renders and the codes never do.
              Rendered ONLY when the server sent a number — a 0 nobody was told is not a zero. */}
          {typeof remaining === "number" && (
            <>
              <p className="text-xs text-slate-600">
                {recoveryCountLabel(remaining)}
              </p>
              {recoveryWarning(remaining) && (
                <p
                  className={
                    "text-xs " +
                    (recoveryWarning(remaining)!.loud
                      ? "text-danger"
                      : "text-warn")
                  }
                >
                  {recoveryWarning(remaining)!.text}
                </p>
              )}
            </>
          )}
          <ErrorText>{error}</ErrorText>
          <Button type="submit" disabled={busy} className="w-full">
            {busy ? "Verifying…" : "Verify"}
          </Button>
        </form>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">Welcome back</h1>
      <p className="mt-1 text-sm text-slate-400">
        Sign in to {window.location.host}
      </p>
      {meta && meta.sso_providers.length > 0 && (
        <>
          <SsoSection providers={meta.sso_providers} onError={setError} />
          {/* The design leads with SSO and puts the password form under an OR — that ordering is
              the recommendation, not decoration. */}
          <div className="mt-5 flex items-center gap-3">
            <span className="h-px flex-1 bg-white/10" />
            <span className="font-mono text-[10px] tracking-widest text-slate-600">
              OR
            </span>
            <span className="h-px flex-1 bg-white/10" />
          </div>
        </>
      )}

      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Email">
          <Input
            type="email"
            name="username"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
        </Field>
        <Field label="Password">
          <Input
            type="password"
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>

      {/* ⛔ A SECURITY PROPERTY, NOT REASSURANCE. Sign-up and reset answer the same 202 whether or
          not the address exists, so "check your email" must not be read as "that address was
          recognised". Same no-oracle rule the 401s follow. */}

      <div className="mt-5 flex justify-between text-xs text-slate-400">
        {/* ⛔ THERE IS NO PUBLIC SIGNUP. EVER. (founder-ruled)
            A self-hosted control plane is owned by ONE COMPANY. Install creates the CP admin; everyone
            else arrives by INVITATION — the invite mints the account and the invited person sets their own
            password from that link. An account-creation form on this page offers a stranger a door into
            someone's private deployment, and there is no version of that which makes sense.

            ⚠ THE LINK IS GONE UNCONDITIONALLY, not hidden behind setup_complete. A conditional link says
            "sometimes you may sign up"; the ruling is that you never may. The server refuses regardless
            (signup_closed), so this is the affordance matching the rule rather than guarding it. */}
        <span />
        <Link to="/forgot-password" className="hover:text-slate-200">
          Forgot password?
        </Link>
      </div>
    </AuthLayout>
  );
}

// SsoSection (enterprise only — hidden entirely in the open build via meta). SSO
// is configured per-org, so the user names their organization, then picks a
// provider; we redirect the browser to the IdP URL the API returns.
function SsoSection({
  providers,
  onError,
}: {
  providers: string[];
  onError: (m: string) => void;
}) {
  const [org, setOrg] = useState("");
  async function start(provider: "google" | "microsoft") {
    if (!org) {
      onError("Enter your organization to sign in with SSO.");
      return;
    }
    const { data, error } = await api.GET("/api/v1/auth/sso/{provider}/start", {
      params: { path: { provider }, query: { org } },
    });
    if (error || !data) {
      onError(apiErrorMessage(error, "Could not start single sign-on."));
      return;
    }
    window.location.href = data.redirect_url;
  }
  return (
    <div className="mt-5">
      {/* ⛔ THE ORG SLUG IS A PRECONDITION, NOT AN AFTERTHOUGHT. `/auth/sso/{provider}/start`
          requires ?org=, so the field comes BEFORE the buttons — the previous order offered two
          buttons that could only error until a field below them was filled. */}
      {/* ⛔ RELABELLED IN S12.5, AND THE OLD LABEL WAS THE DEFECT.
          It said `Organization`, sat above the password form, and did nothing on the password path — its
          value reaches exactly one call, the `?org=` query on `/auth/sso/{provider}/start`. So it read as
          tenant selection and was not: a user in two organizations would type the one they wanted, sign in
          with a password, and land in the other with nothing explaining why.

          ⚠ AND S12.5 MADE IT WORSE BEFORE IT MADE IT BETTER. Once the header carries a real switcher,
          a second control that looks like it steers is not merely useless — it competes with the correct
          one. A control that appears to steer and does not is worse than no control. */}
      <Field label="Where should we send you to sign in?">
        <Input
          value={org}
          onChange={(e) => setOrg(e.target.value)}
          placeholder="your-company"
        />
        <p className="mt-1 text-badge text-ink-secondary">
          Only for single sign-on.
        </p>
      </Field>
      <div className="mt-3 flex gap-2">
        {providers.includes("google") && (
          <button
            type="button"
            onClick={() => start("google")}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-white/10 bg-ink-900 px-3 py-2.5 text-sm font-medium text-white transition-colors hover:bg-white/5"
          >
            <GoogleMark />
            Google
          </button>
        )}
        {providers.includes("microsoft") && (
          <button
            type="button"
            onClick={() => start("microsoft")}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg border border-white/10 bg-ink-900 px-3 py-2.5 text-sm font-medium text-white transition-colors hover:bg-white/5"
          >
            <MicrosoftMark />
            Microsoft
          </button>
        )}
      </div>
    </div>
  );
}

/* Provider marks, inline so the login page makes no third-party request before authentication —
   a logo fetched from a CDN would tell that CDN who is looking at our login page. */
function GoogleMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M23 12.27c0-.79-.07-1.54-.2-2.27H12v4.3h6.18a5.3 5.3 0 0 1-2.29 3.47v2.88h3.7C21.74 18.7 23 15.76 23 12.27z"
      />
      <path
        fill="#34A853"
        d="M12 23c3.1 0 5.7-1.03 7.6-2.79l-3.71-2.88c-1.03.69-2.35 1.1-3.89 1.1-2.99 0-5.52-2.02-6.43-4.73H1.74v2.97A11 11 0 0 0 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.57 13.7a6.6 6.6 0 0 1 0-4.22V6.51H1.74a11 11 0 0 0 0 9.87l3.83-2.68z"
      />
      <path
        fill="#EA4335"
        d="M12 5.55c1.69 0 3.2.58 4.4 1.72l3.28-3.28C17.7 2.11 15.1 1 12 1A11 11 0 0 0 1.74 6.51l3.83 2.97C6.48 7.57 9.01 5.55 12 5.55z"
      />
    </svg>
  );
}

function MicrosoftMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#F25022" d="M2 2h9.5v9.5H2z" />
      <path fill="#7FBA00" d="M12.5 2H22v9.5h-9.5z" />
      <path fill="#00A4EF" d="M2 12.5h9.5V22H2z" />
      <path fill="#FFB900" d="M12.5 12.5H22V22h-9.5z" />
    </svg>
  );
}
