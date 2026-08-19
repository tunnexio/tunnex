import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, apiErrorMessage, type Meta } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AuthLayout } from "../components/AuthLayout";
import { recoveryCountLabel, recoveryWarning } from "../lib/authhero";
import { ErrorText, Field, Input } from "../components/ui";

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

  const [showPassword, setShowPassword] = useState(false);

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
      setError(apiErrorMessage(error, "Invalid email or password."));
      return;
    }
    if (data.mfa_required) {
      setChallenge(data.challenge ?? null);
      setRemaining(
        (data as { recovery_codes_remaining?: number })
          .recovery_codes_remaining,
      );
      return;
    }
    if (data.user) {
      setUser(data.user);
      finish();
    }
  }

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
        <h1 className="text-2xl font-bold text-white text-center">
          Two-factor authentication
        </h1>
        <p className="mt-1.5 text-sm text-slate-400 text-center">
          Password accepted — no session yet. Enter the 6-digit code from your
          authenticator app, or a recovery code.
        </p>
        <form onSubmit={verify} className="mt-6 space-y-4">
          <Field label="Code">
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="000000"
              required
              autoFocus
              autoComplete="one-time-code"
              className="bg-[#18181B] border-white/10 text-white rounded-xl py-3"
            />
          </Field>
          {typeof remaining === "number" && (
            <>
              <p className="text-xs text-slate-500">
                {recoveryCountLabel(remaining)}
              </p>
              {recoveryWarning(remaining) && (
                <p
                  className={
                    "text-xs " +
                    (recoveryWarning(remaining)!.loud
                      ? "text-rose-500"
                      : "text-amber-500")
                  }
                >
                  {recoveryWarning(remaining)!.text}
                </p>
              )}
            </>
          )}
          <ErrorText>{error}</ErrorText>
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-xl bg-[#B03A45] hover:bg-[#a0313b] active:bg-[#8f2a33] text-white font-medium py-3 text-sm transition-all duration-200 disabled:opacity-50 active:scale-[0.99] mt-4"
          >
            {busy ? "Verifying…" : "Verify"}
          </button>
        </form>
      </AuthLayout>
    );
  }

  const ssoProviders =
    meta && meta.sso_providers.length > 0
      ? meta.sso_providers
      : ["google", "microsoft"];

  return (
    <AuthLayout>
      <h1 className="text-2xl font-bold text-white text-center">Welcome back</h1>
      <p className="mt-1 text-sm text-slate-400 text-center">
        Sign in to {window.location.host}
      </p>

      <SsoSection providers={ssoProviders} onError={setError} />

      <div className="my-5 flex items-center gap-3">
        <span className="h-px flex-1 bg-white/10" />
        <span className="font-mono text-[10px] tracking-widest text-slate-500 uppercase">
          OR
        </span>
        <span className="h-px flex-1 bg-white/10" />
      </div>

      <form onSubmit={submit} className="mt-4 space-y-4">
        <div className="space-y-1.5">
          <input
            type="email"
            name="username"
            aria-label="Email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email"
            required
            autoFocus
            className="w-full rounded-xl border border-white/10 bg-[#1A1A1E] px-4 py-3 text-sm text-white placeholder:text-slate-500 transition-all focus:border-rose-500/60 focus:outline-none focus:ring-1 focus:ring-rose-500/60"
          />
        </div>

        <div className="space-y-1.5">
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              name="password"
              aria-label="Password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
              className="w-full rounded-xl border border-white/10 bg-[#1A1A1E] px-4 py-3 pr-11 text-sm text-white placeholder:text-slate-500 transition-all focus:border-rose-500/60 focus:outline-none focus:ring-1 focus:ring-rose-500/60"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              <EyeIcon open={showPassword} />
            </button>
          </div>
          <div className="flex justify-end">
            <Link
              to="/forgot-password"
              className="text-xs font-medium text-[#B03A45] hover:text-[#c44551] transition-colors"
            >
              Forgot password?
            </Link>
          </div>
        </div>

        <ErrorText>{error}</ErrorText>

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl bg-[#B03A45] hover:bg-[#a0313b] active:bg-[#8f2a33] text-white font-medium py-3 text-sm transition-all duration-200 disabled:opacity-50 active:scale-[0.99] mt-2"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </AuthLayout>
  );
}

function SsoSection({
  providers,
  onError,
}: {
  providers: string[];
  onError: (m: string) => void;
}) {
  // ⛔ THE ORGANIZATION FIELD IS GONE FROM THE DEFAULT PATH, AND NOT BECAUSE IT WAS TIDIED AWAY.
  // Nobody signing in knows their tenant SLUG — they know their email and which button their
  // company uses. The slug is OPTIONAL on the start endpoint now and the server derives the sole
  // org configured for the provider, failing closed on zero or two-plus (see soleSSOOrg).
  //
  // ⚠ IT COMES BACK FOR EXACTLY ONE ERROR, because the server's own remedy for `sso_org_ambiguous`
  // is "specify your organization" — and a page that prints that with no field to type it in is a
  // dead end. Every other failure (`sso_not_configured`, a network blip) is NOT the person's to
  // fix, so it stays a message and never grows an input that implies they typed something wrong.
  const [showOrgInput, setShowOrgInput] = useState(false);
  const [org, setOrg] = useState("");
  // Which button produced the ambiguity — so Enter in the field retries THAT provider instead of
  // making someone re-aim at a button they already pressed.
  const [pending, setPending] = useState<"google" | "microsoft" | null>(null);

  async function start(provider: "google" | "microsoft") {
    const slug = org.trim();
    const { data, error } = await api.GET("/api/v1/auth/sso/{provider}/start", {
      // Omitted entirely when blank — an empty string is a slug the server would try to look up.
      params: { path: { provider }, query: slug ? { org: slug } : undefined },
    });
    if (error || !data) {
      const code = (error as { error?: { code?: string } } | undefined)?.error
        ?.code;
      if (code === "sso_org_ambiguous") {
        setShowOrgInput(true);
        setPending(provider);
      }
      onError(apiErrorMessage(error, "Could not start single sign-on."));
      return;
    }
    window.location.href = data.redirect_url;
  }

  return (
    <div className="mt-6 space-y-3">
      <div className="flex flex-col gap-2.5">
        {providers.includes("google") && (
          <button
            type="button"
            onClick={() => start("google")}
            className="flex w-full items-center justify-center gap-3 rounded-xl border border-white/10 bg-[#1C1C20] px-4 py-3 text-sm font-medium text-slate-200 transition-all duration-200 hover:border-white/20 hover:bg-[#25252B] active:scale-[0.99]"
          >
            <GoogleMark />
            Continue with Google
          </button>
        )}
        {providers.includes("microsoft") && (
          <button
            type="button"
            onClick={() => start("microsoft")}
            className="flex w-full items-center justify-center gap-3 rounded-xl border border-white/10 bg-[#1C1C20] px-4 py-3 text-sm font-medium text-slate-200 transition-all duration-200 hover:border-white/20 hover:bg-[#25252B] active:scale-[0.99]"
          >
            <MicrosoftMark />
            Continue with Microsoft
          </button>
        )}
      </div>

      {/* ⛔ A FIELD WITH NO WAY TO SUBMIT IT IS A DEAD END, WHICH IS WHAT THIS WAS. The server's
          remedy reads "specify your organization to continue", and the first version of this put a
          bare input under it: Enter did nothing, and nothing said to press the provider button a
          SECOND time. Enter now retries the provider that produced the ambiguity, and the hint says
          so — an escape hatch nobody can operate is not an escape hatch. */}
      {showOrgInput && (
        <div className="space-y-1.5 pt-1">
          <input
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && pending && org.trim()) {
                e.preventDefault();
                void start(pending);
              }
            }}
            placeholder="your-company (organization slug)"
            aria-label="Organization slug"
            autoFocus
            className="w-full rounded-xl border border-white/10 bg-[#1A1A1E] px-4 py-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-rose-500/60"
          />
          <p className="text-[11px] text-slate-500">
            Press Enter to continue, or pick your provider again.
          </p>
        </div>
      )}
    </div>
  );
}

function EyeIcon({ open }: { open: boolean }) {
  return open ? (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ) : (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
      <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
      <path d="M6.61 6.61A13.52 13.52 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
      <line x1="2" y1="2" x2="22" y2="22" />
    </svg>
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
