import { useEffect, useState } from "react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { PRODUCT_NAME } from "./brand";
import { api } from "./lib/api";
import { resolveMfaGateRoute } from "./lib/authroute";
import { AuthProvider, useAuth } from "./lib/auth";
import { AuthLayout } from "./components/AuthLayout";
import { MfaSettings } from "./components/MfaSettings";
import { AppShell } from "./components/AppShell";
import { OrgProvider } from "./lib/useOrg";
import VisualGallery from "./pages/VisualGallery";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import AcceptInvite from "./pages/AcceptInvite";
import VerifyEmail from "./pages/VerifyEmail";
import { ChangePassword } from "./pages/ChangePassword";
import VerifyPending from "./pages/VerifyPending";
import CreateOrg from "./pages/CreateOrg";
import CliAuth from "./pages/CliAuth";
import CliDevice from "./pages/CliDevice";
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import Gateways from "./pages/Gateways";
import Sites from "./pages/Sites";
import RoutedRanges from "./pages/RoutedRanges";
import Kubernetes from "./pages/Kubernetes";
import Agents from "./pages/Agents";
import Access from "./pages/Access";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import AccessEvents from "./pages/AccessEvents";
import AuditLog from "./pages/AuditLog";

/**
 * App is the router + auth shell (S4.1). Authenticated pages live under AppShell
 * behind RequireAuth; the design system (brand, tokens, primitives) is wired so a
 * brand-kit swap touches only brand.tsx + the Tailwind palette. Login/signup/SSO
 * screens (S4.2) and the dashboard/users/settings/audit pages (S4.3–S4.6) fill in
 * the placeholder nav items.
 */
export default function App() {
  // The tab title comes from the brand module (the static index.html title is a
  // pre-hydration fallback), keeping the product name a single source of truth.
  useEffect(() => {
    document.title = PRODUCT_NAME;
  }, []);
  return (
    <AuthProvider>
      <Routes>
        {/* The visual gallery is BUILD-FLAGGED OFF. `VITE_VISUAL_GALLERY` is unset in every production build,
            so Vite's dead-code elimination drops the route and the import. Only the visual-regression job
            builds with it on, and `test/visualgallery.test.ts` asserts the flag defaults off — an unshipped
            surface must be PROVEN unshipped, not assumed.
            Deliberately OUTSIDE RequireAuth: the gallery renders primitives with fixture data and touches no
            API, so a login would add a dependency the snapshot does not need. */}
        {import.meta.env.VITE_VISUAL_GALLERY === "1" && (
          <Route path="/__visual" element={<VisualGallery />} />
        )}
        <Route
          path="/login"
          element={
            <AnonOnly>
              <Login />
            </AnonOnly>
          }
        />
        <Route
          path="/signup"
          element={
            <AnonOnly>
              <Signup />
            </AnonOnly>
          }
        />
        <Route
          path="/forgot-password"
          element={
            <AnonOnly>
              <ForgotPassword />
            </AnonOnly>
          }
        />
        {/* Reset + verify are reached from emailed links; usable while logged out
            and harmless while logged in, so they are not auth-gated. */}
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/accept-invite" element={<AcceptInvite />} />
        <Route path="/verify-email" element={<VerifyEmail />} />
        {/* Authenticated area. The onboarding funnel (S4.7) lives BETWEEN auth and
            the shell: /create-org and /verify-pending are reachable while
            authenticated with no org yet; the shell itself is gated by RequireOrg. */}
        <Route element={<RequireAuth />}>
          <Route
            path="/create-org"
            element={
              <RequireNoOrg>
                <CreateOrg />
              </RequireNoOrg>
            }
          />
          {/* ⛔ THE FORCED PASSWORD CHANGE. Org-independent by construction — the bootstrap admin belongs
              to no organization, so this cannot live inside the shell. */}
          <Route path="/change-password" element={<ChangePassword />} />
          <Route path="/verify-pending" element={<VerifyPending />} />
          {/* S5.1 CLI auth: the browser consent leg (`tunnex login`) and the
              device-code approval page. Authenticated but org-independent. */}
          <Route path="/cli-auth" element={<CliAuth />} />
          <Route path="/cli-device" element={<CliDevice />} />
          {/* S7.5.5 D8: a MFA-enforcement-gated user (org requires 2FA, none set up) is routed here
              by RequireAuth — enrollment only, until they confirm a TOTP. Org-independent. */}
          <Route path="/enroll-mfa" element={<ForcedEnroll />} />
          <Route
            element={
              <RequireOrg>
                {/* ⛔ THE PROVIDER SITS INSIDE RequireOrg, DELIBERATELY. RequireOrg answers "do you have any
                    organization at all" and routes a user with none into the create-org funnel. Mounting the
                    org context above it would make every page's org seam load for users who are being sent
                    away from every page. */}
                <OrgProvider>
                  <AppShell />
                </OrgProvider>
              </RequireOrg>
            }
          >
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/gateways" element={<Gateways />} />
            <Route path="/sites" element={<Sites />} />
            <Route path="/routed-ranges" element={<RoutedRanges />} />
            <Route path="/kubernetes" element={<Kubernetes />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/access" element={<Access />} />
            <Route path="/users" element={<Users />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/access-events" element={<AccessEvents />} />
            <Route path="/audit" element={<AuditLog />} />
          </Route>
        </Route>
        {/* Default: the shell decides (RequireAuth bounces anon users to /login). */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AuthProvider>
  );
}

// RequireAuth gates the authenticated area: it waits out the /me bootstrap (no
// login flash for an already-authenticated user), then redirects anonymous users
// to /login. Renders the nested routes via <Outlet />.
function RequireAuth() {
  const { state } = useAuth();
  const location = useLocation();
  if (state.status === "loading") return <FullScreenLoading />;
  if (state.status === "anon") {
    // Preserve the intended destination so it survives the login round-trip —
    // the CLI login flow (`tunnex login` → /cli-auth?…) on a fresh machine
    // depends on landing back on /cli-auth WITH its query params (S5.1).
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  // S7.5.5 D8: an enrollment-gated user is confined to the enrollment ceremony until they set up 2FA;
  // once the gate clears they are released back to the app (WF-3 — the inverse redirect the original
  // code was missing, which trapped a now-enrolled user on /enroll-mfa). The SERVER enforces the gate
  // (default-deny middleware, typed mfa_enrollment_required 403); this is the client routing so the
  // user lands on the ceremony rather than hitting dead 403s. Decision is a pure fn (authroute.ts),
  // table-pinned in BOTH directions (resolveMfaGateRoute).
  // ⛔ THE PASSWORD WALL IS ROUTED BEFORE EVERYTHING ELSE, INCLUDING THE MFA GATE. The credential was
  // printed to logs; until it is replaced this account may authenticate and do nothing else, and the
  // server enforces exactly that. Without this redirect the user meets the refusal as a red error on
  // whichever page they happened to land on — which is what shipped, and what an operator actually saw.
  if (
    state.user.must_change_password &&
    location.pathname !== "/change-password"
  ) {
    return <Navigate to="/change-password" replace />;
  }
  const gateRoute = resolveMfaGateRoute(
    Boolean(state.user.mfa_enrollment_required),
    location.pathname,
  );
  if (gateRoute) {
    return <Navigate to={gateRoute} replace />;
  }
  return <Outlet />;
}

// ForcedEnroll is the enrollment-gated landing (D8): the shared MfaSettings ceremony with a
// blocking header + a sign-out escape. Confirming clears mfa_enrollment_required (MfaSettings updates
// the auth user), and RequireAuth then releases the user to the app.
function ForcedEnroll() {
  const { logout } = useAuth();
  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">
        Set up two-factor authentication
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Your organization requires 2FA. Finish setup to continue to Tunnex.
      </p>
      <div className="mt-5">
        <MfaSettings />
      </div>
      <button
        type="button"
        className="mt-4 text-xs text-slate-400 underline hover:text-slate-200"
        onClick={logout}
      >
        Sign out
      </button>
    </AuthLayout>
  );
}

// RequireNoOrg is RequireOrg's inverse, guarding the create-org step itself
// (S4.8/F4): a user who ALREADY belongs to an org and navigates to /create-org
// manually is re-routed to the dashboard at VISIT time — previously only the
// submit path re-checked (403 → membership re-check), so the form rendered
// pointlessly. Fail-open on a fetch error: the form is safe to show (the
// submit path still ends in the server's answer).
function RequireNoOrg({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<"loading" | "none" | "has">("loading");
  const { state } = useAuth();
  const mayCreate = state.status === "authed" && Boolean(state.user.cp_admin);

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/organizations")
      .then(({ data, error }) => {
        if (cancelled) return;
        if (error) return setStatus("none"); // fail open to the form
        setStatus((data?.length ?? 0) > 0 ? "has" : "none");
      })
      .catch(() => {
        if (!cancelled) setStatus("none");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (status === "loading") return <FullScreenLoading />;
  // ⛔ THE FORM IS NEVER OFFERED TO SOMEONE WHO CANNOT USE IT.
  //
  // RequireNoOrg used to ask ONE question — "do you have an organization?" — and a brand-new account has
  // none, so it rendered the form. That account does not hold `cp_admin`, so submitting it hit a
  // refusal. ⚠ A form offered to someone who cannot use it is worse than no form: it costs them the
  // attempt to learn what the screen could have said first.
  //
  // ⭐ The invitation card is the correct destination for exactly this state, it already exists, and it
  // was previously one FAILED SUBMIT away. Now it is the first thing they see.
  // ⛔ A CAPABILITY HOLDER IS NOT BOUNCED. RequireNoOrg guards the onboarding funnel — it stops a user who
  // already has an org from re-entering the SIGNUP step. But this route is now also the only place org
  // creation lives, reached from the switcher's "+ New", so bouncing a holder to /dashboard would make the
  // affordance a dead link.
  if (status === "has" && !mayCreate)
    return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

// RequireOrg is the onboarding funnel's router (S4.7). It gates the app shell on
// having at least one organization, sending a user with none through the funnel:
//   - >=1 membership          -> render the shell
//   - 0 memberships, verified -> /create-org (the explicit create-org step)
//   - 0 memberships, unverified -> /verify-pending (create-org is verified-gated)
// The SSO-JIT and invite paths never trip this: they produce a membership, so the
// caller already has >=1 org and lands straight in the shell.
//
// This runs one GET /organizations per shell entry (the layout route stays mounted
// across page navigations, so it does NOT refetch on every nav).
//
// ⭐ THE "deliberate small duplication" THIS COMMENT USED TO NAME IS GONE (S12.5). Every page fetched its
// own org list and took index zero; they now read `useOrg()`, which the OrgProvider below this guard
// supplies once. The deferred `useCurrentOrg` hook this comment was waiting for is `lib/useOrg.tsx`.
//
// ⚠ THIS GUARD'S OWN FETCH STAYS, and is not the duplication that was removed. It asks a different
// question — "any org at all", answered BEFORE the provider mounts — and folding it into the provider
// would put the funnel's routing decision downstream of the context it gates.
//
// The create-org → /dashboard handoff assumes read-your-writes: after a 201 the
// remounted RequireOrg refetches and must see the new org. That holds for the
// single-primary Postgres this product deploys; a read-replica topology could
// briefly bounce the user back to /create-org (accepted — tunnex has no replicas).
function RequireOrg({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();
  const [status, setStatus] = useState<"loading" | "none" | "has">("loading");

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/organizations")
      .then(({ data, error }) => {
        if (cancelled) return;
        // Fail OPEN on a fetch error: let the shell render and surface the real
        // error, rather than trapping a transient failure in the create-org funnel
        // (an errored fetch is not the same signal as an empty list).
        if (error) return setStatus("has");
        setStatus((data?.length ?? 0) > 0 ? "has" : "none");
      })
      .catch(() => {
        if (!cancelled) setStatus("has");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (status === "loading") return <FullScreenLoading />;
  if (status === "none") {
    const unverified = state.status === "authed" && !state.user.email_verified;
    return (
      <Navigate to={unverified ? "/verify-pending" : "/create-org"} replace />
    );
  }
  return <>{children}</>;
}

// AnonOnly keeps an authenticated user off the login page (sends them to the app).
function AnonOnly({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();
  if (state.status === "loading") return <FullScreenLoading />;
  if (state.status === "authed") return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

function FullScreenLoading() {
  return (
    <div className="grid min-h-full place-items-center text-sm text-slate-500">
      Loading…
    </div>
  );
}
