import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { PRODUCT_NAME } from "../brand";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CeilingUpgrade } from "../components/CeilingUpgrade";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText, Field, Input } from "../components/ui";

// slugify derives a URL slug from the org name, matching the server's slug
// pattern (^[a-z0-9]+(-[a-z0-9]+)*$): lowercase, non-alphanumerics collapse to a
// single hyphen, and leading/trailing hyphens are trimmed.
function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * CreateOrg is the explicit create-organization step in the onboarding funnel
 * (S4.7): a freshly-verified user with zero memberships lands here (routed by
 * RequireOrg) instead of a dead-end dashboard. The SSO-JIT and invite paths never
 * reach here — they already produce a membership.
 *
 * Two refusals are surfaced honestly rather than hidden:
 *  - Unverified email: create-org is verified-gated server-side (requireVerifiedUser),
 *    so we route to /verify-pending up front — the refusal is structural, not a
 *    surprise 403 after the user fills in the form.
 *  - Single-org cap (Community licence): the server owns the limit (org_limit_reached);
 *    on that code we swap the form for an invitation-only message. The UI mirrors
 *    the server's truth, it never invents the permission.
 */
export default function CreateOrg() {
  const { state, logout } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  // The slug tracks the name until the user edits it directly (then it sticks).
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capped, setCapped] = useState(false);
  // ⚠ Distinguishes the two audiences of one refusal: a zero-org visitor (who cannot install anything and
  // needs an invitation) from a capability holder already inside (who can, and should be offered the route).
  const [ceilingMsg, setCeilingMsg] = useState<string | null>(null);
  // ⚠ A HOLDER ALREADY INSIDE vs A ZERO-ORG VISITOR — one refusal, two audiences. The visitor cannot
  // install a licence (no org, no settings screen, no owner role) and needs an invitation; the holder can,
  // and gets the route. `cp_admin` is the honest discriminator: only a holder reaches this page
  // with an organization already in hand.
  const hasOrg = state.status === "authed" && Boolean(state.user.cp_admin);
  const [busy, setBusy] = useState(false);

  // Verified-email gate (decision 3): unverified users can't create an org, so
  // route them to verify first rather than let the POST 403 after data entry.
  if (state.status === "authed" && !state.user.email_verified) {
    return <Navigate to="/verify-pending" replace />;
  }

  // The slug tracks the name (slugify) until the user edits the slug directly;
  // slugify() runs again at submit to trim any transient trailing hyphen.
  const effectiveSlug = slugEdited ? slug : slugify(name);
  const finalSlug = slugify(effectiveSlug);

  function onSlug(v: string) {
    // Lowercase and collapse invalid runs to a single hyphen, but do NOT trim a
    // trailing hyphen here — that would delete the '-' the instant it's typed, so
    // "acme-corp" couldn't be entered left-to-right. Trailing hyphens are trimmed
    // by slugify() at submit. An emptied field unlatches back to name-derived.
    const cleaned = v.toLowerCase().replace(/[^a-z0-9-]+/g, "-");
    setSlug(cleaned);
    setSlugEdited(cleaned.trim() !== "");
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data, error } = await api.POST("/api/v1/organizations", {
        body: { name: name.trim(), slug: finalSlug },
      });
      if (error || !data) {
        // Cap reached: before showing the dead-end, RE-CHECK membership. Between
        // the funnel routing us here (0 orgs) and this refusal, the user may have
        // gained a membership (an invite accepted in another tab, JIT-join, or an
        // admin adding them) — that user belongs in the dashboard, not a dead-end.
        // Only a still-0-membership user sees the invitation-only card (branch 3).
        // ⛔ THE FUNNEL SENDS EVERY 0-MEMBERSHIP USER HERE, AND MOST OF THEM MAY NOT CREATE ANYTHING.
        //
        // Signing up creates an ACCOUNT, never an organization: a stranger with a verified email is
        // refused `invitation_required` by the server. Without this branch they met a bare red error on a
        // form the funnel had just routed them to — told no, with no idea why, and no way forward.
        //
        // ⚠ SAME CARD AS THE CEILING CASE, because the user's situation is identical: they cannot proceed
        // and somebody already inside has to admit them. Only the reason differs, and the server states it.
        if (apiErrorCode(error) === "invitation_required") {
          return setCapped(true);
        }
        // ⭐ THE ORG CEILING NOTICE FINALLY HAS A CALLER AN OWNER CAN REACH. Until the switcher's "+ New",
        // this branch was only reachable by a ZERO-ORG visitor — never by the person who would actually
        // pay. A holder hitting the ceiling here gets the route, not a dead end.
        if (apiErrorCode(error) === "org_limit_reached" && hasOrg) {
          return setCeilingMsg(
            apiErrorMessage(error, "Could not create the organization."),
          );
        }
        if (apiErrorCode(error) === "org_limit_reached") {
          const { data: orgs } = await api.GET("/api/v1/organizations");
          if ((orgs?.length ?? 0) > 0)
            return navigate("/dashboard", { replace: true });
          return setCapped(true);
        }
        return setError(
          apiErrorMessage(error, "Could not create the organization."),
        );
      }
      navigate("/dashboard", { replace: true });
    } catch {
      // A network-level failure rejects instead of returning {error}; without this
      // the button would stay stuck on "Creating…".
      setError("Could not reach the API.");
    } finally {
      setBusy(false);
    }
  }

  // ⛔ THE FORM IS NEVER OFFERED TO SOMEONE WHO CANNOT USE IT.
  //
  // RequireNoOrg asks one question — "do you have an organization?" — and a brand-new account has none, so
  // it routes here. That account does not hold `cp_admin`, so submitting hit a refusal.
  //
  // ⚠ A FORM OFFERED TO SOMEONE WHO CANNOT USE IT IS WORSE THAN NO FORM: it costs them an attempt to learn
  // what the screen could have told them first. The invitation card is the correct destination for exactly
  // this state, it already existed, and it was one FAILED SUBMIT away. Now it is the first thing they see.
  if (state.status === "authed" && !state.user.cp_admin) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Invitation required
        </h1>
        <p className="mt-2 text-sm text-slate-400">
          This {PRODUCT_NAME} deployment is already set up. Accounts join by
          invitation — ask an administrator to invite you, and the invitation
          link will bring you straight in.
        </p>
        <button
          type="button"
          onClick={() => void logout()}
          className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
        >
          Sign out
        </button>
      </AuthLayout>
    );
  }

  if (ceilingMsg) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Organization limit reached
        </h1>
        <CeilingUpgrade message={ceilingMsg} kind="organization" />
      </AuthLayout>
    );
  }

  if (capped) {
    return (
      <AuthLayout>
        <h1 className="text-xl font-semibold text-white">
          Invitation required
        </h1>
        <p className="mt-2 text-sm text-slate-400">
          This {PRODUCT_NAME} deployment already has an organization, and its
          licence allows a single one. Ask an administrator to invite you, then
          sign in to accept.
        </p>
        {/* ⚠ THE ROUTE IS FOR THE ADMINISTRATOR, NOT THIS VISITOR — and saying so is the point.
            Whoever is reading this cannot install a licence: they have no organization, so they have no
            settings screen and no owner role anywhere. Offering them an "install a licence" button would
            be a route to a 403. What they CAN do is tell the person who runs the deployment which limit
            they hit, so the sentence names it and the link goes to the public page rather than into a
            product they cannot yet enter. */}
        <p className="mt-2 text-sm text-slate-400">
          If you run this deployment, its organization limit is raised by
          installing a licence —{" "}
          <a
            href="https://tunnex.io/trial"
            target="_blank"
            rel="noreferrer"
            className="text-accent hover:underline"
          >
            request one ↗
          </a>
          .
        </p>
        {/* ⛔ SIGN OUT, NOT "back to sign in" — AND THE DIFFERENCE WAS AN INFINITE LOOP.
            A link to /login for a user who is ALREADY signed in bounces straight back: /login sees an
            authed session and forwards to /dashboard, RequireOrg finds no membership and forwards to
            /create-org, which lands here again. The only exit was closing the tab.

            ⚠ AND THIS STATE IS NOW PRODUCED BY DESIGN, which is why the dead end had to go. Signing up
            creates an ACCOUNT and never an ORGANIZATION, so every new stranger arrives exactly here and
            stays until somebody inside invites them. The session is the thing trapping them, so ending
            the session is the only honest exit. */}
        <button
          type="button"
          onClick={() => void logout()}
          className="mt-5 inline-block text-xs text-slate-400 hover:text-slate-200"
        >
          Sign out
        </button>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">
        Create your organization
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        One more step — name the organization that will own your gateways,
        devices, and members.
      </p>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <Field label="Organization name">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
            placeholder="Acme Corp"
          />
        </Field>
        <Field label="Slug">
          <Input
            value={effectiveSlug}
            onChange={(e) => onSlug(e.target.value)}
            required
            placeholder="acme-corp"
          />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button
          type="submit"
          disabled={busy || !name.trim() || !finalSlug}
          className="w-full"
        >
          {busy ? "Creating…" : "Create organization"}
        </Button>
      </form>
    </AuthLayout>
  );
}
