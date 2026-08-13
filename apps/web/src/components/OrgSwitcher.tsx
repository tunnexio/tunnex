import { useNavigate } from "react-router-dom";

import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

/**
 * OrgSwitcher selects which organization the UI acts on.
 *
 * ⛔ IT RENDERS NOTHING WHEN THE CALLER HAS ONE ORGANIZATION, and that is not a cosmetic choice. Almost
 * every user has exactly one; a permanent control offering a choice that does not exist trains people to
 * ignore the place where a real choice will later appear.
 *
 * ⚠ SO ITS ABSENCE IS INFORMATION: seeing it means you belong to more than one tenant. That is a fact worth
 * knowing before you delete something.
 *
 * ⭐ AND IT GRANTS NOTHING. Selecting here changes which orgId the pages send; the server resolves the
 * caller's role from its own per-request membership query and answers 404 for anything else. This control
 * can only pick among organizations the server would already authorize.
 */
export function OrgSwitcher() {
  const { orgs, org, setOrg } = useOrg();
  const { state } = useAuth();
  const navigate = useNavigate();
  // ⛔ THE CAPABILITY, NOT A ROLE. `cp_admin` is deployment-scoped — the only such field this
  // product has — because a permission granted inside org A cannot license creating org B.
  //
  // ⚠ AN AFFORDANCE HINT, NEVER THE BOUNDARY. The server refuses regardless (tenancy.checkMayCreateOrg),
  // so a client that ignores this gains nothing; it only decides whether offering the action is honest.
  const mayCreate = state.status === "authed" && Boolean(state.user.cp_admin);

  // ⭐ THE "ABSENT BELOW 2" RULE RELAXES ONLY FOR A HOLDER, and only because the switcher is now the ONLY
  // place org creation lives. A control with one option still teaches nothing — but for someone who may
  // create a second organization it is not a one-option control, it is the entry point.
  if ((orgs.length < 2 && !mayCreate) || !org) return null;

  return (
    <label className="flex min-w-0 items-center gap-2">
      {/* Labelled for screen readers without spending header width — the control's purpose is legible from
          its content (it shows the current org name), so a visible label would be redundant, but an
          unlabelled <select> in a header is unnavigable. */}
      <span className="sr-only">Organization</span>
      <select
        aria-label="Organization"
        value={org.id}
        onChange={(e) => setOrg(e.target.value)}
        className="min-w-0 max-w-[180px] truncate rounded-input border border-line bg-surface-inset px-2 py-[6px] text-cell text-ink-body"
      >
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </select>
      {mayCreate && (
        <button
          type="button"
          onClick={() => navigate("/create-org")}
          className="shrink-0 whitespace-nowrap text-cell text-accent hover:underline"
        >
          + New
        </button>
      )}
    </label>
  );
}
