// Invitations — the view-model.
//
// ⛔ THE GAP THIS CLOSES WAS THE ONLY WRITE-ONLY STATE IN THE PRODUCT THAT IS ITSELF AN ACCESS GRANT.
//
// `resendInvitation` and `revokeInvitation` are keyed by EMAIL ADDRESS, and nothing served the
// addresses. So an operator could create an invitation and then never see it, resend it, or revoke
// it — unless they happened to remember the exact string they typed. A mistyped invite was, in
// practice, unrevokable while still being redeemable into a membership.
//
// The other write-only items (`POST /domains`, `PUT /pool-cidr`, `PUT /idp-sync/{provider}`) are
// CONFIGURATION whose effect is visible somewhere else: a pool has a range, sync has a health tier,
// a domain either captures signups or does not. **An outstanding invitation has no observable effect
// until the moment it becomes a member — and by then the grant has already happened.**

import type { Role } from "./api";
import { can } from "./rbac";

export type Invitation = {
  id: string;
  email: string;
  role: Role;
  expires_at: string;
  created_at: string;
  accepted_at?: string | null;
  revoked_at?: string | null;
  invited_by_user_id?: string | null;
  invited_by_email?: string | null;
};

/**
 * ⛔ FOUR STATES, AND ONLY THREE ARE STORED.
 *
 * The table holds `accepted_at` and `revoked_at` as timestamps and nothing else — there is no
 * status column. **`expired` is DERIVED from `expires_at` against the clock**, which is why the
 * server does not store it: a stored status would be correct at write time and wrong a day later.
 * Same derive-don't-store rule as `sync_health`.
 *
 * Order matters and is not arbitrary: a row can be BOTH accepted and past its expiry, and it is
 * accepted — redemption already happened, so the clock is no longer interesting. Revoked outranks
 * expired for the same reason.
 */
export type InvitationState = "accepted" | "revoked" | "expired" | "pending";

export function invitationState(inv: Invitation, now: Date): InvitationState {
  if (inv.accepted_at) return "accepted";
  if (inv.revoked_at) return "revoked";
  if (new Date(inv.expires_at).getTime() <= now.getTime()) return "expired";
  return "pending";
}

/**
 * ⛔ WHAT AN OPERATOR MAY DO, DERIVED FROM THE STATE — never offered where the server would refuse.
 *
 * `RevokeInvitationByOrgEmail` updates `WHERE … accepted_at IS NULL AND revoked_at IS NULL`, so
 * revoking an accepted or already-revoked row matches ZERO rows and changes nothing. Offering the
 * control there would be a button that reports success and does nothing — worse than absent.
 *
 * ⚠ RESEND IS ALLOWED ON AN EXPIRED ROW ON PURPOSE. `Resend` mints a NEW token and invalidates the
 * old one, so it is the recovery path for an expiry — and it is the *only* one, because there is no
 * "extend". Withholding it there would strand the row with no way forward but a fresh invite.
 */
export function canResend(s: InvitationState): boolean {
  return s === "pending" || s === "expired";
}

export function canRevoke(s: InvitationState): boolean {
  return s === "pending" || s === "expired";
}

/** Permission-first, mirroring the handlers: all four verbs gate on `member:invite`. */
export type InviteGate = { kind: "hidden" } | { kind: "ready" };

export function inviteGate(role: Role | null | undefined): InviteGate {
  return role && can(role, "member:invite")
    ? { kind: "ready" }
    : { kind: "hidden" };
}

export function stateLabel(s: InvitationState): string {
  switch (s) {
    case "pending":
      return "PENDING";
    case "expired":
      return "EXPIRED";
    case "accepted":
      return "ACCEPTED";
    case "revoked":
      return "REVOKED";
  }
}

/**
 * ⛔ A REVOCATION THE OPERATOR DID NOT PERFORM.
 *
 * `SupersedePendingInvites` (`db/queries/invitations.sql`) revokes pending invites when a user joins
 * the org another way — domain-capture JIT being the live path. The row then looks exactly like a
 * hand-revoked one, so a panel that says "revoked" and stops invites someone to go looking for who
 * did it. Naming the other cause is cheaper than the investigation it prevents.
 *
 * ⚠ AND IT DOES NOT CLAIM WHICH ONE HAPPENED. The table records no cause, so asserting "this was
 * superseded" would be a second source of truth about a fact the server never stored.
 */
export const REVOKED_CAUSE_NOTE =
  "Revoked invitations were either withdrawn here, or superseded automatically when the person joined this organization another way (for example a captured email domain).";

/** The inviter can be gone — `invited_by_user_id` is ON DELETE SET NULL. */
export function inviterLabel(inv: Invitation): string {
  return inv.invited_by_email && inv.invited_by_email.trim() !== ""
    ? inv.invited_by_email
    : "account deleted";
}

/**
 * The list, ordered for the operator rather than for the database.
 *
 * The server returns newest-first by `created_at`, which buries the rows that need action under
 * historical ones. **Actionable states float**: pending and expired first (they have controls),
 * then the terminal states, each group newest-first.
 */
const RANK: Record<InvitationState, number> = {
  pending: 0,
  expired: 1,
  revoked: 2,
  accepted: 3,
};

export function orderInvitations(rows: Invitation[], now: Date): Invitation[] {
  return [...rows].sort((a, b) => {
    const d = RANK[invitationState(a, now)] - RANK[invitationState(b, now)];
    if (d !== 0) return d;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
}

/**
 * ⛔ THE COUNT THE PANEL IS ALLOWED TO NAME.
 *
 * Only outstanding invitations — pending plus expired. An accepted row is a member now and belongs
 * to the roster's count, not this one; double-counting it would overstate how many people have a
 * live path into the org, which is the exact number this panel exists to make visible.
 */
export function outstandingCount(rows: Invitation[], now: Date): number {
  return rows.filter((r) => {
    const s = invitationState(r, now);
    return s === "pending" || s === "expired";
  }).length;
}

/**
 * Server error codes, READ OFF `invites.Service` rather than guessed — the first draft of this map
 * invented two codes the service cannot emit, which is untestable against the server by definition.
 *
 * ⛔ AND `invite_pending` IS THE FUNNIEST EVIDENCE FOR THIS WHOLE STORY. Creating a duplicate invite
 * has always answered *"an invitation is already pending for this email; resend or revoke it"*
 * (`invites.go:109`) — instructing the operator to use two verbs that had **no surface at all**, on a
 * row they had **no way to see**. The server has been giving that advice since S1.
 */
export function inviteErrorCopy(code: string | null | undefined): string {
  switch (code) {
    case "invite_pending": // invites.go:109 (409)
      return "An invitation is already pending for that address — resend or revoke it in the list below.";
    case "invite_not_pending": // invites.go:243 (404)
      return "No pending invitation for that address — it may have just been accepted or revoked. Refresh to see the current list.";
    case "invalid_role": // invites.go:97
      return "That role is not one this organization recognises.";
    case "account_deactivated": // invites.go:168 (403)
      return "That account is deactivated; an administrator must reactivate it first.";
    default:
      return "Could not complete the request.";
  }
}
