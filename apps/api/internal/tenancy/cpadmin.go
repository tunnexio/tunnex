package tenancy

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// The deployment-administrator surface (S12.11): the ONE place where a caller acts on an organization they
// are not a member of.
//
// ⛔ THE AUTHORITY IS ASKED BESIDE `RoleIn`, NEVER INSIDE IT. The tempting shortcut is to synthesise an
// `owner` entry per org when building the principal, or to add `if p.CPAdmin { … }` to `authorize()`. Both
// make `RoleIn` LIE, and `RoleIn` is what every org-scoped handler in the product asks — a cross-tenant
// capability would leak into every device list, every policy read, every audit feed at once. The gate for
// these two operations lives in `requireCPAdmin`, which asks a DIFFERENT question on a DIFFERENT route
// prefix, and `authorize()` is untouched.

// GrantOrgRole gives targetUser the named role in orgID, on the authority of the caller's `users.cp_admin`
// rather than on any membership of their own. Creates the membership when the user has none.
//
// ⛔ IT REFUSES TO DEMOTE THE ORGANIZATION'S LAST OWNER, for the reason `guardLastOwner` already exists: an
// org with no owner can never be administered again by anyone inside it. A cross-tenant actor is the one
// MOST likely to do that by accident — they cannot see the roster they are editing, and to them "make this
// person a member" looks the same whether or not the person was the only owner.
//
// ⚠ NO DATA-PLANE PUSH. A membership grant creates no device and moves no peer: the WireGuard peer set and
// the compiled policy are built from DEVICES, and a user who has just been added to an org owns none in it.
// Membership REMOVAL is the direction that strands data-plane state, and this operation cannot remove one.
func (s *Service) GrantOrgRole(ctx context.Context, actor uuid.UUID, actorEmail string, orgID, targetUserID uuid.UUID, newRole string) error {
	if !rbac.ValidRole(newRole) {
		return apierr.BadRequest("invalid_role", "unknown role: "+newRole)
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := q.GetOrganizationByID(ctx, orgID); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return orgNotFound()
			}
			return e
		}
		target, e := q.GetUserByID(ctx, targetUserID)
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("user_not_found", "user not found")
			}
			return e
		}
		// The prior role, or "" when this is a first grant. Both are legitimate here: this operation is how
		// someone with NO membership gets one, so a missing row is an input state, not an error.
		from := ""
		if m, me := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID}); me == nil {
			from = m.Role
		} else if !errors.Is(me, pgx.ErrNoRows) {
			return me
		}
		if from == newRole {
			// ⚠ NOTHING CHANGED, SO NOTHING IS AUDITED. An audit row saying a role was changed to the role it
			// already held is a false statement about an act that did not happen — and repeated calls would
			// bury the real grants under identical no-op rows.
			return nil
		}
		if from == rbac.RoleOwner && newRole != rbac.RoleOwner {
			owners, oe := q.CountOwners(ctx, orgID)
			if oe != nil {
				return oe
			}
			if owners <= 1 {
				return apierr.Conflict("last_owner", "an organization must always have at least one owner")
			}
		}
		if _, e = q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{OrgID: orgID, UserID: targetUserID, Role: newRole}); e != nil {
			return e
		}
		// ⛔ AUDITED INTO THE TARGET ORGANIZATION'S LOG, NOT THE ACTOR'S. A privilege change inside your tenant,
		// made by someone who is not in it, is precisely the event that org's owners are owed sight of — and
		// they read one feed, their own. `audit_logs.org_id` carries no membership constraint, so the row lands
		// in an org the actor belongs to none of.
		//
		// ⚠ THE ACTOR'S EMAIL RIDES IN THE METADATA BECAUSE THE ROSTER CANNOT NAME THEM. The audit screen
		// resolves `actor_id` against the org's member list; an id that is not on it renders as
		// "former member 019fc421" — a confident FALSE claim about a person who was never a member at all.
		// `actor_kind` says what they actually are, and the web resolver reads it.
		return writeAudit(ctx, q, orgID, &actor, "member.role_granted_by_cp_admin", "membership", targetUserID.String(),
			map[string]any{
				"role":         map[string]string{"from": from, "to": newRole},
				"actor_email":  actorEmail,
				"actor_kind":   "cp_admin",
				"target_email": target.Email,
			})
	})
}

// SetCPAdmin grants or revokes the deployment-administrator capability.
//
// ⛔ THE SURFACE EXISTS BECAUSE THE INVARIANT NEEDED SOMETHING TO REFUSE. `cp_admin` was grant-only —
// written once at bootstrap, with no way back — so "a deployment administrator cannot demote themselves
// when they are the last one" was a rule about an act nobody could perform. A guard on an unreachable path
// is a check that cannot fail, which is the class this repo has been bitten by often enough to have a law
// about it.
//
// ⭐ THE GUARD IS "NEVER LEAVE ZERO HOLDERS", WHICH IS STRICTLY STRONGER THAN A SELF-CHECK and simpler to
// read: when only one holder remains, they are the only account that can reach this endpoint, so the
// self-demotion case is contained inside it — and the stronger form additionally survives a future where
// the capability can be revoked by some other path.
//
// ⚠ THERE IS NO PUBLIC SIGNUP. A deployment with zero deployment administrators cannot create an
// organization, cannot grant anyone a role, and cannot recover without direct database access.
func (s *Service) SetCPAdmin(ctx context.Context, actor, targetUserID uuid.UUID, granted bool) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		target, e := q.GetUserByID(ctx, targetUserID)
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("user_not_found", "user not found")
			}
			return e
		}
		if target.CpAdmin == granted {
			return nil // no change, no audit row
		}
		if !granted {
			holders, he := q.CountCPAdmins(ctx)
			if he != nil {
				return he
			}
			// ⚠ SUBTRACT THE TARGET ONLY IF THE COUNT INCLUDED THEM. CountCPAdmins counts holders who can
			// actually sign in (live + active); a deactivated holder is not one of them, so revoking a
			// deactivated holder must not be read as spending the last live one.
			remaining := holders
			if target.Status == "active" {
				remaining--
			}
			if remaining < 1 {
				return apierr.Conflict("last_cp_admin",
					"this is the only deployment administrator who can sign in. Grant the capability to "+
						"someone else first — a deployment with none cannot create organizations, cannot "+
						"grant roles, and has no public signup to recover through.")
			}
		}
		n, e := q.SetCPAdmin(ctx, sqlc.SetCPAdminParams{ID: targetUserID, CpAdmin: granted})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("user_not_found", "user not found")
		}
		action := "cp_admin.revoked"
		if granted {
			action = "cp_admin.granted"
		}
		return writeDeploymentAudit(ctx, q, actor, action, "user", targetUserID.String(),
			map[string]any{"target_email": target.Email})
	})
}

// writeDeploymentAudit records an act that belongs to NO organization.
//
// ⛔ `org_id` IS NULL ON PURPOSE, and that has a cost worth stating: these rows appear in no org's audit
// feed, because every audit read is org-scoped. Picking an arbitrary org to file them under would put a
// deployment-wide event in one tenant's history and hide it from the others — a worse lie than an
// unsurfaced row. The precedent is `cliauth.auditUserScoped`, which spans orgs for the same reason.
//
// ⚠ REGISTERED: a deployment-scoped audit READ does not exist yet. The rows are written and immutable
// (the append-only trigger covers them); nothing serves them.
func writeDeploymentAudit(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{}, // NULL — deployment-scoped, belongs to no tenant
		ActorUserID: pgtype.UUID{Bytes: [16]byte(actor), Valid: true},
		Action:      action,
		TargetType:  &targetType,
		TargetID:    &targetID,
		Metadata:    b,
	})
	return err
}
