package tenancy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// SessionRevoker revokes all of a user's sessions (implemented by the session
// store). Deactivation uses it to cut live access immediately.
type SessionRevoker interface {
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) error
}

// DevicePusher nudges the nodes carrying a user's peers to reconcile now, so an
// account state change (de/reactivation) removes/restores that user's peers from
// the data plane within seconds. Implemented by devices.Service.
type DevicePusher interface {
	PushUserNodes(ctx context.Context, userID uuid.UUID)
	// PushOrgNodes signals all org gateways — used for org-wide policy changes like
	// member removal (S7.2 F1 4th recompile+push trigger).
	PushOrgNodes(ctx context.Context, orgID uuid.UUID)
}

// MembershipService provides org-scoped membership reads. Every method scopes by
// org_id (see the query-lint), so it cannot return another tenant's rows.
type MembershipService struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	revoker SessionRevoker
	pusher  DevicePusher
	crl     CRLRebuilder
}

// CRLRebuilder regenerates an org's signed OpenVPN CRL from the full current revoked set.
//
// ⛔ OPTIONAL, AND ITS ABSENCE IS FAIL-CLOSED IN THE RIGHT DIRECTION. The certs are marked revoked inside the
// deactivation transaction whether or not this is wired; without it the org's published CRL is merely STALE
// until the next rebuild, so the worst case is the pre-existing behaviour (ccd-exclusive alone), never worse.
type CRLRebuilder interface {
	RebuildCRL(ctx context.Context, orgID uuid.UUID) error
}

// WithCRLRebuilder wires the OpenVPN CRL rebuild into the deactivate/reactivate cascade.
func (s *MembershipService) WithCRLRebuilder(c CRLRebuilder) *MembershipService {
	s.crl = c
	return s
}

// NewMembershipService builds a membership service over the given pool.
func NewMembershipService(pool *pgxpool.Pool, revoker SessionRevoker) *MembershipService {
	return &MembershipService{pool: pool, q: sqlc.New(pool), revoker: revoker}
}

// WithDevicePusher wires the offboarding peer cascade (optional).
func (s *MembershipService) WithDevicePusher(p DevicePusher) *MembershipService {
	s.pusher = p
	return s
}

// DeactivateMember freezes a user's account (status only — memberships and role
// history are preserved for a clean reactivation) and revokes every live
// session. It refuses to deactivate the sole owner of any org (last-owner
// invariant) so an org can never be orphaned.
func (s *MembershipService) DeactivateMember(ctx context.Context, actor, orgID, targetUserID uuid.UUID) error {
	_, err := s.deactivate(ctx, orgID, targetUserID, func(q *sqlc.Queries) error {
		return writeAudit(ctx, q, orgID, &actor, "user.deactivated", "user", targetUserID.String(), map[string]any{})
	})
	return err
}

// DeactivateMemberBySync is the idp-sync (S7.5.2) deprovision path: the SAME full sweep as
// DeactivateMember, but audited to a first-class NAMED system actor ("idp-sync") — not NULL, not a
// borrowed admin — with the CAUSE in metadata, so a compliance reader sees "revoked by idp-sync
// because <cause>" (same discipline as device.self_approved). cause is e.g. "disabled_in_directory".
// Returns didAct=false when the user was ALREADY deactivated (idempotent no-op) so a still-listed
// disabled member doesn't re-audit + re-push on every poll (#7).
func (s *MembershipService) DeactivateMemberBySync(ctx context.Context, orgID, targetUserID uuid.UUID, cause string) (bool, error) {
	return s.deactivate(ctx, orgID, targetUserID, func(q *sqlc.Queries) error {
		return writeSystemAudit(ctx, q, orgID, "idp-sync", "user.deactivated", "user", targetUserID.String(),
			map[string]any{"cause": cause})
	})
}

// RevokeOrgAccessBySync removes only this org's remaining access when directory
// provenance is exhausted. The global identity and memberships in other orgs
// remain intact; the membership row is retained for audit/rejoin purposes.
func (s *MembershipService) RevokeOrgAccessBySync(ctx context.Context, orgID, targetUserID uuid.UUID, cause string) (bool, error) {
	if _, err := s.q.GetMembershipIncludingRevoked(ctx, sqlc.GetMembershipIncludingRevokedParams{OrgID: orgID, UserID: targetUserID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	var changed int64
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		var err error
		changed, err = q.RevokeMembershipAccess(ctx, sqlc.RevokeMembershipAccessParams{OrgID: orgID, UserID: targetUserID})
		if err != nil || changed == 0 {
			return err
		}
		return writeSystemAudit(ctx, q, orgID, "idp-sync", "user.org_access_revoked", "user", targetUserID.String(), map[string]any{"cause": cause})
	}); err != nil {
		return false, err
	}
	if changed == 0 {
		return false, nil
	}
	if s.revoker != nil {
		if err := s.revoker.DeleteAllForUser(ctx, targetUserID); err != nil {
			return false, err
		}
	}
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return true, nil
}

// deactivate is the shared core: last-owner guard, status flip + CLI-cred sweep + audit (in one tx),
// then live-session revoke + org-wide push. The audit row is written by writeAuditFn so the human
// and system callers attribute the SAME action to different, legible actors. Returns didAct=false
// (no error) when the user is ALREADY deactivated — an idempotent no-op: no second audit row, no
// redundant sweep/push.
func (s *MembershipService) deactivate(ctx context.Context, orgID, targetUserID uuid.UUID, writeAuditFn func(*sqlc.Queries) error) (bool, error) {
	// target must belong to the acting org (authorization scope).
	if _, err := s.q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, apierr.NotFound("member_not_found", "member not found")
		}
		return false, err
	}
	// #7: already deactivated → idempotent no-op (no re-audit, no re-sweep, no re-push).
	u, err := s.q.GetUserByID(ctx, targetUserID)
	if err != nil {
		return false, err
	}
	if u.Status == "deactivated" {
		return false, nil
	}
	sole, err := s.q.CountOrgsWhereSoleOwner(ctx, targetUserID)
	if err != nil {
		return false, err
	}
	if sole > 0 {
		// Never orphan an org — even from sync. The sync caller degrades that config's health
		// on this error so an operator sees "couldn't deprovision the sole owner".
		return false, apierr.Conflict("last_owner", "this user is the only owner of an organization and cannot be deactivated")
	}
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: targetUserID, Status: "deactivated"}); e != nil {
			return e
		}
		// Deactivation sweeps CLI credentials too (S5.1, session parity) — in the
		// SAME tx as the status flip, so the sweep can't be lost between the two.
		if e := cliauth.SweepUser(ctx, q, targetUserID); e != nil {
			return e
		}
		// ⛔ AND IT REACHES THE CRL. Without this the refusal was CONFIGURATIONAL ONLY: the device leaves the
		// CCD roster and `ccd-exclusive` refuses the client — one mechanism, living in the AGENT, on a
		// certificate that is still cryptographically valid. A gateway whose server.conf lost that flag would
		// admit a deactivated user's OpenVPN client on cert alone.
		//
		// > **A REFUSAL THAT DEPENDS ENTIRELY ON A CONFIG FLAG ON A REMOTE BOX IS NOT DEFENCE IN DEPTH.**
		//
		// Same transaction as the status flip, for the reason the CLI sweep is: a revocation that can be lost
		// between two statements is a revocation an operator was told happened.
		if _, e := q.RevokeOVPNCertsForDeactivatedUser(ctx, sqlc.RevokeOVPNCertsForDeactivatedUserParams{
			OrgID: orgID, UserID: targetUserID,
		}); e != nil {
			return e
		}
		return writeAuditFn(q)
	}); err != nil {
		return false, err
	}
	// Cut live access immediately (belt-and-suspenders with the SessionAuth
	// status check that also 401s any in-flight session).
	if s.revoker != nil {
		if err := s.revoker.DeleteAllForUser(ctx, targetUserID); err != nil {
			return false, err
		}
	}
	// Offboarding cascade: the user's peers fall out of every node's desired state
	// (the peer query requires an active owner). ORG-WIDE push (S7.2 finding #1): not
	// just this user's own device-nodes — under Zero Trust enforcing, a DIFFERENT
	// node hosting another user's device that referenced this now-inactive user as a
	// policy group-destination must ALSO recompile so the ex-member's /32 leaves its
	// ruleset within the <5s spec. PushUserNodes would miss those nodes on a
	// multi-gateway org (single-gateway hid this; the multi-node test guards it).
	// The CRL is republished from the full revoked set, AFTER the tx commits — a CRL naming a serial whose
	// revocation later rolled back would refuse a credential the database still considers live.
	if s.crl != nil {
		if err := s.crl.RebuildCRL(ctx, orgID); err != nil {
			return false, err
		}
	}
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return true, nil
}

// ReactivateMember restores a frozen user; memberships/roles are intact.
func (s *MembershipService) ReactivateMember(ctx context.Context, actor, orgID, targetUserID uuid.UUID) error {
	if _, err := s.q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		return err
	}
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: targetUserID, Status: "active"}); e != nil {
			return e
		}
		// ⛔ THE SYMMETRIC HALF — shipping the revoke without this would be a ONE-WAY DOOR: the user would come
		// back active everywhere while their OpenVPN client stayed on the CRL. Control plane green, data plane
		// refusing, operator told it succeeded — the exact defect on record for the node-restore path.
		//
		// ⚠ `user_deactivated` ONLY: a cert revoked deliberately, or cascaded by a gateway revoke, is not
		// revived by a user coming back. Reactivation reverses its own act and no one else's.
		if _, e := q.RestoreOVPNCertsForReactivatedUser(ctx, sqlc.RestoreOVPNCertsForReactivatedUserParams{
			OrgID: orgID, UserID: targetUserID,
		}); e != nil {
			return e
		}
		return writeAudit(ctx, q, orgID, &actor, "user.reactivated", "user", targetUserID.String(), map[string]any{})
	}); err != nil {
		return err
	}
	if s.crl != nil {
		if err := s.crl.RebuildCRL(ctx, orgID); err != nil {
			return err
		}
	}
	// Restore the user's peers + policy grants to the data plane promptly. ORG-WIDE
	// (symmetric with deactivate, S7.2 finding #1): nodes referencing this user as a
	// policy group-destination must recompile to re-add their /32.
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return nil
}

func (s *MembershipService) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListMembers returns the BARE membership rows of a single org (no user join,
// no soft-delete filter). The Users UI uses ListMembersWithUser instead (roster
// with name/email/status, soft-deleted excluded); this variant is retained for
// the cross-tenant isolation test. Prefer ListMembersWithUser for anything
// user-facing so soft-deleted users can't leak.
func (s *MembershipService) ListMembers(ctx context.Context, orgID uuid.UUID) ([]sqlc.Membership, error) {
	return s.q.ListMembershipsByOrg(ctx, orgID)
}

// ListMembersWithUser returns the org roster enriched with user fields
// (name/email/status/verified) for the Users page. Org-scoped; excludes
// soft-deleted users, keeps deactivated members (status carries that).
func (s *MembershipService) ListMembersWithUser(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListOrgMembersWithUserRow, error) {
	return s.q.ListOrgMembersWithUser(ctx, orgID)
}

// GetMember returns a membership scoped to (orgID, userID), or a typed not-found
// error. Because the lookup is org-scoped, a user in another org reads as
// not-found — no cross-tenant existence leak.
func (s *MembershipService) GetMember(ctx context.Context, orgID, userID uuid.UUID) (sqlc.Membership, error) {
	m, err := s.q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.Membership{}, apierr.NotFound("member_not_found", "member not found")
	}
	return m, err
}

// ChangeMemberRole changes a member's role, enforcing the RBAC relational rules
// (actorRole vs target vs new) and the last-owner invariant, and records a
// member.role_changed audit event atomically. actor is the acting user (nil only
// for system callers; user-initiated changes must pass it once auth lands).
func (s *MembershipService) ChangeMemberRole(ctx context.Context, actor *uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, newRole string) (sqlc.Membership, error) {
	if !rbac.ValidRole(newRole) {
		return sqlc.Membership{}, apierr.BadRequest("invalid_role", "unknown role: "+newRole)
	}
	var result sqlc.Membership
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		target, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		if e != nil {
			return e
		}
		if !rbac.CanManageMembership(actorRole, target.Role, newRole) {
			return apierr.New(403, "forbidden", "you may not change this member's role")
		}
		if e := s.guardLastOwner(ctx, q, orgID, target.Role, newRole); e != nil {
			return e
		}
		result, e = q.ChangeMemberRole(ctx, sqlc.ChangeMemberRoleParams{OrgID: orgID, UserID: targetUserID, Role: newRole})
		if e != nil {
			return e
		}
		return writeAudit(ctx, q, orgID, actor, "member.role_changed", "membership", targetUserID.String(),
			map[string]any{"role": map[string]string{"from": target.Role, "to": newRole}})
	})
	return result, err
}

// RemoveMember HARD-deletes a membership (the group_members cascade FK then drops the
// user's group rows), enforcing the RBAC relational rules and the last-owner invariant,
// and records member.removed atomically.
//
// INTERNAL-ONLY (S7.2 finding #1): there is deliberately NO HTTP endpoint for hard
// removal today — the exposed offboarding is DeactivateMember (reversible; status
// flip + org-wide push). This method retains the ORG-WIDE PushOrgNodes below so that
// IF a hard-remove endpoint is ever added, it inherits the Zero Trust <5s push
// targeting. A removed member's /32 then leaves EVERY node's ruleset — the compiled
// enterprise policy AND the open-edition mesh WG peer set (ListActiveWireGuardPeersForNode),
// BOTH of which gate on current membership (the identity-binding invariant). Until the
// membership join was added to the peer query, this push rebuilt a query that still
// served the removed member in open-edition mesh — the guarantee this comment claims
// was only half-true. Do not wire an endpoint to this without that push intact.
func (s *MembershipService) RemoveMember(ctx context.Context, actor *uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		target, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		if e != nil {
			return e
		}
		if !rbac.CanManageMembership(actorRole, target.Role, "") {
			return apierr.New(403, "forbidden", "you may not remove this member")
		}
		if e := s.guardLastOwner(ctx, q, orgID, target.Role, ""); e != nil {
			return e
		}
		if _, e := q.RemoveMember(ctx, sqlc.RemoveMemberParams{OrgID: orgID, UserID: targetUserID}); e != nil {
			return e
		}
		return writeAudit(ctx, q, orgID, actor, "member.removed", "membership", targetUserID.String(),
			map[string]any{"role": target.Role})
	})
	if err == nil && s.pusher != nil {
		// F1 4th trigger: member removal is an org-wide policy change (group_members
		// cascade-dropped in the tx). Push ALL org gateways so the ex-member's /32
		// leaves every compiled ruleset within the <5s spec, not just their own nodes.
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return err
}

// guardLastOwner rejects demoting or removing the final owner of an org.
func (s *MembershipService) guardLastOwner(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, targetRole, newRole string) error {
	losingAnOwner := targetRole == rbac.RoleOwner && newRole != rbac.RoleOwner // demotion or removal
	if !losingAnOwner {
		return nil
	}
	owners, err := q.CountOwners(ctx, orgID)
	if err != nil {
		return err
	}
	if owners <= 1 {
		return apierr.Conflict("last_owner", "an organization must always have at least one owner")
	}
	return nil
}
