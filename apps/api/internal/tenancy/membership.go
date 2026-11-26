package tenancy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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

// MemberActionOption carries the per-request facts a people-management action needs beyond the actor's
// role (RBAC-0): the step-up check the HTTP layer requires, and whether the actor is a deployment
// administrator. Options keep system callers (directory sync, tests) free of HTTP concerns.
type MemberActionOption func(*memberAction)

type memberAction struct {
	stepUp  func(context.Context) error
	cpAdmin bool
}

// WithStepUp runs fn AFTER the relational checks (membership, owner rules, last owner) and BEFORE any
// write, so an administrator is never asked to re-authenticate for an action that would be refused anyway.
func WithStepUp(fn func(context.Context) error) MemberActionOption {
	return func(a *memberAction) { a.stepUp = fn }
}

// ActorIsCPAdmin marks the actor as a deployment administrator (users.cp_admin).
func ActorIsCPAdmin(v bool) MemberActionOption {
	return func(a *memberAction) { a.cpAdmin = v }
}

func memberActionFrom(opts []MemberActionOption) memberAction {
	var a memberAction
	for _, o := range opts {
		if o != nil {
			o(&a)
		}
	}
	return a
}

func (a memberAction) runStepUp(ctx context.Context) error {
	if a.stepUp == nil {
		return nil
	}
	return a.stepUp(ctx)
}

// Provenance of a removal of access (migration 0246). Reactivation reverses only its own act.
const (
	sourceMemberAdmin = "member_admin"
	sourceIdpSync     = "idp_sync"
)

// Deactivation scope, recorded in the audit metadata.
const (
	scopeAccount      = "account"
	scopeOrganization = "organization"
)

func errOwnerOnly(verb string) error {
	return apierr.New(403, "forbidden", "Only an owner can "+verb+" an owner.")
}

func errDirectoryManaged() error {
	return apierr.Conflict("directory_managed", "Directory sync removed this person's access because they are disabled or removed in your identity provider. Re-enable them there; the next sync restores their access.")
}

func errDeactivatedElsewhere() error {
	return apierr.Conflict("deactivated_elsewhere", "This person was deactivated by another organization on this server. Ask a deployment administrator to reactivate them.")
}

// DeactivateMember removes a person's access on behalf of an administrator of orgID (RBAC-0 D3).
//
//   - Relational rules: only an owner may deactivate an owner (CanManageMembership), and the org's last
//     ACTIVE owner cannot be deactivated. Checked inside the transaction under the org lock.
//   - Scope: ACCOUNT-WIDE (users.status, CLI credentials, sessions) only when this is the person's only
//     organization and they are not a deployment administrator — today's behaviour for a single-org
//     deployment. Otherwise ORGANIZATION-SCOPED (memberships.access_revoked_at): an org's administrators
//     have authority over that org, not over the person's other tenancies.
func (s *MembershipService) DeactivateMember(ctx context.Context, actor uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, opts ...MemberActionOption) error {
	a := memberActionFrom(opts)
	_, err := s.deactivate(ctx, deactivation{
		orgID: orgID, target: targetUserID, source: sourceMemberAdmin, actorRole: actorRole, human: true, stepUp: a.runStepUp,
		audit: func(q *sqlc.Queries, scope string) error {
			return writeAudit(ctx, q, orgID, &actor, "user.deactivated", "user", targetUserID.String(), map[string]any{"scope": scope})
		},
	})
	return err
}

// DeactivateMemberBySync is the idp-sync (S7.5.2) deprovision path: the SAME sweep and the SAME scope rule
// as DeactivateMember, audited to a first-class NAMED system actor ("idp-sync") with the CAUSE in metadata.
// Returns didAct=false when there was nothing left to remove (idempotent no-op) so a still-listed disabled
// member doesn't re-audit + re-push on every poll (#7).
func (s *MembershipService) DeactivateMemberBySync(ctx context.Context, orgID, targetUserID uuid.UUID, cause string) (bool, error) {
	return s.deactivate(ctx, deactivation{
		orgID: orgID, target: targetUserID, source: sourceIdpSync,
		audit: func(q *sqlc.Queries, scope string) error {
			return writeSystemAudit(ctx, q, orgID, "idp-sync", "user.deactivated", "user", targetUserID.String(),
				map[string]any{"cause": cause, "scope": scope})
		},
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
		changed, err = q.RevokeMembershipAccess(ctx, sqlc.RevokeMembershipAccessParams{OrgID: orgID, UserID: targetUserID, Source: sourceIdpSync})
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

type deactivation struct {
	orgID, target uuid.UUID
	source        string
	actorRole     string // human callers only
	human         bool
	stepUp        func(context.Context) error
	audit         func(q *sqlc.Queries, scope string) error
}

// deactivate is the shared core for the human and directory-sync callers. Everything that decides
// (membership, owner rules, last owner, scope) and everything that writes runs in ONE transaction under
// the org lock; the live-session cut, CRL rebuild and org-wide push follow the commit.
func (s *MembershipService) deactivate(ctx context.Context, d deactivation) (bool, error) {
	var acted bool
	var scope string
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := q.LockMembershipOrganization(ctx, d.orgID); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("member_not_found", "member not found")
			}
			return e
		}
		// Directory reconciliation can revoke org access before its disabled-user sweep, so sync still acts
		// on a retained (revoked) membership in this exact org; a person acts only on an active one.
		m, e := q.GetMembershipIncludingRevoked(ctx, sqlc.GetMembershipIncludingRevokedParams{OrgID: d.orgID, UserID: d.target})
		if errors.Is(e, pgx.ErrNoRows) || (e == nil && d.human && m.AccessRevokedAt.Valid) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		if e != nil {
			return e
		}
		if d.human && !rbac.CanManageMembership(d.actorRole, m.Role, "") {
			return errOwnerOnly("deactivate")
		}
		u, e := q.GetUserDeactivation(ctx, d.target)
		if e != nil {
			return e
		}
		if u.Status == "deactivated" {
			return nil // #7: already deactivated account-wide → idempotent no-op
		}
		others, e := q.CountOtherActiveMemberships(ctx, sqlc.CountOtherActiveMembershipsParams{UserID: d.target, OrgID: d.orgID})
		if e != nil {
			return e
		}
		account := others == 0 && !u.CpAdmin
		if !account && m.AccessRevokedAt.Valid {
			return nil // already no access in this org → idempotent no-op
		}
		// Never orphan an org — even from sync. The sync caller degrades that config's health on this
		// error so an operator sees "couldn't deprovision the sole owner".
		if m.Role == rbac.RoleOwner && !m.AccessRevokedAt.Valid {
			owners, oe := q.CountOwners(ctx, d.orgID)
			if oe != nil {
				return oe
			}
			if owners <= 1 {
				return apierr.Conflict("last_owner", "this user is the only owner of this organization and cannot be deactivated")
			}
		}
		if account {
			sole, se := q.CountOrgsWhereSoleOwner(ctx, d.target)
			if se != nil {
				return se
			}
			if sole > 0 {
				return apierr.Conflict("last_owner", "this user is the only owner of an organization and cannot be deactivated")
			}
		}
		if d.stepUp != nil {
			if se := d.stepUp(ctx); se != nil {
				return se
			}
		}
		if account {
			if _, e := q.DeactivateUserAccount(ctx, sqlc.DeactivateUserAccountParams{ID: d.target, Source: d.source, OrgID: pgtype.UUID{Bytes: d.orgID, Valid: true}}); e != nil {
				return e
			}
			// Deactivation sweeps CLI credentials too (S5.1, session parity) — in the SAME tx as the
			// status flip, so the sweep can't be lost between the two.
			if e := cliauth.SweepUser(ctx, q, d.target); e != nil {
				return e
			}
			scope = scopeAccount
		} else {
			// Org-scoped: the person keeps every other organization. Sessions and CLI credentials
			// survive because the principal is rebuilt per request from NON-revoked memberships, so this
			// org simply disappears from them on the next request.
			if _, e := q.RevokeMembershipAccess(ctx, sqlc.RevokeMembershipAccessParams{OrgID: d.orgID, UserID: d.target, Source: d.source}); e != nil {
				return e
			}
			scope = scopeOrganization
		}
		// ⛔ AND IT REACHES THE CRL. Without this the refusal was CONFIGURATIONAL ONLY: the device leaves the
		// CCD roster and `ccd-exclusive` refuses the client — one mechanism, living in the AGENT, on a
		// certificate that is still cryptographically valid. Same transaction as the access change: a
		// revocation that can be lost between two statements is one an operator was told happened.
		if _, e := q.RevokeOVPNCertsForDeactivatedUser(ctx, sqlc.RevokeOVPNCertsForDeactivatedUserParams{OrgID: d.orgID, UserID: d.target}); e != nil {
			return e
		}
		acted = true
		return d.audit(q, scope)
	})
	if err != nil || !acted {
		return false, err
	}
	// Cut live access immediately for an account-wide deactivation (belt-and-suspenders with the
	// SessionAuth status check that also 401s any in-flight session).
	if scope == scopeAccount && s.revoker != nil {
		if err := s.revoker.DeleteAllForUser(ctx, d.target); err != nil {
			return false, err
		}
	}
	// The CRL is republished from the full revoked set, AFTER the tx commits — a CRL naming a serial whose
	// revocation later rolled back would refuse a credential the database still considers live.
	if s.crl != nil {
		if err := s.crl.RebuildCRL(ctx, d.orgID); err != nil {
			return false, err
		}
	}
	// Offboarding cascade, ORG-WIDE (S7.2 finding #1): every node referencing this person as a policy
	// group-destination must recompile so their /32 leaves its ruleset within the <5s spec.
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, d.orgID)
	}
	return true, nil
}

// ReactivateMember restores a person deactivated by THIS org's administrators (RBAC-0 D3). It never
// reverses directory sync (directory_managed) or another organization's act (deactivated_elsewhere).
func (s *MembershipService) ReactivateMember(ctx context.Context, actor uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, opts ...MemberActionOption) error {
	a := memberActionFrom(opts)
	var acted bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := q.LockMembershipOrganization(ctx, orgID); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("member_not_found", "member not found")
			}
			return e
		}
		m, e := q.GetMembershipIncludingRevoked(ctx, sqlc.GetMembershipIncludingRevokedParams{OrgID: orgID, UserID: targetUserID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		if e != nil {
			return e
		}
		if !rbac.CanManageMembership(actorRole, m.Role, "") {
			return errOwnerOnly("reactivate")
		}
		if m.AccessRevokedAt.Valid {
			source, se := q.GetMembershipRevocationSource(ctx, sqlc.GetMembershipRevocationSourceParams{OrgID: orgID, UserID: targetUserID})
			if se != nil {
				return se
			}
			if source != sourceMemberAdmin {
				return errDirectoryManaged()
			}
			if e := a.runStepUp(ctx); e != nil {
				return e
			}
			if _, e := q.RestoreMembershipAccess(ctx, sqlc.RestoreMembershipAccessParams{OrgID: orgID, UserID: targetUserID, Source: sourceMemberAdmin}); e != nil {
				return e
			}
		} else {
			u, e := q.GetUserDeactivation(ctx, targetUserID)
			if e != nil {
				return e
			}
			if u.Status != "deactivated" {
				return nil // already active: nothing to reverse
			}
			switch {
			case u.DeactivationSource != nil && *u.DeactivationSource == sourceIdpSync:
				return errDirectoryManaged()
			case u.DeactivationSource != nil:
				if !(u.DeactivatedByOrgID.Valid && uuid.UUID(u.DeactivatedByOrgID.Bytes) == orgID) && !a.cpAdmin {
					return errDeactivatedElsewhere()
				}
			default:
				// Legacy row (deactivated before provenance was recorded): this org may reverse it only
				// when it is the person's only organization; otherwise a deployment administrator.
				others, oe := q.CountOtherActiveMemberships(ctx, sqlc.CountOtherActiveMembershipsParams{UserID: targetUserID, OrgID: orgID})
				if oe != nil {
					return oe
				}
				if others > 0 && !a.cpAdmin {
					return errDeactivatedElsewhere()
				}
			}
			if e := a.runStepUp(ctx); e != nil {
				return e
			}
			if _, e := q.ReactivateUserAccount(ctx, targetUserID); e != nil {
				return e
			}
		}
		// ⛔ THE SYMMETRIC HALF — the user would otherwise come back while their OpenVPN client stayed on the
		// CRL. ⚠ `user_deactivated` ONLY: reactivation reverses its own act and no one else's.
		if _, e := q.RestoreOVPNCertsForReactivatedUser(ctx, sqlc.RestoreOVPNCertsForReactivatedUserParams{OrgID: orgID, UserID: targetUserID}); e != nil {
			return e
		}
		acted = true
		return writeAudit(ctx, q, orgID, &actor, "user.reactivated", "user", targetUserID.String(), map[string]any{})
	})
	if err != nil || !acted {
		return err
	}
	if s.crl != nil {
		if err := s.crl.RebuildCRL(ctx, orgID); err != nil {
			return err
		}
	}
	// Restore the user's peers + policy grants to the data plane promptly (ORG-WIDE, symmetric with
	// deactivate, S7.2 finding #1).
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
	return nil
}

// RestoreForSync is directory sync's half of RBAC-0 D3: when the directory lists the person as ACTIVE in a
// mapped group again, sync — and only sync — reverses its OWN earlier deprovisioning in this org: an
// org-scoped `idp_sync` revocation, an account-wide `idp_sync` deactivation made from this org, and the
// OpenVPN certificates that deprovisioning revoked here. An administrator's deactivation is never touched.
// Returns didAct=false when there was nothing of sync's to restore (the common case on every poll).
func (s *MembershipService) RestoreForSync(ctx context.Context, orgID, targetUserID uuid.UUID) (bool, error) {
	var acted, certs bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		m, e := q.GetMembershipIncludingRevoked(ctx, sqlc.GetMembershipIncludingRevokedParams{OrgID: orgID, UserID: targetUserID})
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if m.AccessRevokedAt.Valid {
			source, se := q.GetMembershipRevocationSource(ctx, sqlc.GetMembershipRevocationSourceParams{OrgID: orgID, UserID: targetUserID})
			if se != nil {
				return se
			}
			if source != sourceIdpSync {
				return nil // an administrator's deactivation stands
			}
			if _, e := q.RestoreMembershipAccess(ctx, sqlc.RestoreMembershipAccessParams{OrgID: orgID, UserID: targetUserID, Source: sourceIdpSync}); e != nil {
				return e
			}
			acted = true
		}
		u, e := q.GetUserDeactivation(ctx, targetUserID)
		if e != nil {
			return e
		}
		if u.Status == "deactivated" {
			if u.DeactivationSource == nil || *u.DeactivationSource != sourceIdpSync || !u.DeactivatedByOrgID.Valid || uuid.UUID(u.DeactivatedByOrgID.Bytes) != orgID {
				return nil // not this org's directory's act; the account stays deactivated
			}
			if _, e := q.ReactivateUserAccount(ctx, targetUserID); e != nil {
				return e
			}
			acted = true
		}
		restored, e := q.RestoreOVPNCertsForReactivatedUser(ctx, sqlc.RestoreOVPNCertsForReactivatedUserParams{OrgID: orgID, UserID: targetUserID})
		if e != nil {
			return e
		}
		certs = len(restored) > 0
		if !acted {
			return nil
		}
		return writeSystemAudit(ctx, q, orgID, "idp-sync", "user.reactivated", "user", targetUserID.String(), map[string]any{"cause": "active_in_directory"})
	})
	if err != nil || (!acted && !certs) {
		return false, err
	}
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
func (s *MembershipService) ChangeMemberRole(ctx context.Context, actor *uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, newRole string, opts ...MemberActionOption) (sqlc.Membership, error) {
	if _, err := rbac.NormalizeHumanRoles([]string{newRole}); err != nil {
		return sqlc.Membership{}, apierr.BadRequest("invalid_role", err.Error())
	}
	return s.changeRoles(ctx, actor, actorRole, orgID, targetUserID, nil, newRole, memberActionFrom(opts))
}

// ChangeMemberRoles atomically replaces the entire human role set.
func (s *MembershipService) ChangeMemberRoles(ctx context.Context, actor *uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, roles []string, opts ...MemberActionOption) (sqlc.Membership, error) {
	normalized, err := rbac.NormalizeHumanRoles(roles)
	if err != nil {
		return sqlc.Membership{}, apierr.BadRequest("invalid_role", err.Error())
	}
	return s.changeRoles(ctx, actor, actorRole, orgID, targetUserID, normalized, "", memberActionFrom(opts))
}

func (s *MembershipService) changeRoles(ctx context.Context, actor *uuid.UUID, actorRole string, orgID, targetUserID uuid.UUID, roles []string, legacyRole string, a memberAction) (sqlc.Membership, error) {
	var result sqlc.Membership
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// Serialize owner-count checks and role writes across different members.
		if _, e := q.LockMembershipOrganization(ctx, orgID); e != nil {
			return e
		}
		target, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: targetUserID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("member_not_found", "member not found")
		}
		if e != nil {
			return e
		}
		if legacyRole != "" {
			roles = []string{legacyRole}
			for _, r := range target.Roles {
				if r != target.Role && r != legacyRole {
					roles = append(roles, r)
				}
			}
			roles, _ = rbac.NormalizeHumanRoles(roles)
		}
		if !rbac.CanManageMembership(actorRole, target.Role, roles[0]) {
			return apierr.New(403, "forbidden", "you may not change this member's roles")
		}
		if e := s.guardLastOwner(ctx, q, orgID, target, roles[0]); e != nil {
			return e
		}
		if e := a.runStepUp(ctx); e != nil {
			return e
		}
		result, e = q.ChangeMemberRoles(ctx, sqlc.ChangeMemberRolesParams{OrgID: orgID, UserID: targetUserID, Roles: roles})
		if e != nil {
			return e
		}
		return writeAudit(ctx, q, orgID, actor, "member.role_changed", "membership", targetUserID.String(),
			map[string]any{"roles": map[string][]string{"from": target.Roles, "to": result.Roles}})
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
		if e := s.guardLastOwner(ctx, q, orgID, target, ""); e != nil {
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

// guardLastOwner rejects demoting or removing the final ACTIVE owner of an org (RBAC-0 D6: a
// deactivated or revoked owner cannot administer the org, so it does not count).
func (s *MembershipService) guardLastOwner(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, target sqlc.Membership, newRole string) error {
	losingAnOwner := target.Role == rbac.RoleOwner && newRole != rbac.RoleOwner // demotion or removal
	if !losingAnOwner {
		return nil
	}
	owners, err := q.CountOwners(ctx, orgID)
	if err != nil {
		return err
	}
	if !target.AccessRevokedAt.Valid {
		u, err := q.GetUserDeactivation(ctx, target.UserID)
		if err != nil {
			return err
		}
		if u.Status == "active" {
			owners-- // the target is one of the active owners being lost
		}
	}
	if owners < 1 {
		return apierr.Conflict("last_owner", "an organization must always have at least one owner")
	}
	return nil
}
