// Package tenancy holds the multi-tenant core services (organizations,
// memberships). It is edition-aware: the org limit comes from the enterprise
// boundary, so the open build caps org creation while the enterprise build does
// not — without any conditional logic leaking into the HTTP layer.
//
// Every mutation writes an audit_logs row in the SAME transaction as the change,
// so an org can never be created/updated/deleted without a corresponding audit
// record. The actor is currently null (endpoints are unauthenticated until S2).
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// actorFromCtx returns the acting user id from the authenticated principal, or
// nil for system callers (seed/migration).
func actorFromCtx(ctx context.Context) *uuid.UUID {
	if p, ok := authctx.PrincipalFrom(ctx); ok {
		id := p.UserID
		return &id
	}
	return nil
}

// Service provides organization operations.
type Service struct {
	// licence answers the entitlement questions. ⚠ nil means Community — the fail-open default.
	licence *licence.Manager
	pool    *pgxpool.Pool
	q       *sqlc.Queries
}

// NewService builds a tenancy service over the given pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: sqlc.New(pool)}
}

// withTx runs fn inside a transaction (mutation + audit are atomic). When the
// service was constructed without a pool (tests injecting a tx), fn runs on the
// pre-set querier directly so the caller controls the transaction.
func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetupComplete reports whether this deployment has ever been set up.
//
// ⛔ THE SAME SIGNAL THE ORG BOUNDARY AND THE SIGNUP GATE USE — one question, one answer, three consumers.
// Counting soft-deleted rows means deleting every organization cannot reopen setup.
func (s *Service) SetupComplete(ctx context.Context) (bool, error) {
	ever, err := s.q.CountOrganizationsEver(ctx)
	return ever > 0, err
}

// PublicSignupOpen answers whether `/auth/signup` may still admit a stranger.
//
// ⛔ IT IS KEYED ON USERS, NOT ORGANIZATIONS, AND THAT CLOSES A RACE THAT WAS REAL.
//
// SetupComplete asks "has this deployment ever had an ORGANIZATION", which is zero on a fresh install —
// so signup stayed open from `docker compose up` until the operator got round to creating the first org.
// On a public address that window belongs to whoever finds it first: sign up, create the first
// organization, own the deployment. `bootstrap.EnsureAdmin` exists precisely to make the first
// administrator a deliberate act, and an open form running beside it gave the same power away for free.
//
// ⚠ A ONE-CLICK INSTALLER TURNS THAT WINDOW INTO A PRODUCT FEATURE. `curl … | sh` ends with a running,
// publicly-reachable, unclaimed control plane — and the time between "up" and "the operator reads the
// credential" is exactly the time an attacker has. Measured in minutes on a good day.
//
// ⭐ THE SIGNAL IS THE SAME ONE EnsureAdmin USES, so the two can never disagree: `CountUsers` counts
// SOFT-DELETED rows, meaning "has this deployment ever had a user". EnsureAdmin runs at every boot and
// mints the administrator when that count is zero — so from the first successful start there is always at
// least one user, and this returns false forever after. No flag, no setting, nothing to configure wrong.
//
// ⛔ AND THAT MAKES PUBLIC SIGNUP UNREACHABLE IN PRACTICE, WHICH IS THE INTENT AND NOT A SIDE EFFECT. The
// bootstrap administrator REPLACED signup as the first-run path; leaving both alive was the defect. Every
// remaining way in is an act by someone already inside — invitation, or SSO domain capture — and both are
// proven independent of this endpoint by TestAdmissionPathsDoNotDependOnSignup.
func (s *Service) PublicSignupOpen(ctx context.Context) (bool, error) {
	ever, err := s.q.CountUsers(ctx)
	if err != nil {
		// ⚠ FAIL CLOSED. A read error must not be read as "nobody is here yet" — that is the one answer
		// that opens the door. Everywhere else in this product an unknown fails toward showing more; here
		// an unknown hands the deployment away.
		return false, err
	}
	return ever == 0, nil
}

// checkMayCreateOrg answers WHO may bring an organization into existence, which is a different question
// from HOW MANY may exist (that is checkOrgCeiling, and it is commercial).
//
// ⭐ TWO CALLERS ARE LEGITIMATE AND THE CONDITION IS SELF-CLOSING — no setting, nothing to configure
// wrong, nothing an operator must remember to turn on:
//
//  1. BOOTSTRAP — the deployment has ZERO organizations. Somebody has to make the first one, and on a
//     fresh install there is nobody inside to invite them. ⚠ This window closes BY ITSELF the instant the
//     first org exists, which is why it needs no flag: the condition that opens it is destroyed by using
//     it, exactly once, forever.
//
//  2. A HOLDER of `users.cp_admin` — the deployment itself has said this person may.
//
//     ⛔ NOT "IS A MEMBER OF SOMETHING", WHICH IS WHAT THIS ACCEPTED BEFORE AND IS THE WRONG SEAM.
//     Membership in org A is authority INSIDE org A; it cannot license creating org B, which A has no
//     relationship to. Every authority the identity model carries is `map[orgID]role` — org-keyed by
//     construction — so "may this person create AN ORGANIZATION" had no carrier at all until 0073.
//
// ⛔ EVERYONE ELSE IS REFUSED, AND THAT IS THE WHOLE FIX. A verified account with no membership lands
// NOWHERE until it is invited or its domain is captured — and both of those are acts by someone already
// inside. Which is precisely what the invitation flow already assumed: `/accept-invite` is `security: []`
// and mints the account itself, so being invited IS the admission and the account is only the credential.
//
// ⚠ THE REFUSAL IS 403 WITH A HUMAN REASON, not a 404. Hiding the endpoint would leave a signed-up user
// staring at a funnel that silently goes nowhere; they need to be told an invitation is how they get in.
func (s *Service) checkMayCreateOrg(ctx context.Context, creator uuid.UUID) error {
	ever, err := s.q.CountOrganizationsEver(ctx)
	if err != nil {
		return err
	}
	if ever == 0 {
		return nil // bootstrap: this deployment has never been set up
	}
	may, err := s.q.UserIsCPAdmin(ctx, creator)
	if err != nil {
		return err
	}
	if may {
		return nil // the deployment granted this person the capability
	}
	// ⚠ REGISTERED HERE, BESIDE THE CHANGE THAT ALTERED ITS MEANING: `/api/v1/auth/signup` HAS NO RATE
	// LIMIT. The only throttle in the router is `rekeyOnly(newRekeyThrottle(...))`, scoped to the agent
	// re-key path.
	//
	// ⛔ THE CODE DID NOT CHANGE. THE CONSEQUENCE DID. Signup was always unlimited — but it used to end in
	// an organization, so it collided with the org ceiling and a flood stopped at one. Now it ends in a
	// bare account, and NOTHING bounds it: unlimited rows in `users`, one verification email per attempt.
	//
	// > ## ⭐ **A PRE-EXISTING GAP BECAME A NEW EXPOSURE WITH NOBODY EDITING IT — the limit that had been
	// > ## accidentally containing it was removed by a fix that was right for a different reason.**
	//
	// Not fixed here on purpose: a limiter bolted onto the end of a security change is the shape that
	// gets tuned wrong. It needs its own pass, with the CLI-refusal item.
	return apierr.Forbidden("invitation_required",
		"This deployment is already set up. New organizations can only be created by someone who is "+
			"already a member — ask an administrator to invite you, then sign in to accept.")
}

// checkOrgCeiling refuses creating an organization beyond the licensed ceiling.
//
// ⚠ A nil manager means Community — the fail-open default. A deployment that upgrades into this code keeps
// its one organization rather than losing the ability to create at all.
func (s *Service) checkOrgCeiling(ctx context.Context) error {
	tier := s.effectiveTier()
	ceiling, _ := licence.OrgCeilingFor(tier)
	if ceiling == nil {
		return nil // unlimited
	}
	count, err := s.q.CountOrganizations(ctx)
	if err != nil {
		return err
	}
	if count < int64(*ceiling) {
		return nil
	}
	// ⭐ THE REFUSAL NAMES THE BAND AND THE CEILING, like the gateway one. ⚠ AND THE ERROR CODE IS
	// UNCHANGED (`org_limit_reached`) ON PURPOSE: apps/web's CreateOrg funnel branches on that code to swap
	// the form for an invitation-only card. Changing the code would silently break a shipped flow that no
	// test here covers.
	return apierr.Forbidden("org_limit_reached", s.orgRefusal(tier, *ceiling, count))
}

// effectiveTier resolves the entitlement tier. ⚠ nil manager => Community, the fail-open default.
func (s *Service) effectiveTier() licence.Tier {
	if s.licence == nil {
		return licence.TierCommunity
	}
	return s.licence.Evaluate(time.Now()).Tier
}

// orgRefusal is the message an operator reads. Extracted so the wording is testable without a database.
func (s *Service) orgRefusal(tier licence.Tier, ceiling int, count int64) string {
	unit := "organizations"
	if ceiling == 1 {
		unit = "organization"
	}
	return fmt.Sprintf(
		"This deployment is on the %s band, which allows %d %s, and %d already exist. "+
			"Nothing existing is affected — this applies only to creating a new organization. "+
			"To add another, upgrade the licence.",
		tier, ceiling, unit, count)
}

// WithLicence wires the entitlement source. ⚠ Optional: a Service without one behaves as Community.
func (s *Service) WithLicence(m *licence.Manager) *Service {
	s.licence = m
	return s
}

// CreateOrganization creates an organization (enforcing the edition cap), makes
// the creator its first owner, and records an org.created audit event — all
// atomically.
func (s *Service) CreateOrganization(ctx context.Context, creator uuid.UUID, name, slug string) (sqlc.Organization, error) {
	// ⛔ THE ORGANIZATION CEILING — AT CREATION ONLY (S12.1 slice 5).
	//
	// Community 1 · trial 1 · Starter and above unlimited. An EXISTING org never disappears: this is checked
	// here and nowhere else, so a deployment that lapses keeps every org it has and simply cannot create
	// another. Same rule as the gateway ceiling, and for the same reason.
	//
	// ⚠ THIS REPLACES A COMPILE-TIME CONSTANT. `enterprise.Unlimited` was a build-tag const, so the check
	// was eliminated at compile time in the enterprise binary — the branch was not present, rather than
	// present-and-false. With one binary the question is a runtime one and must be asked every time.
	if err := s.checkOrgCeiling(ctx); err != nil {
		return sqlc.Organization{}, err
	}
	// ⛔ SIGNING UP CREATES AN ACCOUNT. IT MUST NEVER CREATE AN ORGANIZATION. (founder-ruled)
	//
	// `/api/v1/auth/signup` is `security: []` — open to anyone who can reach the deployment, with no
	// invitation, no allow-list and no domain restriction. Until this line, a stranger could sign up,
	// verify an email they control, and become OWNER of a new organization on a private VPN control plane.
	//
	// ⛔ AND THE ONLY THING STOPPING THEM WAS A COMMERCIAL NUMBER. The org ceiling held it to one on
	// Community — so the product's sole signup control was a limit the customer PAYS TO REMOVE. Install
	// Growth and you have bought 19 more self-service owner slots; install Scale and there is no limit at
	// all. A licence must never be the thing standing between an anonymous visitor and ownership.
	if err := s.checkMayCreateOrg(ctx, creator); err != nil {
		return sqlc.Organization{}, err
	}

	var org sqlc.Organization
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		var e error
		org, e = q.CreateOrganization(ctx, sqlc.CreateOrganizationParams{Name: name, Slug: slug})
		if e != nil {
			return mapDBError(e)
		}
		if _, e = q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{OrgID: org.ID, UserID: creator, Role: rbac.RoleOwner}); e != nil {
			return e
		}
		// ⛔ BOOTSTRAP GRANTS THE CAPABILITY, IN THE SAME TRANSACTION THAT USES IT.
		//
		// The first account creates the first organization because the deployment has never been set up —
		// and must not have to re-derive that permission afterwards, because the condition that allowed it
		// is destroyed by the act. Writing the grant here means the founder's authority OUTLIVES the
		// window it came from, and the window itself stays shut forever.
		//
		// ⚠ Idempotent and harmless for an existing holder: this path is only reachable when `ever == 0`.
		if e = q.GrantCPAdmin(ctx, creator); e != nil {
			return e
		}
		return writeAudit(ctx, q, org.ID, &creator, "org.created", "organization", org.ID.String(),
			map[string]any{"name": name, "slug": slug})
	})
	if err != nil {
		return sqlc.Organization{}, err
	}
	return org, nil
}

// ListOrganizationsForUser returns the live organizations the user belongs to.
func (s *Service) ListOrganizationsForUser(ctx context.Context, userID uuid.UUID) ([]sqlc.Organization, error) {
	return s.q.ListOrganizationsForUser(ctx, userID)
}

// GetOrganization returns a live organization or a typed not-found error.
func (s *Service) GetOrganization(ctx context.Context, id uuid.UUID) (sqlc.Organization, error) {
	org, err := s.q.GetOrganizationByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.Organization{}, orgNotFound()
	}
	return org, err
}

// ListOrganizations returns all live organizations.
func (s *Service) ListOrganizations(ctx context.Context) ([]sqlc.Organization, error) {
	return s.q.ListOrganizations(ctx)
}

// SetOVPNEnabled flips the org's OpenVPN opt-in (S9.1 D-S9.5-OPTIN). Unlock-then-opt-in: OFF by
// default; enabling makes the OVPN capability available on the org's gateways (the agent then runs
// the server). Disabling is NOT revocation — issued client certs SURVIVE (D-S9.5-OPTIN d); a
// re-enable restores service with the same certs.
func (s *Service) SetOVPNEnabled(ctx context.Context, id uuid.UUID, enabled bool) (sqlc.Organization, error) {
	var org sqlc.Organization
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		o, e := q.SetOrgOVPNEnabled(ctx, sqlc.SetOrgOVPNEnabledParams{ID: id, OvpnEnabled: enabled})
		if errors.Is(e, pgx.ErrNoRows) {
			return orgNotFound()
		}
		if e != nil {
			return e
		}
		org = o
		// review #4: the opt-in toggle unlocks the ENTIRE OpenVPN surface (server + PKI + cert delivery).
		// D-S9.5-OPTIN required an attributable audit; mirror every sibling org toggle — withTx + writeAudit,
		// BOTH directions. Swallowed-audit at a feature's on-switch is the worst placement for it.
		action := "org.ovpn_disabled"
		if enabled {
			action = "org.ovpn_enabled"
		}
		return writeAudit(ctx, q, id, actorFromCtx(ctx), action, "organization", id.String(), map[string]any{"enabled": enabled})
	})
	return org, err
}

// UpdateOrganization updates the mutable settings (name only — slug is
// immutable) and records an org.updated audit event atomically.
func (s *Service) UpdateOrganization(ctx context.Context, id uuid.UUID, name string) (sqlc.Organization, error) {
	var org sqlc.Organization
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		before, e := q.GetOrganizationByID(ctx, id)
		if errors.Is(e, pgx.ErrNoRows) {
			return orgNotFound()
		}
		if e != nil {
			return e
		}
		org, e = q.UpdateOrganizationName(ctx, sqlc.UpdateOrganizationNameParams{ID: id, Name: name})
		if e != nil {
			return e
		}
		return writeAudit(ctx, q, id, actorFromCtx(ctx), "org.updated", "organization", id.String(),
			map[string]any{"name": map[string]string{"from": before.Name, "to": name}})
	})
	if err != nil {
		return sqlc.Organization{}, err
	}
	return org, nil
}

// OrgResources is what an organization still owns. Zero everywhere is the only state in which it may be
// deleted.
type OrgResources struct {
	Gateways           int64 `json:"gateways"`
	Devices            int64 `json:"devices"`
	Sites              int64 `json:"sites"`
	Clusters           int64 `json:"clusters"`
	MachineCredentials int64 `json:"machine_credentials"`
}

// Empty reports whether nothing is left to strand.
func (r OrgResources) Empty() bool {
	return r.Gateways == 0 && r.Devices == 0 && r.Sites == 0 && r.Clusters == 0 && r.MachineCredentials == 0
}

// Blockers lists what is in the way, in the operator's words, largest obstacle first.
func (r OrgResources) Blockers() []string {
	var out []string
	add := func(n int64, one, many string) {
		if n == 1 {
			out = append(out, fmt.Sprintf("1 %s", one))
		} else if n > 1 {
			out = append(out, fmt.Sprintf("%d %s", n, many))
		}
	}
	add(r.Gateways, "gateway", "gateways")
	add(r.Sites, "site", "sites")
	add(r.Devices, "device", "devices")
	add(r.Clusters, "Kubernetes cluster", "Kubernetes clusters")
	add(r.MachineCredentials, "machine credential", "machine credentials")
	return out
}

// OrgResourceCount reports what an organization still owns, for the preflight the delete screen shows
// BEFORE anyone types a confirmation.
func (s *Service) OrgResourceCount(ctx context.Context, id uuid.UUID) (OrgResources, error) {
	r, err := s.q.CountOrgResources(ctx, id)
	if err != nil {
		return OrgResources{}, err
	}
	return OrgResources{
		Gateways: r.Gateways, Devices: r.Devices, Sites: r.Sites,
		Clusters: r.Clusters, MachineCredentials: r.MachineCredentials,
	}, nil
}

// SoftDeleteOrganization soft-deletes an org and records org.deleted atomically.
//
// ⛔ IT REFUSES WHILE THE ORGANIZATION STILL OWNS ANYTHING, and the reason is what "delete" does here.
// This is a SOFT delete: the row gets `deleted_at` and nothing else happens. Every gateway keeps running
// on the customer's own server, every device keeps its pool address, every machine credential keeps
// authenticating — all of it now owned by an organization no screen will ever show again.
//
// > ## ⛔ **THAT IS NOT A DELETION, IT IS AN ABANDONMENT** — and the resources it strands are the ones
// > ## carrying live traffic.
//
// ⚠ THE REFUSAL NAMES EVERY BLOCKER AT ONCE. Revealing one per attempt turns a destructive verb into a
// guessing game, and each attempt is a fresh chance to type the confirmation on the wrong organization.
//
// ⭐ NOT A FORCE FLAG. A cascade would have to revoke gateways, strand device configs and kill credentials
// across a tenant in one click, with no undo — the blast radius belongs to the operator doing it
// deliberately, one surface at a time, where each of those acts already has its own confirmation.
func (s *Service) SoftDeleteOrganization(ctx context.Context, id uuid.UUID) error {
	res, err := s.OrgResourceCount(ctx, id)
	if err != nil {
		return err
	}
	if !res.Empty() {
		return apierr.Conflict("org_not_empty",
			"This organization still has "+strings.Join(res.Blockers(), ", ")+". Deleting it would leave "+
				"them running with no organization to manage them from — gateways keep carrying traffic and "+
				"credentials keep authenticating. Remove them first, then delete the organization.")
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.SoftDeleteOrganization(ctx, id)
		if e != nil {
			return e
		}
		if n == 0 {
			return orgNotFound()
		}
		return writeAudit(ctx, q, id, actorFromCtx(ctx), "org.deleted", "organization", id.String(), map[string]any{})
	})
}

// writeAudit records an audit event in the caller's transaction. actor may be
// nil, which means a SYSTEM action (seed/migration/automation) — never an
// unattributed user action. Once auth lands (S2), user-initiated mutations
// (including every role change) MUST pass a non-nil actor.
func writeAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	actorID := pgtype.UUID{}
	if actor != nil {
		actorID = pgtype.UUID{Bytes: [16]byte(*actor), Valid: true}
	}
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: [16]byte(orgID), Valid: true},
		ActorUserID: actorID,
		Action:      action,
		TargetType:  &targetType,
		TargetID:    &targetID,
		Metadata:    b,
	})
	return err
}

// writeSystemAudit records a system/service-initiated audit event (no human actor) with a NAMED
// actor in actor_system (e.g. "idp-sync") + the cause in metadata. See migration 0027.
func writeSystemAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actorSystem, action, targetType, targetID string, meta map[string]any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: [16]byte(orgID), Valid: true},
		ActorSystem: &actorSystem,
		Action:      action,
		TargetType:  &targetType,
		TargetID:    &targetID,
		Metadata:    b,
	})
	return err
}

func orgNotFound() error { return apierr.NotFound("org_not_found", "organization not found") }

// mapDBError converts known Postgres errors into typed API errors.
func mapDBError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return apierr.Conflict("slug_taken", "that organization slug is already in use")
	}
	return err
}

// OnlineWindow is the SINGLE SOURCE OF TRUTH for S3.6's online approximation: a
// device is "seen recently" if its last handshake is within this window
// (WireGuard has no live state). The HTTP device-list threshold aliases this
// (see http.onlineThreshold) so the dashboard tile and the per-device dot can
// never drift apart.
//
// Read predicates only need the LOWER bound (handshake >= now-OnlineWindow). The
// upper bound (handshake must not be in the future — which would pin a device
// "online" forever) is a DATA INVARIANT enforced once at ingestion in
// nodes.Service.ReportStatus (future handshakes past a small skew are dropped),
// so last_handshake_at is never future-dated at rest. Do not re-implement that
// clamp per read site — it would diverge from deviceOnline and duplicate the fix.
const OnlineWindow = 3 * time.Minute

// Overview is the dashboard aggregate for an org.
type Overview struct {
	Members        int64
	Devices        int64
	Nodes          int64
	Online         int64
	RecentActivity []sqlc.AuditLog
}

// Overview returns the org's counts + a recent audit slice for the dashboard
// home in a single service call (one API round-trip). Every read is org-scoped.
func (s *Service) Overview(ctx context.Context, orgID uuid.UUID, activityActor *uuid.UUID) (Overview, error) {
	var o Overview
	var err error
	if o.Members, err = s.q.CountMembersByOrg(ctx, orgID); err != nil {
		return Overview{}, err
	}
	if o.Devices, err = s.q.CountActiveDevicesByOrg(ctx, orgID); err != nil {
		return Overview{}, err
	}
	if o.Nodes, err = s.q.CountActiveNodesByOrg(ctx, orgID); err != nil {
		return Overview{}, err
	}
	since := pgtype.Timestamptz{Time: time.Now().Add(-OnlineWindow), Valid: true}
	if o.Online, err = s.q.CountOnlineDevicesByOrg(ctx, sqlc.CountOnlineDevicesByOrgParams{OrgID: orgID, LastHandshakeAt: since}); err != nil {
		return Overview{}, err
	}
	// Latest 10, no filters/cursor — the same extended query the audit viewer uses
	// (all narg filters left nil/NULL = the unfiltered head of the feed).
	p := sqlc.ListAuditLogsByOrgParams{OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, Lim: 10}
	if activityActor != nil {
		p.Actor = pgtype.UUID{Bytes: *activityActor, Valid: true}
	}
	o.RecentActivity, err = s.q.ListAuditLogsByOrg(ctx, p)
	if err != nil {
		return Overview{}, err
	}
	return o, nil
}

// AuditFilter is the optional filter/cursor set for the audit-log viewer. A nil
// field means "unfiltered"; CursorTS+CursorID together fetch the page after that
// keyset position ((created_at,id) DESC).
type AuditFilter struct {
	Actor    *uuid.UUID
	Action   *string
	From, To *time.Time
	CursorTS *time.Time
	CursorID *uuid.UUID
	Limit    int32
}

// ListAuditLogs returns a keyset page of the org's audit feed, newest first,
// through the SAME extended query the dashboard's latest-N slice uses (no forked
// activity source). Org-scoped by the query-lint; every read stays within orgID.
func (s *Service) ListAuditLogs(ctx context.Context, orgID uuid.UUID, f AuditFilter) ([]sqlc.AuditLog, error) {
	p := sqlc.ListAuditLogsByOrgParams{OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, Lim: f.Limit}
	if f.Actor != nil {
		p.Actor = pgtype.UUID{Bytes: *f.Actor, Valid: true}
	}
	p.Action = f.Action
	if f.From != nil {
		p.FromTs = pgtype.Timestamptz{Time: *f.From, Valid: true}
	}
	if f.To != nil {
		p.ToTs = pgtype.Timestamptz{Time: *f.To, Valid: true}
	}
	// Both cursor halves or neither — a half-cursor would silently disable paging.
	if f.CursorTS != nil && f.CursorID != nil {
		p.CursorTs = pgtype.Timestamptz{Time: *f.CursorTS, Valid: true}
		p.CursorID = pgtype.UUID{Bytes: *f.CursorID, Valid: true}
	}
	return s.q.ListAuditLogsByOrg(ctx, p)
}

// RecordLicenseInstall audits a licence installation (S12.1 slice 6).
//
// ⛔ IT BELONGS IN THE RECORD BESIDE ORG DELETION. Installing a licence changes what the WHOLE deployment
// may do — gateway count, org count, whether SSO exists at all.
//
// ⚠ THE KEY ITSELF IS NEVER RECORDED. The licence id, tier and kid identify it completely for any later
// question; the key is a credential and an audit row is not where credentials go.
func (s *Service) RecordLicenseInstall(ctx context.Context, orgID, actor uuid.UUID, meta map[string]any) error {
	return writeAudit(ctx, s.q, orgID, &actor, "license.installed", "license", "", meta)
}
