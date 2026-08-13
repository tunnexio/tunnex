// Command seed populates the database with a demo organization and owner user.
//
// Contract (S0.6):
//   - Idempotent: running it twice yields the same state (upserts on fixed IDs).
//   - Non-destructive: it refuses to run against a database that already holds
//     real (non-demo) data, unless TUNNEX_SEED_FORCE=true.
//   - Fixed IDs: the demo org/user use the documented constants in
//     internal/seeddata so tests can reference them without querying.
//
// Domain tables arrive in S1.1; until then there is nothing to seed and this
// command no-ops cleanly. The idempotency/safety scaffolding is in place so
// S1.1 only fills in the actual upserts (marked below).
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/seeddata"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("seed_config_error", slog.String("error", "DATABASE_URL is required"))
		os.Exit(1)
	}
	force := os.Getenv("TUNNEX_SEED_FORCE") == "true"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("seed_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	// Pre-S1.1: the organizations table does not exist yet. No-op cleanly.
	hasOrgs, err := tableExists(ctx, pool, "organizations")
	if err != nil {
		logger.Error("seed_check_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if !hasOrgs {
		logger.Info("seed_skipped",
			slog.String("reason", "no seedable tables yet (pre-S1.1)"),
			slog.String("demo_org_id", seeddata.DemoOrgID),
		)
		return
	}

	// Non-destructive guard: refuse if the DB holds real (non-demo) orgs.
	realCount, err := countRealOrgs(ctx, pool)
	if err != nil {
		logger.Error("seed_check_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if realCount > 0 && !force {
		logger.Error("seed_refused",
			slog.Int64("real_orgs", realCount),
			slog.String("hint", "database has real data; set TUNNEX_SEED_FORCE=true to override"),
		)
		os.Exit(1)
	}

	// Idempotent upsert of the demo org + owner + membership (fixed IDs).
	q := sqlc.New(pool)
	orgID := uuid.MustParse(seeddata.DemoOrgID)
	userID := uuid.MustParse(seeddata.DemoOwnerUserID)

	if _, err := q.UpsertOrganization(ctx, sqlc.UpsertOrganizationParams{
		ID: orgID, Name: seeddata.DemoOrgName, Slug: seeddata.DemoOrgSlug,
	}); err != nil {
		logger.Error("seed_org_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: userID, Email: seeddata.DemoOwnerEmail, Name: seeddata.DemoOwnerName,
		// ⛔ THE ONLY SEEDED ACCOUNT THAT MAY CREATE AN ORGANIZATION. Stated here rather than inherited
		// from a column default, because it is a deployment fact and this fixture is what a fresh install
		// gets. Without it a fresh rig's demo owner has no "+ New" and cannot run the lifecycle walk.
		CpAdmin: true,
	}); err != nil {
		logger.Error("seed_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// The demo owner is verified so it can immediately perform org-mutating
	// actions (verified-gating, S2.2).
	if err := q.MarkEmailVerified(ctx, userID); err != nil {
		logger.Error("seed_verify_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// Set the demo owner's password (DemoOwnerPassword) so it can log in via
	// local auth — the whole point of the demo credential.
	phc, err := password.Hash(seeddata.DemoOwnerPassword)
	if err != nil {
		logger.Error("seed_hash_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: userID, PasswordHash: &phc}); err != nil {
		logger.Error("seed_password_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{
		OrgID: orgID, UserID: userID, Role: "owner",
	}); err != nil {
		logger.Error("seed_membership_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// A second member (plain 'member' role) so the roster is populated and the
	// role-gated Users UI is testable. Verified + password-set so it can log in.
	// Seeded via idempotent upserts (no audit rows — keeps the dashboard's
	// "No activity yet" empty state intact).
	memberID := uuid.MustParse(seeddata.DemoMemberUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: memberID, Email: seeddata.DemoMemberEmail, Name: seeddata.DemoMemberName,
		CpAdmin: false,
	}); err != nil {
		logger.Error("seed_member_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := q.MarkEmailVerified(ctx, memberID); err != nil {
		logger.Error("seed_member_verify_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	mphc, err := password.Hash(seeddata.DemoMemberPassword)
	if err != nil {
		logger.Error("seed_member_hash_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: memberID, PasswordHash: &mphc}); err != nil {
		logger.Error("seed_member_password_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{
		OrgID: orgID, UserID: memberID, Role: "member",
	}); err != nil {
		logger.Error("seed_member_membership_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// An admin whose email is deliberately UNVERIFIED (no MarkEmailVerified): the
	// UI must hide mutating controls for them (server would 403 email_not_verified)
	// even though their role grants member:invite/manage. Can still log in
	// (login is allowed unverified) so the gate is testable.
	unverifiedAdminID := uuid.MustParse(seeddata.DemoUnverifiedAdminUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: unverifiedAdminID, Email: seeddata.DemoUnverifiedAdminEmail, Name: seeddata.DemoUnverifiedAdminName,
		CpAdmin: false,
	}); err != nil {
		logger.Error("seed_uadmin_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	uaphc, err := password.Hash(seeddata.DemoUnverifiedAdminPassword)
	if err != nil {
		logger.Error("seed_uadmin_hash_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: unverifiedAdminID, PasswordHash: &uaphc}); err != nil {
		logger.Error("seed_uadmin_password_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if _, err := q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{
		OrgID: orgID, UserID: unverifiedAdminID, Role: "admin",
	}); err != nil {
		logger.Error("seed_uadmin_membership_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// A VERIFIED user with NO membership — the fresh-signup state the onboarding
	// funnel targets (S4.7). In the open edition the demo org already occupies the
	// single-org slot, so this user's create-org attempt is refused
	// (org_limit_reached) and the UI lands on the invitation-only card; routing +
	// cap are thus testable against the REAL API, not a mock.
	noOrgID := uuid.MustParse(seeddata.DemoNoOrgUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: noOrgID, Email: seeddata.DemoNoOrgEmail, Name: seeddata.DemoNoOrgName,
		CpAdmin: false,
	}); err != nil {
		logger.Error("seed_noorg_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	noorgPHC, err := password.Hash(seeddata.DemoNoOrgPassword)
	if err != nil {
		logger.Error("seed_noorg_hash_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: noOrgID, PasswordHash: &noorgPHC}); err != nil {
		logger.Error("seed_noorg_password_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// Verified so the funnel routes them to /create-org (the verified branch), and
	// deliberately given NO membership (no UpsertMembership).
	if err := q.MarkEmailVerified(ctx, noOrgID); err != nil {
		logger.Error("seed_noorg_verify_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ── THE CROSS-TENANT FIXTURE (S12.11) ─────────────────────────────────────────────────────────────
	//
	// ⛔ THE DEMO OWNER CANNOT DEMONSTRATE THIS SURFACE. They hold `cp_admin` and belong to the demo org,
	// so every grant they make is an ordinary in-tenant act. The property S12.11 exists for — acting on an
	// organization you are NOT a member of — needs a holder on the outside and an organization on the far
	// side of the boundary. Both are seeded here; neither is a member of the other's world.
	// ⚠ THE CAPABILITY IS WRITTEN AS A LITERAL AT EVERY CALL SITE, NEVER PASSED THROUGH A HELPER
	// PARAMETER. `TestSeedStatesOrgCreationCapability` reads this FILE — that is the whole design, because
	// a database query would pass on the rig where migration 0073 already backfilled — and a helper taking
	// `cpAdmin bool` would hide the fact from the only reader that can answer for a fresh install.
	credential := func(id uuid.UUID, email, pw string, verified bool) {
		h, err := password.Hash(pw)
		if err != nil {
			logger.Error("seed_hash_failed", slog.String("email", email), slog.String("error", err.Error()))
			os.Exit(1)
		}
		if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: id, PasswordHash: &h}); err != nil {
			logger.Error("seed_password_failed", slog.String("email", email), slog.String("error", err.Error()))
			os.Exit(1)
		}
		if verified {
			if err := q.MarkEmailVerified(ctx, id); err != nil {
				logger.Error("seed_verify_failed", slog.String("email", email), slog.String("error", err.Error()))
				os.Exit(1)
			}
		}
	}

	// ⚠ THE SECOND HOLDER, AND IT IS A MEMBER OF NOTHING. This is what a real install actually mints at
	// bootstrap: an administrator of the DEPLOYMENT who has joined no tenant.
	cpAdminID := uuid.MustParse(seeddata.DemoCPAdminUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: cpAdminID, Email: seeddata.DemoCPAdminEmail, Name: seeddata.DemoCPAdminName,
		CpAdmin: true,
	}); err != nil {
		logger.Error("seed_cpadmin_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	credential(cpAdminID, seeddata.DemoCPAdminEmail, seeddata.DemoCPAdminPassword, true)

	// A verified account with no membership, existing only to be granted one across the boundary.
	// ⛔ NOT the no-org onboarding fixture: that one models an account awaiting an invitation, and giving
	// it a membership would delete the state onboarding.spec.ts drives to the invitation card.
	granteeID := uuid.MustParse(seeddata.DemoGranteeUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: granteeID, Email: seeddata.DemoGranteeEmail, Name: seeddata.DemoGranteeName,
		CpAdmin: false,
	}); err != nil {
		logger.Error("seed_grantee_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	credential(granteeID, seeddata.DemoGranteeEmail, seeddata.DemoGranteePassword, true)

	sandboxOrgID := uuid.MustParse(seeddata.DemoSandboxOrgID)
	if _, err := q.UpsertOrganization(ctx, sqlc.UpsertOrganizationParams{
		ID: sandboxOrgID, Name: seeddata.DemoSandboxOrgName, Slug: seeddata.DemoSandboxOrgSlug,
	}); err != nil {
		logger.Error("seed_sandbox_org_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// ⚠ ITS OWNER IS A SEPARATE ACCOUNT ON PURPOSE. Making the demo owner a member of both would change
	// what every existing spec's org switcher renders — a fixture addition is not licensed to alter the
	// state other specs were written against.
	sandboxOwnerID := uuid.MustParse(seeddata.DemoSandboxOwnerUserID)
	if _, err := q.UpsertUser(ctx, sqlc.UpsertUserParams{
		ID: sandboxOwnerID, Email: seeddata.DemoSandboxOwnerEmail, Name: seeddata.DemoSandboxOwnerName,
		CpAdmin: false,
	}); err != nil {
		logger.Error("seed_sandbox_user_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	credential(sandboxOwnerID, seeddata.DemoSandboxOwnerEmail, seeddata.DemoSandboxOwnerPassword, true)
	if _, err := q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{
		OrgID: sandboxOrgID, UserID: sandboxOwnerID, Role: "owner",
	}); err != nil {
		logger.Error("seed_sandbox_membership_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("seed_complete",
		slog.String("demo_org_id", seeddata.DemoOrgID),
		slog.String("demo_owner_email", seeddata.DemoOwnerEmail),
		slog.String("sandbox_org_id", seeddata.DemoSandboxOrgID),
		slog.String("cp_admin_email", seeddata.DemoCPAdminEmail),
	)
}

func tableExists(ctx context.Context, pool *pgxpool.Pool, name string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM information_schema.tables
		   WHERE table_schema = 'public' AND table_name = $1
		 )`, name).Scan(&exists)
	return exists, err
}

// countRealOrgs counts LIVE organizations that are not the fixed demo org.
// Soft-deleted orgs are excluded — they are not "real data" for the guard, and
// counting them would wrongly block a reseed after demo data was deleted.
func countRealOrgs(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var n int64
	// ⛔ BOTH SEEDED ORGS ARE EXCLUDED, OR THE SEED REFUSES TO RE-RUN AFTER ITS OWN FIRST RUN. The guard
	// asks "does this database hold REAL data" — a fixture row this seeder wrote is not real data, and
	// leaving the sandbox org out of the list would have made `make seed` idempotent exactly once.
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM organizations WHERE id <> $1 AND id <> $2 AND deleted_at IS NULL`,
		seeddata.DemoOrgID, seeddata.DemoSandboxOrgID).Scan(&n)
	return n, err
}
