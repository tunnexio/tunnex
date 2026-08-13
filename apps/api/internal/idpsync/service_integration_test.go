package idpsync_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsync"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsyncspec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type nopPusher struct{ calls int }

func (p *nopPusher) PushOrgNodes(context.Context, uuid.UUID) { p.calls++ }

type nopDeprov struct{}

func (nopDeprov) DeactivateForSync(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return true, nil
}
func (nopDeprov) RevokeOrgAccess(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return true, nil
}

type recordingDeprov struct{ calls int }

func (d *recordingDeprov) DeactivateForSync(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return false, nil
}
func (d *recordingDeprov) RevokeOrgAccess(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	d.calls++
	return true, nil
}

func testSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	s, err := crypto.NewSealer(make([]byte, 32)) // all-zero key is fine for a test
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func newService(t *testing.T, pool *pgxpool.Pool) *idpsync.Service {
	return idpsync.NewService(pool, testSealer(t), &nopPusher{}, nopDeprov{}, testLogger())
}

// D1 refuse-unless-empty: a POPULATED manual group cannot be converted to directory sync. This is
// the app-layer half of disjointness the schema CHECK can't express (it can't see member count).
func TestMapGroup_RefusesPopulatedManualGroup(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()
	grp := uuid.New()
	exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, org, "o-"+org.String()[:8])
	exec(t, pool, `INSERT INTO users (id,email,name) VALUES ($1,$2,'u')`, user, user.String()[:8]+"@t.io")
	exec(t, pool, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, user)
	exec(t, pool, `INSERT INTO user_groups (id,org_id,name,origin) VALUES ($1,$2,'eng','manual')`, grp, org)
	exec(t, pool, `INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,'manual')`, org, grp, user)

	svc := newService(t, pool)
	mustConfig(t, svc, ctx, org)

	_, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "g-1", GroupID: &grp})
	if !hasCode(err, 409, "group_not_empty") {
		t.Fatalf("binding a populated manual group must be 409 group_not_empty, got %v", err)
	}

	// After emptying it, the same bind SUCCEEDS and flips origin to idp_sync.
	exec(t, pool, `DELETE FROM group_members WHERE org_id=$1 AND group_id=$2`, org, grp)
	g, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "g-1", GroupID: &grp})
	if err != nil {
		t.Fatalf("binding an EMPTY manual group must succeed, got %v", err)
	}
	if g.Origin != "idp_sync" || g.IdpProvider == nil || *g.IdpProvider != "microsoft" || g.IdpGroupID == nil || *g.IdpGroupID != "g-1" {
		t.Fatalf("bound group not flipped to idp_sync/microsoft/g-1: %+v", g)
	}

	// A second bind of the now-synced group is refused (already directory-managed).
	if _, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "g-2", GroupID: &grp}); !hasCode(err, 409, "group_already_synced") {
		t.Fatalf("re-binding a synced group must be 409 group_already_synced, got %v", err)
	}
}

// Creating a fresh idp_sync group works and the same (provider,idp_group_id) can't be mapped twice.
func TestMapGroup_CreateAndDuplicate(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org := uuid.New()
	exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, org, "o-"+org.String()[:8])
	svc := newService(t, pool)
	mustConfig(t, svc, ctx, org)

	if _, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "grp-eng", Name: "Engineering"}); err != nil {
		t.Fatalf("create idp_sync group: %v", err)
	}
	if _, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "grp-eng", Name: "Dup"}); !hasCode(err, 409, "conflict") {
		t.Fatalf("mapping the same directory group twice must 409, got %v", err)
	}
}

// D1 other half: an idp_sync group's membership is reconciler-owned, so a MANUAL add/remove is
// refused (409). Together with refuse-unless-empty this makes manual and idp origins disjoint at
// the app layer, above the schema CHECK.
func TestManualEditOfSyncedGroupRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, org, "o-"+org.String()[:8])
	exec(t, pool, `INSERT INTO users (id,email,name) VALUES ($1,$2,'u')`, user, user.String()[:8]+"@t.io")
	exec(t, pool, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, user)

	svc := newService(t, pool)
	mustConfig(t, svc, ctx, org)
	g, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "grp-eng", Name: "Engineering"})
	if err != nil {
		t.Fatalf("create synced group: %v", err)
	}

	psvc := policy.NewService(pool)
	if err := psvc.AddGroupMember(ctx, org, g.ID, user); !hasCode(err, 409, "idp_managed_group") {
		t.Fatalf("manual AddGroupMember on a synced group must 409 idp_managed_group, got %v", err)
	}
	if err := psvc.RemoveGroupMember(ctx, org, g.ID, user); !hasCode(err, 409, "idp_managed_group") {
		t.Fatalf("manual RemoveGroupMember on a synced group must 409 idp_managed_group, got %v", err)
	}
}

func mustConfig(t *testing.T, svc *idpsync.Service, ctx context.Context, org uuid.UUID) {
	t.Helper()
	if _, err := svc.UpsertConfig(ctx, org, "microsoft", idpsyncspec.ConfigInput{
		ClientID: "cid", ClientSecret: "sec", TenantID: "tid", Enabled: true,
	}); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
}

func exec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func hasCode(err error, status int, code string) bool {
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == status && ae.Code == code
}

type firstSaveProvider struct{ members []idpsync.DirectoryMember }

func (p firstSaveProvider) ListGroupMembers(context.Context, string) ([]idpsync.DirectoryMember, error) {
	return p.members, nil
}
func (p firstSaveProvider) ResolveUserStatus(context.Context, string) (idpsync.UserStatus, error) {
	return idpsync.StatusActive, nil
}

// TestFirstSaveMapAndTrigger exercises the exact operator sequence that differs
// from credential replacement: initial PUT, map, then immediate Sync now.
func TestFirstSaveMapAndTrigger(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, org, "o-"+org.String()[:8])
	exec(t, pool, `INSERT INTO users (id,email,name) VALUES ($1,$2,'u')`, user, user.String()[:8]+"@t.io")
	exec(t, pool, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, user)
	svc := newService(t, pool)
	svc.SetProviderFactory(func(sqlc.IdpSyncConfig, string) (idpsync.DirectoryProvider, error) {
		return firstSaveProvider{members: []idpsync.DirectoryMember{{ExternalID: "ext", Email: user.String()[:8] + "@t.io", Status: idpsync.StatusActive}}}, nil
	})
	if _, err := svc.UpsertConfig(ctx, org, "microsoft", idpsyncspec.ConfigInput{ClientID: "cid", ClientSecret: "secret", TenantID: "tenant", Enabled: true}); err != nil {
		t.Fatalf("initial credential save: %v", err)
	}
	if _, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "ext-group", Name: "Engineering"}); err != nil {
		t.Fatalf("map after first save: %v", err)
	}
	if _, err := svc.Trigger(ctx, org, "microsoft"); err != nil {
		t.Fatalf("immediate Sync now after first save: %v", err)
	}
}

func TestIdpAccessProvenanceOnlySourceAndPreservation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, otherOrg, user, groupA, groupB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, pair := range []struct {
		id   uuid.UUID
		slug string
	}{{org, "a"}, {otherOrg, "b"}} {
		exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, pair.id, pair.slug+"-"+pair.id.String()[:8])
	}
	exec(t, pool, `INSERT INTO users (id,email,name) VALUES ($1,$2,'u')`, user, user.String()[:8]+"@t.io")
	for _, oid := range []uuid.UUID{org, otherOrg} {
		exec(t, pool, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, oid, user)
	}
	for _, gid := range []uuid.UUID{groupA, groupB} {
		exec(t, pool, `INSERT INTO user_groups (id,org_id,name,origin,idp_provider,idp_group_id) VALUES ($1,$2,$3,'idp_sync','microsoft',$4)`, gid, org, "g-"+gid.String()[:8], gid.String())
	}
	deprov := &recordingDeprov{}
	svc := idpsync.NewService(pool, testSealer(t), &nopPusher{}, deprov, testLogger())
	// Only-source removal revokes this org, while the other org remains untouched.
	exec(t, pool, `DELETE FROM membership_access_sources WHERE org_id=$1 AND user_id=$2`, org, user)
	exec(t, pool, `INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,'idp_sync')`, org, groupA, user)
	if _, err := svc.AddIdpGroupMember(ctx, org, groupA, user, "ext"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RemoveIdpGroupMember(ctx, org, groupA, user); err != nil {
		t.Fatal(err)
	}
	if deprov.calls != 1 {
		t.Fatalf("only-source removal must revoke once, got %d", deprov.calls)
	}
	// A second mapped group preserves access and is idempotent on repeated removal.
	exec(t, pool, `UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, org, user)
	exec(t, pool, `INSERT INTO membership_access_sources (org_id,user_id,source_type,source_key) VALUES ($1,$2,'idp_sync',$3)`, org, user, groupA.String())
	exec(t, pool, `INSERT INTO membership_access_sources (org_id,user_id,source_type,source_key) VALUES ($1,$2,'idp_sync',$3)`, org, user, groupB.String())
	exec(t, pool, `INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,'idp_sync')`, org, groupB, user)
	if _, err := svc.RemoveIdpGroupMember(ctx, org, groupB, user); err != nil {
		t.Fatal(err)
	}
	if deprov.calls != 1 {
		t.Fatalf("multiple-source removal must preserve access, got %d revocations", deprov.calls)
	}
	if _, err := svc.RemoveIdpGroupMember(ctx, org, groupB, user); err != nil {
		t.Fatal(err)
	}
	if deprov.calls != 1 {
		t.Fatalf("repeated removal must be idempotent, got %d revocations", deprov.calls)
	}
	var revoked *time.Time
	if err := pool.QueryRow(ctx, `SELECT access_revoked_at FROM memberships WHERE org_id=$1 AND user_id=$2`, otherOrg, user).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != nil {
		t.Fatal("other organization membership must remain active")
	}
}

// TestUnmapWritesAnAuditRow pins the first of the two destructive-and-silent verbs (S14.15).
//
// ⛔ UnmapGroup DELETES EVERY MEMBER of a group and pushes org-wide, and it wrote NO audit row —
// while its siblings (`UpsertConfig`, the reconciler's own membership writes) all audit normally.
// An access-affecting deletion with no record that a human did it, on the surface that decides who
// can reach what. The 204 carries no body either, so before this there was no trace anywhere.
func TestUnmapWritesAnAuditRow(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org, actor, member := uuid.New(), uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO organizations (id,name,slug) VALUES ($1,'o',$2)`, org, "o-"+org.String()[:8])
	for _, u := range []uuid.UUID{actor, member} {
		exec(t, pool, `INSERT INTO users (id,email,name) VALUES ($1,$2,'u')`, u, u.String()[:8]+"@t.io")
		exec(t, pool, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, u)
	}
	svc := newService(t, pool)
	if _, err := svc.UpsertConfig(ctx, org, "microsoft", idpsyncspec.ConfigInput{
		ClientID: "c", ClientSecret: "s", TenantID: "t", Enabled: true,
	}); err != nil {
		t.Fatalf("config: %v", err)
	}
	g, err := svc.MapGroup(ctx, org, "microsoft", idpsyncspec.MapInput{IdpGroupID: "grp-1", Name: "Eng"})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	// TWO members, so the recorded count is a real number and not incidentally right at 0 or 1.
	exec(t, pool, `INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,'idp_sync')`, org, g.ID, actor)
	exec(t, pool, `INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,'idp_sync')`, org, g.ID, member)

	if err := svc.UnmapGroup(ctx, org, "microsoft", g.ID); err != nil {
		t.Fatalf("unmap: %v", err)
	}

	var n int
	var meta string
	if err := pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(metadata::text),'') FROM audit_logs
		   WHERE org_id = $1 AND action = 'idp_sync.group_unmapped'`, org).Scan(&n, &meta); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if n != 1 {
		t.Fatalf("un-mapping must leave exactly ONE audit row, got %d", n)
	}
	// ⛔ THE SERVER'S OWN COUNT, taken inside the same transaction as the delete. The response body
	// is empty, so this row is the only place the blast radius is ever stated.
	// Read the VALUE out of the jsonb rather than substring-matching the rendered text: postgres
	// prints `"members_removed": 2` WITH a space, so a literal `"members_removed":2` match fails on
	// a correct row. Second time a matcher of mine has been defeated by the format it scans.
	var removed int
	if err := pool.QueryRow(ctx,
		`SELECT (metadata->>'members_removed')::int FROM audit_logs
		   WHERE org_id = $1 AND action = 'idp_sync.group_unmapped'`, org).Scan(&removed); err != nil {
		t.Fatalf("metadata read: %v", err)
	}
	if removed != 2 {
		t.Fatalf("the audit row must record how many members were removed; want 2, got %d (meta=%s)", removed, meta)
	}
}
