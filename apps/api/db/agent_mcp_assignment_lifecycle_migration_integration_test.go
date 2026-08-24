package db_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestAgentMCPAssignmentLifecycleMigrationPostgres proves 0109 against a
// disposable database only. It deliberately seeds the two ambiguity shapes
// that 0108 allowed: duplicate rows on one empty group and one device reached
// through two groups (including the same profile twice).
func TestAgentMCPAssignmentLifecycleMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0109 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s18_mcp_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	u := *base
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 108); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	otherOrg, otherUser, otherNode := uuid.New(), uuid.New(), uuid.New()
	groupEmpty, groupA, groupB, groupSame, groupValid := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	profileA, profileB, profileValid, otherProfile := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	otherGroup := uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S18 MCP',$2,'10.240.0.0/24')`, org, "s18-mcp-"+org.String()[:8])
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, user, "s18-"+user.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, user)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gw',$3)`, node, org, "s18-"+node.String())
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S18 MCP other',$2,'10.241.0.0/24')`, otherOrg, "s18-mcp-"+otherOrg.String()[:8])
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, otherUser, "s18-"+otherUser.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, otherOrg, otherUser)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gw',$3)`, otherNode, otherOrg, "s18-"+otherNode.String())
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,'agent',$5,'10.240.0.2','active','agent')`, device, org, user, node, "s18-"+device.String())
	for _, group := range []uuid.UUID{groupEmpty, groupA, groupB, groupSame, groupValid} {
		exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,$3)`, group, org, "g-"+group.String()[:8])
	}
	exec(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4),($1,$5,$3,$4),($1,$6,$3,$4)`, org, groupA, device, user, groupB, groupSame)
	for _, profile := range []uuid.UUID{profileA, profileB, profileValid} {
		exec(`INSERT INTO agent_mcp_profiles(id,org_id,name,endpoint) VALUES($1,$2,$3,$4)`, profile, org, "p-"+profile.String()[:8], "https://mcp.example/"+profile.String()[:8])
	}
	exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,'same-looking-group')`, otherGroup, otherOrg)
	exec(`INSERT INTO agent_mcp_profiles(id,org_id,name,endpoint) VALUES($1,$2,'same-looking-profile','https://mcp.example/other')`, otherProfile, otherOrg)
	// Simulate legacy/imported 0108 rows that predate or bypassed its advisory
	// trigger. 0109 must fail closed for those persisted ambiguity classes,
	// rather than assuming every historical row was written by today's path.
	exec(`DROP TRIGGER agent_mcp_profile_assignment_one_per_agent ON agent_mcp_profile_assignments`)
	exec(`DROP TRIGGER agent_mcp_profile_member_one_per_agent ON agent_group_members`)
	// Empty-group duplicate plus one populated agent inheriting two different
	// profiles through two groups. The other organization is intentionally an
	// identical-looking but unambiguous singleton.
	exec(`INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3),($1,$4,$3),($1,$2,$5),($1,$4,$6),($1,$2,$7),($1,$8,$9)`, org, profileA, groupEmpty, profileB, groupA, groupB, groupSame, profileValid, groupValid)
	exec(`INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3)`, otherOrg, otherProfile, otherGroup)
	if err := db.MigrateTo(u.String(), 109); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_profile_assignments WHERE org_id=$1 AND state='active'`, org).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("unambiguous singleton must remain active, active=%d", active)
	}
	var quarantined int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_profile_assignments WHERE org_id=$1 AND state='quarantined' AND quarantine_reason='legacy_mcp_assignment_ambiguity'`, org).Scan(&quarantined); err != nil {
		t.Fatal(err)
	}
	if quarantined != 5 {
		t.Fatalf("want all provenance rows quarantined, got %d", quarantined)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND actor_system='migration:0109' AND action='agent_mcp_profile.ambiguity_quarantined' AND metadata->>'cause'='legacy_mcp_assignment_ambiguity'`, org).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 4 {
		t.Fatalf("want one migration audit per quarantined group, got %d", audits)
	}
	var otherActive, otherAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_mcp_profile_assignments WHERE org_id=$1 AND state='active'`, otherOrg).Scan(&otherActive); err != nil {
		t.Fatal(err)
	}
	if otherActive != 1 {
		t.Fatalf("Org B singleton must remain active, active=%d", otherActive)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='agent_mcp_profile.ambiguity_quarantined'`, otherOrg).Scan(&otherAudits); err != nil {
		t.Fatal(err)
	}
	if otherAudits != 0 {
		t.Fatalf("Org A ambiguity must not audit Org B, audits=%d", otherAudits)
	}

	// The partial index permits retained history but never a second active row
	// for a group. Once an assignment is ended, atomic replacement has room to
	// create exactly one new active assignment.
	replacementProfile := uuid.New()
	exec(`INSERT INTO agent_mcp_profiles(id,org_id,name,endpoint) VALUES($1,$2,'replacement','https://mcp.example/replacement')`, replacementProfile, org)
	if _, err := pool.Exec(ctx, `INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3)`, org, replacementProfile, groupValid); err == nil {
		t.Fatal("second active assignment on one group must fail")
	}
	exec(`UPDATE agent_mcp_profile_assignments SET state='unassigned', ended_at=now() WHERE org_id=$1 AND agent_group_id=$2 AND state='active'`, org, groupValid)
	exec(`INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3)`, org, replacementProfile, groupValid)
	var activeReplacement, historical int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='active'), count(*) FILTER (WHERE state='unassigned') FROM agent_mcp_profile_assignments WHERE org_id=$1 AND agent_group_id=$2`, org, groupValid).Scan(&activeReplacement, &historical); err != nil {
		t.Fatal(err)
	}
	if activeReplacement != 1 || historical != 1 {
		t.Fatalf("replacement must preserve one history row and one active row, active=%d history=%d", activeReplacement, historical)
	}
	if err := db.DownOne(u.String()); err == nil {
		t.Fatal("0109 down must refuse lifecycle history loss")
	}
}

// TestAgentMCPAssignmentLifecycleMigrationFreshChain proves a clean database
// can take the full migration chain through 0109 and cleanly return to 0108
// before lifecycle state is used. It also proves archival state blocks a
// rollback rather than erasing historical meaning.
func TestAgentMCPAssignmentLifecycleMigrationFreshChain(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0109 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s18_mcp_clean_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	u := *base
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 109); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(u.String()); err != nil {
		t.Fatalf("clean 0109 down must succeed: %v", err)
	}
	version, dirty, ok, err := db.Version(u.String())
	if err != nil || !ok || dirty || version != 108 {
		t.Fatalf("clean down must return to 0108, version=%d dirty=%v ok=%v err=%v", version, dirty, ok, err)
	}
	if err := db.MigrateTo(u.String(), 109); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	org, profile := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S18 archive',$2,'10.242.0.0/24')`, org, "s18-archive-"+org.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_mcp_profiles(id,org_id,name,endpoint,archived_at) VALUES($1,$2,'archived','https://mcp.example/archive',now())`, profile, org); err != nil {
		t.Fatal(err)
	}
	if err := db.DownOne(u.String()); err == nil {
		t.Fatal("0109 down must refuse archived profile state loss")
	}
}

// TestAgentMCPAssignmentLifecycleConcurrencyPostgres uses independent
// transactions with bounded deadlines. It proves advisory-lock serialization
// for every write direction rather than trusting a SELECT-only trigger.
func TestAgentMCPAssignmentLifecycleConcurrencyPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0109 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s18_mcp_race_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	u := *base
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), 109); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'S18 race',$2,'10.243.0.0/24')`, org, "s18-race-"+org.String()[:8])
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, user, "s18-race-"+user.String()[:8]+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, user)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gw',$3)`, node, org, "s18-race-"+node.String())
	nextIP := 10
	newDevice := func(name string) uuid.UUID {
		id := uuid.New()
		ip := fmt.Sprintf("10.243.0.%d", nextIP)
		nextIP++
		exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,$5,$6,$7,'active','agent')`, id, org, user, node, name, "s18-race-"+id.String(), ip)
		return id
	}
	newGroup := func(name string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,$3)`, id, org, name)
		return id
	}
	newProfile := func(name string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO agent_mcp_profiles(id,org_id,name,endpoint) VALUES($1,$2,$3,$4)`, id, org, name, "https://mcp.example/"+id.String())
		return id
	}
	runTwo := func(t *testing.T, writeA, writeB func(context.Context) error) []error {
		t.Helper()
		raceCtx, raceCancel := context.WithTimeout(ctx, 8*time.Second)
		defer raceCancel()
		start := make(chan struct{})
		results := make([]error, 2)
		var wg sync.WaitGroup
		for i, write := range []func(context.Context) error{writeA, writeB} {
			wg.Add(1)
			go func(i int, write func(context.Context) error) {
				defer wg.Done()
				<-start
				results[i] = write(raceCtx)
			}(i, write)
		}
		close(start)
		wg.Wait()
		if raceCtx.Err() != nil {
			t.Fatalf("race must not deadlock: %v", raceCtx.Err())
		}
		return results
	}
	writeAssignment := func(group, profile uuid.UUID) func(context.Context) error {
		return func(writeCtx context.Context) error {
			tx, err := pool.Begin(writeCtx)
			if err != nil {
				return err
			}
			defer tx.Rollback(writeCtx)
			if _, err := tx.Exec(writeCtx, `INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3)`, org, profile, group); err != nil {
				return err
			}
			return tx.Commit(writeCtx)
		}
	}
	writeMember := func(group, device uuid.UUID) func(context.Context) error {
		return func(writeCtx context.Context) error {
			tx, err := pool.Begin(writeCtx)
			if err != nil {
				return err
			}
			defer tx.Rollback(writeCtx)
			if _, err := tx.Exec(writeCtx, `INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4)`, org, group, device, user); err != nil {
				return err
			}
			return tx.Commit(writeCtx)
		}
	}
	assertOneConflict := func(t *testing.T, results []error) {
		t.Helper()
		successes := 0
		for _, err := range results {
			if err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("want exactly one committing write, results=%v", results)
		}
		for _, err := range results {
			if err == nil {
				continue
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || (pgErr.Code != "23505" && pgErr.Code != "P0001") {
				t.Fatalf("losing write must be classified conflict, err=%v", err)
			}
		}
	}

	// Assignment racing another assignment: the active-only group index admits
	// one winner and preserves the loser as a classified conflict.
	raceGroup := newGroup("assignment-race")
	assertOneConflict(t, runTwo(t, writeAssignment(raceGroup, newProfile("assignment-race-a")), writeAssignment(raceGroup, newProfile("assignment-race-b"))))

	// Assignment racing member add: the device already inherits one profile.
	// Depending on scheduling, either the assignment or member write wins; both
	// cannot commit because either would create multiple effective profiles.
	deviceA := newDevice("assignment-member-race")
	baseGroup, targetGroup := newGroup("base"), newGroup("target")
	exec(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4)`, org, baseGroup, deviceA, user)
	exec(`INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3)`, org, newProfile("base-profile"), baseGroup)
	assertOneConflict(t, runTwo(t, writeAssignment(targetGroup, newProfile("target-profile")), writeMember(targetGroup, deviceA)))

	// Two membership writes race for groups that each carry a different active
	// profile. The per-device advisory lock serializes them and one loses.
	deviceB := newDevice("member-member-race")
	memberGroupA, memberGroupB := newGroup("member-a"), newGroup("member-b")
	exec(`INSERT INTO agent_mcp_profile_assignments(org_id,profile_id,agent_group_id) VALUES($1,$2,$3),($1,$4,$5)`, org, newProfile("member-profile-a"), memberGroupA, newProfile("member-profile-b"), memberGroupB)
	assertOneConflict(t, runTwo(t, writeMember(memberGroupA, deviceB), writeMember(memberGroupB, deviceB)))

	var multiEffective int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT m.device_id FROM agent_group_members m JOIN agent_mcp_profile_assignments a ON a.org_id=m.org_id AND a.agent_group_id=m.agent_group_id AND a.state='active' WHERE m.org_id=$1 GROUP BY m.device_id HAVING count(*) > 1) invalid`, org).Scan(&multiEffective); err != nil {
		t.Fatal(err)
	}
	if multiEffective != 0 {
		t.Fatalf("no agent may end with multiple effective assignments, got %d", multiEffective)
	}
}
