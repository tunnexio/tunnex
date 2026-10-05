package sandboxes

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

type fixture struct {
	ctx                                        context.Context
	pool                                       *pgxpool.Pool
	store                                      *Store
	org, user, other, template, resource, node uuid.UUID
	sshPublicKey                               string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx, pool := fixtureTemplate.New(t)
	f := fixture{ctx, pool, NewStore(pool), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), publicTerminalKey(t)}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,sandboxes_enabled) VALUES($1,'sandbox feature',$2,'10.99.0.0/24','enforcing',true)`, f.org, f.org.String())
	for _, id := range []uuid.UUID{f.user, f.other} {
		exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'member',now())`, id, id.String()+"@example.test")
		exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, id)
	}
	exec(`INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'terminal',$3,'[{"cidr":"10.1.0.0/16","protocol":"any","port_low":0,"port_high":0}]',256,3600,true)`, f.template, f.org, "sha256:"+strings.Repeat("a", 64))
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high) VALUES($1,$2,'private','10.1.0.0/16','tcp',22,22)`, f.resource, f.org)
	exec(`INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES($1,'user',$2,'resource',$3)`, f.org, f.user, f.resource)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'gateway',$3)`, f.node, f.org, f.node.String())
	return f
}
func (f fixture) input(key string) CreateInput {
	return CreateInput{TemplateID: f.template, Name: "work", Requested: []Scope{{CIDR: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}}, TTLSeconds: 3600, IdempotencyKey: key, SSHPublicKeys: []string{f.sshPublicKey}}
}

func TestSandboxStorePostgresAuthorizationIdempotencyAndQuota(t *testing.T) {
	f := newFixture(t)
	in := f.input("one")
	type result struct {
		s      Sandbox
		replay bool
		err    error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(2)
	for range 2 {
		go func() {
			start.Done()
			start.Wait()
			s, r, e := f.store.Create(f.ctx, f.org, f.user, in)
			results <- result{s, r, e}
		}()
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.s.Identity.ID != b.s.Identity.ID || a.replay == b.replay {
		t.Fatalf("idempotency failed: %+v %+v", a, b)
	}
	if _, err := f.store.Get(f.ctx, f.org, f.other, a.s.Identity.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nonowner read: %v", err)
	}
	if _, err := f.store.Get(f.ctx, uuid.New(), f.user, a.s.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross org read: %v", err)
	}
	changed := in
	changed.Name = "different"
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatch replay: %v", err)
	}
	outside := f.input("outside")
	outside.Requested[0].CIDR = "10.2.0.0/16"
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, outside); err == nil {
		t.Fatal("outside scope admitted")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET max_sandboxes_per_user=2 WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	results = make(chan result, 2)
	start.Add(2)
	for _, key := range []string{"two", "three"} {
		go func(key string) {
			start.Done()
			start.Wait()
			s, r, e := f.store.Create(f.ctx, f.org, f.user, f.input(key))
			results <- result{s, r, e}
		}(key)
	}
	a, b = <-results, <-results
	if (a.err == nil) == (b.err == nil) || (!errors.Is(a.err, ErrQuota) && !errors.Is(b.err, ErrQuota)) {
		t.Fatalf("quota race failed: %v %v", a.err, b.err)
	}
	var existing Sandbox
	if a.err == nil {
		existing = a.s
	} else {
		existing = b.s
	}
	stopped, err := f.store.SetDesired(f.ctx, f.org, f.user, existing.Identity.ID, existing.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, existing.Identity.ID, existing.Revision, "started"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation accepted: %v", err)
	}
	deleted, err := f.store.SetDesired(f.ctx, f.org, f.user, existing.Identity.ID, stopped.Revision, "deleted")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, existing.Identity.ID, deleted.Revision, "started"); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending deletion resurrected: %v", err)
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Get(f.ctx, f.org, f.user, existing.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removed member reads: %v", err)
	}
}

func TestSandboxStorePostgresPeerBindingAndPolicyWithdrawal(t *testing.T) {
	f := newFixture(t)
	created, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET creator_id=$2 WHERE id=$1`, created.Identity.ID, f.other); err == nil {
		t.Fatal("creator mutable")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET maximum_scope='[]' WHERE id=$1`, f.template); err == nil {
		t.Fatal("template cap mutable")
	}
	peer := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'sandbox',$5,'10.99.0.4','sandbox')`, peer, f.org, f.user, f.node, peer.String()); err == nil {
		t.Fatal("unbound peer accepted")
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'sandbox',$5,'10.99.0.4','sandbox')`, peer, f.org, f.user, f.node, peer.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE sandboxes SET peer_id=$2 WHERE id=$1`, created.Identity.ID, peer); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE devices SET kind='agent' WHERE id=$1`, peer); err == nil {
		t.Fatal("bound sandbox retyped agent")
	}
	check := func(want int) {
		t.Helper()
		snapshot, e := policy.BuildSnapshotWithQueries(f.ctx, sqlc.New(f.pool), f.org)
		if e != nil {
			t.Fatal(e)
		}
		if got := len(policy.Compile(snapshot)[f.node].Allow); got != want {
			t.Fatalf("policy allows=%d want %d", got, want)
		}
	}
	// The same real peer participates in enforcement but never in human/agent rosters.
	humans, e := sqlc.New(f.pool).ListDevicesByOrg(f.ctx, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if len(humans) != 0 {
		t.Fatal("sandbox appears in human device roster")
	}
	agents, e := sqlc.New(f.pool).ListAgentsForOrg(f.ctx, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if len(agents) != 0 {
		t.Fatal("sandbox appears in AI Agent roster")
	}
	check(1)
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET enabled=false WHERE id=$1`, f.template); err != nil {
		t.Fatal(err)
	}
	check(0)
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, f.template); err != nil {
		t.Fatal(err)
	}
	check(1)
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM policy_rules WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	check(0)
}

func TestSandboxStorePostgresModeVerificationAndDowngrade(t *testing.T) {
	f := newFixture(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET email_verified_at=NULL WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("unverified")); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unverified creates: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET email_verified_at=now() WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("disabled")); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled creates: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	created, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("mode"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=false,zero_trust_mode='off' WHERE id=$1`, f.org); err == nil {
		t.Fatal("existing sandbox permits blanket mesh")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE memberships SET role='ai-view' WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Get(f.ctx, f.org, f.user, created.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("AI-only role reads: %v", err)
	}
}

func TestSandboxStorePostgresDowngradeRefusesState(t *testing.T) {
	f := newFixture(t)
	down, err := db.MigrationsFS.ReadFile("migrations/0181_sandboxes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	enrollmentDown, e := db.MigrationsFS.ReadFile("migrations/0182_sandbox_enrollment.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(enrollmentDown, down...)
	skillsDown, e := db.MigrationsFS.ReadFile("migrations/0183_sandbox_skills.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(skillsDown, down...)
	customDown, e := db.MigrationsFS.ReadFile("migrations/0184_sandbox_custom_skills.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(customDown, down...)
	runtimeDown, e := db.MigrationsFS.ReadFile("migrations/0185_sandbox_runtime_bindings.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(runtimeDown, down...)
	launchDown, e := db.MigrationsFS.ReadFile("migrations/0186_sandbox_launch_operations.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(launchDown, down...)
	withdrawalDown, e := db.MigrationsFS.ReadFile("migrations/0188_sandbox_network_withdrawals.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(withdrawalDown, down...)
	terminalDown, e := db.MigrationsFS.ReadFile("migrations/0189_sandbox_terminal_identities.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(terminalDown, down...)
	epochDown, e := db.MigrationsFS.ReadFile("migrations/0192_sandbox_start_epochs.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(epochDown, down...)
	delegationDown, e := db.MigrationsFS.ReadFile("migrations/0194_sandbox_delegation.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(delegationDown, down...)
	remoteRouteDown, e := db.MigrationsFS.ReadFile("migrations/0195_sandbox_remote_terminal_routes.down.sql")
	if e != nil {
		t.Fatal(e)
	}
	down = append(remoteRouteDown, down...)
	for _, name := range []string{"0196_sandbox_runner_enrollments.down.sql", "0197_sandbox_runner_qualification_trials.down.sql"} {
		extension, err := db.MigrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		down = append(extension, down...)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, string(down)); err == nil {
		tx.Rollback(f.ctx)
		t.Fatal("downgrade discarded template state")
	}
	if err = tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM sandbox_templates WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, string(down)); err != nil {
		tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	// Roll back the proof so test fixture remains fully migrated until cleanup.
	if err = tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
}
