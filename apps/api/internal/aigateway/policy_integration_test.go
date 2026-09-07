package aigateway

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type policyEngineFixture struct {
	mu           sync.Mutex
	keys         map[string]EngineKey
	active       map[string]bool
	models       map[string][]string
	fail         bool
	usage        float64
	beforeEnsure func()
}

func newPolicyEngineFixture() *policyEngineFixture {
	return &policyEngineFixture{keys: map[string]EngineKey{}, active: map[string]bool{}, models: map[string][]string{}}
}
func (e *policyEngineFixture) EnsureKey(_ context.Context, name, provider string, models, keyIDs []string) (EngineKey, error) {
	if e.beforeEnsure != nil {
		e.beforeEnsure()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return EngineKey{}, errors.New("private fixture failure")
	}
	if provider != "openrouter" || len(keyIDs) == 0 {
		return EngineKey{}, errors.New("bad fixture scope")
	}
	k, ok := e.keys[name]
	if !ok {
		k = EngineKey{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String(), Value: "sk-bf-" + uuid.NewString()}
		e.keys[name] = k
	}
	e.active[k.ID] = true
	e.models[k.ID] = slices.Clone(models)
	return k, nil
}
func (e *policyEngineFixture) DisableKey(_ context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return errors.New("private failure")
	}
	e.active[id] = false
	return nil
}
func (e *policyEngineFixture) Price(context.Context, string, string) (Price, error) {
	v := 0.0001
	return Price{Known: true, InputCostPerToken: &v, OutputCostPerToken: &v}, nil
}
func (e *policyEngineFixture) Usage(context.Context, []string, time.Time, time.Time) (Usage, error) {
	return Usage{TotalCost: e.usage}, nil
}

type policyFixture struct {
	*aiCredentialFixture
	policies *Policies
	engine   *policyEngineFixture
	team     uuid.UUID
}

func newPolicyFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *policyFixture {
	f := &policyFixture{aiCredentialFixture: newAICredentialFixture(t, ctx, pool), engine: newPolicyEngineFixture(), team: uuid.New()}
	f.enable()
	sealer, _ := crypto.NewSealer(bytes.Repeat([]byte{9}, 32))
	f.policies = NewPolicies(pool, sealer, f.engine)
	f.service.resolver = f.policies
	f.group(f.team)
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a", "openrouter/b"}, []string{"provider-key"}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, f.team, true, nil, 0); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *policyFixture) group(team uuid.UUID) {
	f.t.Helper()
	f.exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,$3)`, team, f.org, team.String())
	f.exec(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4)`, f.org, team, f.device, f.owner)
}
func (f *policyFixture) reconcile() Assignment {
	f.t.Helper()
	a, err := f.policies.Reconcile(f.ctx, f.org, f.device)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}
func (f *policyFixture) binding(team uuid.UUID) (string, int64) {
	f.t.Helper()
	var id string
	var rev int64
	if err := f.pool.QueryRow(f.ctx, `SELECT native_key_id,binding_revision FROM ai_gateway_key_bindings WHERE org_id=$1 AND device_id=$2 AND team_id=$3`, f.org, f.device, team).Scan(&id, &rev); err != nil {
		f.t.Fatal(err)
	}
	return id, rev
}

func TestAIPoliciesPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	t.Run("retained_binding_cap_refuses_without_history_purge", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		for i := 0; i < 63; i++ {
			team := uuid.New()
			f.group(team)
			if _, err := f.policies.PutTeam(ctx, f.org, f.owner, team, []string{"openrouter/a"}, []string{"provider-key"}, nil, 0); err != nil {
				t.Fatal(err)
			}
			f.exec(`INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,'fixture-never-opened',1)`, f.org, f.device, team, uuid.NewString())
		}
		if a := f.reconcile(); a.Status != "applied" {
			t.Fatal("64th binding refused")
		}
		newTeam := uuid.New()
		f.group(newTeam)
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, newTeam, []string{"openrouter/a"}, []string{"provider-key"}, nil, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, newTeam, true, nil, 1); err != nil {
			t.Fatal(err)
		}
		a, err := f.policies.Reconcile(ctx, f.org, f.device)
		var capError *apierr.Error
		if a.Status != "error" || !errors.As(err, &capError) || capError.Status != 429 {
			t.Fatal("65th retained binding accepted")
		}
		var count int
		if pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1`, f.org).Scan(&count) != nil || count != 64 {
			t.Fatal("history purged or cap exceeded")
		}
		if len(f.engine.keys) != 1 {
			t.Fatal("cap overflow created native key")
		}
	})
	t.Run("concurrent_org_cap_allows_exactly_one_binding", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		for range 63 {
			team := uuid.New()
			f.group(team)
			if _, err := f.policies.PutTeam(ctx, f.org, f.owner, team, []string{"openrouter/a"}, []string{"provider-key"}, nil, 0); err != nil {
				t.Fatal(err)
			}
			f.exec(`INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,'unused-fixture',1)`, f.org, f.device, team, uuid.NewString())
		}
		second := uuid.New()
		f.exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) SELECT $1,org_id,user_id,node_id,'second agent',$2,'active','agent' FROM devices WHERE id=$3`, second, second.String(), f.device)
		f.exec(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4)`, f.org, f.team, second, f.owner)
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, second, f.team, true, nil, 0); err != nil {
			t.Fatal(err)
		}
		type result struct {
			a   Assignment
			err error
		}
		results := make(chan result, 2)
		for _, device := range []uuid.UUID{f.device, second} {
			go func() { a, err := f.policies.Reconcile(ctx, f.org, device); results <- result{a, err} }()
		}
		applied, limited := 0, 0
		for range 2 {
			r := <-results
			if r.err == nil && r.a.Status == "applied" {
				applied++
				continue
			}
			var ae *apierr.Error
			if errors.As(r.err, &ae) && ae.Status == 429 && r.a.Status == "error" {
				limited++
				continue
			}
			t.Fatalf("unexpected reconcile result: %s %v", r.a.Status, r.err)
		}
		if applied != 1 || limited != 1 || len(f.engine.keys) != 1 {
			t.Fatal("org cap race created extra native key")
		}
		var count int
		if pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1`, f.org).Scan(&count) != nil || count != 64 {
			t.Fatal("org cap exceeded")
		}
	})
	t.Run("management_team_reconcile_stays_scoped", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		otherOrg := newPolicyFixture(t, ctx, pool)
		otherTeam, second := uuid.New(), uuid.New()
		f.group(otherTeam)
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, otherTeam, []string{"openrouter/a"}, []string{"provider-key"}, nil, 0); err != nil {
			t.Fatal(err)
		}
		f.exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) SELECT $1,org_id,user_id,node_id,'other agent',$2,'active','agent' FROM devices WHERE id=$3`, second, second.String(), f.device)
		f.exec(`INSERT INTO agent_group_members(org_id,agent_group_id,device_id,created_by_user_id) VALUES($1,$2,$3,$4)`, f.org, otherTeam, second, f.owner)
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, second, otherTeam, true, nil, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.policies.ReconcileTeam(ctx, f.org, f.team, 16); err != nil {
			t.Fatal(err)
		}
		var target, unrelated, foreign string
		for _, row := range []struct {
			org, device uuid.UUID
			dest        *string
		}{{f.org, f.device, &target}, {f.org, second, &unrelated}, {otherOrg.org, otherOrg.device, &foreign}} {
			if err := pool.QueryRow(ctx, `SELECT status FROM ai_gateway_assignments WHERE org_id=$1 AND device_id=$2`, row.org, row.device).Scan(row.dest); err != nil {
				t.Fatal(err)
			}
		}
		if target != "applied" || unrelated != "pending" || foreign != "pending" || len(f.engine.keys) != 1 {
			t.Fatal("management reconciliation crossed org/team boundary")
		}
	})
	t.Run("concurrent_team_compare_and_swap", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		results := make(chan error, 2)
		for range 2 {
			go func() {
				_, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{"provider-key"}, nil, 1)
				results <- err
			}()
		}
		wins := 0
		for range 2 {
			if <-results == nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("concurrent writers won %d times", wins)
		}
	})
	t.Run("team_write_waits_for_reconcile_then_invalidates_applied_revision", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		entered, release := make(chan struct{}), make(chan struct{})
		f.engine.beforeEnsure = func() { close(entered); <-release }
		reconciled := make(chan error, 1)
		go func() { _, err := f.policies.Reconcile(ctx, f.org, f.device); reconciled <- err }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("reconcile never entered engine")
		}
		written := make(chan error, 1)
		go func() {
			_, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/b"}, []string{"provider-key"}, nil, 1)
			written <- err
		}()
		wait, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		for {
			var blocked bool
			if err := pool.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%ai_gateway_team_policies%' AND query LIKE '%FOR UPDATE%')`).Scan(&blocked); err != nil {
				close(release)
				t.Fatal(err)
			}
			if blocked {
				break
			}
			select {
			case err := <-written:
				close(release)
				t.Fatalf("team edit did not wait: %v", err)
			case <-wait.Done():
				close(release)
				t.Fatal("writer did not block")
			case <-time.After(10 * time.Millisecond):
			}
		}
		close(release)
		if err := <-reconciled; err != nil {
			t.Fatal(err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		f.engine.beforeEnsure = nil
		if _, err := f.service.Issue(ctx, f.raw); err == nil {
			t.Fatal("new team revision authorized stale native policy")
		}
	})
	t.Run("pending_applied_tightening_and_stable_key", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		if _, err := f.service.Issue(ctx, f.raw); err == nil {
			t.Fatal("pending policy issued credential")
		}
		if a := f.reconcile(); a.Status != "applied" || a.AppliedRevision != 1 || a.AppliedTeamRevision != 1 {
			t.Fatalf("not applied: %+v", a)
		}
		c := f.mint()
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/a"); err != nil {
			t.Fatal(err)
		}
		native, _ := f.binding(f.team)
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/b"}, []string{"provider-key"}, nil, 1); err != nil {
			t.Fatal(err)
		}
		assignments, err := f.policies.ListAssignments(ctx, f.org)
		if err != nil || assignments[0].Status != "pending" {
			t.Fatal("team drift invisible")
		}
		if _, err = f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
			t.Fatal("stale team policy authorized")
		}
		f.engine.fail = true
		if a := f.reconcile(); a.Status != "error" || a.AppliedTeamRevision != 1 {
			t.Fatal("failed reconcile marked applied")
		}
		f.engine.fail = false
		if err = f.policies.ReconcileTeam(ctx, f.org, f.team, 16); err != nil {
			t.Fatal(err)
		}
		after, _ := f.binding(f.team)
		if after != native {
			t.Fatal("policy edit reset accounting identity")
		}
		if _, err = f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
			t.Fatal("removed model authorized")
		}
		if _, err = f.service.Authorize(ctx, c.Token, "openrouter/b"); err != nil {
			t.Fatal(err)
		}
		if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{"provider-key"}, nil, 1); err == nil {
			t.Fatal("stale write accepted")
		}
	})
	t.Run("override_narrows_and_group_removal_denies", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, f.team, true, []string{"openrouter/outside"}, 1); err == nil {
			t.Fatal("broad override accepted")
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, f.team, true, []string{"openrouter/a"}, 1); err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		c := f.mint()
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/b"); err == nil {
			t.Fatal("override widened permission")
		}
		f.exec(`DELETE FROM agent_group_members WHERE org_id=$1 AND device_id=$2`, f.org, f.device)
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
			t.Fatal("removed membership authorized")
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, f.team, false, nil, 2); err != nil {
			t.Fatalf("explicit disable after removal: %v", err)
		}
		if a := f.reconcile(); a.Status != "disabled" {
			t.Fatal("disabled not applied")
		}
		native, _ := f.binding(f.team)
		if f.engine.active[native] {
			t.Fatal("native key not disabled")
		}
	})
	t.Run("team_move_retains_history_and_returned_key", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		f.reconcile()
		old, _ := f.binding(f.team)
		second := uuid.New()
		f.group(second)
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, second, []string{"openrouter/b"}, []string{"provider-key"}, nil, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, second, true, nil, 1); err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		next, _ := f.binding(second)
		if old == next || f.engine.active[old] || !f.engine.active[next] {
			t.Fatal("team move did not isolate native keys")
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, f.device, f.team, true, nil, 2); err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		returned, _ := f.binding(f.team)
		if returned != old || f.engine.active[next] {
			t.Fatal("return reset accounting identity")
		}
		var count int
		if pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1`, f.org).Scan(&count) != nil || count != 2 {
			t.Fatal("history lost")
		}
	})
	t.Run("tenant_isolation_and_archive", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		other := newPolicyFixture(t, ctx, pool)
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, other.team, []string{"openrouter/a"}, []string{"key"}, nil, 0); err == nil {
			t.Fatal("cross tenant team policy")
		}
		if _, err := f.policies.PutAssignment(ctx, f.org, f.owner, other.device, f.team, true, nil, 0); err == nil {
			t.Fatal("cross tenant device assignment")
		}
		f.reconcile()
		c := f.mint()
		f.exec(`UPDATE agent_groups SET archived_at=now() WHERE org_id=$1 AND id=$2`, f.org, f.team)
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
			t.Fatal("archived team authorized")
		}
		f.policies.ReconcilePending(ctx, 16)
		native, _ := f.binding(f.team)
		if f.engine.active[native] {
			t.Fatal("archived group native key active")
		}
	})
	t.Run("soft_limit_is_observational_and_preserved", func(t *testing.T) {
		f := newPolicyFixture(t, ctx, pool)
		limit := 1.0
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{"provider-key"}, &limit, 1); err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		c := f.mint()
		f.engine.usage = 1
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/a"); err == nil {
			t.Fatal("spent threshold allowed")
		}
		if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a", "openrouter/b"}, []string{"provider-key"}, &limit, 2); err != nil {
			t.Fatal(err)
		}
		f.reconcile()
		if _, err := f.service.Authorize(ctx, c.Token, "openrouter/b"); err == nil {
			t.Fatal("policy edit reset spend")
		}
	})
}

func TestAIPolicyValidation(t *testing.T) {
	for _, models := range [][]string{nil, {"*"}, {"openai/a"}, {"openrouter/"}, {"openrouter/a", "openrouter/a"}, {"openrouter/a?route=x"}} {
		if _, ok := canonicalModels(models, false); ok {
			t.Fatal("invalid model set accepted")
		}
	}
}

func TestAIPolicyRetryAdvancesPastTimedOutTarget(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	first := newPolicyFixture(t, ctx, pool)
	second := newPolicyFixture(t, ctx, pool)
	// Force a deterministic first target without relying on random UUID order.
	first.exec(`UPDATE ai_gateway_assignments SET last_reconcile_at=now()-interval '2 hours' WHERE org_id=$1`, first.org)
	first.exec(`UPDATE ai_gateway_assignments SET last_reconcile_at=now()-interval '1 hour' WHERE org_id=$1`, second.org)
	deadline, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	first.engine.beforeEnsure = func() { <-deadline.Done() }
	if err := first.policies.ReconcilePending(deadline, 1); err == nil {
		t.Fatal("timed-out native reconciliation reported success")
	}
	first.engine.beforeEnsure = nil
	// A later pass must select the untouched second target, not retry the
	// expired first transaction forever. The engine seam handles either org.
	if err := first.policies.ReconcilePending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	assignments, err := first.policies.ListAssignments(ctx, second.org)
	if err != nil || len(assignments) != 1 || assignments[0].Status != "applied" {
		t.Fatal("timed-out target starved another pending assignment")
	}
}
