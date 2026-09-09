package aigateway

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"os"
	"strings"
	"sync"
	"testing"
)

type providerFixtureEngine struct {
	*policyEngineFixture
	mu     sync.Mutex
	values map[string]ProviderKeySpec
	fail   bool
	tests  int
}

func newProviderFixtureEngine() *providerFixtureEngine {
	return &providerFixtureEngine{policyEngineFixture: newPolicyEngineFixture(), values: map[string]ProviderKeySpec{}}
}
func (e *providerFixtureEngine) EnsureProvider(context.Context, string, string) error { return nil }
func (e *providerFixtureEngine) PutProviderKey(_ context.Context, s ProviderKeySpec, secret *string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return errors.New("secret-never-public")
	}
	if _, ok := e.values[s.ID]; !ok && secret == nil {
		return errors.New("missing")
	}
	e.values[s.ID] = s
	return nil
}
func (e *providerFixtureEngine) VerifyProviderKey(_ context.Context, s ProviderKeySpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.values[s.ID]
	if !ok || v.Revision != s.Revision || v.Enabled != s.Enabled {
		return errors.New("scope")
	}
	return nil
}
func (e *providerFixtureEngine) DeleteProviderKey(_ context.Context, s ProviderKeySpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.values[s.ID]
	if !ok {
		return nil
	}
	if v.Enabled || v.Revision != s.Revision {
		return errors.New("scope")
	}
	delete(e.values, s.ID)
	return nil
}
func (e *providerFixtureEngine) TestProviderKey(context.Context, ProviderKeySpec) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tests++
	return !e.fail, nil
}
func (e *providerFixtureEngine) ProviderModels(context.Context, string, string, int, int) (ProviderModelPage, error) {
	return ProviderModelPage{Models: []ProviderModel{{ID: "openrouter/a", Name: "A"}}, Total: 1}, nil
}
func TestAIProvidersPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	f.policies.engine = engine
	input := func(models ...string) ProviderInput {
		secret := "fixture-secret-never-public"
		return ProviderInput{Provider: "openrouter", Name: "Provider", Models: models, Enabled: true, Secret: &secret}
	}
	if _, err := f.policies.CreateProvider(ctx, f.org, f.owner, input("openrouter/a")); err == nil {
		t.Fatal("default management allowed")
	}
	f.policies.EnableProviderManagement(true)
	create := func(models ...string) ProviderConnection {
		t.Helper()
		p, err := f.policies.CreateProvider(ctx, f.org, f.owner, input(models...))
		if err != nil || p.Status != "applied" {
			t.Fatalf("create: %+v %v", p, err)
		}
		return p
	}
	a, b := create("openrouter/a"), create("openrouter/b")
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a", "openrouter/b"}, []string{a.KeyID, b.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	credential := f.mint()
	// Union scopes permit metadata updates and disable; removed referenced models refuse.
	update := input("openrouter/a")
	update.Secret = nil
	update.Name = "Renamed"
	a, err := f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, update, a.Revision)
	if err != nil || a.Status != "applied" {
		t.Fatalf("union metadata %+v %v", a, err)
	}
	update.Models = []string{"openrouter/c"}
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, update, a.Revision); err == nil {
		t.Fatal("referenced model removed")
	}
	update.Models = []string{"openrouter/a"}
	update.Enabled = false
	a, err = f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, update, a.Revision)
	if err != nil || a.Status != "disabled" {
		t.Fatalf("disable %+v %v", a, err)
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{a.KeyID}, nil, 2); err == nil {
		t.Fatal("disabled policy accepted")
	}
	if _, err = f.service.Issue(ctx, f.raw); err == nil {
		t.Fatal("disabled connection issued credential")
	}
	if _, err = f.service.Authorize(ctx, credential.Token, "openrouter/a"); err == nil {
		t.Fatal("disabled connection admitted inference")
	}
	if got := f.reconcile(); got.Status != "error" {
		t.Fatalf("disabled connection still active %+v", got)
	}
	update.Enabled = true
	a, err = f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, update, a.Revision)
	if err != nil {
		t.Fatal(err)
	}
	// Two same-revision mutations produce one winner, never both.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, update, a.Revision)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners %d", wins)
	}
	other := newPolicyFixture(t, ctx, pool)
	if _, err = f.policies.UpdateProvider(ctx, other.org, other.owner, b.ID, input("openrouter/b"), b.Revision); err == nil {
		t.Fatal("cross org mutation")
	}
	if _, err = other.policies.PutTeam(ctx, other.org, other.owner, other.team, []string{"openrouter/b"}, []string{b.KeyID}, nil, 1); err == nil {
		t.Fatal("cross org key accepted")
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{"unknown-operator-key"}, nil, 2); err == nil {
		t.Fatal("implicit legacy allowed")
	}
	if err = f.policies.DeleteProvider(ctx, f.org, f.owner, b.ID, b.Revision); err == nil {
		t.Fatal("referenced deletion")
	}
	// Failed create stores no secret, refuses admission and allows missing-native delete.
	engine.mu.Lock()
	engine.fail = true
	engine.mu.Unlock()
	failed, err := f.policies.CreateProvider(ctx, f.org, f.owner, input("openrouter/c"))
	if err != nil || failed.Status != "error" {
		t.Fatalf("failed state %+v %v", failed, err)
	}
	retry := input("openrouter/c")
	retry.Secret = nil
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, failed.ID, retry, failed.Revision); err == nil {
		t.Fatal("error retry without secret")
	}
	if err = f.policies.DeleteProvider(ctx, f.org, f.owner, failed.ID, failed.Revision); err != nil {
		t.Fatal("missing-native delete", err)
	}
	engine.mu.Lock()
	engine.fail = false
	engine.mu.Unlock()
	free := create("openrouter/c")
	// Simulate native deletion succeeding but its CP completion being lost.
	engine.mu.Lock()
	delete(engine.values, free.KeyID)
	engine.mu.Unlock()
	if err = f.policies.DeleteProvider(ctx, f.org, f.owner, free.ID, free.Revision); err != nil {
		t.Fatal("lost deletion recovery", err)
	}
	var tombstones int
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_provider_connections WHERE org_id=$1 AND deleted_at IS NOT NULL`, f.org).Scan(&tombstones) != nil || tombstones != 2 {
		t.Fatal("ownership tombstones missing")
	}
	items, legacy, err := f.policies.ListProviders(ctx, f.org)
	if err != nil || len(items) != 2 || len(legacy) != 1 {
		t.Fatalf("list %d %v %v", len(items), legacy, err)
	}
	var stored string
	if pool.QueryRow(ctx, `SELECT coalesce(string_agg(metadata::text,','),'') FROM audit_logs WHERE org_id=$1`, f.org).Scan(&stored) != nil || strings.Contains(stored, "secret") {
		t.Fatal("secret in audit")
	}
	checked, err := f.policies.TestProvider(ctx, f.org, f.owner, b.ID, b.Revision)
	if err != nil || checked.LastTestStatus != "success" || checked.LastTestAt == nil {
		t.Fatalf("test %+v %v", checked, err)
	}
	if _, err = f.policies.TestProvider(ctx, f.org, f.owner, uuid.New(), 1); err == nil {
		t.Fatal("missing provider tested")
	}
}
func TestAIProviderValidation(t *testing.T) {
	key := "valid-key"
	in := ProviderInput{Name: "valid", Provider: "openrouter", Models: []string{"openrouter/a"}, Secret: &key}
	for _, bad := range []string{"", "with space", "line\nkey", strings.Repeat("x", 4097)} {
		in.Secret = &bad
		if _, err := validateProviderInput(in, true); err == nil {
			t.Fatal("invalid secret allowed")
		}
	}
}

func TestAIProviderMigrationSnapshot(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	migration, err := os.ReadFile("../../db/migrations/0144_ai_provider_connections.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, collision := range []bool{false, true} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackAI(tx)
		// Roll back all later provider references inside this disposable test
		// transaction before replaying the historical provider migration.
		if _, err = tx.Exec(ctx, `DROP TABLE ai_workload_models; DROP TABLE ai_user_model_grants; DROP TABLE ai_provider_connections; DROP TABLE ai_provider_legacy_keys`); err != nil {
			t.Fatal(err)
		}
		if collision {
			if _, err = tx.Exec(ctx, `UPDATE ai_gateway_team_policies SET key_ids=ARRAY['tnx-managed-'||$2] WHERE org_id=$1`, f.org, uuid.NewString()); err != nil {
				t.Fatal(err)
			}
		}
		_, err = tx.Exec(ctx, string(migration))
		if collision {
			if err == nil || !strings.Contains(err.Error(), "reserved tnx-managed-") {
				t.Fatalf("collision not refused: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_provider_legacy_keys WHERE org_id=$1 AND key_id='provider-key'`, f.org).Scan(&count); err != nil || count != 1 {
				t.Fatal("legacy snapshot missing", err)
			}
		}
		rollbackAI(tx)
	}
}

type scopedProviderFixture struct {
	*providerFixtureEngine
	scopes []EngineProviderScope
}

func (e *scopedProviderFixture) EnsureScopedKey(ctx context.Context, name string, scopes []EngineProviderScope) (EngineKey, error) {
	e.scopes = scopes
	// Stable synthetic identity independent of changes to the provider set.
	return e.policyEngineFixture.EnsureKey(ctx, name, "openrouter", []string{"fixture"}, []string{"fixture"})
}
func TestAIProvidersMixedScopesPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := &scopedProviderFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-secret"
	create := func(provider, model string) ProviderConnection {
		t.Helper()
		p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Name: provider, Provider: provider, Models: []string{model}, Enabled: true, Secret: &secret})
		if err != nil || p.Status != "applied" {
			t.Fatalf("create %+v %v", p, err)
		}
		return p
	}
	a := create("openai", "openai/gpt-fixture")
	b := create("anthropic", "anthropic/claude-fixture")
	if _, err := f.policies.UpdateProvider(ctx, f.org, f.owner, a.ID, ProviderInput{Name: "switch", Provider: "gemini", Models: []string{"gemini/gemini-fixture"}, Enabled: true, Secret: &secret}, a.Revision); err == nil {
		t.Fatal("provider changed")
	}
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openai/gpt-fixture"}, []string{"provider-key"}, nil, 1); err == nil {
		t.Fatal("legacy covered direct provider")
	}
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openai/gpt-fixture", "anthropic/claude-fixture", "openrouter/openai/gpt-fixture"}, []string{a.KeyID, b.KeyID, "provider-key"}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	id, _ := f.binding(f.team)
	if len(engine.scopes) != 3 || engine.scopes[0].Provider != "anthropic" || engine.scopes[1].Provider != "openai" || engine.scopes[2].Provider != "openrouter" || engine.scopes[2].Models[0] != "openai/gpt-fixture" {
		t.Fatalf("mixed scopes %+v", engine.scopes)
	}
	if engine.scopes[0].KeyIDs[0] != b.KeyID || engine.scopes[1].KeyIDs[0] != a.KeyID || engine.scopes[2].KeyIDs[0] != "provider-key" {
		t.Fatal("key grouping escaped provider")
	}
	// Legacy engines must refuse mixed scopes rather than collapse them.
	f.policies.engine = engine.providerFixtureEngine
	if got := f.reconcile(); got.Status != "error" {
		t.Fatal("legacy engine accepted mixed scopes")
	}
	f.policies.engine = engine
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openai/gpt-fixture"}, []string{a.KeyID}, nil, 2); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	after, _ := f.binding(f.team)
	if id != after || len(engine.scopes) != 1 || engine.scopes[0].Provider != "openai" {
		t.Fatal("scope removal changed identity or retained extra scopes")
	}
	down, err := os.ReadFile("../../db/migrations/0145_ai_provider_registry.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAI(tx)
	if _, err = tx.Exec(ctx, `UPDATE ai_provider_connections SET deleted_at=statement_timestamp() WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "retained non-OpenRouter") {
		t.Fatal("rollback erased retained provider ownership", err)
	}
}

func TestAIExpandedProvidersPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := &scopedProviderFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-expanded"
	var stable string
	revision := int64(1)
	for _, provider := range []string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek"} {
		model := provider + "/fixture"
		in := ProviderInput{Provider: provider, Name: provider, Models: []string{model}, Enabled: true, Secret: &secret}
		p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
		if err != nil || p.Status != "applied" {
			t.Fatalf("%s create %+v %v", provider, p, err)
		}
		if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{model}, []string{"provider-key"}, nil, revision); provider != "openrouter" && err == nil {
			t.Fatal("legacy covered direct provider")
		} else if err == nil {
			revision++
		}
		if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{model}, []string{p.KeyID}, nil, revision); err != nil {
			t.Fatal(err)
		}
		revision++
		f.reconcile()
		id, _ := f.binding(f.team)
		if stable != "" && stable != id {
			t.Fatal("provider change reset accounting identity")
		}
		stable = id
		if len(engine.scopes) != 1 || engine.scopes[0].Provider != provider || engine.scopes[0].KeyIDs[0] != p.KeyID || engine.scopes[0].Models[0] != "fixture" {
			t.Fatal("provider routing mismatch")
		}
	}
	down, err := os.ReadFile("../../db/migrations/0147_ai_provider_inventory.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAI(tx)
	if _, err = tx.Exec(ctx, `UPDATE ai_provider_connections SET deleted_at=statement_timestamp() WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "retained added-provider") {
		t.Fatal("rollback erased retained provider ownership", err)
	}
}
