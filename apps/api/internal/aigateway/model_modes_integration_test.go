package aigateway

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestModelModesPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	f.policies.engine = newProviderFixtureEngine()
	f.policies.EnableProviderManagement(true)
	secret := "synthetic-mode-provider-secret"
	in := ProviderInput{Provider: "openrouter", Name: "Mode fixture", Models: []string{"openrouter/a"}, Enabled: true, Secret: &secret, ModelModes: map[string]ModelMode{"openrouter/a": ModeEmbedding}}
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
	if err != nil || p.Status != "applied" || p.ModelModes["openrouter/a"] != ModeEmbedding {
		t.Fatal(p, err)
	}
	// An older caller omitting mode preserves retained values, defaults additions.
	in.Secret = nil
	in.ModelModes = nil
	in.Models = []string{"openrouter/a", "openrouter/b"}
	p, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision)
	if err != nil || p.ModelModes["openrouter/a"] != ModeEmbedding || p.ModelModes["openrouter/b"] != ModeChat {
		t.Fatal(p, err)
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{p.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	credential := f.mint()
	grant, err := f.service.Authorize(ctx, credential.Token, "openrouter/a")
	if err != nil || grant.Mode != ModeEmbedding {
		t.Fatal("trusted mode missing", grant, err)
	}
	in.ModelModes = map[string]ModelMode{"openrouter/a": ModeCompletion}
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision); usageStatus(err) != 409 {
		t.Fatal("referenced mode changed", err)
	}
	if _, err = f.policies.UpdateProvider(ctx, uuid.New(), f.owner, p.ID, in, p.Revision); usageStatus(err) != 404 {
		t.Fatal("cross-org mode update", err)
	}
	// Conflicting exact model modes across selected credential scopes refuse.
	other := ProviderInput{Provider: "openrouter", Name: "Other mode", Models: []string{"openrouter/a"}, Enabled: true, Secret: &secret}
	q, err := f.policies.CreateProvider(ctx, f.org, f.owner, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{p.KeyID, q.KeyID}, nil, 2); err == nil {
		t.Fatal("ambiguous model mode policy accepted")
	}
	// Database refuses extraneous keys, null/unknown modes and non-object maps.
	for _, raw := range []string{`{"openrouter/absent":"chat"}`, `{"openrouter/a":null}`, `{"openrouter/a":"bogus"}`, `[]`, `null`} {
		if _, err = pool.Exec(ctx, `UPDATE ai_provider_connections SET model_modes=$3 WHERE org_id=$1 AND id=$2`, f.org, p.ID, raw); err == nil {
			t.Fatal("invalid database mode map", raw)
		}
	}
	// Two allowed metadata mutations at one revision still produce one winner.
	in.ModelModes = nil
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("mode revision race winners=%d", wins)
	}
	down, err := os.ReadFile("../../db/migrations/0150_ai_model_modes.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("rollback erased retained non-chat modes")
	}
	if _, err = pool.Exec(ctx, `UPDATE ai_provider_connections SET deleted_at=statement_timestamp() WHERE org_id=$1 AND id=$2`, f.org, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(down)); err == nil {
		t.Fatal("rollback erased non-chat tombstone")
	}
}

func TestModelModesCustomNamespacePostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	f.policies.engine = newProviderFixtureEngine()
	f.policies.EnableProviderManagement(true)
	f.policies.ConfigureCustomProviders(loadPublicFixturePolicy(t))
	endpoint := "https://models.example.com/base"
	secret := "synthetic-mode-key"
	in := ProviderInput{Provider: "custom", Name: "Custom mode", EndpointURL: &endpoint, Models: []string{"deployment"}, ModelModes: map[string]ModelMode{"deployment": ModeRerank}, Enabled: true, Secret: &secret}
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
	if err != nil || len(p.Models) != 1 || p.ModelModes[p.Models[0]] != ModeRerank {
		t.Fatal(p, err)
	}
	in.Secret = nil
	in.ModelModes = map[string]ModelMode{"custom-" + uuid.NewString() + "/deployment": ModeEmbedding}
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision); usageStatus(err) != 400 {
		t.Fatal("foreign mode namespace accepted", err)
	}
	in.ModelModes = nil
	p, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision)
	if err != nil || p.ModelModes[p.Models[0]] != ModeRerank {
		t.Fatal("custom raw model mode not retained", p, err)
	}
}

func loadPublicFixturePolicy(t *testing.T) *aiegress.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"public_https":true,"protected_hosts":["control.internal"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := aiegress.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
