package aigateway

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func customFixturePolicy(t *testing.T) *aiegress.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endpoints.json")
	if err := os.WriteFile(path, []byte(`{"endpoints":[{"name":"Internal","url":"http://internal.example:8080/base","allowed_cidrs":["10.20.0.0/16"]},{"name":"Other","url":"https://other.example/base","allowed_cidrs":["10.30.0.0/16"]}],"protected_hosts":["control.invalid"],"denied_cidrs":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := aiegress.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAICustomProviderNormalization(t *testing.T) {
	s := &Policies{providerManagement: true, customPolicy: customFixturePolicy(t)}
	// Direct normalization uses a fixture engine and nonnil pool in integration;
	// parse errors and namespace validation are independently tested below.
	id := uuid.New()
	prefix := "custom-" + id.String()
	if p, m, ok := splitProviderModel(prefix + "/vendor/model"); !ok || p != prefix || m != "vendor/model" {
		t.Fatal("custom parser")
	}
	for _, bad := range []string{"custom/model", "custom-00000000-0000-0000-0000-000000000000/model", "custom-not-a-uuid/model"} {
		if _, _, ok := splitProviderModel(bad); ok {
			t.Fatal("foreign namespace syntax")
		}
	}
	endpoint := "http://internal.example:8080/base/"
	secret := "fixture"
	in, err := validateProviderInput(ProviderInput{Provider: "custom", Name: "Internal", EndpointURL: &endpoint, Models: []string{"vendor/model", "custom-model"}, Secret: &secret}, true)
	if err != nil || *in.EndpointURL != "http://internal.example:8080/base" {
		t.Fatal("endpoint normalization", err)
	}
	one := 1.0
	called := false
	s.engine = usageEngineFixture{price: func(_ context.Context, p, m string) (Price, error) {
		called = true
		if p != prefix || m != "vendor/model" {
			t.Fatal("custom pricing namespace mismatch")
		}
		return Price{}, nil
	}}
	if err = s.enforceCost(context.Background(), usageTxFixture{}, uuid.New(), uuid.New(), prefix+"/vendor/model", &one); usageStatus(err) != 403 || !called {
		t.Fatal("unknown custom price admitted")
	}
	if s.customPolicy.AllowsEndpoint("http://internal.example:8080/other") {
		t.Fatal("basepath escaped")
	}
}
func TestAICustomProvidersPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := &scopedProviderFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	endpoint := "http://internal.example:8080/base"
	secret := "fixture-custom"
	in := ProviderInput{Provider: "custom", Name: "Internal", EndpointURL: &endpoint, Models: []string{"vendor/model", "custom-model"}, Enabled: true, Secret: &secret}
	if _, err := f.policies.CreateProvider(ctx, f.org, f.owner, in); err == nil {
		t.Fatal("custom without egress policy allowed")
	}
	f.policies.ConfigureCustomProviders(customFixturePolicy(t))
	if !f.policies.CustomAvailable() || len(f.policies.ApprovedCustomEndpoints()) != 2 || len(f.policies.ApprovedCustomEndpoints()[0].AllowedCIDRs) != 0 {
		t.Fatal("custom inventory")
	}
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
	if err != nil || p.Status != "applied" {
		t.Fatalf("create %+v %v", p, err)
	}
	prefix := "custom-" + p.ID.String() + "/"
	for _, model := range p.Models {
		if !strings.HasPrefix(model, prefix) {
			t.Fatal("native namespace escaped")
		}
	}
	spec := engine.values[p.KeyID]
	if spec.Provider != "custom-"+p.ID.String() || spec.BaseURL != endpoint {
		t.Fatal("native custom routing mismatch")
	}
	update := in
	update.Secret = nil
	update.Models = p.Models
	p, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, update, p.Revision)
	if err != nil || p.Status != "applied" {
		t.Fatal("owned canonical update", err)
	}
	update.Models = []string{"custom-" + uuid.NewString() + "/model"}
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, update, p.Revision); err == nil {
		t.Fatal("foreign canonical namespace accepted")
	}
	update.Models = p.Models
	otherEndpoint := "https://other.example/base"
	update.EndpointURL = &otherEndpoint
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, update, p.Revision); err == nil {
		t.Fatal("endpoint changed")
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, p.Models, []string{p.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	credential := f.mint()
	if len(engine.scopes) != 1 || engine.scopes[0].Provider != "custom-"+p.ID.String() {
		t.Fatal("custom scope grouping")
	}
	other := newPolicyFixture(t, ctx, pool)
	if _, err = f.policies.CustomProviderModels(ctx, other.org, p.ID, "", 50, 0); err == nil {
		t.Fatal("foreign catalog connection")
	}
	f.policies.ConfigureCustomProviders(nil)
	if _, err = f.service.Authorize(ctx, credential.Token, p.Models[0]); err == nil {
		t.Fatal("removed approval admitted inference")
	}
	if _, err = f.service.Issue(ctx, f.raw); err == nil {
		t.Fatal("removed approval issued credential")
	}
	if got := f.reconcile(); got.Status != "error" {
		t.Fatal("removed approval reconciled active")
	}
	before := engine.tests
	if _, err = f.policies.TestProvider(ctx, f.org, f.owner, p.ID, p.Revision); err == nil || engine.tests != before {
		t.Fatal("removed approval reached native test")
	}
	down, err := os.ReadFile("../../db/migrations/0146_ai_custom_provider.down.sql")
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
	if _, err = tx.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "retained connections") {
		t.Fatal("custom rollback erased ownership", err)
	}
}
