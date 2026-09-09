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

func TestAISageMakerProvidersPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := &scopedProviderFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"endpoints":[{"name":"SageMaker","provider":"sagemaker","url":"http://bridge.example:8200","allowed_cidrs":["10.20.0.0/16"]},{"name":"Custom","url":"http://custom.example:8080","allowed_cidrs":["10.20.0.0/16"]}],"protected_hosts":["control.invalid"]}`), 0600)
	policy, err := aiegress.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	f.policies.ConfigureCustomProviders(policy)
	if !f.policies.SageMakerAvailable() || !f.policies.CustomAvailable() || len(f.policies.ApprovedSageMakerEndpoints()) != 1 || len(f.policies.ApprovedCustomEndpoints()) != 1 {
		t.Fatal("inventory separation")
	}
	endpoint, secret := "http://bridge.example:8200", "fixture-client-key"
	in := ProviderInput{Provider: "sagemaker", Name: "AWS endpoint", EndpointURL: &endpoint, Secret: &secret, Models: []string{"operator-alias"}, Enabled: true}
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
	if err != nil || p.Status != "applied" {
		t.Fatal(p, err)
	}
	if p.Models[0] != "custom-"+p.ID.String()+"/operator-alias" || engine.values[p.KeyID].Provider != "custom-"+p.ID.String() {
		t.Fatal("owned namespace")
	}
	in.Provider = "custom"
	if _, err = f.policies.CreateProvider(ctx, f.org, f.owner, in); usageStatus(err) != 400 {
		t.Fatal("cross type endpoint allowed", err)
	}
	in.Provider = "sagemaker"
	in.Models = p.Models
	in.Secret = nil
	if _, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, in, p.Revision); err != nil {
		t.Fatal("canonical update", err)
	}
	if _, err = f.policies.CustomProviderModels(ctx, uuid.New(), p.ID, "", 50, 0); usageStatus(err) != 404 {
		t.Fatal("foreign catalog", err)
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, p.Models, []string{p.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	cred := f.mint()
	if _, err = f.service.Authorize(ctx, cred.Token, p.Models[0]); err != nil {
		t.Fatal(err)
	}
	// Reclassifying the installation endpoint cannot silently retain authorization.
	policy.Endpoints[0].Provider = "custom"
	if _, err = f.service.Authorize(ctx, cred.Token, p.Models[0]); err == nil {
		t.Fatal("endpoint type change admitted")
	}
	down, err := os.ReadFile("../../db/migrations/0148_ai_sagemaker_provider.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAI(tx)
	if _, err = tx.Exec(ctx, `UPDATE ai_provider_connections SET deleted_at=statement_timestamp() WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "retained connections") {
		t.Fatal("rollback erased tombstone", err)
	}
}
