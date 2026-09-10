package aigateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAISelfServiceProvidersPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := &scopedProviderFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"public_https":true,"endpoints":[],"protected_hosts":["control.internal"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := aiegress.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	f.policies.ConfigureCustomProviders(policy)
	endpoint, secret := "https://resource.cognitiveservices.azure.com/openai", "private-fixture-key"
	in := ProviderInput{Provider: "azure_foundry", Name: "Public Foundry", EndpointURL: &endpoint, Secret: &secret, Models: []string{"my-deployment"}, Enabled: true}
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, in)
	if err != nil || p.Status != "applied" || p.EndpointURL == nil || *p.EndpointURL != endpoint {
		t.Fatal(p, err)
	}
	if len(policy.Endpoints) != 0 || p.Models[0] != "custom-"+p.ID.String()+"/my-deployment" {
		t.Fatal("created endpoint approval or lost model scope")
	}
	if err = pool.QueryRow(ctx, `SELECT endpoint_url FROM ai_provider_connections WHERE org_id=$1 AND id=$2`, f.org, p.ID).Scan(&endpoint); err != nil || endpoint != *p.EndpointURL {
		t.Fatal("public persistence", err)
	}
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, p.Models, []string{p.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	cred := f.mint()
	if _, err = f.service.Authorize(ctx, cred.Token, p.Models[0]); err != nil {
		t.Fatal("public connection cannot be used", err)
	}
	policy.PublicHTTPS = false
	if _, err = f.service.Authorize(ctx, cred.Token, p.Models[0]); err == nil {
		t.Fatal("public mode removal left admission open")
	}
	policy.PublicHTTPS = true
	for _, bad := range []string{"https://127.0.0.1/openai", "https://10.1.2.3/openai", "http://resource.openai.azure.com/openai", "https://resource.cognitiveservices.azure.com/models"} {
		in.EndpointURL = &bad
		if _, err = f.policies.CreateProvider(ctx, f.org, f.owner, in); usageStatus(err) != 400 {
			t.Fatal("invalid public endpoint persisted", err)
		}
	}
}
