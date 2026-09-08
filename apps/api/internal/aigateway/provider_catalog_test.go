package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
)

func catalogPolicies(t *testing.T, handler http.HandlerFunc) *Policies {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(`{"public_https":true,"endpoints":[{"provider":"sagemaker","name":"reserved","url":"https://reserved.example.com/base","allowed_cidrs":["8.8.8.8/32"]}],"protected_hosts":["control.internal"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := aiegress.LoadPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	s := &Policies{providerManagement: true, pool: &pgxpool.Pool{}, engine: newProviderFixtureEngine()}
	s.ConfigureCustomProviders(policy)
	if err := s.ConfigureLiteLLMBridge(srv.URL, "fixture-admin-token"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAIProviderDraftCatalog(t *testing.T) {
	calls := 0
	s := catalogPolicies(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/model-catalog" || r.Header.Get("Authorization") != "Bearer fixture-admin-token" {
			t.Error("request boundary")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["endpoint_url"] != "https://resource.cognitiveservices.azure.com/openai" || body["api_key"] != "fixture-private-key" || body["provider"] != "azure_foundry" || len(body) != 6 {
			t.Error("draft catalog payload")
		}
		w.Write([]byte(`{"items":[{"id":"gpt-5","name":"gpt-5"}],"total":1,"limit":50,"offset":0,"irrelevant":"not reflected"}`))
	})
	if !s.PublicEndpointsAvailable() || !s.FoundryAvailable() || len(s.ApprovedFoundryEndpoints()) != 0 {
		t.Fatal("public endpoint needs manual registration")
	}
	in := ProviderCatalogInput{Provider: "azure_foundry", EndpointURL: "https://resource.cognitiveservices.azure.com/openai/", Secret: "fixture-private-key", Query: "gpt", Limit: 50}
	org, actor := uuid.New(), uuid.New()
	for i := 0; i < 6; i++ {
		page, err := s.SearchProviderCatalog(context.Background(), org, actor, in)
		if err != nil || page.Total != 1 || len(page.Models) != 1 || page.Models[0].ID != "gpt-5" {
			t.Fatal(page, err)
		}
	}
	if _, err := s.SearchProviderCatalog(context.Background(), org, actor, in); usageStatus(err) != 429 || calls != 6 {
		t.Fatal("shared rate bound", err)
	}
	for _, change := range []func(*ProviderCatalogInput){
		func(i *ProviderCatalogInput) { i.Provider = "openai" }, func(i *ProviderCatalogInput) { i.Secret = "" },
		func(i *ProviderCatalogInput) { i.EndpointURL = "https://127.0.0.1/openai" }, func(i *ProviderCatalogInput) { i.EndpointURL = "https://resource.openai.azure.com/models" },
		func(i *ProviderCatalogInput) { i.Query = strings.Repeat("x", 101) }, func(i *ProviderCatalogInput) { i.Limit = 101 }, func(i *ProviderCatalogInput) { i.Offset = -1 },
		func(i *ProviderCatalogInput) {
			i.Provider = "custom"
			i.EndpointURL = "https://reserved.example.com/base"
		},
	} {
		bad := in
		change(&bad)
		if _, err := s.SearchProviderCatalog(context.Background(), uuid.New(), actor, bad); usageStatus(err) != 400 {
			t.Fatal("invalid draft accepted", err)
		}
	}
	if _, err := s.SearchProviderCatalog(context.Background(), uuid.Nil, actor, in); usageStatus(err) != 403 {
		t.Fatal("missing organization", err)
	}
	if _, err := s.SearchProviderCatalog(context.Background(), org, uuid.Nil, in); usageStatus(err) != 403 {
		t.Fatal("missing actor", err)
	}
	if calls != 6 {
		t.Fatal("invalid draft reached bridge")
	}
}

func TestAIProviderDraftCatalogRefusesUnsafeResults(t *testing.T) {
	for _, body := range []string{
		`{"error":"fixture-private-key"}`,
		`{"items":[{"id":"fixture-private-key","name":"fixture-private-key"}],"total":1,"limit":50,"offset":0}`,
		`{"items":[{"id":"a","name":"fixture-private-key"}],"total":1,"limit":50,"offset":0}`,
		`{"items":[{"id":"a","name":"a"},{"id":"a","name":"a"}],"total":2,"limit":50,"offset":0}`,
		`{"items":[],"total":10001,"limit":50,"offset":0}`,
		`{"items":[],"total":0,"limit":100,"offset":0}`,
		`{"items":[{"id":"custom-00000000-0000-4000-8000-000000000001/other","name":"custom-00000000-0000-4000-8000-000000000001/other"}],"total":1,"limit":50,"offset":0}`,
		strings.Repeat("x", 65537),
	} {
		t.Run(body[:min(len(body), 32)], func(t *testing.T) {
			s := catalogPolicies(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			_, err := s.SearchProviderCatalog(context.Background(), uuid.New(), uuid.New(), ProviderCatalogInput{Provider: "custom", EndpointURL: "https://models.example.com", Secret: "fixture-private-key", Limit: 50})
			if usageStatus(err) != 503 || strings.Contains(err.Error(), "fixture-private-key") {
				t.Fatal("unsanitized result", err)
			}
		})
	}
}
