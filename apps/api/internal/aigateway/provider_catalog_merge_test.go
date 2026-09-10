package aigateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

type catalogMergeFixture struct {
	*providerFixtureEngine
	page ProviderModelPage
	err  error
}

func (f *catalogMergeFixture) ProviderModels(_ context.Context, _ string, _ string, limit, offset int) (ProviderModelPage, error) {
	if limit != 100 || offset != 0 {
		panic("catalog must use the existing bounded engine page")
	}
	return f.page, f.err
}

func TestCatalogMergeUsesRealEnginePagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if r.URL.Path != "/api/models" || q.Get("provider") != "anthropic" || q.Get("limit") != "100" {
			t.Error("unexpected catalog request", r.URL.Path, q)
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		models := []map[string]string{}
		for i := offset; i < min(offset+100, 101); i++ {
			models = append(models, map[string]string{"provider": "anthropic", "name": fmt.Sprintf("claude-opus-private-%03d", i)})
		}
		json.NewEncoder(w).Encode(map[string]any{"models": models, "total": 101})
	}))
	defer srv.Close()
	engine, err := NewEngine(srv.URL, "fixture-admin", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	page, err := mergedProviderCatalog(context.Background(), engine, "anthropic", ModeChat, false, nil, "opus", 100, 1)
	if err != nil || calls != 2 || page.Total <= 101 || len(page.Models) != 100 {
		t.Fatal("native pages and reference models were not merged", page, calls, err)
	}
	foundNative, foundReference := false, false
	for _, model := range page.Models {
		foundNative = foundNative || model.ID == "anthropic/claude-opus-private-000"
		foundReference = foundReference || model.ID == "anthropic/claude-opus-5"
	}
	if !foundNative || !foundReference {
		t.Fatal("missing native or newer reference model")
	}
}
func TestCatalogMergePreservesNativeAndReferenceModels(t *testing.T) {
	provider := "anthropic"
	fixture := &catalogMergeFixture{page: ProviderModelPage{Models: []ProviderModel{{ID: "anthropic/claude-opus-4-1", Name: "claude-opus-4-1"}, {ID: "anthropic/claude-opus-private", Name: "claude-opus-private"}}, Total: 2}}
	page, err := mergedProviderCatalog(context.Background(), fixture, provider, ModeChat, false, nil, "opus", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, model := range page.Models {
		if seen[model.ID] {
			t.Fatal("duplicate", model.ID)
		}
		seen[model.ID] = true
	}
	for _, id := range []string{"anthropic/claude-opus-5", "anthropic/claude-opus-private", "anthropic/claude-opus-4-1"} {
		if !seen[id] {
			t.Fatal("missing", id)
		}
	}
	paged, err := mergedProviderCatalog(context.Background(), fixture, provider, ModeChat, false, nil, "opus", 1, 1)
	if err != nil || paged.Total != page.Total || len(paged.Models) != 1 || paged.Models[0] != page.Models[1] {
		t.Fatal("pagination", paged, err)
	}
}
func TestSavedFoundryCatalogPreservesAliasesAndReferenceFallback(t *testing.T) {
	provider := "custom-00000000-0000-4000-8000-000000000001"
	fixture := &catalogMergeFixture{page: ProviderModelPage{Models: []ProviderModel{{ID: provider + "/my-deployment", Name: "my-deployment"}}, Total: 1}}
	page, err := mergedProviderCatalog(context.Background(), fixture, provider, ModeChat, true, nil, "my-deployment", 50, 0)
	if err != nil || page.Total != 1 || page.Models[0].ID != provider+"/my-deployment" {
		t.Fatal("live alias missing", page, err)
	}
	fixture.err = errEngine
	page, err = mergedProviderCatalog(context.Background(), fixture, provider, ModeChat, true, nil, "claude-opus-5", 50, 0)
	if err != nil || page.Total != 1 || page.Models[0].ID != provider+"/claude-opus-5" {
		t.Fatal("reference fallback missing", page, err)
	}
	page, err = mergedProviderCatalog(context.Background(), fixture, provider, ModeChat, true, []ProviderModel{{ID: provider + "/saved-alias", Name: "saved-alias"}}, "saved-alias", 50, 0)
	if err != nil || page.Total != 1 {
		t.Fatal("configured alias missing", page, err)
	}
}
