package aigateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

type savedCatalogFixture struct {
	*providerFixtureEngine
	calls int
	spec  ProviderKeySpec
	fail  bool
}

func (e *savedCatalogFixture) SavedProviderCatalog(_ context.Context, s ProviderKeySpec, mode ModelMode, query string, limit, offset int) (ProviderModelPage, error) {
	e.calls++
	e.spec = s
	if e.fail {
		return ProviderModelPage{}, errors.New("engine-detail-never-public")
	}
	return ProviderModelPage{Models: []ProviderModel{{ID: "groq/live-model", Name: "groq/live-model"}}, Total: 1}, nil
}

func TestAISavedProviderCatalogPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	e := &savedCatalogFixture{providerFixtureEngine: newProviderFixtureEngine()}
	f.policies.engine = e
	f.policies.EnableProviderManagement(true)
	secret := "synthetic-saved-key"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "groq", Name: "Saved Groq", Models: []string{"groq/existing"}, Secret: &secret, Enabled: true})
	if err != nil || p.Status != "applied" {
		t.Fatal("fixture create", err)
	}
	reset := func() {
		if err := f.policies.ConfigureNativeProviderOperations(); err != nil {
			t.Fatal(err)
		}
		e.fail = false
	}

	t.Run("live", func(t *testing.T) {
		reset()
		before := e.calls
		page, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0)
		if err != nil || !live || e.calls != before+1 || len(page.Models) != 1 || page.Models[0].ID != "groq/live-model" {
			t.Fatal(page, live, err)
		}
		if !reflect.DeepEqual(e.spec, providerSpec(p)) {
			t.Fatal("engine was not given the saved key's exact scope")
		}
	})
	t.Run("live-failure-falls-back-to-merged", func(t *testing.T) {
		reset()
		e.fail = true
		want, err := f.policies.ProviderModels(ctx, "groq", "", 50, 0)
		if err != nil || len(want.Models) == 0 {
			t.Fatal("reference fixture", err)
		}
		page, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0)
		if err != nil || live || !reflect.DeepEqual(page, want) {
			t.Fatal("fallback differs from the connection-less list", live, err)
		}
	})
	t.Run("non-chat-fallback-uses-mode-reference", func(t *testing.T) {
		reset()
		e.fail = true
		want, _ := ProviderReferenceModels("groq", ModeAudioTranscription, "", 50, 0)
		page, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeAudioTranscription, "", 50, 0)
		if err != nil || live || !reflect.DeepEqual(page, want) {
			t.Fatal(page, live, err)
		}
	})
	t.Run("limiter-falls-back-without-engine-call", func(t *testing.T) {
		reset()
		for i := 0; i < 6; i++ {
			if _, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0); err != nil || !live {
				t.Fatal("within limit", err)
			}
		}
		before := e.calls
		if _, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0); err != nil || live || e.calls != before {
			t.Fatal("limiter not shared", live, err)
		}
	})
	t.Run("operations-off-falls-back", func(t *testing.T) {
		f.policies.probes = nil
		before := e.calls
		if _, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0); err != nil || live || e.calls != before {
			t.Fatal(live, err)
		}
	})
	for _, tc := range []struct {
		name     string
		org, id  uuid.UUID
		provider string
		status   int
	}{
		{"foreign-org", uuid.New(), p.ID, "groq", 404},
		{"foreign-id", f.org, uuid.New(), "groq", 404},
		{"provider-mismatch", f.org, p.ID, "openai", 400},
		{"endpoint-provider", f.org, p.ID, "custom", 400},
		{"unknown-provider", f.org, p.ID, "other", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			before := e.calls
			_, live, err := f.policies.SavedProviderModels(ctx, tc.org, tc.id, tc.provider, ModeChat, "", 50, 0)
			if usageStatus(err) != tc.status || live || e.calls != before {
				t.Fatalf("status=%d want=%d engine calls=%d", usageStatus(err), tc.status, e.calls-before)
			}
		})
	}
	t.Run("invalid-bounds", func(t *testing.T) {
		reset()
		for _, bad := range []func() (ProviderModelPage, bool, error){
			func() (ProviderModelPage, bool, error) {
				return f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", "other", "", 50, 0)
			},
			func() (ProviderModelPage, bool, error) {
				return f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, strings.Repeat("x", 101), 50, 0)
			},
			func() (ProviderModelPage, bool, error) {
				return f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 101, 0)
			},
			func() (ProviderModelPage, bool, error) {
				return f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, -1)
			},
		} {
			if _, _, err := bad(); usageStatus(err) != 400 {
				t.Fatal("invalid request accepted", err)
			}
		}
	})
	t.Run("disabled-falls-back", func(t *testing.T) {
		reset()
		disabled, err := f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, ProviderInput{Provider: p.Provider, Name: p.Name, Models: p.Models, Enabled: false}, p.Revision)
		if err != nil || disabled.Enabled {
			t.Fatal(err)
		}
		before := e.calls
		if _, live, err := f.policies.SavedProviderModels(ctx, f.org, p.ID, "groq", ModeChat, "", 50, 0); err != nil || live || e.calls != before {
			t.Fatal("disabled credential listed live", live, err)
		}
	})
}

func TestSavedProviderCatalogEngineBoundary(t *testing.T) {
	spec := ProviderKeySpec{Provider: "groq", ID: "tnx-managed-" + uuid.NewString(), Revision: 3, Models: []string{"groq/existing"}, Enabled: true}
	for _, tc := range []struct {
		name, response string
		ok             bool
	}{
		{"valid", `{"items":[{"id":"groq/a","name":"groq/a"},{"id":"groq/b","name":"groq/b"}],"total":2,"limit":50,"offset":0,"api_key":"never-expose"}`, true},
		{"empty", `{"items":[],"total":0,"limit":50,"offset":0}`, true},
		{"foreign-prefix", `{"items":[{"id":"openai/a","name":"openai/a"}],"total":1,"limit":50,"offset":0}`, false},
		{"no-prefix", `{"items":[{"id":"groq","name":"groq"}],"total":1,"limit":50,"offset":0}`, false},
		{"unsorted", `{"items":[{"id":"groq/b","name":"groq/b"},{"id":"groq/a","name":"groq/a"}],"total":2,"limit":50,"offset":0}`, false},
		{"wrong-page", `{"items":[],"total":0,"limit":10,"offset":0}`, false},
		{"missing-items", `{"total":0,"limit":50,"offset":0}`, false},
		{"custom-namespace", `{"items":[{"id":"custom-` + uuid.NewString() + `/a","name":"x"}],"total":1,"limit":50,"offset":0}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(fixtureProviderKey(spec))
					return
				}
				calls++
				time.Sleep(30 * time.Millisecond)
				if r.URL.Path != "/api/tunnex/saved-model-catalog" {
					t.Error("wrong private path", r.URL.Path)
				}
				var in map[string]any
				json.NewDecoder(r.Body).Decode(&in)
				if len(in) != 7 || in["provider"] != "groq" || in["key_id"] != spec.ID || in["key_name"] != spec.ID+"-r3" || in["mode"] != "chat" || in["query"] != "" || in["limit"] != float64(50) || in["offset"] != float64(0) {
					t.Error("unexpected catalog payload", in)
				}
				w.Write([]byte(tc.response))
			}))
			defer srv.Close()
			e, _ := NewEngine(srv.URL, "admin", "fixture")
			// Metadata's short header deadline must not truncate a provider list.
			e.client.Transport.(*http.Transport).ResponseHeaderTimeout = 10 * time.Millisecond
			page, err := e.SavedProviderCatalog(context.Background(), spec, ModeChat, "", 50, 0)
			if calls != 1 {
				t.Fatal("catalog request absent")
			}
			if tc.ok != (err == nil) {
				t.Fatal(page, err)
			}
			encoded, _ := json.Marshal(page)
			if strings.Contains(string(encoded), "never-expose") {
				t.Fatal("engine field reflected")
			}
		})
	}
	t.Run("refused-before-request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				stale := spec
				stale.Revision = 2
				json.NewEncoder(w).Encode(fixtureProviderKey(stale))
				return
			}
			t.Error("catalog requested with a stale, endpoint or invalid key scope")
		}))
		defer srv.Close()
		e, _ := NewEngine(srv.URL, "admin", "fixture")
		endpoint := spec
		endpoint.BaseURL = "https://provider.invalid"
		custom := spec
		custom.Provider = "custom-" + uuid.NewString()
		for _, s := range []ProviderKeySpec{spec, endpoint, custom} {
			if _, err := e.SavedProviderCatalog(context.Background(), s, ModeChat, "", 50, 0); err == nil {
				t.Fatal("refused scope accepted")
			}
		}
		if _, err := e.SavedProviderCatalog(context.Background(), spec, "other", "", 50, 0); err == nil {
			t.Fatal("invalid mode accepted")
		}
	})
}
