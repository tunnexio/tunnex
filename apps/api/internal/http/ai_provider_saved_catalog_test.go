package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// savedCatalogEngine is a provider engine with the saved-key catalog. It never
// sees or returns a provider key.
type savedCatalogEngine struct {
	userAccessEngine
	mu      sync.Mutex
	fail    bool
	calls   int
	retains []aigateway.ProviderModel
}

func (*savedCatalogEngine) EnsureProvider(context.Context, string, string) error { return nil }
func (*savedCatalogEngine) PutProviderKey(context.Context, aigateway.ProviderKeySpec, *string) error {
	return nil
}
func (*savedCatalogEngine) VerifyProviderKey(context.Context, aigateway.ProviderKeySpec) error {
	return nil
}
func (*savedCatalogEngine) TestProviderKey(context.Context, aigateway.ProviderKeySpec) (bool, error) {
	return true, nil
}
func (*savedCatalogEngine) DeleteProviderKey(context.Context, aigateway.ProviderKeySpec) error {
	return nil
}
func (e *savedCatalogEngine) ProviderModels(context.Context, string, string, int, int) (aigateway.ProviderModelPage, error) {
	return aigateway.ProviderModelPage{Models: e.retains, Total: len(e.retains)}, nil
}
func (e *savedCatalogEngine) SavedProviderCatalog(_ context.Context, s aigateway.ProviderKeySpec, _ aigateway.ModelMode, _ string, _, _ int) (aigateway.ProviderModelPage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	if e.fail {
		return aigateway.ProviderModelPage{}, errors.New("engine-detail-never-public")
	}
	return aigateway.ProviderModelPage{Models: []aigateway.ProviderModel{{ID: s.Provider + "/live-only", Name: s.Provider + "/live-only"}}, Total: 1}, nil
}
func (e *savedCatalogEngine) engineCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func TestAIProviderModelsSavedStandardConnection(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, other := uuid.New(), uuid.New()
	groq, foreign := uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []uuid.UUID{org, other} {
		exec(`INSERT INTO organizations(id,name,slug,ai_gateway_enabled) VALUES($1,'Fixture',$2,true)`, o, "fixture-"+o.String())
	}
	insert := func(id, owner uuid.UUID, provider string) {
		exec(`INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,applied_revision,status) VALUES($1,$2,$3,$4,'Fixture',ARRAY[$5],true,1,1,'applied')`, id, owner, "tnx-managed-"+id.String(), provider, provider+"/existing")
	}
	insert(groq, org, "groq")
	insert(foreign, other, "groq")
	engine := &savedCatalogEngine{}
	policies := aigateway.NewPolicies(pool, nil, engine)
	policies.EnableProviderManagement(true)
	srv := aiSocketServer(t, Deps{AIPolicies: policies, AuthFn: func(r *http.Request) *authctx.Principal {
		role := r.Header.Get("X-Fixture-Role")
		if role == "" {
			return nil
		}
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: role}}
	}})
	get := func(t *testing.T, query, role string) (int, api.AIProviderModelList, string) {
		t.Helper()
		res := aiSocketRequest(t, srv, "GET", "/api/v1/organizations/"+org.String()+"/ai-gateway/models?"+query, "", "", role)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out api.AIProviderModelList
		if res.StatusCode == 200 && json.Unmarshal(raw, &out) != nil {
			t.Fatal("decode", string(raw))
		}
		return res.StatusCode, out, string(raw)
	}
	reset := func() {
		if err := policies.ConfigureNativeProviderOperations(); err != nil {
			t.Fatal(err)
		}
		engine.mu.Lock()
		engine.fail = false
		engine.mu.Unlock()
	}

	t.Run("live", func(t *testing.T) {
		reset()
		code, out, raw := get(t, "provider=groq&connection_id="+groq.String(), "owner")
		if code != 200 || out.Source == nil || *out.Source != api.AIProviderModelListSourceProvider || len(out.Items) != 1 || out.Items[0].Id != "groq/live-only" {
			t.Fatal(code, raw)
		}
	})
	t.Run("live-failure-falls-back", func(t *testing.T) {
		reset()
		engine.mu.Lock()
		engine.fail = true
		engine.mu.Unlock()
		code, out, raw := get(t, "provider=groq&connection_id="+groq.String()+"&query=gemma", "owner")
		_, plain, _ := get(t, "provider=groq&query=gemma", "owner")
		if code != 200 || out.Source == nil || *out.Source != api.AIProviderModelListSourceReference || len(out.Items) == 0 || out.Total != plain.Total {
			t.Fatal(code, raw)
		}
		for _, item := range out.Items {
			if !strings.HasPrefix(item.Id, "groq/") || item.Id == "groq/live-only" {
				t.Fatal("fallback is not the reference list", item.Id)
			}
		}
		if strings.Contains(raw, "engine-detail-never-public") {
			t.Fatal("engine detail escaped")
		}
	})
	t.Run("refused", func(t *testing.T) {
		for _, tc := range []struct {
			name, query, role string
			want              int
		}{
			{"other-org-connection", "provider=groq&connection_id=" + foreign.String(), "owner", 404},
			{"missing-connection", "provider=groq&connection_id=" + uuid.NewString(), "owner", 404},
			{"provider-mismatch", "provider=openai&connection_id=" + groq.String(), "owner", 400},
			{"anonymous", "provider=groq&connection_id=" + groq.String(), "", 401},
		} {
			t.Run(tc.name, func(t *testing.T) {
				reset()
				before := engine.engineCalls()
				code, _, raw := get(t, tc.query, tc.role)
				if code != tc.want || engine.engineCalls() != before {
					t.Fatalf("status=%d want=%d engine calls=%d %s", code, tc.want, engine.engineCalls()-before, raw)
				}
			})
		}
	})
	t.Run("viewer-gets-reference-without-provider-call", func(t *testing.T) {
		reset()
		engine.mu.Lock()
		savedBefore := engine.calls
		engine.mu.Unlock()
		code, out, raw := get(t, "provider=groq&connection_id="+groq.String(), "ai-view")
		engine.mu.Lock()
		savedAfter := engine.calls
		engine.mu.Unlock()
		if code != 200 || out.Source == nil || *out.Source != api.AIProviderModelListSourceReference || savedAfter != savedBefore {
			t.Fatalf("status=%d saved-catalog calls=%d %s", code, savedAfter-savedBefore, raw)
		}
		for _, item := range out.Items {
			if item.Id == "groq/live-only" {
				t.Fatal("a viewer received the live list", raw)
			}
		}
	})
	t.Run("other-paths-carry-no-source", func(t *testing.T) {
		reset()
		before := engine.engineCalls()
		for _, query := range []string{"provider=groq", "provider=groq&mode=embedding", "provider=azure_foundry"} {
			code, out, raw := get(t, query, "owner")
			if code != 200 || out.Source != nil || strings.Contains(raw, `"source"`) {
				t.Fatal(query, code, raw)
			}
		}
		// Endpoint providers keep their connection-scoped catalog and errors.
		if code, _, raw := get(t, "provider=custom", "owner"); code != 400 || strings.Contains(raw, `"source"`) {
			t.Fatal("custom without a connection", code, raw)
		}
		if code, _, raw := get(t, "provider=custom&connection_id="+groq.String(), "owner"); code == 200 || strings.Contains(raw, `"source"`) {
			t.Fatal("custom catalog served a standard connection", code, raw)
		}
		if engine.engineCalls() != before {
			t.Fatal("saved catalog called outside the standard connection path")
		}
	})
}
