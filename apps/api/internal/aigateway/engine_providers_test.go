package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixtureProviderKey(s ProviderKeySpec) map[string]any {
	name, models, _ := nativeProviderSpec(s)
	return map[string]any{"id": s.ID, "name": name, "models": models, "enabled": s.Enabled, "weight": 1, "blacklisted_models": []string{}, "value": map[string]any{"type": "plain_text", "value": "<REDACTED>"}, "status": "success"}
}
func TestProviderEnginePreservesMaskedSecretAndRefusesDrift(t *testing.T) {
	for _, mode := range []string{"valid", "foreign-id", "foreign-name", "future-revision", "raw-secret", "ref-secret", "broader-model", "disabled", "wrong-weight", "batch", "aliases", "native-error", "unknown-test-status", "credential-refused"} {
		t.Run(mode, func(t *testing.T) {
			old := ProviderKeySpec{ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{"openrouter/openai/gpt-4o-mini"}, Enabled: true}
			next := old
			next.Revision = 2
			key := fixtureProviderKey(old)
			writes := 0
			switch mode {
			case "foreign-id":
				key["id"] = "foreign"
			case "foreign-name":
				key["name"] = "foreign"
			case "future-revision":
				key["name"] = old.ID + "-r3"
			case "raw-secret":
				key["value"] = map[string]any{"type": "plain_text", "value": "never-forward-this-raw-secret"}
			case "ref-secret":
				key["value"] = map[string]any{"type": "env", "ref": "env.PRIVATE_KEY", "value": "********"}
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if mode == "native-error" {
					w.WriteHeader(500)
					w.Write([]byte(`{"error":"SECRET_ERROR_MARKER"}`))
					return
				}
				if r.Method == "PUT" {
					writes++
					var payload map[string]any
					if json.NewDecoder(r.Body).Decode(&payload) != nil {
						t.Error("invalid write")
					}
					v, ok := payload["value"].(map[string]any)
					if !ok || v["value"] != "<REDACTED>" {
						t.Error("secret not internally preserved")
					}
					key = fixtureProviderKey(next)
					switch mode {
					case "broader-model":
						key["models"] = []string{"*"}
					case "disabled":
						key["enabled"] = false
					case "wrong-weight":
						key["weight"] = 2
					case "batch":
						key["use_for_batch_api"] = true
					case "aliases":
						key["aliases"] = map[string]any{"a": "b"}
					}
				}
				if strings.HasSuffix(r.URL.Path, "/refresh-models") {
					if mode == "unknown-test-status" {
						key["status"] = "unknown"
					}
					if mode == "credential-refused" {
						key["status"] = "list_models_failed"
					}
				}
				json.NewEncoder(w).Encode(key)
			}))
			defer srv.Close()
			e, _ := NewEngine(srv.URL, "admin", "fixture")
			err := e.PutProviderKey(context.Background(), next, nil)
			if mode == "valid" || mode == "unknown-test-status" || mode == "credential-refused" {
				if err != nil {
					t.Fatal(err)
				}
				ok, err := e.TestProviderKey(context.Background(), next)
				if mode == "unknown-test-status" {
					if err == nil {
						t.Fatal("unknown test accepted")
					}
				} else if mode == "credential-refused" {
					if err != nil || ok {
						t.Fatal("HTTP200 credential failure accepted")
					}
				} else if err != nil || !ok || writes != 1 {
					t.Fatal("valid operation failed")
				}
				return
			}
			if err == nil {
				t.Fatal("drift accepted")
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "never-forward") {
				t.Fatal("secret in error")
			}
			if (mode == "raw-secret" || mode == "ref-secret" || mode == "foreign-id" || mode == "foreign-name" || mode == "future-revision") && writes != 0 {
				t.Fatal("unsafe readback reached mutation")
			}
		})
	}
}
func TestProviderEngineInputScopeAndCatalog(t *testing.T) {
	calls := 0
	mode := "valid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if r.URL.Path != "/api/models" || q.Get("provider") != "openrouter" || q.Get("unfiltered") != "true" || q.Get("limit") != "2" {
			t.Error("catalog scope wrong")
		}
		models := []map[string]any{{"name": "openai/gpt-4o-mini", "provider": "openrouter", "accessible_by_keys": []string{"native-secret-id"}}}
		if mode == "duplicate" {
			models = append(models, models[0])
		}
		if mode == "foreign" {
			models[0]["provider"] = "other"
		}
		json.NewEncoder(w).Encode(map[string]any{"models": models, "total": 1})
	}))
	defer srv.Close()
	e, _ := NewEngine(srv.URL, "admin", "fixture")
	s := ProviderKeySpec{ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{"openrouter/openai/gpt-4o-mini"}, Enabled: true}
	for _, secret := range []string{"", "env.PRIVATE", "vault.path", "has space", "<REDACTED>", strings.Repeat("x", 4097)} {
		if e.PutProviderKey(context.Background(), s, &secret) == nil {
			t.Fatal("invalid secret accepted")
		}
	}
	if e.DeleteProviderKey(context.Background(), s) == nil || calls != 0 {
		t.Fatal("enabled delete or invalid input reached native")
	}
	page, err := e.ProviderModels(context.Background(), "", 2, 0)
	if err != nil || len(page.Models) != 1 || page.Models[0].ID != "openrouter/openai/gpt-4o-mini" {
		t.Fatal("catalog failed")
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "native-secret-id") {
		t.Fatal("native key leaked")
	}
	for _, m := range []string{"duplicate", "foreign"} {
		mode = m
		if _, err = e.ProviderModels(context.Background(), "", 2, 0); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
	before := calls
	if _, err = e.ProviderModels(context.Background(), "", 101, 0); err == nil || calls != before {
		t.Fatal("catalog bound not applied")
	}
}
func TestProviderEngineInitAndCancelledWrite(t *testing.T) {
	created := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/providers" {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["provider"] != "openrouter" || len(body["keys"].([]any)) != 0 {
				t.Error("initializer changed keys")
			}
			created = true
			w.Write([]byte(`{}`))
			return
		}
		if !created {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{"name":"openrouter","network_config":{"max_retries":0}}`))
	}))
	defer srv.Close()
	e, _ := NewEngine(srv.URL, "admin", "fixture")
	if e.EnsureProvider(context.Background()) != nil || !created {
		t.Fatal("initialization failed")
	}
	if e.EnsureProvider(context.Background()) != nil {
		t.Fatal("existing provider failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if e.EnsureProvider(ctx) == nil || time.Since(start) > time.Second {
		t.Fatal("cancel ignored")
	}
}
