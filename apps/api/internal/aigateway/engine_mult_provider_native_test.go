package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// Only local provider protocol fixtures are used; this is not a paid-provider smoke.
func TestEngineNativeCoreFourScopes(t *testing.T) {
	nativeProviderScopeQualification(t, []string{"openai", "anthropic", "gemini", "openrouter"}, []string{"gpt-4o-mini", "claude-sonnet-4-20250514", "gemini-2.0-flash", "openai/gpt-4o-mini"}, false)
}
func TestEngineNativeExpandedProviders(t *testing.T) {
	nativeProviderScopeQualification(t, []string{"groq", "mistral", "cerebras", "xai", "deepseek"}, []string{"llama-3.3-70b-versatile", "mistral-small-latest", "llama3.1-8b", "grok-3-mini", "deepseek-chat"}, true)
}
func nativeProviderScopeQualification(t *testing.T, names, models []string, strictAuth bool) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("explicit pinned native binary required")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != binarySHA256 {
		t.Fatal("pin mismatch")
	}
	providers := map[string]any{}
	arrivals := make([]atomic.Int32, len(names))
	for i, name := range names {
		i, name := i, name
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strictAuth {
				prefix := ""
				if name == "groq" {
					prefix = "/openai"
				}
				path := prefix + "/v1/chat/completions"
				if r.Method == "GET" {
					path = prefix + "/v1/models"
				}
				if name == "deepseek" {
					path = "/chat/completions"
					if r.Method == "GET" {
						path = "/models"
					}
				}
				if r.URL.Path != path {
					t.Errorf("%s unexpected native route %s", name, r.URL.Path)
					w.WriteHeader(404)
					return
				}
			}

			credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if name == "anthropic" {
				credential = r.Header.Get("x-api-key")
			}
			if name == "gemini" {
				credential = r.Header.Get("x-goog-api-key")
			}
			// Unauthenticated catalog fetches are allowed by some native adapters, but
			// authenticated refresh and every inference must carry the actual key.
			if credential != "fixture-"+name && (strictAuth || credential != "" || r.Method != "GET") {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"message":"fixture refused","type":"authentication_error","code":401}}`)
				return
			}
			if r.Method == "GET" {
				if name == "gemini" {
					fmt.Fprintf(w, `{"models":[{"name":"models/%s","displayName":"Fixture","supportedGenerationMethods":["generateContent"]}]}`, models[i])
				} else {
					fmt.Fprintf(w, `{"data":[{"id":"%s","name":"Fixture","type":"model"}],"has_more":false}`, models[i])
				}
				return
			}
			arrivals[i].Add(1)
			var request struct {
				Stream bool `json:"stream"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.Stream || strings.Contains(r.URL.Path, "streamGenerateContent") {
				w.Header().Set("Content-Type", "text/event-stream")
				switch name {
				case "anthropic":
					events := []string{`{"type":"message_start","message":{"id":"msg_fixture","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"qualified"}}`, `{"type":"content_block_stop","index":0}`, `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`, `{"type":"message_stop"}`}
					for _, event := range events {
						var kind struct {
							Type string `json:"type"`
						}
						_ = json.Unmarshal([]byte(event), &kind)
						fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind.Type, event)
					}
				case "gemini":
					fmt.Fprint(w, "data: "+`{"candidates":[{"content":{"role":"model","parts":[{"text":"qualified"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}`+"\n\n")
				default:
					fmt.Fprintf(w, "data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", `{"id":"chatcmpl_fixture","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"qualified"},"finish_reason":null}]}`, `{"id":"chatcmpl_fixture","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
				}
				return
			}
			switch name {
			case "anthropic":
				io.WriteString(w, `{"id":"msg_fixture","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"qualified"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
			case "gemini":
				io.WriteString(w, `{"candidates":[{"content":{"role":"model","parts":[{"text":"qualified"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}`)
			default:
				fmt.Fprintf(w, `{"id":"chatcmpl_fixture","object":"chat.completion","model":"%s","choices":[{"index":0,"message":{"role":"assistant","content":"qualified"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, models[i])
			}
		}))
		defer fixture.Close()
		fixtureBase := fixture.URL
		if name == "groq" {
			fixtureBase += "/openai"
		}
		providers[name] = map[string]any{"network_config": map[string]any{"base_url": fixtureBase, "allow_private_network": true, "max_retries": 0}, "keys": []any{}}
	}
	dir := t.TempDir()
	write := func(name string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("prices.json", map[string]any{})
	write("params.json", map[string]any{})
	config := map[string]any{"encryption_key": "fixture-encryption-key-32-bytes-only", "client": map[string]any{"enforce_auth_on_inference": true, "enable_logging": false, "disable_content_logging": true}, "config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}}, "framework": map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "prices.json"), "model_parameters_url": "file://" + filepath.Join(dir, "params.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}}, "governance": map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": false}}, "providers": providers}
	write("config.json", config)
	base, stop := startEngine(t, binary, dir)
	defer func() { stop() }()
	engine, err := NewEngine(base, "fixture-admin", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scopes := []EngineProviderScope{}
	for i, name := range names {
		if err = engine.EnsureProvider(ctx, name, ""); err != nil {
			t.Fatalf("%s init: %v", name, err)
		}
		spec := ProviderKeySpec{Provider: name, ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{name + "/" + models[i]}, Enabled: true}
		secret := "fixture-" + name
		if err = engine.PutProviderKey(ctx, spec, &secret); err != nil {
			t.Fatalf("%s create: %v", name, err)
		}
		if ok, e := engine.TestProviderKey(ctx, spec); e != nil || !ok {
			t.Fatalf("%s valid credential failed: %v", name, e)
		}
		spec.Revision++
		bad := "invalid-fixture-key"
		if err = engine.PutProviderKey(ctx, spec, &bad); err != nil {
			t.Fatal(err)
		}
		if ok, e := engine.TestProviderKey(ctx, spec); e != nil || ok {
			t.Fatalf("%s bad credential not refused: %v", name, e)
		}
		spec.Revision++
		if err = engine.PutProviderKey(ctx, spec, &secret); err != nil {
			t.Fatal(err)
		}
		page, catalogErr := engine.ProviderModels(ctx, name, models[i], 100, 0)
		if catalogErr != nil || len(page.Models) == 0 {
			t.Fatalf("%s catalog unavailable: %v", name, catalogErr)
		}
		found := false
		for _, model := range page.Models {
			if !strings.HasPrefix(model.ID, name+"/") {
				t.Fatal("catalog crossed provider boundary")
			}
			if model.ID == name+"/"+models[i] {
				found = true
			}
		}
		if !found {
			t.Fatal("canonical catalog model missing")
		}
		scopes = append(scopes, EngineProviderScope{Provider: name, Models: []string{models[i]}, KeyIDs: []string{spec.ID}})
	}
	key, err := engine.EnsureScopedKey(ctx, "fixture-mixed-provider", scopes[:1])
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := engine.readKey(ctx, key.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	originalConfigID := original.ProviderConfigs[0].ID
	expanded, err := engine.EnsureScopedKey(ctx, "fixture-mixed-provider", scopes)
	if err != nil || expanded != key {
		t.Fatalf("add provider changed identity or failed: %v", err)
	}
	readback, _, err := engine.readKey(ctx, key.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range readback.ProviderConfigs {
		if pc.Provider == names[0] && pc.ID != originalConfigID {
			t.Fatal("retained provider config ID changed")
		}
	}
	infer := func(i int, wantOK bool) {
		t.Helper()
		body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"fixture"}],"max_tokens":4}`, names[i]+"/"+models[i])
		r, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key.Value)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
		response.Body.Close()
		if wantOK {
			var reply struct {
				Error   json.RawMessage `json:"error"`
				Choices []struct {
					Message struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"message"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
			}
			if response.StatusCode != 200 || json.Unmarshal(b, &reply) != nil || (len(reply.Error) > 0 && string(reply.Error) != "null") || len(reply.Choices) != 1 || reply.Choices[0].Message.Role != "assistant" || reply.Choices[0].Message.Content != "qualified" || reply.Choices[0].FinishReason != "stop" {
				t.Fatalf("%s invalid completion status %d", names[i], response.StatusCode)
			}
		}
		if !wantOK && response.StatusCode != 403 {
			t.Fatalf("removed provider expected403 got%d", response.StatusCode)
		}
	}
	for i := range names {
		infer(i, true)
		if arrivals[i].Load() != 1 {
			t.Fatal("missing native authenticated inference")
		}
	}
	for i := range names {
		body := fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"fixture"}],"max_tokens":4}`, names[i]+"/"+models[i])
		r, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key.Value)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("%s streaming status%d", names[i], response.StatusCode)
		}
		if e = qualifiedSSE("/v1/chat/completions", response.Header.Get("Content-Type"), string(b)); e != nil {
			t.Fatalf("%s streaming: %v", names[i], e)
		}
		if arrivals[i].Load() != 2 {
			t.Fatal("missing native stream arrival")
		}
	}
	narrowed, err := engine.EnsureScopedKey(ctx, "fixture-mixed-provider", scopes[:1])
	if err != nil || narrowed != key {
		t.Fatalf("remove changed identity: %v", err)
	}
	infer(1, false)
	if arrivals[1].Load() != 2 {
		t.Fatal("removed provider reached upstream")
	}
	stop()
	delete(config, "providers")
	write("config.json", config)
	base, stop = startEngine(t, binary, dir)
	engine, err = NewEngine(base, "fixture-admin", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := engine.EnsureScopedKey(ctx, "fixture-mixed-provider", scopes[:1])
	if err != nil || recovered != key {
		t.Fatalf("restart identity changed: %v", err)
	}
	infer(0, true)
	infer(2, false)
	t.Logf("%d native provider protocols (JSON + SSE), catalog and refresh refusal passed; scope add/remove/restart preserved identity; synthetic fixtures only", len(names))
}
