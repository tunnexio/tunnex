package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/maximhq/bifrost/core/schemas"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic local providers exercise the actual pinned Bifrost transports. No
// paid provider calls or network credentials are used by these tests.
func TestTunnexNativeProbeModes(t *testing.T) {
	for _, tc := range []struct{ mode, path, body string }{
		{"chat", "/chat/completions", `{"id":"fixture","object":"chat.completion","model":"fixture","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"OK"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`},
		{"completion", "/completions", `{"id":"fixture","object":"text_completion","model":"fixture","choices":[{"index":0,"finish_reason":"stop","text":"OK"}]}`},
		{"embedding", "/embeddings", `{"object":"list","model":"fixture","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}]}`},
		{"audio_speech", "/audio/speech", string(tunnexWAV())},
		{"audio_transcription", "/audio/transcriptions", `{"text":"OK"}`},
		{"image_generation", "/images/generations", `{"created":1,"data":[{"b64_json":"` + base64.StdEncoding.EncodeToString([]byte("fixture-image")) + `"}]}`},
		{"video_generation", "/videos", `{"id":"fixture-video","object":"video","model":"fixture","status":"queued"}`},
		{"rerank", "/rerank", `{"id":"fixture","results":[{"index":0,"relevance_score":0.9}]}`},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, tc.path) || r.Header.Get("Authorization") != "Bearer fixture-private-key" {
					t.Errorf("unexpected transport %s %s", r.Method, r.URL.Path)
				}
				if tc.mode == "audio_speech" {
					w.Header().Set("Content-Type", "audio/wav")
				} else {
					w.Header().Set("Content-Type", "application/json")
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: srv.URL, AllowPrivateNetwork: true}}
			if tc.mode == "rerank" {
				cfg.CustomProviderConfig = &schemas.CustomProviderConfig{CustomProviderKey: "fixture-rerank", BaseProviderType: "openai", AllowedRequests: &schemas.AllowedRequests{Rerank: true}}
			}
			out := tunnexProbe(tunnexOperation{Provider: "openai", Model: "openai/fixture", Mode: tc.mode, Secret: "fixture-private-key"}, cfg)
			if out.Status != "success" || out.Failure != nil || calls != 1 {
				t.Fatalf("mode %s status=%s failure=%+v calls=%d", tc.mode, out.Status, out.Failure, calls)
			}
		})
	}
}
func TestTunnexProbeSanitizesProviderFailure(t *testing.T) {
	for _, code := range []int{401, 403, 429, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":{"message":"fixture-private-key upstream details"}}`))
		}))
		cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: srv.URL, AllowPrivateNetwork: true}}
		out := tunnexProbe(tunnexOperation{Provider: "openai", Model: "openai/fixture", Mode: "chat", Secret: "fixture-private-key"}, cfg)
		raw, _ := json.Marshal(out)
		if out.Status != "error" || out.Failure == nil || out.Failure.HTTPStatus == nil || *out.Failure.HTTPStatus != code || strings.Contains(string(raw), "fixture-private-key") {
			t.Fatalf("unsafe failure %s", raw)
		}
		srv.Close()
	}
}
func TestTunnexEndpointTypeAndCredentialBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"public_https":true,"endpoints":[{"url":"http://private.test","provider":"sagemaker"}]}`), 0600)
	t.Setenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE", path)
	for _, tc := range []struct {
		provider, endpoint string
		want               bool
	}{
		{"custom", "http://private.test", false}, {"sagemaker", "http://private.test", true},
		{"azure_foundry", "https://resource.services.ai.azure.com/openai", true},
		{"azure_foundry", "https://unrelated.test/openai", false},
		{"custom", "https://resource.services.ai.azure.com/anthropic", false},
		{"custom", "https://user:pass@provider.test", false},
		{"custom", "https://provider.test?override=x", false},
	} {
		if got := tunnexEndpointAllowed(tc.provider, tc.endpoint); got != tc.want {
			t.Fatalf("%s %s=%v", tc.provider, tc.endpoint, got)
		}
	}
	if tunnexSecret("env.SECRET") || tunnexSecret("fixture key") || tunnexSecret("") {
		t.Fatal("secret reference accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := tunnexFailure(ctx, &schemas.BifrostError{Error: &schemas.ErrorField{Message: "private-key"}})
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), "private-key") {
		t.Fatal("message leaked")
	}
}

func TestTunnexNineNativeProviderChatTransports(t *testing.T) {
	for _, kind := range []string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch kind {
				case "anthropic":
					if r.Header.Get("x-api-key") != "fixture-private-key" || r.Header.Get("anthropic-version") == "" || r.Header.Get("Authorization") != "" {
						t.Error("anthropic authentication")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"id":"fixture","type":"message","role":"assistant","model":"fixture","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
				case "gemini":
					if r.Header.Get("x-goog-api-key") != "fixture-private-key" {
						t.Error("gemini authentication")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1,"totalTokenCount":2}}`))
				default:
					if r.Header.Get("Authorization") != "Bearer fixture-private-key" {
						t.Error("OpenAI protocol authentication")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"id":"fixture","object":"chat.completion","model":"fixture","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"OK"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
				}
			}))
			defer server.Close()
			cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: server.URL, AllowPrivateNetwork: true}}
			out := tunnexProbe(tunnexOperation{Provider: kind, Model: kind + "/fixture", Mode: "chat", Secret: "fixture-private-key"}, cfg)
			if out.Status != "success" || calls != 1 {
				t.Fatalf("%s: status %s, failure %+v, calls %d", kind, out.Status, out.Failure, calls)
			}
		})
	}
}
func TestTunnexProbeResponseBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": "fixture", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": strings.Repeat("x", (1<<20)+1)}}}})
	}))
	defer server.Close()
	cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: server.URL, AllowPrivateNetwork: true}}
	out := tunnexProbe(tunnexOperation{Provider: "openai", Model: "openai/fixture", Mode: "chat", Secret: "fixture-private-key"}, cfg)
	if out.Status != "error" || out.Failure == nil {
		t.Fatal("oversized provider response accepted")
	}
}

func TestTunnexFoundryNativeAuthenticatedTLSConnect(t *testing.T) {
	for _, suffix := range []string{"/openai", "/anthropic"} {
		t.Run(suffix, func(t *testing.T) {
			host := "fixture.services.ai.azure.com"
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			calls, tunnels := 0, 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				want := suffix + "/v1/chat/completions"
				if suffix == "/anthropic" {
					want = suffix + "/v1/messages"
					if r.Header.Get("x-api-key") != "fixture-private-key" || r.Header.Get("anthropic-version") == "" || r.Header.Get("Authorization") != "" {
						t.Error("Foundry Anthropic credential transport")
					}
				} else if r.Header.Get("Authorization") != "Bearer fixture-private-key" {
					t.Error("Foundry OpenAI credential transport")
				}
				if r.URL.Path != want {
					t.Errorf("provider path %s want %s", r.URL.Path, want)
				}
				w.Header().Set("Content-Type", "application/json")
				if suffix == "/anthropic" {
					w.Write([]byte(`{"id":"fixture","type":"message","role":"assistant","model":"fixture","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
				} else {
					w.Write([]byte(`{"id":"fixture","object":"chat.completion","model":"fixture","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"OK"}}]}`))
				}
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.StartTLS()
			defer server.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != host+":443" || r.Header.Get("Proxy-Authorization") != "Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcGFzc3dvcmQ=" {
					w.WriteHeader(403)
					return
				}
				remote, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					w.WriteHeader(502)
					return
				}
				client, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					remote.Close()
					return
				}
				tunnels++
				client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { io.Copy(remote, client); remote.Close() }()
				io.Copy(client, remote)
				client.Close()
			}))
			defer proxy.Close()
			path := filepath.Join(t.TempDir(), "policy.json")
			endpoint := "https://" + host + suffix
			raw, _ := json.Marshal(map[string]any{"endpoints": []any{map[string]string{"provider": "azure_foundry", "url": endpoint}}})
			os.WriteFile(path, raw, 0600)
			t.Setenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE", path)
			t.Setenv("TUNNEX_AI_CUSTOM_PROXY_URL", strings.Replace(proxy.URL, "http://", "http://fixture-user:fixture-password@", 1))
			cfg := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{CACertPEM: schemas.NewSecretVar(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))}}
			in := tunnexOperation{Provider: "azure_foundry", Model: "fixture", Mode: "chat", Secret: "fixture-private-key", Endpoint: endpoint}
			if !tunnexValidate(in, false) {
				t.Fatal("installation endpoint refused")
			}
			out := tunnexProbe(in, cfg)
			if out.Status != "success" || calls != 1 || tunnels != 1 {
				t.Fatalf("TLS CONNECT status %s failure %+v calls %d tunnels %d", out.Status, out.Failure, calls, tunnels)
			}
		})
	}
}

// The saved-key catalog shares the draft listing. A stored provider config
// points the native transport at a synthetic provider; the key never returns.
func TestTunnexCatalogSavedConfigListsWithoutKey(t *testing.T) {
	for _, kind := range []string{"openai", "groq"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/models") || r.Header.Get("Authorization") != "Bearer fixture-private-key" {
					t.Errorf("unexpected list transport %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"object":"list","data":[{"id":"zeta","object":"model"},{"id":"alpha","object":"model"},{"id":"leak-fixture-private-key","object":"model"},{"id":"beta","object":"model"}]}`))
			}))
			defer server.Close()
			native := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: server.URL, AllowPrivateNetwork: true}}
			in := tunnexOperation{Provider: kind, Mode: "chat", Secret: "fixture-private-key", Query: "", Limit: 2, Offset: 0}
			if !tunnexValidate(in, true) {
				t.Fatal("catalog input refused")
			}
			code, body := tunnexCatalog(in, native)
			raw, _ := json.Marshal(body)
			if code != 200 || calls == 0 || strings.Contains(string(raw), "fixture-private-key") {
				t.Fatalf("code %d calls %d body %s", code, calls, raw)
			}
			want := `{"items":[{"id":"` + kind + `/alpha","name":"` + kind + `/alpha"},{"id":"` + kind + `/beta","name":"` + kind + `/beta"}],"limit":2,"offset":0,"total":3}`
			if string(raw) != want {
				t.Fatalf("got %s want %s", raw, want)
			}
			in.Query, in.Offset = "ZET", 0
			if code, body = tunnexCatalog(in, native); code != 200 || body["total"] != 1 {
				t.Fatalf("query filter %d %v", code, body)
			}
		})
	}
}
func TestTunnexCatalogSanitizesProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"message":"fixture-private-key rejected"}}`))
	}))
	defer server.Close()
	native := &schemas.ProviderConfig{NetworkConfig: schemas.NetworkConfig{BaseURL: server.URL, AllowPrivateNetwork: true}}
	code, body := tunnexCatalog(tunnexOperation{Provider: "groq", Mode: "chat", Secret: "fixture-private-key", Limit: 50}, native)
	if code != 503 || body != nil {
		t.Fatalf("provider failure surfaced: %d %v", code, body)
	}
}
func TestTunnexSavedSecretBindsKeyRevisionAndState(t *testing.T) {
	on, off := true, false
	id := "tnx-managed-00000000-0000-4000-8000-000000000001"
	key := func(id, name string, enabled *bool, models ...string) schemas.Key {
		return schemas.Key{ID: id, Name: name, Value: *schemas.NewSecretVar("fixture-private-key"), Enabled: enabled, Models: models}
	}
	for _, tc := range []struct {
		name, id, keyName string
		keys              []schemas.Key
		want              string
	}{
		{"enabled", id, id + "-r2", []schemas.Key{key(id, id+"-r2", &on, "existing")}, "fixture-private-key"},
		{"disabled-without-models", id, id + "-r2", []schemas.Key{key(id, id+"-r2", &off)}, "fixture-private-key"},
		{"disabled-with-models", id, id + "-r2", []schemas.Key{key(id, id+"-r2", &off, "existing")}, ""},
		{"unknown-state", id, id + "-r2", []schemas.Key{key(id, id+"-r2", nil)}, ""},
		{"stale-revision", id, id + "-r1", []schemas.Key{key(id, id+"-r2", &on)}, ""},
		{"other-key", id, id + "-r2", []schemas.Key{key("tnx-managed-other", id+"-r2", &on)}, ""},
		{"unowned-key", "operator-key", "operator-key-r2", []schemas.Key{key("operator-key", "operator-key-r2", &on)}, ""},
		{"empty-name", id, "", []schemas.Key{key(id, "", &on)}, ""},
	} {
		if got := tunnexSavedSecret(tc.keys, tc.id, tc.keyName); got != tc.want {
			t.Fatalf("%s: got %q", tc.name, got)
		}
	}
}
