package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The native proxy fixture validates mandatory CONNECT routing; aiegress tests
// independently exercise destination resolution/address enforcement.
func TestEngineNativeCustomProxy(t *testing.T) {
	for _, tls := range []bool{false, true} {
		name := "HTTP"
		if tls {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) { nativeCustomProxy(t, tls, "") })
	}
	t.Run("FoundryOpenAIV1", func(t *testing.T) { nativeCustomProxy(t, true, "/openai") })
}
func nativeCustomProxy(t *testing.T, useTLS bool, prefix string) {
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
	var arrivals, tunnels atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-custom-secret" {
			w.WriteHeader(401)
			return
		}
		wantPath := prefix + "/v1/chat/completions"
		if r.Method == http.MethodGet {
			wantPath = prefix + "/v1/models"
		}
		if r.URL.Path != wantPath || r.URL.RawQuery != "" {
			t.Errorf("unexpected upstream path: %s", r.URL.RequestURI())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		arrivals.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `{"data":[{"id":"fixture-model"}]}`)
			return
		}
		var request struct {
			Stream bool   `json:"stream"`
			Model  string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Model != "fixture-model" {
			t.Errorf("upstream model was not the raw deployment: %q", request.Model)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: "+`{"choices":[{"index":0,"delta":{"content":"qualified"},"finish_reason":null}]}`+"\n\ndata: "+`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n")
			return
		}
		io.WriteString(w, `{"id":"fixture","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"qualified"},"finish_reason":"stop"}]}`)
	}))
	if useTLS {
		upstream.StartTLS()
	} else {
		upstream.Start()
	}
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != u.Host || r.Header.Get("Proxy-Authorization") != "Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcGFzc3dvcmQ=" {
			w.WriteHeader(403)
			return
		}
		c, e := net.Dial("tcp", u.Host)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer c.Close()
		h, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer h.Close()
		tunnels.Add(1)
		buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		done := make(chan struct{})
		go func() { io.Copy(c, buf); close(done) }()
		io.Copy(h, c)
		h.Close()
		c.Close()
		<-done
	}))
	defer proxy.Close()
	dir := t.TempDir()
	env := []string{}
	if useTLS {
		certPath := filepath.Join(dir, "ca.pem")
		if os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600) != nil {
			t.Fatal("certificate write")
		}
		env = append(env, "SSL_CERT_FILE="+certPath)
	}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if os.WriteFile(filepath.Join(dir, name), b, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	write("prices.json", map[string]any{})
	write("params.json", map[string]any{})
	write("config.json", map[string]any{"encryption_key": "fixture-encryption-key-32-bytes-only", "client": map[string]any{"enforce_auth_on_inference": true, "disable_content_logging": true}, "config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}}, "framework": map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "prices.json"), "model_parameters_url": "file://" + filepath.Join(dir, "params.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}}, "governance": map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": false}}})
	pu, _ := url.Parse(proxy.URL)
	pu.User = url.UserPassword("fixture-user", "fixture-password")
	env = append(env, "TUNNEX_AI_CUSTOM_PROXY_URL="+pu.String())
	base, stop := startEngine(t, binary, dir, env...)
	defer stop()
	engine, e := NewEngine(base, "fixture-admin", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.ConfigureCustomProxy(pu.String()); e != nil {
		t.Fatal(e)
	}
	provider := "custom-" + uuid.NewString()
	upstreamBase := upstream.URL + prefix
	ctx := context.Background()
	if e = engine.EnsureProvider(ctx, provider, upstreamBase); e != nil {
		t.Fatal("custom init", e)
	}
	spec := ProviderKeySpec{Provider: provider, BaseURL: upstreamBase, ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{provider + "/fixture-model"}, Enabled: true}
	secret := "fixture-custom-secret"
	if e = engine.PutProviderKey(ctx, spec, &secret); e != nil {
		t.Fatal("custom key", e)
	}
	if ok, e := engine.TestProviderKey(ctx, spec); e != nil || !ok {
		t.Fatal("custom auth", e)
	}
	key, e := engine.EnsureKey(ctx, "custom-fixture-key", provider, []string{"fixture-model"}, []string{spec.ID})
	if e != nil {
		t.Fatal(e)
	}
	infer := func() int {
		r, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"`+provider+`/fixture-model","messages":[{"role":"user","content":"fixture"}]} `))
		r.Header.Set("Authorization", "Bearer "+key.Value)
		r.Header.Set("Content-Type", "application/json")
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		var body struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
				Finish string `json:"finish_reason"`
			} `json:"choices"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if resp.StatusCode == 200 && (len(body.Error) > 0 || len(body.Choices) != 1 || body.Choices[0].Message.Content != "qualified" || body.Choices[0].Finish != "stop") {
			t.Fatal("invalid native completion")
		}
		return resp.StatusCode
	}
	if infer() != 200 || tunnels.Load() == 0 {
		t.Fatal("custom inference missing authenticated tunnel")
	}
	r, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(`{"model":"`+provider+`/fixture-model","stream":true,"messages":[{"role":"user","content":"fixture"}]}`))
	r.Header.Set("Authorization", "Bearer "+key.Value)
	r.Header.Set("Content-Type", "application/json")
	response, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	stream, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("custom stream status")
	}
	assertQualifiedSSE(t, "/v1/chat/completions", response.Header.Get("Content-Type"), string(stream))
	// Stop the native process to close pooled tunnels, then stop only this fixture proxy.
	stop()
	proxy.Close()
	before := arrivals.Load()
	base, stop = startEngine(t, binary, dir, env...)
	defer stop()
	if infer() == 200 || arrivals.Load() != before {
		t.Fatal("dead proxy fell through to direct upstream")
	}
	stop()
	for _, badEnv := range []string{"absent", "", "malformed-proxy-url"} {
		invalidEnv := []string{}
		for _, entry := range env {
			if !strings.HasPrefix(entry, "TUNNEX_AI_CUSTOM_PROXY_URL=") {
				invalidEnv = append(invalidEnv, entry)
			}
		}
		if badEnv != "absent" {
			invalidEnv = append(invalidEnv, "TUNNEX_AI_CUSTOM_PROXY_URL="+badEnv)
		}
		base, stop = startEngine(t, binary, dir, invalidEnv...)
		check, e := NewEngine(base, "fixture-admin", "fixture-password")
		if e != nil {
			t.Fatal(e)
		}
		if check.ConfigureCustomProxy(pu.String()) != nil {
			t.Fatal("fixture proxy config")
		}
		if check.EnsureProvider(ctx, provider, upstreamBase) == nil {
			t.Fatal("invalid native proxy environment accepted by readback")
		}
		if infer() == 200 || arrivals.Load() != before {
			t.Fatal("invalid native proxy environment fell through to direct")
		}
		stop()
	}
	t.Log("custom HTTP native credential/catalog/inference uses authenticated CONNECT; stopped proxy refuses without direct upstream")
}
