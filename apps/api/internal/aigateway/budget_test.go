package aigateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This is a qualification test of native soft thresholds, not a strict-cap test.
// All prices and tokens are synthetic; no provider credentials are read.
func TestBifrostBudgetQualification(t *testing.T) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("set AI0_BIFROST_BINARY to pinned binary")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != binarySHA256 {
		t.Fatal("binary digest mismatch")
	}
	var arrivals atomic.Int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		arrivals.Add(1)
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		if body.Model == "priced" {
			entered <- struct{}{}
			<-release
		}
		if body.Model == "failed" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"fixture rejection","type":"invalid_request_error"}}`)
			return
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"id\":\"budget\",\"object\":\"chat.completion.chunk\",\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n", body.Model)
			w.(http.Flusher).Flush()
			fmt.Fprintf(w, "data: {\"id\":\"budget\",\"object\":\"chat.completion.chunk\",\"model\":%q,\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1,\"total_tokens\":5}}\n\ndata: [DONE]\n\n", body.Model)
			return
		}
		fmt.Fprintf(w, `{"id":"budget","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`, body.Model)
	}))
	defer provider.Close()
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
	prices := map[string]any{}
	for _, model := range []string{"priced", "streamed", "failed"} {
		prices[model] = map[string]any{"provider": "openrouter", "mode": "chat", "input_cost_per_token": 1, "output_cost_per_token": 1}
	}
	write("pricing.json", prices)
	write("parameters.json", map[string]any{})
	keys := []any{}
	for _, id := range []string{"concurrent", "unknown", "stream", "error", "idle"} {
		keys = append(keys, map[string]any{"id": id, "name": id, "value": "sk-bf-fixture-" + id, "is_active": true, "rate_limit": map[string]any{"id": "rate-" + id, "token_max_limit": 10000, "token_reset_duration": "1d", "request_max_limit": 10000, "request_reset_duration": "1d"}, "budgets": []any{map[string]any{"id": "budget-" + id, "max_limit": 1, "reset_duration": "1d"}}, "provider_configs": []any{map[string]any{"provider": "openrouter", "allowed_models": []string{"priced", "unknown", "streamed", "failed"}, "key_ids": []string{"provider-fixture"}, "weight": 1}}})
	}
	write("config.json", map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": false, "disable_content_logging": true},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"framework":    map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "pricing.json"), "model_parameters_url": "file://" + filepath.Join(dir, "parameters.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
		"governance":   map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "ai0", "admin_password": "fixture-admin-only", "disable_auth_on_inference": false}, "virtual_keys": keys},
		"providers":    map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "provider-fixture", "name": "provider-fixture", "value": "fixture-provider-only", "models": []string{"priced", "unknown", "streamed", "failed"}, "weight": 1}}}},
	})
	base, stop := startEngine(t, binary, dir)
	defer func() { stop() }()
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(key, model string, stream bool) (int, string, error) {
		payload, _ := json.Marshal(map[string]any{"model": "openrouter/" + model, "messages": []any{map[string]string{"role": "user", "content": "OK"}}, "max_tokens": 8, "stream": stream})
		r, _ := http.NewRequest("POST", base+"/v1/chat/completions", bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Bf-Vk", "sk-bf-fixture-"+key)
		res, e := client.Do(r)
		if e != nil {
			return 0, "", e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return res.StatusCode, string(b), e
	}
	counter := func(id, objectID, field string) float64 {
		t.Helper()
		r, _ := http.NewRequest("GET", base+"/api/governance/virtual-keys/"+id, nil)
		r.SetBasicAuth("ai0", "fixture-admin-only")
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		var value any
		if e = json.Unmarshal(b, &value); e != nil {
			t.Fatalf("admin JSON status %d: %v", res.StatusCode, e)
		}
		var find func(any) (float64, bool)
		find = func(v any) (float64, bool) {
			switch x := v.(type) {
			case map[string]any:
				if x["id"] == objectID {
					n, ok := x[field].(float64)
					return n, ok
				}
				for _, n := range x {
					if a, ok := find(n); ok {
						return a, true
					}
				}
			case []any:
				for _, n := range x {
					if a, ok := find(n); ok {
						return a, true
					}
				}
			}
			return 0, false
		}
		n, ok := find(value)
		if !ok {
			t.Fatalf("budget missing for %s; status %d", id, res.StatusCode)
		}
		return n
	}
	usage := func(id string) float64 { return counter(id, "budget-"+id, "current_usage") }
	waitUsage := func(id string, want float64) {
		t.Helper()
		for end := time.Now().Add(15 * time.Second); ; {
			n := usage(id)
			if math.Abs(n-want) < 1e-8 {
				return
			}
			if time.Now().After(end) {
				t.Fatalf("%s usage=%v want=%v", id, n, want)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			s, b, e := call("concurrent", "priced", false)
			if e == nil && (s != 200 || !strings.Contains(b, "OK")) {
				e = fmt.Errorf("concurrent response %d", s)
			}
			results <- e
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(8 * time.Second):
			close(release)
			t.Fatal("both concurrent requests did not reach provider")
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		if e := <-results; e != nil {
			t.Fatal(e)
		}
	}
	waitUsage("concurrent", 10)
	waitUsage("idle", 0)
	before := arrivals.Load()
	s, b, e := call("concurrent", "priced", false)
	if e != nil || s != 402 || !strings.Contains(strings.ToLower(b), "budget") || arrivals.Load() != before {
		t.Fatalf("post-threshold denial status=%d error=%v arrivals=%d", s, e, arrivals.Load()-before)
	}
	for i := 0; i < 2; i++ {
		s, _, e = call("unknown", "unknown", false)
		if e != nil || s != 200 {
			t.Fatalf("unknown price status=%d error=%v", s, e)
		}
	}
	waitUsage("unknown", 0)
	s, b, e = call("stream", "streamed", true)
	if e != nil || s != 200 || !strings.Contains(b, "OK") {
		t.Fatalf("stream status=%d err=%v", s, e)
	}
	waitUsage("stream", 5)
	before = arrivals.Load()
	s, _, e = call("error", "failed", false)
	if e != nil || s != 400 || arrivals.Load() != before+1 {
		t.Fatalf("error/no-retry status=%d err=%v arrivals=%d", s, e, arrivals.Load()-before)
	}
	waitUsage("error", 0)
	stop()
	base, stop = startEngine(t, binary, dir)
	waitUsage("concurrent", 10)
	waitUsage("stream", 5)
	waitUsage("unknown", 0)
	waitUsage("idle", 0)
	for _, expected := range []struct {
		id               string
		tokens, requests float64
	}{{"concurrent", 10, 2}, {"stream", 5, 1}, {"unknown", 10, 2}, {"idle", 0, 0}, {"error", 0, 0}} {
		for field, want := range map[string]float64{"token_current_usage": expected.tokens, "request_current_usage": expected.requests} {
			if got := counter(expected.id, "rate-"+expected.id, field); got != want {
				t.Fatalf("%s %s=%v want=%v", expected.id, field, got, want)
			}
		}
	}
	before = arrivals.Load()
	s, b, e = call("concurrent", "priced", false)
	if e != nil || s != 402 || !strings.Contains(strings.ToLower(b), "budget") || arrivals.Load() != before {
		t.Fatalf("persisted threshold refusal status=%d err=%v", s, e)
	}
	s, _, e = call("idle", "unknown", false)
	if e != nil || s != 200 {
		t.Fatalf("healthy post-restart status=%d err=%v", s, e)
	}
	t.Log("native per-key attribution: 10 concurrent, 5 streamed, 0 idle/error/uncosted; all persisted after graceful restart; 1-unit threshold allowed two overlapping 5-unit requests then denied new requests with 402; unknown prices execute uncharged")
}
