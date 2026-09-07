package ai0

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpenRouterSmoke requires explicit opt-in and a caller-provided private
// credential file. It makes exactly two bounded requests through the adapter
// and real engine. Synthetic local identity is NOT enrolled-agent acceptance.
func TestOpenRouterSmoke(t *testing.T) {
	if os.Getenv("AI0_ALLOW_PAID_SMOKE") != "yes" {
		t.Skip("paid smoke is explicitly opt-in")
	}
	binary := os.Getenv("AI0_BIFROST_BINARY")
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("pinned binary unavailable")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != binarySHA256 {
		t.Fatal("binary digest mismatch")
	}
	keyPath := os.Getenv("AI0_OPENROUTER_KEY_FILE")
	info, err := os.Stat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("credential must be a private regular file")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || len(strings.TrimSpace(string(key))) == 0 {
		t.Fatal("provider credential unavailable")
	}
	dir := t.TempDir()
	config := map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": false, "disable_content_logging": true, "max_request_body_size_mb": 1},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"governance": map[string]any{
			"auth_config": map[string]any{"is_enabled": true, "admin_username": "ai0", "admin_password": "fixture-admin-only", "disable_auth_on_inference": false},
			"virtual_keys": []any{map[string]any{"id": "ai0-smoke", "name": "ai0-smoke", "value": nativeVK, "is_active": true,
				"provider_configs": []any{map[string]any{"provider": "openrouter", "allowed_models": []string{"openai/gpt-4o-mini"}, "key_ids": []string{"ai0-openrouter"}, "weight": 1}}}},
		},
		"providers": map[string]any{"openrouter": map[string]any{
			"network_config": map[string]any{"max_retries": 0},
			"keys":           []any{map[string]any{"id": "ai0-openrouter", "name": "ai0-openrouter", "value": "env.AI0_OPENROUTER_KEY", "models": []string{"openai/gpt-4o-mini"}, "weight": 1}},
		}},
	}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	base, stop := startEngine(t, binary, dir, "AI0_OPENROUTER_KEY="+strings.TrimSpace(string(key)))
	defer stop()
	adapter, err := NewAdapter(base, func(_ context.Context, token, model string) (Grant, error) {
		if token != "fixture-smoke-agent" || model != "openrouter/openai/gpt-4o-mini" {
			return Grant{}, errors.New("denied")
		}
		return Grant{Tenant: "fixture-tenant", Agent: "fixture-agent", VirtualKey: nativeVK, Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/chat/completions", "/anthropic/v1/messages"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"Reply with OK only."}],"max_tokens":16,"stream":true}`))
		r.Header.Set("Authorization", "Bearer fixture-smoke-agent")
		w := httptest.NewRecorder()
		adapter.ServeHTTP(w, r)
		body, _ := io.ReadAll(w.Result().Body)
		if w.Code != 200 || !w.Flushed || !strings.Contains(string(body), "OK") {
			t.Fatalf("OpenRouter smoke path=%s status=%d bytes=%d; content withheld", path, w.Code, len(body))
		}
		if strings.Contains(string(body), string(key)) || strings.Contains(string(body), nativeVK) {
			t.Fatal("credential leaked in response")
		}
		t.Logf("OpenRouter path=%s model=openai/gpt-4o-mini status=200 streamed=true output_limit=16 identity=synthetic", path)
	}
}
