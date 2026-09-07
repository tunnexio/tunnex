package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestProviderEngineNativeLifecycle(t *testing.T) {
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
	var authGood, authBad, inference atomic.Int32
	const secret = "synthetic-ui-onboarding-good-key"
	const bad = "synthetic-ui-onboarding-bad-key"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			inference.Add(1)
			w.WriteHeader(400)
			return
		}
		if r.URL.Path == "/v1/auth/key" {
			if r.Header.Get("Authorization") != "Bearer "+secret && r.Header.Get("Authorization") != "Bearer legacy-fixture-key" {
				authBad.Add(1)
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"message":"synthetic auth refusal","type":"authentication_error"}}`)
				return
			}
			authGood.Add(1)
		}
		io.WriteString(w, `{"data":[{"id":"openai/gpt-4o-mini","name":"Fixture model"}]}`)
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
	write("prices.json", map[string]any{"openai/gpt-4o-mini": map[string]any{"provider": "openrouter", "mode": "chat"}})
	write("parameters.json", map[string]any{})
	config := map[string]any{"encryption_key": "fixture-encryption-key-32-bytes-only", "client": map[string]any{"enforce_auth_on_inference": true, "enable_logging": true, "disable_content_logging": true}, "config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}}, "logs_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "logs.db")}}, "framework": map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "prices.json"), "model_parameters_url": "file://" + filepath.Join(dir, "parameters.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}}, "governance": map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "provider-fixture-admin", "admin_password": "provider-fixture-password", "disable_auth_on_inference": false}}, "providers": map[string]any{"openrouter": map[string]any{"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0}, "keys": []any{map[string]any{"id": "legacy-fixture", "name": "legacy-fixture", "value": "env.OPENROUTER_API_KEY", "models": []string{"*"}, "weight": 1, "enabled": true}}}}}
	write("config.json", config)
	base, stop := startEngine(t, binary, dir, "OPENROUTER_API_KEY=legacy-fixture-key")
	defer func() { stop() }()
	engine, err := NewEngine(base, "provider-fixture-admin", "provider-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = engine.EnsureProvider(ctx, "openrouter"); err != nil {
		t.Fatal(err)
	}
	spec := ProviderKeySpec{Provider: "openrouter", ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: []string{"openrouter/openai/gpt-4o-mini"}, Enabled: true}
	value := secret
	if err = engine.PutProviderKey(ctx, spec, &value); err != nil {
		t.Fatal(err)
	}
	ok, err := engine.TestProviderKey(ctx, spec)
	if err != nil || !ok {
		t.Fatal("valid auth test failed")
	}
	vk, err := engine.EnsureKey(ctx, "provider-fixture-vk", "openrouter", []string{"openai/gpt-4o-mini"}, []string{spec.ID})
	if err != nil {
		t.Fatal(err)
	}
	spec.Revision++
	if err = engine.PutProviderKey(ctx, spec, nil); err != nil {
		t.Fatal("masked preserve failed", err)
	}
	value = bad
	spec.Revision++
	if err = engine.PutProviderKey(ctx, spec, &value); err != nil {
		t.Fatal(err)
	}
	ok, err = engine.TestProviderKey(ctx, spec)
	if err != nil || ok {
		t.Fatal("HTTP200 bad credential not refused")
	}
	value = secret
	spec.Revision++
	if err = engine.PutProviderKey(ctx, spec, &value); err != nil {
		t.Fatal(err)
	}
	page, err := engine.ProviderModels(ctx, "openrouter", "gpt-4o-mini", 50, 0)
	if err != nil || len(page.Models) == 0 {
		t.Fatal("native catalog missing")
	}
	spec.Enabled = false
	spec.Revision++
	if err = engine.PutProviderKey(ctx, spec, nil); err != nil {
		t.Fatal(err)
	}
	if err = engine.VerifyProviderKey(ctx, spec); err != nil {
		t.Fatal(err)
	}
	// Never delete this referenced key. An independent unreferenced key covers deletion.
	spare := ProviderKeySpec{Provider: "openrouter", ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: spec.Models, Enabled: false}
	if err = engine.PutProviderKey(ctx, spare, &value); err != nil {
		t.Fatal(err)
	}
	if err = engine.DeleteProviderKey(ctx, spare); err != nil {
		t.Fatal(err)
	}
	if err = engine.DeleteProviderKey(ctx, spare); err != nil {
		t.Fatal("delete retry failed")
	}
	spec.Enabled = true
	spec.Revision++
	if err = engine.PutProviderKey(ctx, spec, nil); err != nil {
		t.Fatal(err)
	}
	stop()
	delete(config, "providers")
	write("config.json", config)
	base, stop = startEngine(t, binary, dir, "OPENROUTER_API_KEY=legacy-fixture-key")
	engine, err = NewEngine(base, "provider-fixture-admin", "provider-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.VerifyProviderKey(ctx, spec); err != nil {
		t.Fatal("managed key lost after DB ownership transition", err)
	}
	legacy, _, err := engine.providerKey(ctx, "openrouter", "legacy-fixture")
	if err != nil || legacy.ID != "legacy-fixture" {
		t.Fatal("legacy key lost")
	}
	recovered, err := engine.EnsureKey(ctx, "provider-fixture-vk", "openrouter", []string{"openai/gpt-4o-mini"}, []string{spec.ID})
	if err != nil || recovered != vk {
		t.Fatal("scoped virtual key changed")
	}
	ok, err = engine.TestProviderKey(ctx, spec)
	if err != nil || !ok || authGood.Load() == 0 || authBad.Load() == 0 || inference.Load() != 0 {
		t.Fatal("native lifecycle qualification failed")
	}
	stop()
	// Inspect only this stopped test's fresh SQLite. No shared DB or container.
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(py, "-c", `import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); rows=c.execute('SELECT encryption_status FROM config_keys').fetchall(); print(all(r[0]=='encrypted' for r in rows)); print('\\n'.join(c.iterdump()))`, filepath.Join(dir, "config.db"))
	dump, err := command.Output()
	if err != nil {
		t.Fatal("fixture encryption check failed")
	}
	if !strings.HasPrefix(string(dump), "True\n") || strings.Contains(string(dump), secret) || strings.Contains(string(dump), bad) {
		t.Fatal("provider secret persistence not encrypted")
	}
	// Fresh database: initialize the shared provider without any configured key.
	dir = t.TempDir()
	config["config_store"] = map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}}
	config["logs_store"] = map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "logs.db")}}
	write("config.json", config)
	base, stop = startEngine(t, binary, dir)
	engine, err = NewEngine(base, "provider-fixture-admin", "provider-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.EnsureProvider(ctx, "openrouter"); err != nil {
		t.Fatal("fresh empty-provider initialization failed", err)
	}
	if err = engine.EnsureProvider(ctx, "openrouter"); err != nil {
		t.Fatal("provider initialization was not idempotent", err)
	}
	var keys struct {
		Keys  []json.RawMessage `json:"keys"`
		Total int               `json:"total"`
	}
	if _, err = engine.request(ctx, http.MethodGet, "/api/providers/openrouter/keys", nil, nil, &keys); err != nil || keys.Total != 0 || len(keys.Keys) != 0 {
		t.Fatal("fresh initialization invented provider keys")
	}
	stop()
	t.Log("native single-key create/rotation/masked edit/disable/delete-spare, credential refusal, cached catalog, DB-owned restart and preserved legacy+virtual key passed; zero inference")
}
