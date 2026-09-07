package aigateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/testbifrost"
)

var binarySHA256 = testbifrost.BinarySHA256

const nativeVK = "sk-bf-ai0-fixture-key-only"

// TestBifrostNative uses a real pinned engine and synthetic provider. It never
// reads provider credentials or calls a paid provider. The environment switch
// is explicit because the binary is not downloaded or run by ordinary tests.
func TestBifrostNative(t *testing.T) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("set AI0_BIFROST_BINARY to the pinned platform binary")
	}
	f, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != binarySHA256 {
		t.Fatal("binary digest does not match qualification pin")
	}
	var arrivals atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `{"data":[]}`)
			return
		}
		arrivals.Add(1)
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad payload", 400)
			return
		}
		if body["model"] != "allowed" {
			t.Error("native governance allowed denied model")
		}
		if body["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			if r.URL.Path == "/v1/responses" {
				for _, event := range []string{
					`{"type":"response.created","sequence_number":0,"response":{"id":"resp_fixture","object":"response","model":"allowed","status":"in_progress","output":[]}}`,
					`{"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":{"id":"msg_fixture","type":"message","status":"in_progress","role":"assistant","content":[]}}`,
					`{"type":"response.content_part.added","sequence_number":2,"item_id":"msg_fixture","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}`,
					`{"type":"response.output_text.delta","sequence_number":3,"item_id":"msg_fixture","output_index":0,"content_index":0,"delta":"OK"}`,
					`{"type":"response.output_text.done","sequence_number":4,"item_id":"msg_fixture","output_index":0,"content_index":0,"text":"OK"}`,
					`{"type":"response.completed","sequence_number":5,"response":{"id":"resp_fixture","object":"response","model":"allowed","status":"completed","output":[{"id":"msg_fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"OK","annotations":[]}]}],"usage":{"input_tokens":4,"output_tokens":1,"total_tokens":5}}}`,
				} {
					io.WriteString(w, "data: "+event+"\n\n")
					w.(http.Flusher).Flush()
				}
				return
			}
			io.WriteString(w, "data: {\"id\":\"fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"allowed\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n")
			w.(http.Flusher).Flush()
			io.WriteString(w, "data: {\"id\":\"fixture\",\"object\":\"chat.completion.chunk\",\"model\":\"allowed\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":1,\"total_tokens\":5}}\n\ndata: [DONE]\n\n")
		} else {
			io.WriteString(w, `{"id":"fixture","object":"chat.completion","model":"allowed","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`)
		}
	}))
	defer provider.Close()
	dir := t.TempDir()
	config := map[string]any{
		"client":       map[string]any{"enforce_auth_on_inference": true, "enable_logging": false, "disable_content_logging": true, "max_request_body_size_mb": 1},
		"config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}},
		"governance": map[string]any{
			"auth_config": map[string]any{"is_enabled": true, "admin_username": "ai0", "admin_password": "fixture-admin-only", "disable_auth_on_inference": false},
			"virtual_keys": []any{
				map[string]any{"id": "ai0-agent-a", "name": "ai0-agent-a", "value": nativeVK, "is_active": true, "provider_configs": []any{map[string]any{"provider": "openrouter", "allowed_models": []string{"allowed"}, "key_ids": []string{"ai0-provider"}, "weight": 1}}},
				map[string]any{"id": "ai0-agent-b", "name": "ai0-agent-b", "value": nativeVK + "-independent", "is_active": true, "provider_configs": []any{map[string]any{"provider": "openrouter", "allowed_models": []string{"allowed"}, "key_ids": []string{"ai0-provider"}, "weight": 1}}},
			},
		},
		"providers": map[string]any{"openrouter": map[string]any{
			"network_config": map[string]any{"base_url": provider.URL, "allow_private_network": true, "max_retries": 0},
			"keys":           []any{map[string]any{"id": "ai0-provider", "name": "ai0-provider", "value": "fixture-provider-only", "models": []string{"allowed", "denied"}, "weight": 1}},
		}},
	}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	base, stop := startEngine(t, binary, dir)
	defer stop()
	client := &http.Client{Timeout: 15 * time.Second}
	call := func(path, model, key string, stream bool) (int, string, string) {
		payload, _ := json.Marshal(map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": "Reply OK"}}, "max_tokens": 8, "stream": stream})
		r, _ := http.NewRequest("POST", base+path, bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("X-Bf-Vk", key)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return res.StatusCode, res.Header.Get("Content-Type"), string(b)
	}
	assertDenial := func(status int, body string, wantStatus int, wantMessage string) {
		t.Helper()
		var response struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if status != wantStatus || json.Unmarshal([]byte(body), &response) != nil || response.Error.Message != wantMessage {
			t.Fatalf("native refusal status=%d body=%s; want status=%d message=%q", status, body, wantStatus, wantMessage)
		}
	}
	for _, tc := range []struct {
		key, model string
		status     int
		message    string
	}{
		{"", "openrouter/allowed", 401, "virtual key is required. Provide a virtual key via the x-bf-vk header."},
		{"sk-bf-invalid", "openrouter/allowed", 401, "virtual key not found. The provided virtual key does not exist or has been revoked."},
		{nativeVK, "openrouter/denied", 403, "Model 'denied' is not allowed for this virtual key"},
	} {
		status, _, body := call("/v1/chat/completions", tc.model, tc.key, false)
		assertDenial(status, body, tc.status, tc.message)
	}
	if arrivals.Load() != 0 {
		t.Fatalf("native refusal had %d provider arrivals", arrivals.Load())
	}
	for _, path := range []string{"/v1/chat/completions", "/anthropic/v1/messages"} {
		status, contentType, body := call(path, "openrouter/allowed", nativeVK, true)
		if status != 200 {
			t.Fatalf("native stream %s status=%d body=%s", path, status, body)
		}
		assertQualifiedSSE(t, path, contentType, body)
	}
	if arrivals.Load() != 2 {
		t.Fatalf("expected two allowed arrivals, got %d", arrivals.Load())
	}
	res, err := client.Get(base + "/api/governance/virtual-keys")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 && res.StatusCode != 403 {
		t.Fatalf("admin not protected: %d", res.StatusCode)
	}
	t.Log("native model denial: zero arrivals; OpenAI and Anthropic streams passed; unauthenticated admin refused")
	update, _ := http.NewRequest("PUT", base+"/api/governance/virtual-keys/ai0-agent-a", strings.NewReader(`{"is_active":false}`))
	update.SetBasicAuth("ai0", "fixture-admin-only")
	update.Header.Set("Content-Type", "application/json")
	res, err = client.Do(update)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("native revocation failed: %d", res.StatusCode)
	}
	status, _, body := call("/v1/chat/completions", "openrouter/allowed", nativeVK, false)
	assertDenial(status, body, 403, "Virtual key is inactive")
	if arrivals.Load() != 2 {
		t.Fatal("revoked key reached provider")
	}
	stop()
	base, stop = startEngine(t, binary, dir)
	defer stop()
	status, _, body = call("/v1/chat/completions", "openrouter/allowed", nativeVK, false)
	assertDenial(status, body, 403, "Virtual key is inactive")
	if arrivals.Load() != 2 {
		t.Fatal("revocation did not survive restart")
	}
	readback, _ := http.NewRequest("GET", base+"/api/governance/virtual-keys/ai0-agent-a", nil)
	readback.SetBasicAuth("ai0", "fixture-admin-only")
	res, err = client.Do(readback)
	if err != nil {
		t.Fatal(err)
	}
	readBody, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	var persisted struct {
		VirtualKey struct {
			ID       string `json:"id"`
			IsActive *bool  `json:"is_active"`
		} `json:"virtual_key"`
	}
	if err != nil || res.StatusCode != 200 || json.Unmarshal(readBody, &persisted) != nil || persisted.VirtualKey.ID != "ai0-agent-a" || persisted.VirtualKey.IsActive == nil || *persisted.VirtualKey.IsActive {
		t.Fatalf("persisted revocation readback failed: status=%d body=%s", res.StatusCode, readBody)
	}
	status, _, body = call("/v1/chat/completions", "openrouter/allowed", nativeVK+"-independent", false)
	if status != 200 || !strings.Contains(body, "OK") || arrivals.Load() != 3 {
		t.Fatalf("independent active key failed after restart: status=%d body=%s arrivals=%d", status, body, arrivals.Load())
	}
	t.Log("admin API revoked virtual key; new requests refused before and after restart")
}

func startEngine(t *testing.T, binary, dir string, environment ...string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strings.Split(l.Addr().String(), ":")[1]
	l.Close()
	cmd := exec.Command(binary, "-host", "127.0.0.1", "-port", port, "-app-dir", dir, "-log-level", "error")
	// Fixture runtime has no access to inherited provider credentials.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, environment...)
	logFile, err := os.OpenFile(filepath.Join(dir, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		logFile.Close()
	}
	base := "http://127.0.0.1:" + port
	client := &http.Client{Timeout: time.Second}
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); {
		select {
		case err := <-done:
			stopped = true
			logFile.Close()
			t.Fatalf("engine exited: %v (runtime log withheld to avoid credential disclosure)", err)
		default:
		}
		res, err := client.Get(base + "/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return base, stop
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatal("engine readiness timed out (runtime log withheld to avoid credential disclosure)")
	return "", func() {}
}
