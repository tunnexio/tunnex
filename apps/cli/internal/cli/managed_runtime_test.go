package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagedAgentRuntimeEntrypointPolls204AppliesReportsAndCancels(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	credentialPath := filepath.Join(dir, "runtime-credential")
	statePath := filepath.Join(dir, "runtime-state.json")
	if err := WriteFileAtomic0600(configPath, []byte("[Interface]\nPrivateKey = LOCAL-PRIVATE\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = old\nEndpoint = old:1\nAllowedIPs = 10.0.0.0/24\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic0600(credentialPath, []byte("tnx_runtime_test\n")); err != nil {
		t.Fatal(err)
	}
	if err := saveManagedRuntimeState(statePath, ManagedRuntimeState{Server: "PLACEHOLDER", ClientVersion: "test"}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var polls, reports int
	var applied []string
	cancel := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tnx_runtime_test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/agent/runtime/poll" {
			mu.Lock()
			polls++
			p := polls
			mu.Unlock()
			if p == 1 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"revision": 1, "device_id": "00000000-0000-0000-0000-000000000001", "org_id": "00000000-0000-0000-0000-000000000002", "address": "10.0.0.2/32", "gateway_endpoint": "gw.example:51820", "gateway_public_key": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", "allowed_ips": []string{"10.0.0.0/24"}, "dns": []string{}, "persistent_keepalive": 25})
				return
			}
			if p == 2 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if p == 3 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			select {
			case <-cancel:
			case <-time.After(100 * time.Millisecond):
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/v1/agent/runtime/report" {
			mu.Lock()
			reports++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	state, _ := loadManagedRuntimeState(statePath)
	state.Server = server.URL
	if err := saveManagedRuntimeState(statePath, state); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunManagedAgent(ctx, ManagedRuntimeOptions{StatePath: statePath, CredentialPath: credentialPath, ConfigPath: configPath, Interval: 10 * time.Millisecond, Backoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, PollWait: 1, ClientVersion: "test", ApplyCommand: func(_ context.Context, path, action string) error {
			if action == "apply" {
				b, _ := os.ReadFile(path)
				mu.Lock()
				applied = append(applied, string(b))
				mu.Unlock()
			}
			return nil
		}})
	}()
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		ready := polls >= 3 && reports >= 1 && len(applied) == 1
		mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("runtime entrypoint did not complete poll/204/apply/report/retry sequence")
		case <-time.After(time.Millisecond):
		}
	}
	stop()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("runtime stop error = %v", err)
	}
	mu.Lock()
	gotConfig := applied[0]
	mu.Unlock()
	if !strings.Contains(gotConfig, "PrivateKey = LOCAL-PRIVATE") {
		t.Fatalf("apply lost local private key: %s", gotConfig)
	}
	persisted, err := loadManagedRuntimeState(statePath)
	if err != nil || persisted.AppliedRevision != 1 {
		t.Fatalf("durable applied revision = %+v, err=%v", persisted, err)
	}
}

func TestManagedAgentRuntimeLongPollTickerAndBoundedBackoff(t *testing.T) {
	opts := DefaultManagedRuntimeOptions()
	if opts.ConfigPath != "/etc/wireguard/runtime.conf" {
		t.Fatalf("managed runtime config path = %q; want Ubuntu/AppArmor-compatible WireGuard path", opts.ConfigPath)
	}
	if opts.PollWait <= 0 || opts.PollWait > 60 || opts.Interval <= 0 {
		t.Fatalf("long-poll/ticker defaults are outside bounds: wait=%d interval=%s", opts.PollWait, opts.Interval)
	}
	if opts.Backoff <= 0 || opts.MaxBackoff < opts.Backoff || opts.Jitter == nil {
		t.Fatalf("backoff defaults are invalid: initial=%s max=%s jitter=%v", opts.Backoff, opts.MaxBackoff, opts.Jitter != nil)
	}
	for _, delay := range []time.Duration{time.Nanosecond, time.Second, opts.MaxBackoff} {
		for range 100 {
			got := opts.Jitter(delay)
			if got <= 0 || got > delay {
				t.Fatalf("jitter(%s) = %s, want positive and <= input", delay, got)
			}
			if delay > time.Nanosecond && got < delay/2 {
				t.Fatalf("jitter(%s) = %s, want upper-half retry window", delay, got)
			}
		}
	}
}

func TestManagedAgentRuntimeRestartPersistsAppliedRevision(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := saveManagedRuntimeState(statePath, ManagedRuntimeState{Server: "http://127.0.0.1:1", ClientVersion: "test", AppliedRevision: 7}); err != nil {
		t.Fatal(err)
	}
	state, err := loadManagedRuntimeState(statePath)
	if err != nil || state.AppliedRevision != 7 || state.ClientVersion != "test" {
		t.Fatalf("restart state = %+v, err=%v", state, err)
	}
}

func TestManagedAgentRuntimeTerminalUnauthorizedExitsCleanAfterDisable(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	credentialPath := filepath.Join(dir, "runtime-credential")
	statePath := filepath.Join(dir, "runtime-state.json")
	if err := WriteFileAtomic0600(configPath, []byte("[Interface]\nPrivateKey = LOCAL-PRIVATE\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic0600(credentialPath, []byte("tnx_runtime_revoked\n")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "refused", http.StatusUnauthorized)
	}))
	defer server.Close()
	if err := saveManagedRuntimeState(statePath, ManagedRuntimeState{Server: server.URL, ClientVersion: "test", AppliedRevision: 1}); err != nil {
		t.Fatal(err)
	}

	disabled := 0
	err := RunManagedAgent(context.Background(), ManagedRuntimeOptions{
		StatePath: statePath, CredentialPath: credentialPath, ConfigPath: configPath,
		Interval: time.Second, Backoff: time.Millisecond, MaxBackoff: time.Second,
		PollWait: 1, ClientVersion: "test", Jitter: func(d time.Duration) time.Duration { return d },
		ApplyCommand: func(_ context.Context, _ string, action string) error {
			if action == "disable" {
				disabled++
			}
			return nil
		},
	})
	if err != nil || disabled != 1 {
		t.Fatalf("terminal unauthorized = err %v, disable attempts %d; want clean exit after one disable", err, disabled)
	}
	state, err := loadManagedRuntimeState(statePath)
	if err != nil || state.AppliedRevision != 0 {
		t.Fatalf("terminal offboard state=%+v err=%v; want applied revision 0", state, err)
	}
}

func TestManagedAgentRuntimeTerminalUnauthorizedDisableFailureStaysNonzero(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	credentialPath := filepath.Join(dir, "runtime-credential")
	statePath := filepath.Join(dir, "runtime-state.json")
	if err := WriteFileAtomic0600(configPath, []byte("[Interface]\nPrivateKey = LOCAL-PRIVATE\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic0600(credentialPath, []byte("tnx_runtime_revoked\n")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "refused", http.StatusUnauthorized)
	}))
	defer server.Close()
	if err := saveManagedRuntimeState(statePath, ManagedRuntimeState{Server: server.URL, ClientVersion: "test", AppliedRevision: 1}); err != nil {
		t.Fatal(err)
	}

	disableErr := errors.New("wg disable refused")
	err := RunManagedAgent(context.Background(), ManagedRuntimeOptions{
		StatePath: statePath, CredentialPath: credentialPath, ConfigPath: configPath,
		Interval: time.Second, Backoff: time.Millisecond, MaxBackoff: time.Second,
		PollWait: 1, ClientVersion: "test", Jitter: func(d time.Duration) time.Duration { return d },
		ApplyCommand: func(_ context.Context, _ string, action string) error {
			if action == "disable" {
				return disableErr
			}
			return nil
		},
	})
	if !errors.Is(err, ErrRuntimeUnauthorized) || !errors.Is(err, disableErr) {
		t.Fatalf("terminal unauthorized disable failure = %v; want both causes", err)
	}
}

func TestManagedRuntimeStateDoesNotPersistCredentialOrAcceptLegacyEmbeddedSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime-state.json")
	state := ManagedRuntimeState{Server: "https://cp.example", ClientVersion: "test"}

	encoded := string(mustJSON(state))
	if strings.Contains(encoded, "tnx_runtime_secret") || strings.Contains(encoded, `"credential"`) || strings.Contains(encoded, "PrivateKey") || strings.Contains(encoded, "token") {
		t.Fatalf("runtime state serializes secret material: %s", encoded)
	}
	if err := saveManagedRuntimeState(path, state); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "tnx_runtime_secret") || strings.Contains(string(persisted), `"credential"`) {
		t.Fatalf("runtime state file contains embedded credential: %s", persisted)
	}

	legacy := []byte(`{"server":"https://cp.example","credential":"tnx_runtime_legacy","applied_revision":2,"client_version":"test"}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedRuntimeState(path); err == nil {
		t.Fatal("legacy state with embedded credential must be rejected")
	}
}

func TestManagedRuntimeDisablePropagatesPermissionFailure(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "wg-quick")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'permission denied' >&2\nexit 77\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runWireGuardQuick(context.Background(), "/etc/wireguard/runtime.conf", "disable"); err == nil {
		t.Fatal("wg-quick permission failure must reach the runtime")
	}
}

func TestManagedRuntimeDisableTreatsOnlyProvenAbsentInterfaceAsIdempotent(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "wg-quick")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'Cannot find device \\\"tunnex\\\"' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runWireGuardQuick(context.Background(), "/etc/wireguard/runtime.conf", "disable"); err != nil {
		t.Fatalf("proven absent interface should be idempotent: %v", err)
	}
}

func TestManagedAgentRuntimeRevokedCredentialStopsAndDisables(t *testing.T) {
	applier := &fakeAgentApplier{}
	source := &revokedRuntimeSource{}
	runtime, err := NewAgentRuntimeAt(source, applier, "test", 4, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.CheckOnce(context.Background())
	if !errors.Is(err, ErrRuntimeUnauthorized) || applier.disabled != 1 {
		t.Fatalf("revoked runtime = err %v disabled=%d", err, applier.disabled)
	}
	if runtime.AppliedRevision() != 0 {
		t.Fatalf("revoked runtime revision=%d, want 0", runtime.AppliedRevision())
	}
}

type revokedRuntimeSource struct{}

func (*revokedRuntimeSource) Poll(context.Context, int64, string) (ManagedAgentConfig, error) {
	return ManagedAgentConfig{}, ErrRuntimeUnauthorized
}

func (*revokedRuntimeSource) Report(context.Context, AgentRuntimeReport) error { return nil }
