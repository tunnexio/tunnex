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
	"sync/atomic"
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

func TestMCPOAuthCacheBoundToEndpoint(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("endpoint") != "https://b.example/mcp" {
			t.Error("wrong endpoint")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "token-b", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer server.Close()
	source, err := newManagedRuntimeSource(server.URL, "runtime-test", "", "", "", nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	source.mcpToken = "token-a"
	source.mcpTokenEndpoint = "https://a.example/mcp"
	source.mcpTokenExpires = time.Now().Add(time.Hour)
	got, err := source.MCPProxyAuthorization(t.Context(), "https://b.example/mcp")
	if err != nil || got != "token-b" || calls != 1 {
		t.Fatalf("cross-endpoint cache reused: calls=%d error=%v", calls, err)
	}
	got, err = source.MCPProxyAuthorization(t.Context(), "https://b.example/mcp")
	if err != nil || got != "token-b" || calls != 1 {
		t.Fatal("same endpoint cache failed")
	}
}

// AI-SEC-2: the runtime declares that it forwards MCP to the gateway, and once the control plane names the
// gateway listener it neither observes the MCP server itself nor leases a token for it.
func TestManagedRuntimeDeclaresGatewayCapabilityAndStopsLocalMCPWork(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		http.Error(w, "nothing here", http.StatusNotFound)
	}))
	defer upstream.Close()

	var mu sync.Mutex
	var pollQueries []string
	var reports []map[string]any
	leases := 0
	gatewayURL := any(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/agent/runtime/poll":
			w.Header().Set("Content-Type", "application/json")
			pollQueries = append(pollQueries, r.URL.Query().Get("mcp_gateway"))
			_ = json.NewEncoder(w).Encode(map[string]any{"revision": 1, "device_id": "00000000-0000-0000-0000-000000000001", "org_id": "00000000-0000-0000-0000-000000000002", "address": "10.0.0.2/32", "gateway_endpoint": "gw.example:51820", "gateway_public_key": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", "allowed_ips": []string{"10.0.0.0/24"}, "dns": []string{}, "persistent_keepalive": 25,
				"mcp_upstream": upstream.URL, "mcp_gateway_url": gatewayURL})
		case "/api/v1/agent/runtime/report":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reports = append(reports, body)
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/runtime/mcp-oauth-lease":
			leases++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	state := ManagedRuntimeState{Server: server.URL, ClientVersion: "test"}
	source, err := newManagedRuntimeSource(server.URL, "runtime-test", "", filepath.Join(dir, "runtime.conf"), filepath.Join(dir, "runtime-state.json"), &state, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	// No gateway URL (an older gateway, or grace): the legacy path stays exactly as it was.
	if _, err := source.Poll(t.Context(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if source.currentMCPGatewayURL() != "" || source.currentMCPUpstream() != upstream.URL {
		t.Fatalf("legacy poll: gateway %q upstream %q", source.currentMCPGatewayURL(), source.currentMCPUpstream())
	}
	if err := source.Report(t.Context(), AgentRuntimeReport{AppliedRevision: 1, AttemptedRevision: 1, ClientVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	legacyUpstreamCalls, legacyReport := upstreamCalls.Load(), reports[len(reports)-1]
	mu.Unlock()
	if legacyUpstreamCalls == 0 {
		t.Fatal("legacy report must still observe the MCP server from the agent host")
	}
	if legacyReport["mcp_inventory"] == nil {
		t.Fatalf("legacy report must still carry the inventory: %v", legacyReport)
	}

	// The control plane names the gateway listener: forward only.
	mu.Lock()
	gatewayURL = "http://10.99.0.1:8084/mcp"
	leasesBefore := leases
	mu.Unlock()
	source.mcpToken, source.mcpTokenEndpoint, source.mcpTokenExpires = "held-token", upstream.URL, time.Now().Add(time.Hour)
	if _, err := source.Poll(t.Context(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if got := source.currentMCPGatewayURL(); got != "http://10.99.0.1:8084/mcp" {
		t.Fatalf("gateway URL = %q", got)
	}
	if source.mcpToken != "" {
		t.Fatal("a token leased on the old path must not stay on the agent host once the gateway enforces")
	}
	before := upstreamCalls.Load()
	if err := source.Report(t.Context(), AgentRuntimeReport{AppliedRevision: 1, AttemptedRevision: 1, ClientVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if upstreamCalls.Load() != before {
		t.Fatalf("gateway mode contacted the MCP server %d times from the agent host", upstreamCalls.Load()-before)
	}
	last := reports[len(reports)-1]
	if last["mcp_inventory"] != nil {
		t.Fatalf("gateway mode must not report inventory: %v", last)
	}
	if last["mcp_oauth_discovery"] != nil {
		t.Fatalf("gateway mode must not report OAuth discovery: %v", last)
	}
	if leases != leasesBefore {
		t.Fatalf("gateway mode leased a token %d times", leases-leasesBefore)
	}
	for i, q := range pollQueries {
		if q != "true" {
			t.Fatalf("poll %d sent mcp_gateway=%q, want true", i, q)
		}
	}
}

// ── AI-UX-1 ───────────────────────────────────────────────────────────────────────

func dnsTestConfig(dns ...string) ManagedAgentConfig {
	return ManagedAgentConfig{Revision: 2, Address: "10.0.0.2/32", GatewayEndpoint: "gw.example:51820",
		GatewayPublicKey: "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", AllowedIPs: []string{"10.0.0.0/24"}, DNS: dns, PersistentKeepalive: 25}
}

// wg-quick runs resolvconf for a DNS line and tears the interface down when that fails. A host without
// resolvconf therefore gets a configuration without the line; a host with it gets exactly what it got
// before.
func TestManagedRuntimeOmitsTheDNSLineWithoutResolvconf(t *testing.T) {
	const before = "[Interface]\nPrivateKey = LOCAL-PRIVATE\nAddress = 10.0.0.2/32\nDNS = 10.0.0.53, 10.0.0.54\nMTU = 1420\n\n[Peer]\nPublicKey = MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=\nEndpoint = gw.example:51820\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25\n"
	if got := renderManagedConfig("LOCAL-PRIVATE", dnsTestConfig("10.0.0.53", "10.0.0.54"), true); got != before {
		t.Fatalf("a host with resolvconf must get the configuration it always got:\n%s", got)
	}
	without := renderManagedConfig("LOCAL-PRIVATE", dnsTestConfig("10.0.0.53", "10.0.0.54"), false)
	if strings.Contains(without, "DNS") || without != strings.Replace(before, "DNS = 10.0.0.53, 10.0.0.54\n", "", 1) {
		t.Fatalf("without resolvconf only the DNS line may differ:\n%s", without)
	}
	if a, b := renderManagedConfig("K", dnsTestConfig(), true), renderManagedConfig("K", dnsTestConfig(), false); a != b || strings.Contains(a, "DNS") {
		t.Fatalf("no DNS servers pushed: %q vs %q", a, b)
	}
}

func TestManagedRuntimeApplierLooksForResolvconfOnPATHAtEachApply(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	if err := WriteFileAtomic0600(configPath, []byte("[Interface]\nPrivateKey = LOCAL-PRIVATE\nAddress = 10.0.0.2/32\n")); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var applied []string
	dns := &tunnelDNSState{}
	applier := &wireGuardRuntimeApplier{path: configPath, dns: dns, command: func(_ context.Context, path, action string) error {
		b, _ := os.ReadFile(path)
		applied = append(applied, action+":"+string(b))
		return nil
	}}
	if dns.applied() != nil {
		t.Fatal("nothing is known before the first apply")
	}

	// No resolvconf on PATH: no DNS line, and the runtime knows it left it out.
	if err := applier.Apply(t.Context(), dnsTestConfig("10.0.0.53")); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || strings.Contains(applied[0], "DNS") || !strings.Contains(applied[0], "PrivateKey = LOCAL-PRIVATE") || !strings.Contains(applied[0], "AllowedIPs = 10.0.0.0/24") {
		t.Fatalf("applied without resolvconf: %v", applied)
	}
	if got := dns.applied(); got == nil || *got {
		t.Fatalf("tunnel DNS applied = %v, want false", got)
	}

	// resolvconf is installed later: the next apply writes the line, as on any host that has it.
	if err := os.WriteFile(filepath.Join(bin, "resolvconf"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(t.Context(), dnsTestConfig("10.0.0.53")); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || !strings.Contains(applied[1], "\nDNS = 10.0.0.53\n") {
		t.Fatalf("applied with resolvconf: %v", applied)
	}
	if got := dns.applied(); got == nil || !*got {
		t.Fatalf("tunnel DNS applied = %v, want true", got)
	}

	// A failed apply restores the last-good file and what is known about it.
	if err := os.Remove(filepath.Join(bin, "resolvconf")); err != nil {
		t.Fatal(err)
	}
	failing := &wireGuardRuntimeApplier{path: configPath, dns: dns, command: func() func(context.Context, string, string) error {
		calls := 0
		return func(context.Context, string, string) error {
			if calls++; calls == 1 {
				return errors.New("wg-quick failed")
			}
			return nil
		}
	}()}
	if err := failing.Apply(t.Context(), dnsTestConfig("10.0.0.53")); err == nil {
		t.Fatal("the apply must fail")
	}
	restored, _ := os.ReadFile(configPath)
	if !strings.Contains(string(restored), "\nDNS = 10.0.0.53\n") {
		t.Fatalf("the last-good file was not restored: %s", restored)
	}
	if got := dns.applied(); got == nil || !*got {
		t.Fatalf("after a restored apply, tunnel DNS applied = %v, want true (the restored file has the line)", got)
	}
}

// The runtime declares on every poll that its proxy holds an MCP call open (mcp_hold), reads the server
// list from the configuration, and reports whether the tunnel DNS servers were written.
func TestManagedRuntimeDeclaresHoldReadsServersAndReportsTunnelDNS(t *testing.T) {
	var mu sync.Mutex
	var pollQueries []string
	var reports []map[string]any
	servers := any([]map[string]any{{"name": "orders-db", "default": true}, {"name": "billing", "default": false}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/agent/runtime/poll":
			pollQueries = append(pollQueries, r.URL.Query().Get("mcp_hold")+"/"+r.URL.Query().Get("mcp_gateway"))
			config := map[string]any{"revision": 1, "device_id": "00000000-0000-0000-0000-000000000001", "org_id": "00000000-0000-0000-0000-000000000002", "address": "10.0.0.2/32", "gateway_endpoint": "gw.example:51820", "gateway_public_key": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", "allowed_ips": []string{"10.0.0.0/24"}, "dns": []string{"10.0.0.53"}, "persistent_keepalive": 25,
				"mcp_upstream": nil, "mcp_gateway_url": "http://10.99.0.1:8084/mcp"}
			if servers != nil {
				config["mcp_servers"] = servers
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
		case "/api/v1/agent/runtime/report":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reports = append(reports, body)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	state := ManagedRuntimeState{Server: server.URL, ClientVersion: "test"}
	source, err := newManagedRuntimeSource(server.URL, "runtime-test", "", filepath.Join(dir, "runtime.conf"), filepath.Join(dir, "runtime-state.json"), &state, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := func() map[string]any {
		t.Helper()
		if err := source.Report(t.Context(), AgentRuntimeReport{AppliedRevision: 1, AttemptedRevision: 1, ClientVersion: "test"}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return reports[len(reports)-1]
	}

	if _, err := source.Poll(t.Context(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	got := source.MCPProxyServers(t.Context())
	if len(got) != 2 || got[0] != (MCPProxyServer{Name: "orders-db", Default: true}) || got[1] != (MCPProxyServer{Name: "billing"}) {
		t.Fatalf("servers = %+v", got)
	}
	// Before anything was applied by this process the runtime says nothing about DNS.
	if body := report(); body["tunnel_dns_applied"] != nil {
		t.Fatalf("report before an apply: %v", body)
	}
	source.tunnelDNS = &tunnelDNSState{}
	source.tunnelDNS.set(false)
	if body := report(); body["tunnel_dns_applied"] != false {
		t.Fatalf("report on a host without resolvconf: %v", body)
	}
	source.tunnelDNS.set(true)
	if body := report(); body["tunnel_dns_applied"] != true {
		t.Fatalf("report on a host with resolvconf: %v", body)
	}

	// The control plane stops sending servers (the last one was removed, or it is an older one).
	mu.Lock()
	servers = nil
	mu.Unlock()
	if _, err := source.Poll(t.Context(), 0, "test"); err != nil {
		t.Fatal(err)
	}
	if got := source.MCPProxyServers(t.Context()); len(got) != 0 {
		t.Fatalf("servers after they were withdrawn = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, q := range pollQueries {
		if q != "true/true" {
			t.Fatalf("poll %d sent mcp_hold/mcp_gateway = %q, want true/true", i, q)
		}
	}
}
