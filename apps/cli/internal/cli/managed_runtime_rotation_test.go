package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

func TestManagedRuntimeRotatesBearerWithoutTunnelChurn(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "runtime-credential")
	statePath := filepath.Join(dir, "runtime-state.json")
	configPath := filepath.Join(dir, "runtime.conf")
	old := "tnx_runtime_old_credential_for_test"
	if err := WriteFileAtomic0600(credentialPath, []byte(old+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic0600(configPath, []byte("[Interface]\nPrivateKey = local\n")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var preparedHashes []string
	var candidateBearer string
	promoted := false
	prepareAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/api/v1/agent/runtime/poll":
			if auth == old {
				mu.Lock()
				retired := promoted
				mu.Unlock()
				if retired {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"revision":1,"device_id":"11111111-1111-1111-1111-111111111111","org_id":"22222222-2222-2222-2222-222222222222","address":"10.99.0.7/32","gateway_endpoint":"127.0.0.1:51820","gateway_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.99.0.0/24"],"dns":[],"persistent_keepalive":25,"credential_rotation_revision":2}`))
				return
			}
			mu.Lock()
			candidateBearer = auth
			promoted = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/runtime/credential-candidate":
			if auth != old {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct {
				Revision  int64  `json:"revision"`
				TokenHash string `json:"token_hash"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Revision != 2 || len(body.TokenHash) != 64 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			preparedHashes = append(preparedHashes, body.TokenHash)
			prepareAttempts++
			attempt := prepareAttempts
			mu.Unlock()
			if attempt == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/runtime/report":
			if auth == old || !strings.HasPrefix(auth, "tnx_runtime_") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			cancel()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	if err := saveManagedRuntimeState(statePath, ManagedRuntimeState{Server: server.URL, AppliedRevision: 1, ClientVersion: "test"}); err != nil {
		t.Fatal(err)
	}

	applyCalls := 0
	err := RunManagedAgent(ctx, ManagedRuntimeOptions{
		StatePath: statePath, CredentialPath: credentialPath, ConfigPath: configPath,
		ClientVersion: "test", PollWait: 0, Interval: 5 * time.Millisecond,
		Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond,
		Jitter:       func(d time.Duration) time.Duration { return d },
		ApplyCommand: func(context.Context, string, string) error { applyCalls++; return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime exit = %v, want context cancellation after proof", err)
	}
	mu.Lock()
	hashes := append([]string(nil), preparedHashes...)
	newBearer := candidateBearer
	mu.Unlock()
	if len(hashes) != 2 || hashes[0] != hashes[1] {
		t.Fatalf("prepare retry hashes = %v, want identical lost-response-safe retry", hashes)
	}
	if newBearer == "" || newBearer == old {
		t.Fatal("candidate bearer was not used for poll/report proof")
	}
	stored, err := loadRuntimeCredential(credentialPath)
	if err != nil || stored != newBearer {
		t.Fatalf("stored successor = %q, err=%v", stored, err)
	}
	info, err := os.Stat(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %v, want 0600", info.Mode().Perm())
	}
	for _, scratch := range []string{credentialPath + ".candidate", credentialPath + ".previous"} {
		if _, err := os.Stat(scratch); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rotation scratch remains at %s: %v", scratch, err)
		}
	}
	if applyCalls != 0 {
		t.Fatalf("credential rotation churned WireGuard apply %d time(s)", applyCalls)
	}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/agent/runtime/poll", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+old)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old bearer after promotion = HTTP %d, want 401", response.StatusCode)
	}
}

func TestManagedRuntimeRotationRestartRecoveryAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		want    string
		wantErr error
	}{
		{name: "accepted candidate survives restart", status: http.StatusNoContent, want: "tnx_runtime_candidate_restart"},
		{name: "definite candidate refusal restores previous", status: http.StatusUnauthorized, want: "tnx_runtime_previous_restart", wantErr: ErrRuntimeUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "runtime-credential")
			candidate := "tnx_runtime_candidate_restart"
			previous := "tnx_runtime_previous_restart"
			for file, value := range map[string]string{path: candidate, path + ".candidate": candidate, path + ".previous": previous} {
				if err := WriteFileAtomic0600(file, []byte(value+"\n")); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != candidate {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			state := ManagedRuntimeState{Server: server.URL, ClientVersion: "test", WireGuardRevision: 1}
			source, err := newManagedRuntimeSource(server.URL, candidate, path,
				filepath.Join(dir, "runtime.conf"), filepath.Join(dir, "state.json"), &state, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.Poll(context.Background(), 1, "test")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("restart poll error = %v, want %v", err, tc.wantErr)
			}
			stored, err := loadRuntimeCredential(path)
			if err != nil || stored != tc.want {
				t.Fatalf("restart credential = %q, err=%v, want %q", stored, err, tc.want)
			}
			if _, err := os.Stat(path + ".previous"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("previous scratch remains: %v", err)
			}
			if _, err := os.Stat(path + ".candidate"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("candidate scratch remains: %v", err)
			}
		})
	}
}

func TestManagedRuntimeRefusedCurrentDiscardsUncommittedCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime-credential")
	current := "tnx_runtime_current_before_suspend"
	for file, value := range map[string]string{path: current, path + ".candidate": "tnx_runtime_uncommitted_candidate"} {
		if err := WriteFileAtomic0600(file, []byte(value+"\n")); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	state := ManagedRuntimeState{Server: server.URL, ClientVersion: "test", WireGuardRevision: 1}
	source, err := newManagedRuntimeSource(server.URL, current, path,
		filepath.Join(dir, "runtime.conf"), filepath.Join(dir, "state.json"), &state, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(context.Background(), 1, "test"); !errors.Is(err, ErrRuntimeUnauthorized) {
		t.Fatalf("poll error = %v, want runtime unauthorized", err)
	}
	stored, err := loadRuntimeCredential(path)
	if err != nil || stored != current {
		t.Fatalf("current credential changed = %q, err=%v", stored, err)
	}
	if _, err := os.Stat(path + ".candidate"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate scratch remains after terminal current refusal: %v", err)
	}
}

func TestManagedRuntimeWireGuardCandidateStagesHotAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "runtime-credential")
	configPath := filepath.Join(dir, "runtime.conf")
	statePath := filepath.Join(dir, "runtime-state.json")
	credential := "tnx_runtime_wg_rotation"
	oldPrivate := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	config := "[Interface]\nPrivateKey = " + oldPrivate + "\nAddress = 10.99.0.7/32\n\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 10.99.0.0/24\n"
	for path, contents := range map[string]string{credentialPath: credential + "\n", configPath: config} {
		if err := WriteFileAtomic0600(path, []byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	state := ManagedRuntimeState{Server: "pending", AppliedRevision: 1, ClientVersion: "test", WireGuardRevision: 1}
	phase := 0
	preparedPublicKey := ""
	prepareAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/runtime/wireguard-candidate":
			var body api.AgentWireGuardCandidate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode prepare: %v", err)
			}
			if body.Revision != 2 || body.PublicKey == "" {
				t.Errorf("prepare body = %#v", body)
			}
			if preparedPublicKey != "" && preparedPublicKey != body.PublicKey {
				t.Errorf("lost-response retry changed public key")
			}
			preparedPublicKey = body.PublicKey
			prepareAttempts++
			if prepareAttempts == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/runtime/poll":
			w.Header().Set("Content-Type", "application/json")
			rotation := `,"wireguard_rotation_revision":2,"wireguard_rotation_state":"requested"`
			if phase == 1 {
				rotation = `,"wireguard_rotation_revision":2,"wireguard_rotation_state":"staged"`
			} else if phase >= 2 {
				rotation = `,"wireguard_current_revision":2`
			}
			current := `,"wireguard_current_revision":1`
			if phase >= 2 {
				current = ""
			}
			_, _ = fmt.Fprintf(w, `{"revision":1,"device_id":"11111111-1111-1111-1111-111111111111","org_id":"22222222-2222-2222-2222-222222222222","address":"10.99.0.7/32","gateway_endpoint":"127.0.0.1:51820","gateway_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.99.0.0/24"],"dns":[],"persistent_keepalive":25%s%s}`, current, rotation)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	state.Server = server.URL
	if err := saveManagedRuntimeState(statePath, state); err != nil {
		t.Fatal(err)
	}
	keySwaps := 0
	rotate := func(_ context.Context, _, keyPath string) error {
		keySwaps++
		info, err := os.Stat(keyPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("candidate key mode = %v, err=%v", info.Mode().Perm(), err)
		}
		return nil
	}
	source, err := newManagedRuntimeSource(server.URL, credential, credentialPath, configPath, statePath, &state, 0, rotate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Poll(context.Background(), 1, "test"); err == nil {
		t.Fatal("lost prepare response must be retried, not treated as prepared")
	}
	if _, err := source.Poll(context.Background(), 1, "test"); err != nil || prepareAttempts != 2 {
		t.Fatalf("prepare retry attempts=%d err=%v", prepareAttempts, err)
	}
	phase = 1
	if _, err := source.Poll(context.Background(), 1, "test"); err != nil {
		t.Fatalf("staged poll: %v", err)
	}
	if keySwaps != 1 || state.WireGuardCandidateRevision != 2 || configValue(string(mustRead(t, configPath)), "PrivateKey") == oldPrivate {
		t.Fatalf("hot stage swaps=%d state=%+v config=%s", keySwaps, state, mustRead(t, configPath))
	}
	if _, err := source.Poll(context.Background(), 1, "test"); err != nil || keySwaps != 1 {
		t.Fatalf("repeated staged poll churned key: swaps=%d err=%v", keySwaps, err)
	}
	// Restart after local switch: the persisted candidate state and files are
	// sufficient to observe the committed revision and retire recovery state.
	restarted, err := loadManagedRuntimeState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	phase = 2
	restartedSource, err := newManagedRuntimeSource(server.URL, credential, credentialPath, configPath, statePath, &restarted, 0, rotate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedSource.Poll(context.Background(), 1, "test"); err != nil {
		t.Fatalf("committed restart poll: %v", err)
	}
	if restarted.WireGuardRevision != 2 || restarted.WireGuardCandidateRevision != 0 || keySwaps != 1 {
		t.Fatalf("commit state=%+v swaps=%d", restarted, keySwaps)
	}
	for _, path := range []string{configPath + ".candidate-key", configPath + ".previous"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rotation scratch remains at %s: %v", path, err)
		}
	}
}

func TestManagedRuntimeWireGuardCancellationRestoresLastGood(t *testing.T) {
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "runtime-credential")
	configPath := filepath.Join(dir, "runtime.conf")
	statePath := filepath.Join(dir, "runtime-state.json")
	credential := "tnx_runtime_wg_cancel"
	oldPrivate := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	config := "[Interface]\nPrivateKey = " + oldPrivate + "\nAddress = 10.99.0.7/32\n"
	_ = WriteFileAtomic0600(credentialPath, []byte(credential+"\n"))
	_ = WriteFileAtomic0600(configPath, []byte(config))
	state := ManagedRuntimeState{AppliedRevision: 1, ClientVersion: "test", WireGuardRevision: 1}
	phase := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/runtime/wireguard-candidate" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if phase == 2 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		stateName := "requested"
		if phase == 1 {
			stateName = "staged"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"revision":1,"device_id":"11111111-1111-1111-1111-111111111111","org_id":"22222222-2222-2222-2222-222222222222","address":"10.99.0.7/32","gateway_endpoint":"127.0.0.1:51820","gateway_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_ips":["10.99.0.0/24"],"dns":[],"persistent_keepalive":25,"wireguard_current_revision":1,"wireguard_rotation_revision":2,"wireguard_rotation_state":%q}`, stateName)
	}))
	defer server.Close()
	state.Server = server.URL
	_ = saveManagedRuntimeState(statePath, state)
	keySwaps := 0
	rotate := func(context.Context, string, string) error { keySwaps++; return nil }
	source, _ := newManagedRuntimeSource(server.URL, credential, credentialPath, configPath, statePath, &state, 0, rotate)
	_, _ = source.Poll(context.Background(), 1, "test")
	phase = 1
	if _, err := source.Poll(context.Background(), 1, "test"); err != nil {
		t.Fatal(err)
	}
	phase = 2
	if _, err := source.Poll(context.Background(), 1, "test"); err != nil {
		t.Fatal(err)
	}
	if keySwaps != 2 || state.WireGuardCandidateRevision != 0 || configValue(string(mustRead(t, configPath)), "PrivateKey") != oldPrivate {
		t.Fatalf("cancel restore swaps=%d state=%+v config=%s", keySwaps, state, mustRead(t, configPath))
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
