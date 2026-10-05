package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxBootstrapTLSPrivateHandoffAndNoRetry(t *testing.T) {
	id, peer := uuid.New(), uuid.New()
	calls := 0
	template := "[Interface]\nAddress = 10.99.0.4/32\nPrivateKey = __TUNNEX_PRIVATE_KEY__\n\n[Peer]\nPublicKey = " + strings.Repeat("A", 43) + "=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.99.0.0/24\nPersistentKeepalive = 25\n"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/sandbox/bootstrap" || r.Method != "POST" {
			t.Error("wrong bootstrap protocol")
		}
		var request api.SandboxBootstrapRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.PublicKey) != 44 || !strings.HasPrefix(request.BootstrapToken, "tnx_sandbox_bootstrap_") {
			t.Error("invalid request")
		}
		_ = json.NewEncoder(w).Encode(api.SandboxBootstrapResponse{SandboxId: id, PeerId: peer, Generation: 1, Config: template, RuntimeCredential: "tnx_sandbox_runtime_" + strings.Repeat("A", 43)})
	}))
	defer server.Close()
	directory := filepath.Join(t.TempDir(), "handoff")
	opts := SandboxBootstrapOptions{server.URL, "tnx_sandbox_bootstrap_" + strings.Repeat("A", 43), directory, id, 1, server.Client(), nil}
	opts.HTTPClient = nil
	opts.CACertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	state, err := BootstrapSandbox(context.Background(), opts)
	if err != nil || state.SandboxID != id || state.PeerID != peer || calls != 1 {
		t.Fatal("handoff failed", err)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("handoff directory is not private")
	}
	for _, name := range []string{"wireguard.conf", "runtime-credential", "state.json"} {
		info, err = os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("handoff file is not private")
		}
	}
	config, _ := os.ReadFile(filepath.Join(directory, "wireguard.conf"))
	if strings.Contains(string(config), "__TUNNEX_PRIVATE_KEY__") || !strings.Contains(string(config), "PrivateKey = ") {
		t.Fatal("client private key not inserted")
	}
	if _, err = BootstrapSandbox(context.Background(), opts); err == nil || calls != 1 {
		t.Fatal("existing handoff redeemed again")
	}
	opts.HandoffDir = filepath.Join(t.TempDir(), "wrong-generation")
	opts.Generation = 2
	if _, err = BootstrapSandbox(context.Background(), opts); err == nil || calls != 2 {
		t.Fatal("mismatched response accepted or retried")
	}
	if _, err = os.Stat(opts.HandoffDir); !os.IsNotExist(err) {
		t.Fatal("invalid handoff left files")
	}
}
func TestSandboxBootstrapRefusesHooksDefaultsAndPlainHTTP(t *testing.T) {
	config := "[Interface]\nAddress = 10.99.0.4/32\nPrivateKey = __TUNNEX_PRIVATE_KEY__\n[Peer]\nPublicKey = " + strings.Repeat("A", 43) + "=\nEndpoint = gateway:51820\nAllowedIPs = 10.99.0.0/24\n"
	if !sandboxConfigTemplate(config) {
		t.Fatal("valid bounded template refused")
	}
	for _, invalid := range []string{config + "PostUp = arbitrary\n", strings.Replace(config, "10.99.0.0/24", "0.0.0.0/0", 1), strings.Replace(config, "10.99.0.0/24", "::/0", 1), config + "[Interface]\nPrivateKey = __TUNNEX_PRIVATE_KEY__\n"} {
		if sandboxConfigTemplate(invalid) {
			t.Fatal("unsupported config accepted")
		}
	}
	opts := SandboxBootstrapOptions{Server: "http://example.test", Token: "tnx_sandbox_bootstrap_" + strings.Repeat("A", 43), HandoffDir: filepath.Join(t.TempDir(), "plain"), SandboxID: uuid.New(), Generation: 1}
	if _, err := BootstrapSandbox(context.Background(), opts); err == nil {
		t.Fatal("plain HTTP allowed")
	}
	if _, err := os.Stat(opts.HandoffDir); !os.IsNotExist(err) {
		t.Fatal("preflight touched files")
	}
}

func TestSandboxBootstrapRefusesOversizeRedirectAndAgentCredential(t *testing.T) {
	for _, mode := range []string{"oversize", "redirect", "agent"} {
		t.Run(mode, func(t *testing.T) {
			id := uuid.New()
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "redirect" {
					w.Header().Set("Location", "/another")
					w.WriteHeader(307)
					return
				}
				response := api.SandboxBootstrapResponse{SandboxId: id, PeerId: uuid.New(), Generation: 1, RuntimeCredential: "tnx_runtime_" + strings.Repeat("A", 43), Config: "[Interface]\nAddress = 10.99.0.4/32\nPrivateKey = __TUNNEX_PRIVATE_KEY__\n[Peer]\nPublicKey = " + strings.Repeat("A", 43) + "=\nEndpoint = gateway:51820\nAllowedIPs = 10.99.0.0/24\n"}
				if mode == "oversize" {
					response.Config = strings.Repeat("a", 300000)
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			dir := filepath.Join(t.TempDir(), "rejected")
			opts := SandboxBootstrapOptions{server.URL, "tnx_sandbox_bootstrap_" + strings.Repeat("A", 43), dir, id, 1, server.Client(), nil}
			if _, err := BootstrapSandbox(context.Background(), opts); err == nil || calls != 1 {
				t.Fatal("unsafe response accepted or retried", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("rejected response retained handoff")
			}
		})
	}
}

func TestSandboxBootstrapInvalidScopedCARefusesBeforeReservation(t *testing.T) {
	opts := SandboxBootstrapOptions{Server: "https://example.test", Token: "tnx_sandbox_bootstrap_" + strings.Repeat("A", 43), HandoffDir: filepath.Join(t.TempDir(), "invalid-ca"), SandboxID: uuid.New(), Generation: 1, CACertificatePEM: []byte("invalid public CA")}
	if _, err := BootstrapSandbox(context.Background(), opts); err == nil {
		t.Fatal("invalid CA accepted")
	}
	if _, err := os.Stat(opts.HandoffDir); !os.IsNotExist(err) {
		t.Fatal("invalid trust changed handoff directory")
	}
}
