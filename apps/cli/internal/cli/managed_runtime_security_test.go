package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedRuntimeStateRefusesLegacyEmbeddedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://example.invalid","credential":"tnx_runtime_secret","client_version":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedRuntimeState(path); err == nil || !strings.Contains(err.Error(), "embedded credential") {
		t.Fatalf("legacy embedded credential must be refused, got %v", err)
	}
}

func TestRunWireGuardQuickDownOnlyIgnoresAbsentInterface(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "wg-quick")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nif [ \"$1\" = down ]; then\n  echo \"interface does not exist\" >&2\n  exit 1\nfi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	if err := runWireGuardQuick(context.Background(), "/etc/wireguard/runtime.conf", "disable"); err != nil {
		t.Fatalf("absent interface should be idempotent: %v", err)
	}

	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho permission denied >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := runWireGuardQuick(context.Background(), "/etc/wireguard/runtime.conf", "disable"); err == nil {
		t.Fatal("permission failure must not be swallowed")
	}
}

func TestManagedRuntimeFailedCandidateRestoresActiveLastGood(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	interfacePath := filepath.Join(dir, "runtime.active")
	tool := filepath.Join(dir, "wg-quick")
	old := "[Interface]\nPrivateKey = LOCAL-PRIVATE\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = OLD\nEndpoint = old.example:51820\nAllowedIPs = 10.0.0.0/24\n"
	if err := WriteFileAtomic0600(configPath, []byte(old)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interfacePath, []byte("up"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
action=$1
config=$2
if [ "$action" = down ]; then
  if [ ! -f "$TUNNEX_TEST_INTERFACE" ]; then
    echo 'interface is not up' >&2
    exit 1
  fi
  rm "$TUNNEX_TEST_INTERFACE"
  exit 0
fi
if grep -q 'bad.example' "$config"; then
  echo 'candidate refused' >&2
  exit 1
fi
printf up >"$TUNNEX_TEST_INTERFACE"
`
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TUNNEX_TEST_INTERFACE", interfacePath)

	applier := &wireGuardRuntimeApplier{path: configPath, command: runWireGuardQuick}
	err := applier.Apply(context.Background(), ManagedAgentConfig{
		Revision: 2, Address: "10.0.0.2/32", GatewayEndpoint: "bad.example:51820",
		GatewayPublicKey: "NEW", AllowedIPs: []string{"10.0.0.0/24"},
	})
	if err == nil || !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("candidate apply error = %v; want candidate refusal", err)
	}
	got, readErr := os.ReadFile(configPath)
	if readErr != nil || string(got) != old {
		t.Fatalf("restored config = %q, err=%v; want exact last-good bytes", got, readErr)
	}
	if _, statErr := os.Stat(interfacePath); statErr != nil {
		t.Fatalf("last-good interface was not restored: %v", statErr)
	}
}

func TestManagedRuntimeFailedCandidateSurfacesRestoreFailure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.conf")
	old := "[Interface]\nPrivateKey = LOCAL-PRIVATE\n"
	if err := WriteFileAtomic0600(configPath, []byte(old)); err != nil {
		t.Fatal(err)
	}
	candidateErr := errors.New("candidate apply failed")
	restoreErr := errors.New("last-good apply failed")
	calls := 0
	applier := &wireGuardRuntimeApplier{path: configPath, command: func(context.Context, string, string) error {
		calls++
		if calls == 1 {
			return candidateErr
		}
		return restoreErr
	}}
	err := applier.Apply(context.Background(), ManagedAgentConfig{
		Revision: 2, Address: "10.0.0.2/32", GatewayEndpoint: "bad.example:51820",
		GatewayPublicKey: "NEW", AllowedIPs: []string{"10.0.0.0/24"},
	})
	if !errors.Is(err, candidateErr) || !errors.Is(err, restoreErr) || calls != 2 {
		t.Fatalf("restore failure = %v, calls=%d; want both errors after two applies", err, calls)
	}
}
