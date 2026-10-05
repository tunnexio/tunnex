package sandboxes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// Re-execute only this disposable test binary as a fixed bootstrap fixture.
// No shell, live credential, network endpoint or package install is involved.
func init() {
	if len(os.Args) != 9 || os.Args[1] != "--server" || os.Args[2] != "https://fixture-command.example" {
		return
	}
	directory := os.Args[8]
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
	if err != nil {
		os.Exit(2)
	}
	args, _ := json.Marshal(os.Args[1:])
	if os.WriteFile(filepath.Join(directory, "argv.json"), args, 0600) != nil || os.WriteFile(filepath.Join(directory, "stdin"), body, 0600) != nil {
		os.Exit(2)
	}
	file, err := os.OpenFile(filepath.Join(directory, "calls"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, err = file.Write([]byte("x"))
	if err != nil {
		os.Exit(2)
	}
	file.Close()
	// The production invoker must suppress even a misbehaving client's output.
	fmt.Fprint(os.Stdout, string(body))
	fmt.Fprint(os.Stderr, string(body))
	os.Exit(0)
}

func TestPinnedBootstrapCommandUsesStdinAndRefusesChangedBinary(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner := CommandBootstrap{Binary: binary, SHA256: hex.EncodeToString(hash.Sum(nil))}
	directory := t.TempDir()
	const token = "fixture-token-only"
	if err = runner.Bootstrap(context.Background(), "https://fixture-command.example", uuid.New(), 1, directory, token); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(directory, "argv.json"))
	if err != nil || bytes.Contains(args, []byte(token)) {
		t.Fatal("token leaked into arguments", err)
	}
	stdin, err := os.ReadFile(filepath.Join(directory, "stdin"))
	if err != nil || string(stdin) != token+"\n" {
		t.Fatal("token not supplied on stdin", err)
	}
	runner.SHA256 = strings.Repeat("0", 64)
	if err = runner.Bootstrap(context.Background(), "https://fixture-command.example", uuid.New(), 1, directory, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed binary accepted", err)
	}
	calls, err := os.ReadFile(filepath.Join(directory, "calls"))
	if err != nil || string(calls) != "x" {
		t.Fatal("unverified command executed", err)
	}
}

func TestPersistedWireGuardRejectsExecutableHooks(t *testing.T) {
	private, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	config := "[Interface]\nPrivateKey = " + private + "\nAddress = 10.99.0.4/32\n\n[Peer]\nPublicKey = " + public + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.99.0.0/24\nPersistentKeepalive = 25\n"
	if got, err := persistedWireGuardPublicKey([]byte(config)); err != nil || got != public {
		t.Fatal("persisted key derivation failed", err)
	}
	for _, suffix := range []string{"PostUp = touch /fixture-only\n", "PreDown = true\n", "[Peer]\nPublicKey = " + public + "\n"} {
		if _, err = persistedWireGuardPublicKey([]byte(config + suffix)); !errors.Is(err, ErrConflict) {
			t.Fatal("executable or duplicate section accepted", err)
		}
	}
}
