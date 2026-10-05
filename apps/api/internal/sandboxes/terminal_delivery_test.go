package sandboxes

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func publicTerminalKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(key))
}

func TestTerminalIdentityPublicationAndRetry(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	keys := []string{publicTerminalKey(t), publicTerminalKey(t)}
	first, err := MaterializeTerminal(root, keys)
	if err != nil || first.Directory != "terminal" || !strings.HasPrefix(first.HostKeyFingerprint, "SHA256:") {
		t.Fatal(first, err)
	}
	second, err := MaterializeTerminal(root, []string{keys[1], keys[0]})
	if err != nil || first != second {
		t.Fatal("host identity rotated on retry", err)
	}
	for _, path := range []string{"terminal/host_key", "terminal/authorized_keys", "terminal/sshd_config"} {
		info, err := root.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate terminal file", path, err)
		}
	}
	if _, err = MaterializeTerminal(root, []string{publicTerminalKey(t)}); !errors.Is(err, ErrConflict) {
		t.Fatal("key set silently replaced", err)
	}
	if err = root.WriteFile("terminal/sshd_config", []byte("PasswordAuthentication yes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = MaterializeTerminal(root, keys); !errors.Is(err, ErrConflict) {
		t.Fatal("tampered config accepted", err)
	}
}

func TestTerminalRejectsKeyOptionsAndExistingSymlink(t *testing.T) {
	key := publicTerminalKey(t)
	for _, keys := range [][]string{nil, {key, key}, {"command=\"id\" " + key}, {key + key}, {strings.Repeat("x", 8193)}} {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, err = MaterializeTerminal(root, keys)
		root.Close()
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe authorized key accepted", err)
		}
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = root.Symlink(t.TempDir(), "terminal"); err != nil {
		t.Fatal(err)
	}
	if _, err = MaterializeTerminal(root, []string{key}); !errors.Is(err, ErrConflict) {
		t.Fatal("symlink publication accepted", err)
	}
}
