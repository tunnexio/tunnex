package sandboxes

import (
	"errors"
	"strings"
	"testing"
)

func TestSSHPublicKeysPostgresImmutableIntentAndNormalization(t *testing.T) {
	f := newFixture(t)
	in := f.input("ssh-keys")
	in.SSHPublicKeys = []string{strings.TrimSpace(f.sshPublicKey) + " local-comment"}
	first, replay, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil || replay || len(first.SSHPublicKeys) != 1 || first.SSHPublicKeys[0] != f.sshPublicKey {
		t.Fatal("key normalization failed", err)
	}
	in.SSHPublicKeys = []string{f.sshPublicKey}
	second, replay, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil || !replay || second.Identity.ID != first.Identity.ID {
		t.Fatal("comment changed idempotent intent", err)
	}
	in.SSHPublicKeys = []string{publicTerminalKey(t)}
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrConflict) {
		t.Fatal("new key replay silently altered intent", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET ssh_public_keys='[]' WHERE id=$1`, first.Identity.ID); err == nil {
		t.Fatal("direct immutable-key mutation accepted")
	}
	in = f.input("no-ssh")
	in.SSHPublicKeys = nil
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing SSH key admitted", err)
	}
	in.SSHPublicKeys = []string{"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-only"}
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("private-key text admitted", err)
	}
}
