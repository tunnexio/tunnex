package sandboxes

import (
	"errors"
	"github.com/tunnexio/tunnex/apps/api/db"
	"strings"
	"sync"
	"testing"
)

func TestSavedSSHKeyNormalization(t *testing.T) {
	public := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
	a, err := normalizeSavedSSHKey(" Laptop ", public+" comment")
	if err != nil || a.Name != "Laptop" || !strings.HasPrefix(a.Fingerprint, "SHA256:") {
		t.Fatal(a, err)
	}
	b, err := normalizeSavedSSHKey("Other", public)
	if err != nil || a.Fingerprint != b.Fingerprint || a.PublicKey != b.PublicKey {
		t.Fatal("comments affect identity")
	}
	for _, v := range []string{"-----BEGIN OPENSSH PRIVATE KEY-----", `command="echo unsafe" ` + public, public + "\n" + public, "ssh-ed25519 invalid"} {
		if _, err := normalizeSavedSSHKey("Key", v); !errors.Is(err, ErrInvalid) {
			t.Fatal("admitted invalid key", err)
		}
	}
	for _, name := range []string{" ", strings.Repeat("x", 81), "two\nlines"} {
		if _, err := normalizeSavedSSHKey(name, public); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid name accepted")
		}
	}
}
func TestSavedSSHKeyPostgresOwnershipAndSnapshot(t *testing.T) {
	f := newFixture(t)
	a, err := f.store.SaveSSHKey(f.ctx, f.user, "Laptop", f.sshPublicKey)
	if err != nil || !a.IsDefault {
		t.Fatal(a, err)
	}
	if _, err = f.store.SaveSSHKey(f.ctx, f.user, "Duplicate", strings.TrimSpace(f.sshPublicKey)+" comment"); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate admitted", err)
	}
	if err = f.store.ChangeSavedSSHKey(f.ctx, f.other, a.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross account default admitted", err)
	}
	if err = f.store.ChangeSavedSSHKey(f.ctx, f.other, a.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross account deletion admitted", err)
	}
	if other, err := f.store.SaveSSHKey(f.ctx, f.other, "Other account", f.sshPublicKey); err != nil || !other.IsDefault {
		t.Fatal("account deduplication crossed ownership", err)
	}
	foreign, err := f.store.ListSavedSSHKeys(f.ctx, f.other)
	if err != nil || len(foreign) != 1 || foreign[0].ID == a.ID {
		t.Fatal("cross account list", err)
	}
	in := f.input("saved-key")
	in.SSHPublicKeys = []string{a.PublicKey}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.store.SaveSSHKey(f.ctx, f.user, "Second", publicTerminalKey(t))
	if err != nil || b.IsDefault {
		t.Fatal(b, err)
	}
	if err = f.store.ChangeSavedSSHKey(f.ctx, f.user, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if err = f.store.ChangeSavedSSHKey(f.ctx, f.user, b.ID, false); err != nil {
		t.Fatal(err)
	}
	keys, err := f.store.ListSavedSSHKeys(f.ctx, f.user)
	if err != nil || len(keys) != 1 || keys[0].IsDefault {
		t.Fatal(keys, err)
	}
	got, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || len(got.SSHPublicKeys) != 1 || got.SSHPublicKeys[0] != a.PublicKey {
		t.Fatal("snapshot changed", got, err)
	}
}

func TestSavedSSHKeyPostgresConcurrentDefaultsAndLimit(t *testing.T) {
	f := newFixture(t)
	a, err := f.store.SaveSSHKey(f.ctx, f.user, "First", f.sshPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.store.SaveSSHKey(f.ctx, f.user, "Second", publicTerminalKey(t))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := a.ID
			if i%2 == 1 {
				id = b.ID
			}
			errs <- f.store.ChangeSavedSSHKey(f.ctx, f.user, id, true)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	keys, err := f.store.ListSavedSSHKeys(f.ctx, f.user)
	if err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, k := range keys {
		if k.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatal("concurrent defaults", defaults)
	}
	for i := 2; i < 50; i++ {
		if _, err := f.store.SaveSSHKey(f.ctx, f.user, "Synthetic", publicTerminalKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.SaveSSHKey(f.ctx, f.user, "Over limit", publicTerminalKey(t)); !errors.Is(err, ErrQuota) {
		t.Fatal("account limit", err)
	}
}

func TestSavedSSHKeyPostgresMigrationRoundTrip(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.SaveSSHKey(f.ctx, f.user, "Before rollback", f.sshPublicKey); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0193_saved_ssh_keys.down.sql", "0193_saved_ssh_keys.up.sql"} {
		migration, err := db.MigrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.pool.Exec(f.ctx, string(migration)); err != nil {
			t.Fatal(name, err)
		}
	}
	keys, err := f.store.ListSavedSSHKeys(f.ctx, f.user)
	if err != nil || len(keys) != 0 {
		t.Fatal("rollback retained registry", keys, err)
	}
	if v, err := f.store.SaveSSHKey(f.ctx, f.user, "After migration", f.sshPublicKey); err != nil || !v.IsDefault {
		t.Fatal("registry not restored", v, err)
	}
}
