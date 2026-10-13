//go:build linux

package bgp

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func recoveryIdentityFixture(t *testing.T) (*Process, ProcessIdentity) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned native fixture")
	}
	dir, err := os.MkdirTemp("/root", "tunnex-bgp-crash-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &Process{dir: dir, directory: info, owned: map[string]os.FileInfo{}}
	for _, name := range []string{"supervisor.lock", "bgpd.conf", "zebra.conf"} {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, []byte("owned fixture"), 0600) != nil {
			t.Fatal("create")
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		p.owned[name] = fi
	}
	id, err := p.identity("reserved")
	if err != nil {
		t.Fatal(err)
	}
	return p, id
}

func TestProcessRecoveryPartialAndFinalDeletionIdempotent(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[partial], func(t *testing.T) {
			p, id := recoveryIdentityFixture(t)
			if partial {
				if os.Remove(filepath.Join(p.dir, "bgpd.conf")) != nil {
					t.Fatal("simulate partial deletion")
				}
			}
			if err := RecoverProcess(id); err != nil {
				t.Fatal(err)
			}
			if err := RecoverProcess(id); err != nil {
				t.Fatal("post-final-delete retry", err)
			}
			files, err := os.ReadDir(p.dir)
			if err != nil || len(files) != 0 {
				t.Fatal("residue")
			}
		})
	}
}
func TestProcessRecoveryPreservesForeignAndHeldLock(t *testing.T) {
	p, id := recoveryIdentityFixture(t)
	foreign := filepath.Join(p.dir, "foreign")
	if os.WriteFile(foreign, []byte("foreign"), 0600) != nil {
		t.Fatal("create")
	}
	if RecoverProcess(id) == nil {
		t.Fatal("foreign artifact accepted")
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatal("foreign deleted")
	}
	os.Remove(foreign)
	lock, err := os.OpenFile(filepath.Join(p.dir, "supervisor.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("lock")
	}
	if RecoverProcess(id) == nil {
		t.Fatal("live supervisor lock accepted")
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := filepath.Join(p.dir, "zebra.conf")
	if os.Rename(path, path+".original") != nil {
		t.Fatal("rename")
	}
	if os.WriteFile(path, []byte("replacement"), 0600) != nil {
		t.Fatal("replace")
	}
	if RecoverProcess(id) == nil {
		t.Fatal("replacement accepted")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("replacement deleted")
	}
}

func TestProcessCloseRefusalCanRecoverAfterForeignRemediation(t *testing.T) {
	p, id := recoveryIdentityFixture(t)
	foreign := filepath.Join(p.dir, "operator-retained-foreign")
	if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.Close() == nil || !p.Stopped() {
		t.Fatal("foreign cleanup accepted or tracked process not stopped")
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatal("foreign artifact removed")
	}
	if p.Close() == nil {
		t.Fatal("cached cleanup refusal disappeared")
	}
	// Explicit external remediation removes only the test's foreign artifact.
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := RecoverProcess(id); err != nil {
		t.Fatal("persisted duty could not recover after remediation", err)
	}
	if err := RecoverProcess(id); err != nil {
		t.Fatal("durable empty recovery retry", err)
	}
}
