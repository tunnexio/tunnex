package restorebarrier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartupBarrierNeverTrustsRestoredCompletion(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "restore.pending")
	if Check("") != nil || Check(path) != nil {
		t.Fatal("disabled/absent barrier refused")
	}
	if err := os.WriteFile(path, []byte(`{"completed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if Check(path) == nil {
		t.Fatal("old completion marker reopened listeners")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("absent-target", path); err != nil {
		t.Fatal(err)
	}
	if Check(path) == nil {
		t.Fatal("dangling marker symlink reopened listeners")
	}
}

func TestConfiguredBarrierRequiresItsPrivateRealDirectory(t *testing.T) {
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0700); err != nil {
		t.Fatal(err)
	}
	if Check(filepath.Join(real, "restore.pending")) != nil {
		t.Fatal("valid private barrier directory refused")
	}
	if Check(filepath.Join(real, "missing", "restore.pending")) == nil {
		t.Fatal("missing restore mount reopened listeners")
	}
	if Check("relative.pending") == nil {
		t.Fatal("relative barrier accepted")
	}
	link := filepath.Join(real, "linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if Check(filepath.Join(link, "restore.pending")) == nil {
		t.Fatal("symlinked restore directory accepted")
	}
	if err := os.Chmod(real, 0755); err != nil {
		t.Fatal(err)
	}
	if Check(filepath.Join(real, "restore.pending")) == nil {
		t.Fatal("nonprivate restore directory accepted")
	}
}
