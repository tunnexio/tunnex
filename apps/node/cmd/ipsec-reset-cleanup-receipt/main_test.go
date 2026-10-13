package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateReceiptInputsRejectSymlinkModeAndOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if raw, err := privateRead(path, 2); err != nil || string(raw) != "{}" {
			t.Fatal(err)
		}
	}
	if _, err := privateRead(path, 1); err == nil {
		t.Fatal("oversized input accepted")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateRead(link, 2); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := privateRead(path, 2); err == nil {
		t.Fatal("nonprivate input accepted")
	}
}
