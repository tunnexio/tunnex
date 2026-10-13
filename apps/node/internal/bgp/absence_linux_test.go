//go:build linux

package bgp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanedProcessReadOnlyAbsenceRejectsResidueAndIdentityChange(t *testing.T) {
	p, id := recoveryIdentityFixture(t)
	if RecoverProcess(id) != nil {
		t.Fatal("fixture cleanup")
	}
	id.Stage = "cleaned"
	before, _ := os.Stat(p.dir)
	if ProveCleanedProcessAbsent(context.Background(), id, false) != nil {
		t.Fatal("actual discharged empty directory refused")
	}
	after, _ := os.Stat(p.dir)
	if !os.SameFile(before, after) {
		t.Fatal("proof mutated directory")
	}
	path := filepath.Join(p.dir, "foreign")
	if os.WriteFile(path, []byte("unowned"), 0600) != nil {
		t.Fatal("fixture residue")
	}
	if ProveCleanedProcessAbsent(context.Background(), id, false) == nil {
		t.Fatal("foreign artifact accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("proof deleted residue")
	}
	if os.Remove(path) != nil {
		t.Fatal("fixture cleanup")
	}
	id.DirectoryFile.Inode++
	if ProveCleanedProcessAbsent(context.Background(), id, false) == nil {
		t.Fatal("replaced directory accepted")
	}
}
func TestCleanedProcessReadOnlyAbsenceRejectsLiveChildAndCanceledContext(t *testing.T) {
	p, id := recoveryIdentityFixture(t)
	if RecoverProcess(id) != nil {
		t.Fatal("fixture cleanup")
	}
	id.Stage = "cleaned"
	current, err := childIdentity("test", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	id.Children = []ChildIdentity{current}
	if ProveCleanedProcessAbsent(context.Background(), id, false) == nil {
		t.Fatal("live original child accepted")
	}
	id.Children = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ProveCleanedProcessAbsent(ctx, id, false) == nil {
		t.Fatal("expired proof accepted")
	}
	if entries, err := os.ReadDir(p.dir); err != nil || len(entries) != 0 {
		t.Fatal("proof changed artifacts")
	}
}
func TestCleanedHistoryReadOnlyCensusRejectsSurvivorAndMalformedGeneration(t *testing.T) {
	p, id := recoveryIdentityFixture(t)
	if RecoverProcess(id) != nil {
		t.Fatal("fixture cleanup")
	}
	parent := p.dir
	prefix := "bgp-owned-g"
	directory := filepath.Join(parent, prefix+"1")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("fixture directory")
	}
	if ProveCleanedHistoryAbsent(context.Background(), parent, prefix, 1) != nil {
		t.Fatal("empty compacted generation refused")
	}
	path := filepath.Join(directory, "bgpd.conf")
	if os.WriteFile(path, []byte("survivor"), 0600) != nil {
		t.Fatal("fixture residue")
	}
	if ProveCleanedHistoryAbsent(context.Background(), parent, prefix, 1) == nil {
		t.Fatal("compacted residue accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("proof mutated residue")
	}
	if os.Remove(path) != nil || os.Mkdir(filepath.Join(parent, prefix+"01"), 0700) != nil {
		t.Fatal("fixture cleanup")
	}
	if ProveCleanedHistoryAbsent(context.Background(), parent, prefix, 1) == nil {
		t.Fatal("noncanonical generation accepted")
	}
}
