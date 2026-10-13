package ipsec

import (
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func processStateFixture(t *testing.T) RuntimeJournalEntry {
	e := bgpEntryFixture(t)
	e.BGPProcess = &bgpengine.ProcessIdentity{Generation: 1, BootID: uuid.NewString(), Namespace: e.Allocation.Namespace, Directory: filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g1"), Stage: "reserved", Supervisor: bgpengine.ChildIdentity{Name: "supervisor", PID: 100, StartTicks: 1, Executable: bgpengine.FileIdentity{Device: 1, Inode: 90, Mode: 0755}}, DirectoryFile: bgpengine.FileIdentity{Device: 1, Inode: 1, Mode: uint32(os.ModeDir | 0700)}, Children: []bgpengine.ChildIdentity{}, Files: []bgpengine.NamedFileIdentity{}}
	for i, name := range []string{"bgpd.conf", "supervisor.lock", "zebra.conf"} {
		e.BGPProcess.Files = append(e.BGPProcess.Files, bgpengine.NamedFileIdentity{Name: name, File: bgpengine.FileIdentity{Device: 1, Inode: uint64(i + 2), Mode: 0600}})
	}
	return e
}
func cloneProcessState(e RuntimeJournalEntry) RuntimeJournalEntry {
	p := *e.BGPProcess
	p.Files = append([]bgpengine.NamedFileIdentity{}, p.Files...)
	p.Children = append([]bgpengine.ChildIdentity{}, p.Children...)
	e.BGPProcess = &p
	return e
}
func TestBGPProcessCheckpointOwnershipTransitions(t *testing.T) {
	reserved := processStateFixture(t)
	if !validBGPProcess(reserved) {
		t.Fatal("valid reserve refused")
	}
	partial := cloneProcessState(reserved)
	partial.BGPProcess.Stage = "partial"
	partial.BGPProcess.Children = append(partial.BGPProcess.Children, bgpengine.ChildIdentity{Name: "zebra", PID: 111, StartTicks: 5, Executable: bgpengine.FileIdentity{Device: 1, Inode: 100, Mode: 0755}})
	if !validBGPProcessSuccessor(reserved, partial) {
		t.Fatal("owned child checkpoint refused")
	}
	ready := cloneProcessState(partial)
	ready.BGPProcess.Stage = "ready"
	ready.BGPProcess.Children = append(ready.BGPProcess.Children, bgpengine.ChildIdentity{Name: "bgpd", PID: 112, StartTicks: 6, Executable: bgpengine.FileIdentity{Device: 1, Inode: 101, Mode: 0755}})
	for i, name := range []string{"bgpd.pid", "zebra.pid", "bgpd.vty", "zebra.vty", "zserv.api"} {
		mode := os.FileMode(0600)
		if i >= 2 {
			mode |= os.ModeSocket
		}
		ready.BGPProcess.Files = append(ready.BGPProcess.Files, bgpengine.NamedFileIdentity{Name: name, File: bgpengine.FileIdentity{Device: 1, Inode: uint64(i + 10), Mode: uint32(mode)}})
	}
	sort.Slice(ready.BGPProcess.Files, func(i, j int) bool { return ready.BGPProcess.Files[i].Name < ready.BGPProcess.Files[j].Name })
	if !validBGPProcessSuccessor(partial, ready) {
		t.Fatal("ready checkpoint refused")
	}
	for _, change := range []func(*bgpengine.ProcessIdentity){
		func(p *bgpengine.ProcessIdentity) { p.Files[0].File.Inode++ },
		func(p *bgpengine.ProcessIdentity) { p.Children[0].StartTicks++ },
		func(p *bgpengine.ProcessIdentity) { p.DirectoryFile.Inode++ },
		func(p *bgpengine.ProcessIdentity) { p.BootID = uuid.NewString() },
		func(p *bgpengine.ProcessIdentity) { p.Generation++ },
		func(p *bgpengine.ProcessIdentity) { p.Stage = "reserved" },
	} {
		altered := cloneProcessState(ready)
		change(altered.BGPProcess)
		if validBGPProcessSuccessor(ready, altered) {
			t.Fatal("checkpoint ownership rewrite admitted")
		}
	}
	cleaned := cloneProcessState(ready)
	cleaned.BGPProcess.Stage = "cleaned"
	if !validBGPProcessSuccessor(ready, cleaned) {
		t.Fatal("proved cleanup refused")
	}
	erased := cleaned
	erased.BGPProcess = nil
	if validBGPProcessSuccessor(cleaned, erased) {
		t.Fatal("process duty erased")
	}
	fresh := cloneProcessState(reserved)
	fresh.BGPProcess.BootID = cleaned.BGPProcess.BootID
	fresh.BGPProcess.Generation = 2
	fresh.BGPProcess.Directory = strings.TrimSuffix(fresh.BGPProcess.Directory, "-g1") + "-g2"
	fresh.BGPProcess.DirectoryFile.Inode++
	fresh.BGPProcessRetired = []bgpengine.ProcessIdentity{*cleaned.BGPProcess}
	if !validBGPProcessSuccessor(cleaned, fresh) {
		t.Fatal("fresh generation refused")
	}
	cleaned.BGPProcess.Generation = ^uint64(0)
	fresh.BGPProcess.Generation = 0
	if validBGPProcessSuccessor(cleaned, fresh) {
		t.Fatal("generation wrap admitted")
	}
}
func TestBGPProcessCheckpointMalformedIdentity(t *testing.T) {
	for _, change := range []func(*bgpengine.ProcessIdentity){
		func(p *bgpengine.ProcessIdentity) { p.Directory = "/var/lib/tunnex/bgp-foreign" },
		func(p *bgpengine.ProcessIdentity) { p.Namespace = "net:[0]" },
		func(p *bgpengine.ProcessIdentity) { p.Files[0].File.Mode = 0666 },
		func(p *bgpengine.ProcessIdentity) { p.Files[0].Name = "../foreign" },
		func(p *bgpengine.ProcessIdentity) { p.DirectoryFile.Mode = uint32(os.ModeSymlink | 0700) },
		func(p *bgpengine.ProcessIdentity) { p.Stage = "ready" },
	} {
		e := processStateFixture(t)
		change(e.BGPProcess)
		if validBGPProcess(e) {
			t.Fatal("malformed process identity admitted")
		}
	}
}

func TestBGPProcessUncertainHistoryPreservesOwnership(t *testing.T) {
	before := processStateFixture(t)
	after := cloneProcessState(before)
	after.BGPProcess.Generation = 2
	after.BGPProcess.Directory = strings.TrimSuffix(after.BGPProcess.Directory, "-g1") + "-g2"
	after.BGPProcess.DirectoryFile.Inode++
	after.BGPProcess.Supervisor.PID++
	archived := *before.BGPProcess
	archived.Stage = "retired-uncertain"
	after.BGPProcessRetired = []bgpengine.ProcessIdentity{archived}
	if !validBGPProcessSuccessor(before, after) {
		t.Fatal("uncertain generation history refused")
	}
	for _, change := range []func(*RuntimeJournalEntry){
		func(e *RuntimeJournalEntry) {
			e.BGPProcessRetired[0].Files = append([]bgpengine.NamedFileIdentity{}, e.BGPProcessRetired[0].Files...)
			e.BGPProcessRetired[0].Files[0].File.Inode++
		},
		func(e *RuntimeJournalEntry) { e.BGPProcessRetired[0].Supervisor.PID++ },
		func(e *RuntimeJournalEntry) { e.BGPProcessRetired = nil },
		func(e *RuntimeJournalEntry) { e.BGPProcessRetired[0].Stage = "cleaned" },
		func(e *RuntimeJournalEntry) { e.BGPProcess.Generation = 3 },
	} {
		altered := cloneProcessState(after)
		altered.BGPProcessRetired = append([]bgpengine.ProcessIdentity{}, after.BGPProcessRetired...)
		change(&altered)
		if validBGPProcessSuccessor(before, altered) {
			t.Fatal("uncertain historical duty erased/rewritten")
		}
	}
	old := cloneProcessState(after)
	changed := cloneProcessState(after)
	changed.BGPProcessRetired = append([]bgpengine.ProcessIdentity{}, after.BGPProcessRetired...)
	changed.BGPProcessRetired[0].DirectoryFile.Inode++
	if validBGPProcessSuccessor(old, changed) {
		t.Fatal("retired duty mutated without new generation")
	}
}

func TestBGPProcessSupervisorPrivateExecutableMode(t *testing.T) {
	e := processStateFixture(t)
	e.BGPProcess.Supervisor.Executable.Mode = 0700
	if !validBGPProcess(e) {
		t.Fatal("owned private supervisor executable refused")
	}
	e.BGPProcess.Supervisor.Executable.Mode = 0770
	if validBGPProcess(e) {
		t.Fatal("group writable supervisor executable admitted")
	}
	e.BGPProcess.Supervisor.Executable.Mode = uint32(os.ModeSymlink | 0700)
	if validBGPProcess(e) {
		t.Fatal("supervisor symlink identity admitted")
	}
	e.BGPProcess.Supervisor.Executable.Mode = 0750
	if validBGPProcess(e) {
		t.Fatal("unqualified supervisor executable mode admitted")
	}
}

func TestBGPProcessRetiredUncertaintyRemediation(t *testing.T) {
	e := processStateFixture(t)
	old := *e.BGPProcess
	old.Stage = "retired-uncertain"
	e.BGPProcess = nil
	e.BGPProcessRetired = []bgpengine.ProcessIdentity{old}
	next := e
	next.BGPProcessRetired = append([]bgpengine.ProcessIdentity{}, e.BGPProcessRetired...)
	next.BGPProcessRetired[0].Stage = "cleaned"
	if !validBGPProcessSuccessor(e, next) {
		t.Fatal("proved retired uncertainty remediation refused")
	}
	if validBGPProcessSuccessor(next, e) {
		t.Fatal("cleaned historical duty regressed to uncertain")
	}
	for _, change := range []func(*bgpengine.ProcessIdentity){
		func(p *bgpengine.ProcessIdentity) { p.DirectoryFile.Inode++ },
		func(p *bgpengine.ProcessIdentity) { p.Supervisor.PID++ },
		func(p *bgpengine.ProcessIdentity) { p.Generation++ },
	} {
		altered := next
		altered.BGPProcessRetired = append([]bgpengine.ProcessIdentity{}, next.BGPProcessRetired...)
		change(&altered.BGPProcessRetired[0])
		if validBGPProcessSuccessor(e, altered) {
			t.Fatal("remediation rewrote original ownership identity")
		}
	}
	erased := next
	erased.BGPProcessRetired = nil
	if validBGPProcessSuccessor(e, erased) {
		t.Fatal("remediation erased historical duty")
	}
}
