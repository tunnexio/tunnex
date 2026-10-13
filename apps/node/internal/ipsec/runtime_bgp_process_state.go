package ipsec

import (
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func validBGPProcess(e RuntimeJournalEntry) bool {
	if e.BGPProcess == nil && len(e.BGPProcessRetired) == 0 && e.BGPProcessHistory == nil {
		return true
	}
	if e.ContractVersion != 3 || len(e.BGPProcessRetired) > 16 || (e.BGPProcessHistory != nil && len(e.BGPProcessRetired) != 16) || !validHistoryContinuation(e.BGPProcessHistory) || historyCount(e.BGPProcessHistory) > ^uint64(0)-uint64(len(e.BGPProcessRetired))-1 {
		return false
	}
	for i := range e.BGPProcessRetired {
		p := &e.BGPProcessRetired[i]
		if p.Generation != historyCount(e.BGPProcessHistory)+uint64(i+1) || (p.Stage != "cleaned" && p.Stage != "retired-uncertain") || !validBGPProcessIdentity(e, p, true) {
			return false
		}
	}
	return e.BGPProcess == nil || e.BGPProcess.Generation == historyCount(e.BGPProcessHistory)+uint64(len(e.BGPProcessRetired)+1) && validBGPProcessIdentity(e, e.BGPProcess, false)
}

func validBGPProcessIdentity(e RuntimeJournalEntry, p *bgpengine.ProcessIdentity, historical bool) bool {
	if e.ContractVersion != 3 || !validJournalBGP(e) || p.Generation == 0 || (!historical && p.Namespace != e.Allocation.Namespace) || !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || filepath.Base(p.Directory) != "bgp-"+e.DeliveryID.String()+"-g"+strconv.FormatUint(p.Generation, 10) {
		return false
	}
	boot, err := uuid.Parse(p.BootID)
	if err != nil || boot == uuid.Nil || boot.String() != p.BootID {
		return false
	}
	ns := strings.TrimSuffix(strings.TrimPrefix(p.Namespace, "net:["), "]")
	number, err := strconv.ParseUint(ns, 10, 64)
	if err != nil || number == 0 || p.Namespace != "net:["+strconv.FormatUint(number, 10)+"]" {
		return false
	}
	validFile := func(f bgpengine.FileIdentity, mode os.FileMode) bool {
		return f.Device != 0 && f.Inode != 0 && f.Mode == uint32(mode)
	}
	if !validFile(p.DirectoryFile, os.ModeDir|0700) || p.Files == nil || p.Children == nil || len(p.Files) < 3 || len(p.Files) > 8 || len(p.Children) > 2 {
		return false
	}
	known := map[string]os.FileMode{"supervisor.lock": 0600, "bgpd.conf": 0600, "zebra.conf": 0600, "bgpd.pid": 0600, "zebra.pid": 0600, "bgpd.vty": os.ModeSocket | 0600, "zebra.vty": os.ModeSocket | 0600, "zserv.api": os.ModeSocket | 0600}
	files := map[string]bool{}
	prior := ""
	for _, file := range p.Files {
		mode, ok := known[file.Name]
		if !ok || file.Name <= prior || !validFile(file.File, mode) {
			return false
		}
		prior = file.Name
		files[file.Name] = true
	}
	if !files["supervisor.lock"] || !files["bgpd.conf"] || !files["zebra.conf"] {
		return false
	}
	if p.Supervisor.Name != "supervisor" || p.Supervisor.PID <= 0 || p.Supervisor.StartTicks == 0 || (!validFile(p.Supervisor.Executable, 0700) && !validFile(p.Supervisor.Executable, 0755)) {
		return false
	}
	for i, child := range p.Children {
		name := "zebra"
		if i == 1 {
			name = "bgpd"
		}
		if child.Name != name || child.PID <= 0 || child.PID == p.Supervisor.PID || child.StartTicks == 0 || !validFile(child.Executable, 0755) || i == 1 && child.PID == p.Children[0].PID {
			return false
		}
	}
	switch p.Stage {
	case "reserved":
		return len(p.Children) == 0 && len(p.Files) == 3
	case "partial":
		return len(p.Children) >= 1
	case "ready":
		return len(p.Children) == 2 && len(p.Files) == 8
	case "cleaned":
		return true
	case "retired-uncertain":
		return historical
	default:
		return false
	}
}

// Retired uncertainty may be discharged after independent exact absence proof;
// its original ownership identities remain immutable until a durable cleaned
// prefix is replaced by an exact hash-chain continuation.
func validBGPProcessRetiredSuccessor(before, after []bgpengine.ProcessIdentity) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if reflect.DeepEqual(before[i], after[i]) {
			continue
		}
		if before[i].Stage != "retired-uncertain" || after[i].Stage != "cleaned" {
			return false
		}
		old, next := before[i], after[i]
		old.Stage, next.Stage = "", ""
		if !reflect.DeepEqual(old, next) {
			return false
		}
	}
	return true
}

func validBGPProcessSuccessor(before, after RuntimeJournalEntry) bool {
	normalized, ok := processHistorySuccessorBase(before, after)
	if !ok {
		return false
	}
	before = normalized
	b, a := before.BGPProcess, after.BGPProcess
	if !validBGPProcess(after) {
		return false
	}
	if b == nil {
		return validBGPProcessRetiredSuccessor(before.BGPProcessRetired, after.BGPProcessRetired) && (a == nil || a.Stage == "reserved")
	}
	if a == nil {
		return false
	}
	if a.Generation != b.Generation {
		if b.Generation == ^uint64(0) || a.Generation != b.Generation+1 || a.Stage != "reserved" || len(after.BGPProcessRetired) != len(before.BGPProcessRetired)+1 || !validBGPProcessRetiredSuccessor(before.BGPProcessRetired, after.BGPProcessRetired[:len(before.BGPProcessRetired)]) {
			return false
		}
		archived := *b
		if archived.Stage != "cleaned" {
			archived.Stage = "retired-uncertain"
		}
		return reflect.DeepEqual(archived, after.BGPProcessRetired[len(after.BGPProcessRetired)-1]) && a.BootID == b.BootID && a.Namespace == b.Namespace
	}
	if !validBGPProcessRetiredSuccessor(before.BGPProcessRetired, after.BGPProcessRetired) {
		return false
	}
	if reflect.DeepEqual(b, a) {
		return true
	}
	base := func(p *bgpengine.ProcessIdentity) bgpengine.ProcessIdentity {
		c := *p
		c.Stage = ""
		c.Files = nil
		c.Children = nil
		return c
	}
	if !reflect.DeepEqual(base(b), base(a)) {
		return false
	}
	if a.Stage == "cleaned" {
		return b.Stage != "cleaned" && reflect.DeepEqual(b.Files, a.Files) && reflect.DeepEqual(b.Children, a.Children)
	}
	if !(b.Stage == "reserved" && a.Stage == "partial" || b.Stage == "partial" && (a.Stage == "partial" || a.Stage == "ready")) {
		return false
	}
	if len(a.Children) < len(b.Children) || !reflect.DeepEqual(a.Children[:len(b.Children)], b.Children) {
		return false
	}
	for _, old := range b.Files {
		index := sort.Search(len(a.Files), func(i int) bool { return a.Files[i].Name >= old.Name })
		if index == len(a.Files) || a.Files[index] != old {
			return false
		}
	}
	return true
}
