// Command ipsec-restoration-receipt assembles a lab supervisor receipt from
// verified stop evidence. It never stops a runtime, installs a receipt, or grants
// traffic permission. The runtime independently validates the exact entry.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type proof struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`
	Snapshot struct {
		Boot      string `json:"boot"`
		Container string `json:"container"`
		Namespace struct {
			Inode uint64 `json:"inode"`
		} `json:"namespace"`
	} `json:"snapshot"`
	Termination struct {
		Container string `json:"container"`
		Action    string `json:"action"`
		TimeNS    int64  `json:"time_ns"`
	} `json:"termination"`
	StoppedJournalRawSHA256 string   `json:"stopped_journal_raw_sha256"`
	VerifiedNS              int64    `json:"verified_ns"`
	Checks                  []string `json:"checks"`
}
type receipt struct {
	Version                                                     int
	OwnerID, DeliveryID                                         uuid.UUID
	EntryDigest, BootID, Namespace, Termination, EvidenceDigest string
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func assemble(journal, evidence []byte, boot, ns string) ([]byte, error) {
	var p proof
	if json.Unmarshal(evidence, &p) != nil || p.Version != 1 || p.Kind != "supervisor-confirmed-runtime-stop" || p.Snapshot.Boot != boot || p.StoppedJournalRawSHA256 != digest(journal) || p.Termination.Container != p.Snapshot.Container || p.Termination.Action != "die" || p.Termination.TimeNS <= 0 || p.VerifiedNS < p.Termination.TimeNS {
		return nil, errors.New("stop evidence mismatch")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.Snapshot.Container) {
		return nil, errors.New("container identity missing")
	}
	required := map[string]bool{"exact-stopped-runtime": false, "empty-cgroup": false, "no-namespace-holders-two-passes": false}
	for _, c := range p.Checks {
		if _, ok := required[c]; ok {
			required[c] = true
		}
	}
	for _, ok := range required {
		if !ok {
			return nil, errors.New("incomplete stop evidence")
		}
	}
	id, err := uuid.Parse(boot)
	if err != nil || id == uuid.Nil || id.String() != boot || !regexp.MustCompile(`^net:\[[0-9]+\]$`).MatchString(ns) {
		return nil, errors.New("invalid new runtime identity")
	}
	var j struct {
		Payload struct {
			OwnerID uuid.UUID
			Entries []ipsec.RuntimeJournalEntry
		}
	}
	if json.Unmarshal(journal, &j) != nil || j.Payload.OwnerID == uuid.Nil || len(j.Payload.Entries) == 0 {
		return nil, errors.New("expected one scoped journal obligation")
	}
	var e ipsec.RuntimeJournalEntry
	active := 0
	for _, candidate := range j.Payload.Entries {
		if candidate.Engines[0].Binding.GatewayID != j.Payload.OwnerID {
			return nil, errors.New("foreign retained record")
		}
		if candidate.Phase == ipsec.RuntimeRetainedRefusal {
			continue
		}
		active++
		e = candidate
	}
	if active != 1 {
		return nil, errors.New("expected exactly one active obligation")
	}
	if e.Phase != ipsec.RuntimeApplied || e.ContractVersion != 2 || e.AbsenceOnly || e.ResetCleanup != nil || e.Engines[0].Binding.GatewayID != j.Payload.OwnerID {
		return nil, errors.New("unsupported obligation")
	}
	if p.Snapshot.Namespace.Inode == 0 || e.Allocation.Namespace != fmt.Sprintf("net:[%d]", p.Snapshot.Namespace.Inode) || (e.Restoration != nil && e.Restoration.BootID != p.Snapshot.Boot) {
		return nil, errors.New("prior runtime identity does not match stopped container")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return json.Marshal(receipt{1, j.Payload.OwnerID, e.DeliveryID, digest(raw), boot, ns, p.Kind, digest(evidence)})
}
func privateRead(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errors.New("unsafe input")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("input must be root owned")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("input changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("oversized input")
	}
	return b, nil
}
func main() {
	journal := flag.String("journal", "", "stopped journal snapshot")
	evidence := flag.String("evidence", "", "verified supervisor evidence")
	boot := flag.String("boot", "", "current kernel boot identity")
	ns := flag.String("namespace", "", "current runtime namespace")
	out := flag.String("out", "", "new receipt file; must not exist")
	flag.Parse()
	fail := func() { fmt.Fprintln(os.Stderr, "receipt assembly refused"); os.Exit(1) }
	if os.Geteuid() != 0 {
		fail()
	}
	j, e := privateRead(*journal, 4<<20)
	if e != nil || len(j) > 4<<20 {
		fail()
	}
	p, e := privateRead(*evidence, 1<<20)
	if e != nil || len(p) > 1<<20 {
		fail()
	}
	raw, e := assemble(j, p, *boot, *ns)
	if e != nil {
		fail()
	}
	f, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		fail()
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		f.Close()
		fail()
	}
	if e = f.Sync(); e != nil {
		f.Close()
		fail()
	}
	if f.Close() != nil {
		fail()
	}
	fmt.Println("Exact-entry receipt assembled; installation and runtime acceptance remain separate.")
}
