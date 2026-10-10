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
	"path/filepath"
	"regexp"
	"strings"
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

// The product reader validates the complete checksum, process generations,
// routed duties and retained history on a private copy, never the live journal.
func validateJournal(raw []byte) (uuid.UUID, error) {
	dir, err := os.MkdirTemp("", "tunnex-receipt-journal-")
	if err != nil {
		return uuid.Nil, err
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return uuid.Nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		return uuid.Nil, err
	}
	_, owner, err := ipsec.ReadRuntimeJournalIdentity(dir)
	return owner, err
}
func assemble(journal, evidence []byte, boot, ns string) ([]byte, error) {
	return assembleDelivery(journal, evidence, boot, ns, uuid.Nil)
}
func assembleDelivery(journal, evidence []byte, boot, ns string, selected uuid.UUID) ([]byte, error) {
	var p proof
	if json.Unmarshal(evidence, &p) != nil || p.Version != 1 || p.Kind != "supervisor-confirmed-runtime-stop" || p.Snapshot.Boot != boot || p.StoppedJournalRawSHA256 != digest(journal) || p.Termination.Container != p.Snapshot.Container || p.Termination.Action != "die" || p.Termination.TimeNS <= 0 || p.VerifiedNS < p.Termination.TimeNS {
		return nil, errors.New("stop evidence mismatch")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.Snapshot.Container) {
		return nil, errors.New("container identity missing")
	}
	required := map[string]bool{"exact-stopped-runtime": false, "empty-cgroup": false, "no-namespace-holders-two-passes": false}
	for _, c := range p.Checks {
		if seen, ok := required[c]; !ok || seen {
			return nil, errors.New("unexpected or duplicate stop check")
		}
		required[c] = true
	}
	for _, ok := range required {
		if !ok {
			return nil, errors.New("incomplete stop evidence")
		}
	}
	id, err := uuid.Parse(boot)
	if err != nil || id == uuid.Nil || id.String() != boot || !regexp.MustCompile(`^net:\[[1-9][0-9]*\]$`).MatchString(ns) {
		return nil, errors.New("invalid new runtime identity")
	}
	owner, err := validateJournal(journal)
	if err != nil {
		return nil, errors.New("invalid persisted journal")
	}
	var j struct {
		Payload struct {
			OwnerID uuid.UUID
			Entries []ipsec.RuntimeJournalEntry
		}
	}
	if json.Unmarshal(journal, &j) != nil || j.Payload.OwnerID != owner || len(j.Payload.Entries) == 0 {
		return nil, errors.New("expected one scoped journal obligation")
	}
	var e ipsec.RuntimeJournalEntry
	active := 0
	seen := map[uuid.UUID]bool{}
	for _, candidate := range j.Payload.Entries {
		if candidate.Engines[0].Binding.GatewayID != j.Payload.OwnerID {
			return nil, errors.New("foreign retained record")
		}
		if candidate.Phase == ipsec.RuntimeRetainedRefusal {
			continue
		}
		active++
		if seen[candidate.DeliveryID] || candidate.DeliveryID == uuid.Nil {
			return nil, errors.New("duplicate active delivery")
		}
		seen[candidate.DeliveryID] = true
		if candidate.Phase != ipsec.RuntimeApplied || (candidate.ContractVersion != 2 && candidate.ContractVersion != 3 && candidate.ContractVersion != 4) || candidate.AbsenceOnly || candidate.ResetCleanup != nil {
			return nil, errors.New("unsupported obligation")
		}
		if selected == uuid.Nil || candidate.DeliveryID == selected {
			// A mixed journal may retain independently stopped prior namespaces.
			// Whole-journal eligibility and ownership stay mandatory above; this
			// supervisor stop evidence binds only the exact selected obligation.
			if p.Snapshot.Namespace.Inode == 0 || ns == candidate.Allocation.Namespace || candidate.Allocation.Namespace != fmt.Sprintf("net:[%d]", p.Snapshot.Namespace.Inode) || (candidate.Restoration != nil && candidate.Restoration.BootID != p.Snapshot.Boot) || (candidate.BGPProcess != nil && candidate.BGPProcess.BootID != p.Snapshot.Boot) {
				return nil, errors.New("prior runtime identity does not match stopped container")
			}
			e = candidate
		}
	}
	if active == 0 || active > 256 || (selected == uuid.Nil && active != 1) || (selected != uuid.Nil && !seen[selected]) {
		return nil, errors.New("expected exactly one active obligation")
	}
	if e.Phase != ipsec.RuntimeApplied || (e.ContractVersion != 2 && e.ContractVersion != 3 && e.ContractVersion != 4) || e.AbsenceOnly || e.ResetCleanup != nil || e.Engines[0].Binding.GatewayID != j.Payload.OwnerID {
		return nil, errors.New("unsupported obligation")
	}
	if p.Snapshot.Namespace.Inode == 0 || ns == e.Allocation.Namespace || e.Allocation.Namespace != fmt.Sprintf("net:[%d]", p.Snapshot.Namespace.Inode) || (e.Restoration != nil && e.Restoration.BootID != p.Snapshot.Boot) || (e.BGPProcess != nil && e.BGPProcess.BootID != p.Snapshot.Boot) {
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
	delivery := flag.String("delivery", "", "optional exact active delivery UUID; validates every active obligation")
	out := flag.String("out", "", "new receipt file; must not exist")
	flag.Parse()
	fail := func() { fmt.Fprintln(os.Stderr, "receipt assembly refused"); os.Exit(1) }
	if os.Geteuid() != 0 {
		fail()
	}
	currentBoot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	currentNS, nsErr := os.Readlink("/proc/self/ns/net")
	if err != nil || nsErr != nil || strings.TrimSpace(string(currentBoot)) != *boot || currentNS != *ns {
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
	selected := uuid.Nil
	if *delivery != "" {
		var parseErr error
		selected, parseErr = uuid.Parse(*delivery)
		if parseErr != nil || selected == uuid.Nil || selected.String() != *delivery {
			fail()
		}
	}
	raw, e := assembleDelivery(j, p, *boot, *ns, selected)
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
	parent, e := os.Open(filepath.Dir(*out))
	if e != nil {
		fail()
	}
	if e = parent.Sync(); e != nil {
		parent.Close()
		fail()
	}
	if parent.Close() != nil {
		fail()
	}
	fmt.Println("Exact-entry receipt assembled; installation and runtime acceptance remain separate.")
}
