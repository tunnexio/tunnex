package ipsec

import (
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func journalFixture() RuntimeJournalEntry {
	p := kernelPlanFixture()
	e := daemonFixture()
	p.ConnectionID = e.Binding.ConnectionID
	r := RuntimeJournalEntry{DeliveryID: uuid.New(), SiteID: uuid.New(), OwnershipDigest: strings.Repeat("a", 64), Allocation: p, Phase: RuntimeReserved}
	for i := range r.Engines {
		r.Engines[i] = e
		r.Engines[i].TunnelID = p.Tunnels[i].TunnelID
		r.Engines[i].XFRMID = p.Tunnels[i].XFRMID
		r.Engines[i].RemotePrefixes = p.Tunnels[i].RemotePrefixes
	}
	return r
}
func journalDir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestRuntimeJournalDurableReservationAndLock(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID); err != ErrRuntimeJournal {
		t.Fatal("second owner accepted")
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.Entries()
	if err != nil || len(got) != 1 || got[0].DeliveryID != r.DeliveryID {
		t.Fatal("reservation lost")
	}
	got[0].Engines[0].LocalPrefixes = nil
	again, _ := j.Entries()
	if len(again[0].Engines[0].LocalPrefixes) == 0 {
		t.Fatal("caller mutated journal")
	}
	bad := r
	bad.Allocation.Generation = uuid.New()
	if err = j.Save([]RuntimeJournalEntry{bad}); err != ErrRuntimeJournal {
		t.Fatal("immutable allocation rewritten")
	}
	if err = j.Save(nil); err != ErrRuntimeJournal {
		t.Fatal("obligation forgotten")
	}
}
func TestRuntimeJournalRefusesCorruptionAndUnsafePaths(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	p := filepath.Join(dir, "journal.json")
	raw, _ := os.ReadFile(p)
	raw = []byte(strings.Replace(string(raw), strings.Repeat("a", 64), strings.Repeat("b", 64), 1))
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID); err != ErrRuntimeJournal {
		t.Fatal("corruption accepted")
	}
	unsafe := journalDir(t)
	if err = os.Chmod(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRuntimeJournal(unsafe, uuid.New()); err != ErrRuntimeJournal {
		t.Fatal("public directory accepted")
	}
}
func TestRuntimeJournalAmbiguousDurabilityPoisonsWriter(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	j.syncDirectory = func() error { return errors.New("synthetic") }
	if err = j.Save([]RuntimeJournalEntry{r}); err != ErrRuntimeJournal {
		t.Fatal("failed durability acknowledged")
	}
	if err = j.Save([]RuntimeJournalEntry{r}); err != ErrRuntimeJournal {
		t.Fatal("ambiguous writer continued")
	}
	j.Close()
	j, err = OpenRuntimeJournal(dir, r.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, _ := j.Entries()
	if len(got) != 1 {
		t.Fatal("potential obligation lost")
	}
}

func TestRuntimeJournalRefusesUncheckedStageAndUnknownSecretFields(t *testing.T) {
	r := journalFixture()
	dir := journalDir(t)
	owner := r.Engines[0].Binding.GatewayID
	j, e := OpenRuntimeJournal(dir, owner)
	if e != nil {
		t.Fatal(e)
	}
	advanced := r
	advanced.Phase = RuntimeApplied
	if e = j.Save([]RuntimeJournalEntry{advanced}); e != ErrRuntimeJournal {
		t.Fatal("unreserved application recorded")
	}
	if e = j.Save([]RuntimeJournalEntry{r}); e != nil {
		t.Fatal(e)
	}
	j.Close()
	path := filepath.Join(dir, "journal.json")
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	// Unknown credential material must refuse even when an attacker recomputes
	// every known-field checksum; it is not decoded into an extensible raw map.
	raw = []byte(strings.Replace(string(raw), `"DeliveryID":`, `"PSK":"synthetic-secret","DeliveryID":`, 1))
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenRuntimeJournal(dir, owner); e != ErrRuntimeJournal {
		t.Fatal("unknown secret field accepted")
	}
}

func TestRuntimeJournalIdentityDiscoveryRestoresOnlyKnownOwner(t *testing.T) {
	entry := journalFixture()
	dir := journalDir(t)
	j, err := OpenRuntimeJournal(dir, entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	org, node, err := ReadRuntimeJournalIdentity(dir)
	if err != nil || org != entry.Engines[0].Binding.OrgID || node != entry.Engines[0].Binding.GatewayID {
		t.Fatal("known identity unavailable")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ReadRuntimeJournalIdentity(dir); err == nil {
		t.Fatal("unsafe journal identity accepted")
	}
}

func TestRuntimeJournalAbsenceOnlyCannotBecomeApplied(t *testing.T) {
	entry := journalFixture()
	entry.AbsenceOnly = true
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplying
	if err = j.Save([]RuntimeJournalEntry{entry}); err == nil {
		t.Fatal("unreceived lineage acquired mutation permission")
	}
}
