package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"testing"
)

func TestAssemblyBindsProofAndCanonicalEntry(t *testing.T) {
	owner := uuid.New()
	entry := ipsec.RuntimeJournalEntry{ContractVersion: 2, DeliveryID: uuid.New(), Phase: ipsec.RuntimeApplied}
	entry.Engines[0].Binding.GatewayID = owner
	entry.Allocation.Namespace = "net:[41]"
	retired := entry
	retired.Phase = ipsec.RuntimeRetainedRefusal
	retired.DeliveryID = uuid.New()
	j, _ := json.Marshal(map[string]any{"Payload": map[string]any{"OwnerID": owner, "Entries": []ipsec.RuntimeJournalEntry{retired, entry}}})
	p := proof{Version: 1, Kind: "supervisor-confirmed-runtime-stop", VerifiedNS: 20, Checks: []string{"exact-stopped-runtime", "empty-cgroup", "no-namespace-holders-two-passes"}}
	p.Snapshot.Boot = uuid.NewString()
	p.Snapshot.Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p.StoppedJournalRawSHA256 = digest(j)
	p.Snapshot.Namespace.Inode = 41
	p.Termination.Container = p.Snapshot.Container
	p.Termination.Action = "die"
	p.Termination.TimeNS = 10
	raw, _ := json.Marshal(p)
	got, err := assemble(j, raw, p.Snapshot.Boot, "net:[42]")
	if err != nil {
		t.Fatal(err)
	}
	var r receipt
	json.Unmarshal(got, &r)
	canonical, _ := json.Marshal(entry)
	if r.EntryDigest != digest(canonical) || r.EvidenceDigest != digest(raw) || r.OwnerID != owner {
		t.Fatal("incorrect canonical binding")
	}

	for name, entries := range map[string][]ipsec.RuntimeJournalEntry{
		"no active delivery":         {retired},
		"multiple active deliveries": {entry, entry},
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"Payload": map[string]any{"OwnerID": owner, "Entries": entries}})
			q := p
			q.StoppedJournalRawSHA256 = digest(b)
			proofBytes, _ := json.Marshal(q)
			if _, err := assemble(b, proofBytes, p.Snapshot.Boot, "net:[42]"); err == nil {
				t.Fatal("ambiguous obligation accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*proof){
		"wrong namespace":        func(p *proof) { p.Snapshot.Namespace.Inode = 55 },
		"wrong journal":          func(p *proof) { p.StoppedJournalRawSHA256 = digest([]byte("changed")) },
		"wrong container":        func(p *proof) { p.Termination.Container = "foreign" },
		"missing checks":         func(p *proof) { p.Checks = nil },
		"premature verification": func(p *proof) { p.VerifiedNS = 1 },
		"not dead":               func(p *proof) { p.Termination.Action = "stop" },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			b, _ := json.Marshal(q)
			if _, e := assemble(j, b, p.Snapshot.Boot, "net:[42]"); e == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}
