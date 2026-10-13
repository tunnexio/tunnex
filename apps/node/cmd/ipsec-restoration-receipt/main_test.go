package main

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAssemblyBindsProofAndCanonicalEntry(t *testing.T) {
	owner := uuid.New()
	entry := ipsec.RuntimeJournalEntry{ContractVersion: 2, DeliveryID: uuid.New(), SiteID: uuid.New(), OwnershipDigest: strings.Repeat("a", 64), Phase: ipsec.RuntimeApplied, Recovery: &ipsec.RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}}
	binding := ipsec.Binding{OrgID: uuid.New(), GatewayID: owner, ConnectionID: uuid.New(), DesiredRevision: 1, ConfigurationRevision: 1, PolicyRevision: 1}
	entry.Allocation = ipsec.KernelAllocation{Namespace: "net:[41]", Generation: uuid.New(), ConnectionID: binding.ConnectionID}
	for i := range entry.Engines {
		id := uuid.New()
		remote := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
		entry.Allocation.Tunnels[i] = ipsec.KernelTunnelAllocation{TunnelID: id, Slot: uint8(i + 1), Name: ipsec.KernelTunnelName(id), XFRMID: ipsec.KernelTunnelID(id), InsideAddress: netip.MustParsePrefix([]string{"169.254.10.1/30", "169.254.10.5/30"}[i]), RemotePrefixes: remote, Selected: i == 0, Alias: ipsec.KernelTunnelAlias(entry.Allocation.Generation, id)}
		entry.Engines[i] = ipsec.EngineTunnel{Binding: binding, TunnelID: id, SecretRevision: 1, XFRMID: ipsec.KernelTunnelID(id), LocalAddress: netip.MustParseAddr("192.0.2.1"), RemoteAddress: netip.MustParseAddr("192.0.2.2"), LocalIdentity: netip.MustParseAddr("192.0.2.1"), RemoteIdentity: netip.MustParseAddr("192.0.2.2"), LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, RemotePrefixes: remote}
	}
	retired := entry
	retired.Phase = ipsec.RuntimeRetainedRefusal
	retired.DeliveryID = uuid.New()
	retired.CleanupID = uuid.New()
	retired.CleanupDesiredRevision = 2
	retired.CoveredDeliveryRevision = 1
	journalVersion := 2
	journalBytes := func(entries []ipsec.RuntimeJournalEntry) []byte {
		payload := struct {
			Guards   []any
			Version  int
			OwnerID  uuid.UUID
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}{nil, journalVersion, owner, 1, entries}
		raw, _ := json.Marshal(payload)
		b, _ := json.Marshal(struct {
			Payload  any
			Checksum string
		}{payload, digest(raw)})
		return b
	}
	j := journalBytes([]ipsec.RuntimeJournalEntry{retired, entry})
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

	t.Run("Azure standby static receipt", func(t *testing.T) {
		single := entry
		single.ContractVersion = 4
		single.Recovery = nil
		single.Allocation.ProfileID = ipsec.AzureActiveStandbyStaticProfile
		single.Engines[0].ProfileID = ipsec.AzureActiveStandbyStaticProfile
		single.Engines[1] = ipsec.EngineTunnel{}
		single.Allocation.Tunnels[1] = ipsec.KernelTunnelAllocation{}
		journalVersion = 10
		defer func() { journalVersion = 2 }()
		singleJournal := journalBytes([]ipsec.RuntimeJournalEntry{single})
		stop := p
		stop.StoppedJournalRawSHA256 = digest(singleJournal)
		stopBytes, _ := json.Marshal(stop)
		out, err := assemble(singleJournal, stopBytes, p.Snapshot.Boot, "net:[42]")
		if err != nil {
			t.Fatal("single owned restoration refused", err)
		}
		var r receipt
		json.Unmarshal(out, &r)
		canonical, _ := json.Marshal(single)
		if r.EntryDigest != digest(canonical) {
			t.Fatal("single lineage binding")
		}
		single.Engines[1] = entry.Engines[1]
		bad := journalBytes([]ipsec.RuntimeJournalEntry{single})
		stop.StoppedJournalRawSHA256 = digest(bad)
		stopBytes, _ = json.Marshal(stop)
		if _, err := assemble(bad, stopBytes, p.Snapshot.Boot, "net:[42]"); err == nil {
			t.Fatal("inactive ownership accepted")
		}
	})
	secondRaw, _ := json.Marshal(entry)
	var second ipsec.RuntimeJournalEntry
	json.Unmarshal(secondRaw, &second)
	second.DeliveryID = uuid.New()
	second.SiteID = uuid.New()
	second.Allocation.ConnectionID = uuid.New()
	second.Allocation.Generation = uuid.New()
	for i := range second.Engines {
		id := uuid.New()
		second.Engines[i].TunnelID = id
		second.Engines[i].Binding.ConnectionID = second.Allocation.ConnectionID
		second.Engines[i].XFRMID = ipsec.KernelTunnelID(id)
		second.Allocation.Tunnels[i].TunnelID = id
		second.Allocation.Tunnels[i].Name = ipsec.KernelTunnelName(id)
		second.Allocation.Tunnels[i].XFRMID = ipsec.KernelTunnelID(id)
		second.Allocation.Tunnels[i].Alias = ipsec.KernelTunnelAlias(second.Allocation.Generation, id)
		remote := []netip.Prefix{netip.MustParsePrefix("10.21.0.0/24")}
		second.Engines[i].RemotePrefixes = remote
		second.Allocation.Tunnels[i].RemotePrefixes = remote
	}
	multi := journalBytes([]ipsec.RuntimeJournalEntry{retired, entry, second})
	mp := p
	mp.StoppedJournalRawSHA256 = digest(multi)
	mb, _ := json.Marshal(mp)
	for _, want := range []ipsec.RuntimeJournalEntry{entry, second} {
		out, err := assembleDelivery(multi, mb, p.Snapshot.Boot, "net:[42]", want.DeliveryID)
		if err != nil {
			t.Fatal("two obligations", err)
		}
		var got receipt
		json.Unmarshal(out, &got)
		expected, _ := json.Marshal(want)
		if got.DeliveryID != want.DeliveryID || got.EntryDigest != digest(expected) || got.EvidenceDigest != digest(mb) {
			t.Fatal("wrong selected receipt")
		}
	}
	if _, err := assemble(multi, mb, p.Snapshot.Boot, "net:[42]"); err == nil {
		t.Fatal("implicit multi selection")
	}
	if _, err := assembleDelivery(multi, mb, p.Snapshot.Boot, "net:[42]", uuid.New()); err == nil {
		t.Fatal("missing delivery")
	}
	bad := second
	bad.Allocation.Namespace = "net:[99]"
	badj := journalBytes([]ipsec.RuntimeJournalEntry{entry, bad})
	bp := mp
	bp.StoppedJournalRawSHA256 = digest(badj)
	bb, _ := json.Marshal(bp)
	// Only the selected delivery's prior namespace is covered by this stop
	// evidence. The other obligation remains fully journal-validated and will
	// need its own genuine stop evidence before any restoration.
	if out, err := assembleDelivery(badj, bb, p.Snapshot.Boot, "net:[42]", entry.DeliveryID); err != nil {
		t.Fatal("selected obligation in valid mixed journal refused", err)
	} else {
		var got receipt
		json.Unmarshal(out, &got)
		expected, _ := json.Marshal(entry)
		if got.DeliveryID != entry.DeliveryID || got.EntryDigest != digest(expected) || got.EvidenceDigest != digest(bb) {
			t.Fatal("mixed journal widened selected receipt")
		}
	}
	if _, err := assembleDelivery(badj, bb, p.Snapshot.Boot, "net:[42]", bad.DeliveryID); err == nil {
		t.Fatal("wrong selected prior namespace accepted")
	}
	foreign := second
	foreign.Engines[0].Binding.GatewayID = uuid.New()
	foreignJournal := journalBytes([]ipsec.RuntimeJournalEntry{entry, foreign})
	foreignProof := mp
	foreignProof.StoppedJournalRawSHA256 = digest(foreignJournal)
	foreignProofRaw, _ := json.Marshal(foreignProof)
	if _, err := assembleDelivery(foreignJournal, foreignProofRaw, p.Snapshot.Boot, "net:[42]", entry.DeliveryID); err == nil {
		t.Fatal("unselected foreign owner ignored")
	}
	unsupported := second
	unsupported.Phase = ipsec.RuntimeApplying
	unsupportedJournal := journalBytes([]ipsec.RuntimeJournalEntry{entry, unsupported})
	unsupportedProof := mp
	unsupportedProof.StoppedJournalRawSHA256 = digest(unsupportedJournal)
	unsupportedRaw, _ := json.Marshal(unsupportedProof)
	if _, err := assembleDelivery(unsupportedJournal, unsupportedRaw, p.Snapshot.Boot, "net:[42]", entry.DeliveryID); err == nil {
		t.Fatal("unselected unsupported obligation ignored")
	}
	for name, entries := range map[string][]ipsec.RuntimeJournalEntry{
		"no active delivery":         {retired},
		"multiple active deliveries": {entry, entry},
	} {
		t.Run(name, func(t *testing.T) {
			b := journalBytes(entries)
			q := p
			q.StoppedJournalRawSHA256 = digest(b)
			proofBytes, _ := json.Marshal(q)
			if _, err := assemble(b, proofBytes, p.Snapshot.Boot, "net:[42]"); err == nil {
				t.Fatal("ambiguous obligation accepted")
			}
		})
	}
	for _, ns := range []string{"net:[41]", "net:[0]", "net:[042]"} {
		if _, err := assemble(j, raw, p.Snapshot.Boot, ns); err == nil {
			t.Fatal("invalid replacement namespace accepted", ns)
		}
	}
	for _, corrupt := range [][]byte{append(append([]byte(nil), j...), []byte(" {}")...), []byte(`{"Payload":{},"Checksum":"wrong"}`)} {
		q := p
		q.StoppedJournalRawSHA256 = digest(corrupt)
		proofRaw, _ := json.Marshal(q)
		if _, err := assemble(corrupt, proofRaw, p.Snapshot.Boot, "net:[42]"); err == nil {
			t.Fatal("invalid journal accepted")
		}
	}
	for name, mutate := range map[string]func(*proof){
		"wrong namespace":        func(p *proof) { p.Snapshot.Namespace.Inode = 55 },
		"wrong journal":          func(p *proof) { p.StoppedJournalRawSHA256 = digest([]byte("changed")) },
		"wrong container":        func(p *proof) { p.Termination.Container = "foreign" },
		"missing checks":         func(p *proof) { p.Checks = nil },
		"premature verification": func(p *proof) { p.VerifiedNS = 1 },
		"duplicate checks":       func(p *proof) { p.Checks = append(append([]string(nil), p.Checks...), p.Checks[0]) },
		"foreign check":          func(p *proof) { p.Checks = append(append([]string(nil), p.Checks...), "foreign") },
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

// This synthetic fixture was persisted by the actual native component journal:
// generation one is cleaned retained history and generation two owns ready
// processes/routes. No credential or PSK is represented by RuntimeJournalEntry.
func TestAssemblyBGPV7PreservesWholeNativeEntry(t *testing.T) {
	journal, err := os.ReadFile("testdata/bgp-v7-native-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Payload struct {
			OwnerID uuid.UUID
			Entries []ipsec.RuntimeJournalEntry
		}
	}
	if err = json.Unmarshal(journal, &document); err != nil {
		t.Fatal(err)
	}
	entry := document.Payload.Entries[0]
	if entry.ContractVersion != 3 || entry.BGPProcess == nil || len(entry.BGPProcessRetired) != 1 || entry.BGPRoutes == nil {
		t.Fatal("incomplete native fixture")
	}
	p := proof{Version: 1, Kind: "supervisor-confirmed-runtime-stop", VerifiedNS: 20, Checks: []string{"exact-stopped-runtime", "empty-cgroup", "no-namespace-holders-two-passes"}}
	p.Snapshot.Boot = entry.BGPProcess.BootID
	p.Snapshot.Container = strings.Repeat("a", 64)
	p.Snapshot.Namespace.Inode, _ = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(entry.Allocation.Namespace, "net:["), "]"), 10, 64)
	p.Termination.Container = p.Snapshot.Container
	p.Termination.Action = "die"
	p.Termination.TimeNS = 10
	p.StoppedJournalRawSHA256 = digest(journal)
	proofRaw, _ := json.Marshal(p)
	raw, err := assemble(journal, proofRaw, p.Snapshot.Boot, "net:[42]")
	if err != nil {
		t.Fatal(err)
	}
	wrongBoot := p
	wrongBoot.Snapshot.Boot = uuid.NewString()
	wrongRaw, _ := json.Marshal(wrongBoot)
	if _, err = assemble(journal, wrongRaw, wrongBoot.Snapshot.Boot, "net:[42]"); err == nil {
		t.Fatal("active process from another boot accepted")
	}
	var r receipt
	json.Unmarshal(raw, &r)
	canonical, _ := json.Marshal(entry)
	if r.EntryDigest != digest(canonical) || r.OwnerID != document.Payload.OwnerID {
		t.Fatal("process/routes/history omitted from entry digest")
	}
	// Recompute the envelope checksum to show the product validators, rather
	// than checksum mismatch alone, reject corrupt historical duties.
	var typed struct {
		Payload struct {
			Guards   []json.RawMessage
			Version  int
			OwnerID  uuid.UUID
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}
		Checksum string
	}
	json.Unmarshal(journal, &typed)
	typed.Payload.Entries[0].BGPProcessRetired[0].Generation = 99
	payloadRaw, _ := json.Marshal(typed.Payload)
	typed.Checksum = digest(payloadRaw)
	corrupt, _ := json.Marshal(typed)
	p.StoppedJournalRawSHA256 = digest(corrupt)
	proofRaw, _ = json.Marshal(p)
	if _, err = assemble(corrupt, proofRaw, p.Snapshot.Boot, "net:[42]"); err == nil {
		t.Fatal("invalid process history accepted")
	}
}
