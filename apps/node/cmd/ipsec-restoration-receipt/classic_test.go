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
	"time"
)

func TestAssemblyClassicWholeJournalAndStoppedIdentity(t *testing.T) {
	owner, tunnel, generation := uuid.New(), uuid.New(), uuid.New()
	b := ipsec.Binding{OrgID: uuid.New(), GatewayID: owner, ConnectionID: uuid.New(), DesiredRevision: 2, ConfigurationRevision: 1, PolicyRevision: 1}
	remote := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	e := ipsec.RuntimeJournalEntry{ContractVersion: 4, DeliveryID: uuid.New(), SiteID: uuid.New(), OwnershipDigest: strings.Repeat("a", 64), Phase: ipsec.RuntimeApplied}
	e.Allocation = ipsec.KernelAllocation{ProfileID: ipsec.GCPClassicStaticProfile, Namespace: "net:[41]", Generation: generation, ConnectionID: b.ConnectionID}
	e.Allocation.Tunnels[0] = ipsec.KernelTunnelAllocation{TunnelID: tunnel, Slot: 1, Name: ipsec.KernelTunnelName(tunnel), Alias: ipsec.KernelTunnelAlias(generation, tunnel), XFRMID: ipsec.KernelTunnelID(tunnel), InsideAddress: netip.MustParsePrefix("169.254.10.1/32"), RemotePrefixes: remote, Selected: true}
	e.Engines[0] = ipsec.EngineTunnel{ProfileID: ipsec.GCPClassicStaticProfile, Binding: b, TunnelID: tunnel, SecretRevision: 1, XFRMID: ipsec.KernelTunnelID(tunnel), ReqID: ipsec.KernelTunnelID(tunnel), LocalAddress: netip.MustParseAddr("192.0.2.1"), RemoteAddress: netip.MustParseAddr("192.0.2.2"), LocalIdentity: netip.MustParseAddr("192.0.2.1"), RemoteIdentity: netip.MustParseAddr("192.0.2.2"), LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, RemotePrefixes: remote}
	e.Observed[0] = ipsec.Ownership{Namespace: "net:[41]", InterfaceName: e.Allocation.Tunnels[0].Name, InterfaceIndex: 7, XFRMID: e.Engines[0].XFRMID}
	p := proof{Version: 1, Kind: "supervisor-confirmed-runtime-stop", VerifiedNS: 20, Checks: []string{"exact-stopped-runtime", "empty-cgroup", "no-namespace-holders-two-passes"}}
	p.Snapshot.Boot = uuid.NewString()
	p.Snapshot.Container = strings.Repeat("a", 64)
	p.Snapshot.Namespace.Inode = 41
	p.Snapshot.PID = 101
	p.Snapshot.Started = "2026-10-10T10:00:00Z"
	p.Termination.Container = p.Snapshot.Container
	p.Termination.Action = "die"
	p.Termination.TimeNS = time.Date(2026, 10, 10, 10, 0, 1, 0, time.UTC).UnixNano()
	p.VerifiedNS = p.Termination.TimeNS + 100000000
	var lastJournal, lastEvidence []byte
	run := func(e ipsec.RuntimeJournalEntry, ns string) ([]byte, error) {
		payload := struct {
			Guards   []any
			Version  int
			OwnerID  uuid.UUID
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}{nil, 10, owner, 1, []ipsec.RuntimeJournalEntry{e}}
		raw, _ := json.Marshal(payload)
		j, _ := json.Marshal(struct {
			Payload  any
			Checksum string
		}{payload, digest(raw)})
		p.StoppedJournalRawSHA256 = digest(j)
		raw, _ = json.Marshal(p)
		lastJournal, lastEvidence = j, raw
		return assemble(j, raw, p.Snapshot.Boot, ns)
	}
	raw, err := run(e, "net:[42]")
	if err != nil {
		t.Fatal("valid Classic stopped obligation refused", err)
	}
	var r receipt
	json.Unmarshal(raw, &r)
	canonical, _ := json.Marshal(e)
	if r.EntryDigest != digest(canonical) || r.DeliveryID != e.DeliveryID {
		t.Fatal("entry omitted from exact receipt")
	}
	if _, err = run(e, "net:[41]"); err == nil {
		t.Fatal("same namespace without explicit fresh observation accepted")
	}
	f := freshRuntime{Version: 1, Kind: "supervisor-confirmed-fresh-runtime", Container: p.Snapshot.Container, Boot: p.Snapshot.Boot, Namespace: "net:[41]", PID: 102, PIDStartTicks: 10, StartedAt: "2026-10-10T10:00:02Z", StopEvidenceSHA256: digest(lastEvidence), StoppedJournalSHA256: digest(lastJournal), CurrentJournalSHA256: digest(lastJournal), StartupGateSHA256: strings.Repeat("b", 64), StartupGateDevice: 1, StartupGateInode: 2}
	fresh, _ := json.Marshal(f)
	if _, err = assembleDeliveryFresh(lastJournal, lastEvidence, p.Snapshot.Boot, "net:[41]", uuid.Nil, fresh, lastJournal); err != nil {
		t.Fatal("independently fresh instance with recycled namespace refused", err)
	}
	for name, mutate := range map[string]func(*freshRuntime){"same PID": func(f *freshRuntime) { f.PID = p.Snapshot.PID }, "old started": func(f *freshRuntime) { f.StartedAt = p.Snapshot.Started }, "wrong boot": func(f *freshRuntime) { f.Boot = uuid.NewString() }, "wrong container": func(f *freshRuntime) { f.Container = strings.Repeat("c", 64) }, "wrong namespace": func(f *freshRuntime) { f.Namespace = "net:[99]" }, "wrong stop digest": func(f *freshRuntime) { f.StopEvidenceSHA256 = strings.Repeat("c", 64) }, "wrong journal digest": func(f *freshRuntime) { f.StoppedJournalSHA256 = strings.Repeat("c", 64) }, "missing gate": func(f *freshRuntime) { f.StartupGateInode = 0 }, "missing process identity": func(f *freshRuntime) { f.PIDStartTicks = 0 }} {
		t.Run(name, func(t *testing.T) {
			bad := f
			mutate(&bad)
			b, _ := json.Marshal(bad)
			if _, err := assembleDeliveryFresh(lastJournal, lastEvidence, p.Snapshot.Boot, "net:[41]", uuid.Nil, b, lastJournal); err == nil {
				t.Fatal("unbound fresh evidence accepted")
			}
		})
	}
	type envelope struct {
		Payload struct {
			Guards   []json.RawMessage
			Version  int
			OwnerID  uuid.UUID
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}
		Checksum string
	}
	var doc envelope
	json.Unmarshal(lastJournal, &doc)
	current := func() []byte {
		r, _ := json.Marshal(doc.Payload)
		doc.Checksum = digest(r)
		r, _ = json.Marshal(doc)
		return r
	}
	doc.Payload.Sequence++
	changed := current()
	f.CurrentJournalSHA256 = digest(changed)
	fresh, _ = json.Marshal(f)
	if _, err = assembleDeliveryFresh(lastJournal, lastEvidence, p.Snapshot.Boot, "net:[41]", uuid.Nil, fresh, changed); err != nil {
		t.Fatal("normal guard sequence advance refused", err)
	}
	for name, mutate := range map[string]func(){"changed entry": func() { doc.Payload.Entries[0].OwnershipDigest = strings.Repeat("c", 64) }, "changed owner": func() { doc.Payload.OwnerID = uuid.New() }, "changed version": func() { doc.Payload.Version = 9 }, "sequence rollback": func() { doc.Payload.Sequence = 0 }} {
		t.Run(name, func(t *testing.T) {
			json.Unmarshal(lastJournal, &doc)
			mutate()
			bad := current()
			f.CurrentJournalSHA256 = digest(bad)
			b, _ := json.Marshal(f)
			if _, err := assembleDeliveryFresh(lastJournal, lastEvidence, p.Snapshot.Boot, "net:[41]", uuid.Nil, b, bad); err == nil {
				t.Fatal("current lineage mutation accepted")
			}
		})
	}
	bad := append(append([]byte{}, lastJournal...), []byte(" {}")...)
	f.CurrentJournalSHA256 = digest(bad)
	fresh, _ = json.Marshal(f)
	if _, err = assembleDeliveryFresh(lastJournal, lastEvidence, p.Snapshot.Boot, "net:[41]", uuid.Nil, fresh, bad); err == nil {
		t.Fatal("current checksum/envelope corruption accepted")
	}

	for name, mutate := range map[string]func(*ipsec.RuntimeJournalEntry){"wrong profile": func(e *ipsec.RuntimeJournalEntry) { e.Allocation.ProfileID = ipsec.GCPHABGPProfile }, "inactive engine": func(e *ipsec.RuntimeJournalEntry) { e.Engines[1] = e.Engines[0] }, "inactive allocation": func(e *ipsec.RuntimeJournalEntry) { e.Allocation.Tunnels[1] = e.Allocation.Tunnels[0] }, "inactive ownership": func(e *ipsec.RuntimeJournalEntry) { e.Observed[1] = e.Observed[0] }, "wrong contract": func(e *ipsec.RuntimeJournalEntry) { e.ContractVersion = 3 }, "invented cloud addressing": func(e *ipsec.RuntimeJournalEntry) {
		e.Allocation.Tunnels[0].InsideAddress = netip.MustParsePrefix("169.254.10.1/30")
	}} {
		t.Run(name, func(t *testing.T) {
			bad := e
			mutate(&bad)
			if _, err := run(bad, "net:[42]"); err == nil {
				t.Fatal("invalid complete journal accepted")
			}
		})
	}
	p.Snapshot.Namespace.Inode = 40
	if _, err = run(e, "net:[42]"); err == nil {
		t.Fatal("wrong stopped namespace accepted")
	}
}

func TestAssemblyGCPHAWholeJournal(t *testing.T) {
	raw, err := os.ReadFile("testdata/bgp-v7-native-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Payload struct {
			Guards   []json.RawMessage
			Version  int
			OwnerID  uuid.UUID
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}
		Checksum string
	}
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	e := &document.Payload.Entries[0]
	e.Allocation.ProfileID = ipsec.GCPHABGPProfile
	for i := range e.Engines {
		e.Engines[i].ProfileID = ipsec.GCPHABGPProfile
	}
	payload, _ := json.Marshal(document.Payload)
	document.Checksum = digest(payload)
	journal, _ := json.Marshal(document)
	p := proof{Version: 1, Kind: "supervisor-confirmed-runtime-stop", VerifiedNS: 20, Checks: []string{"exact-stopped-runtime", "empty-cgroup", "no-namespace-holders-two-passes"}}
	p.Snapshot.Boot = e.BGPProcess.BootID
	p.Snapshot.Container = strings.Repeat("a", 64)
	p.Snapshot.Namespace.Inode, _ = strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(e.Allocation.Namespace, "net:["), "]"), 10, 64)
	p.Termination.Container = p.Snapshot.Container
	p.Termination.Action = "die"
	p.Termination.TimeNS = 10
	p.StoppedJournalRawSHA256 = digest(journal)
	evidence, _ := json.Marshal(p)
	out, err := assemble(journal, evidence, p.Snapshot.Boot, "net:[42]")
	if err != nil {
		t.Fatal("valid HA journal refused", err)
	}
	var r receipt
	json.Unmarshal(out, &r)
	canonical, _ := json.Marshal(e)
	if r.EntryDigest != digest(canonical) {
		t.Fatal("HA BGP process/history/routes omitted")
	}
	e.Engines[1].ProfileID = ipsec.GCPClassicStaticProfile
	payload, _ = json.Marshal(document.Payload)
	document.Checksum = digest(payload)
	journal, _ = json.Marshal(document)
	p.StoppedJournalRawSHA256 = digest(journal)
	evidence, _ = json.Marshal(p)
	if _, err = assemble(journal, evidence, p.Snapshot.Boot, "net:[42]"); err == nil {
		t.Fatal("mixed HA/Classic journal accepted")
	}
}
