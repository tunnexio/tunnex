package ipsec

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func journalCapacityGuard(t *testing.T, owner uuid.UUID, revision int64) GuardManifest {
	t.Helper()
	intent := guardFixture()
	intent.OwnerID = owner
	intent.Revision = revision
	intent.Connections = nil
	for i := 0; i < 28; i++ {
		c := guardFixture().Connections[0]
		c.ID = uuid.New()
		c.Remote = []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.20.%d.0/24", i))}
		c.Tunnels[0].InterfaceName = fmt.Sprintf("tnxi-%da", i)
		c.Tunnels[1].InterfaceName = fmt.Sprintf("tnxi-%db", i)
		c.Tunnels[0].InterfaceIndex = 10 + 2*i
		c.Tunnels[1].InterfaceIndex = 11 + 2*i
		c.Tunnels[0].XFRMID = uint32(100 + 2*i)
		c.Tunnels[1].XFRMID = uint32(101 + 2*i)
		c.PermittedInterfaceIndices = []int{c.Tunnels[0].InterfaceIndex}
		c.Grants[0].Destination = c.Remote[0]
		intent.Connections = append(intent.Connections, c)
	}
	m, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := normalizedGuardObjects([]byte(m.ExpectedJSON)); !ok {
		t.Fatal("rendered guard cannot be independently validated")
	}
	if len(m.ExpectedJSON) >= kernelDumpLimit {
		t.Fatal("fixture exceeded unchanged native-object limit")
	}
	return m
}

func TestRuntimeJournalTwoGuardCapacityPreservesRetainedHistory(t *testing.T) {
	olds, entry := retainedRestorationThreeFixture(t)
	for i := 0; i < 16; i++ {
		entry = restoredFixture(entry)
	}
	entries := append(append([]RuntimeJournalEntry{}, olds...), entry)
	owner := entry.Engines[0].Binding.GatewayID
	payload := runtimeJournalPayload{Version: 9, OwnerID: owner, Sequence: 1, Entries: entries}
	if !validJournalPayload(payload) {
		t.Fatal("complete retained graph/history fixture is invalid")
	}
	before, _ := json.Marshal(entries)
	dir := journalDir(t)
	raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	first := journalCapacityGuard(t, owner, 1)
	second := journalCapacityGuard(t, owner, 2)
	t.Logf("history envelope=%d first ExpectedJSON=%d second=%d", len(raw), len(first.ExpectedJSON), len(second.ExpectedJSON))
	if err = j.prepareGuard(first); err != nil {
		t.Fatal("first independently valid template refused", err)
	}
	if err = j.finishGuard(first); err != nil {
		t.Fatal(err)
	}
	one, _ := os.ReadFile(filepath.Join(dir, "journal.json"))
	if len(one) >= kernelDumpLimit {
		t.Fatal("fixture did not isolate temporary two-template transition")
	}
	candidate := cloneJournal(j.payload)
	candidate.Guards = append(candidate.Guards, runtimeGuardTemplate{Namespace: second.Namespace, Revision: second.Revision, Digest: second.Digest, ExpectedJSON: second.ExpectedJSON})
	candidate.Sequence++
	two, _ := json.Marshal(runtimeJournalEnvelope{Payload: candidate, Checksum: journalChecksum(candidate)})
	if len(two) <= kernelDumpLimit {
		t.Fatal("fixture did not exceed native-dump cap with complete two-template duty")
	}
	t.Logf("one-template envelope=%d, temporary two-template envelope=%d, each native template=%d/%d", len(one), len(two), len(first.ExpectedJSON), len(second.ExpectedJSON))
	if err = j.prepareGuard(second); err != nil {
		t.Fatal("bounded journal refused valid two-template transition; history must not be discarded", err)
	}
	if len(j.payload.Guards) != 2 {
		t.Fatal("interrupted replacement duties not both retained")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal("interrupted larger journal cannot reopen", err)
	}
	defer j.Close()
	if len(j.payload.Guards) != 2 {
		t.Fatal("restart lost one potential guard duty")
	}
	after, _ := json.Marshal(j.payload.Entries)
	if string(after) != string(before) {
		t.Fatal("retained lineage/history bytes changed")
	}
	if !reflect.DeepEqual(j.payload.Entries[3].RetainedGuardPredecessors, entry.RetainedGuardPredecessors) {
		t.Fatal("predecessor refs changed")
	}
	if err = j.finishGuard(second); err != nil {
		t.Fatal(err)
	}
	if len(j.payload.Guards) != 1 || j.payload.Guards[0].Digest != second.Digest {
		t.Fatal("verified completion did not finalize successor")
	}
}

func TestRuntimeJournalCapacityStillRefusesOversizeAndTampering(t *testing.T) {
	if kernelDumpLimit != 1<<20 || runtimeJournalLimit != 16<<20 {
		t.Fatal("native limit changed or journal became unbounded")
	}
	entry := journalFixture()
	owner := entry.Engines[0].Binding.GatewayID
	t.Run("oversize private file", func(t *testing.T) {
		dir := journalDir(t)
		f, err := os.OpenFile(filepath.Join(dir, "journal.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(runtimeJournalLimit + 1); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err = OpenRuntimeJournal(dir, owner); err != ErrRuntimeJournal {
			t.Fatal("oversize persisted journal accepted")
		}
		if _, _, err = ReadRuntimeJournalIdentity(dir); err != ErrRuntimeJournal {
			t.Fatal("oversize unlocked identity discovery accepted")
		}
	})
	t.Run("native template stays bounded", func(t *testing.T) {
		j, err := OpenRuntimeJournal(journalDir(t), owner)
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		m := journalCapacityGuard(t, owner, 1)
		m.ExpectedJSON = string(make([]byte, kernelDumpLimit+1))
		if err = j.prepareGuard(m); err != ErrRuntimeJournal {
			t.Fatal("oversize native guard allowed by larger envelope limit")
		}
	})
	t.Run("checksum and private mode remain required", func(t *testing.T) {
		dir := journalDir(t)
		j, err := OpenRuntimeJournal(dir, owner)
		if err != nil {
			t.Fatal(err)
		}
		if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
			t.Fatal(err)
		}
		j.Close()
		path := filepath.Join(dir, "journal.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var envelope runtimeJournalEnvelope
		if json.Unmarshal(raw, &envelope) != nil {
			t.Fatal("fixture decode")
		}
		envelope.Checksum = "0000000000000000000000000000000000000000000000000000000000000000"
		raw, _ = json.Marshal(envelope)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("fixture write")
		}
		if _, err = OpenRuntimeJournal(dir, owner); err != ErrRuntimeJournal {
			t.Fatal("bad checksum accepted")
		}
		envelope.Checksum = journalChecksum(envelope.Payload)
		raw, _ = json.Marshal(envelope)
		if os.WriteFile(path, raw, 0600) != nil || os.Chmod(path, 0644) != nil {
			t.Fatal("fixture mode")
		}
		if _, err = OpenRuntimeJournal(dir, owner); err != ErrRuntimeJournal {
			t.Fatal("public persisted journal accepted")
		}
	})
}

func TestRuntimeJournalOversizedWriterPreservesPriorDuty(t *testing.T) {
	base := restorationFixture()
	base.Phase = RuntimeApplied
	for slot := range base.Engines {
		base.Engines[slot].LocalPrefixes = nil
		base.Engines[slot].RemotePrefixes = nil
		for i := 0; i < 64; i++ {
			base.Engines[slot].LocalPrefixes = append(base.Engines[slot].LocalPrefixes, netip.MustParsePrefix(fmt.Sprintf("10.11.%d.0/24", i)))
			base.Engines[slot].RemotePrefixes = append(base.Engines[slot].RemotePrefixes, netip.MustParsePrefix(fmt.Sprintf("10.21.%d.0/24", i)))
		}
		base.Allocation.Tunnels[slot].RemotePrefixes = base.Engines[slot].RemotePrefixes
	}
	for i := 0; i < 16; i++ {
		base = restoredFixture(base)
	}
	owner := base.Engines[0].Binding.GatewayID
	first := journalCapacityGuard(t, owner, 1)
	second := journalCapacityGuard(t, owner, 2)
	prior := runtimeJournalPayload{Version: 9, OwnerID: owner, Sequence: 1, Entries: []RuntimeJournalEntry{}, Guards: []runtimeGuardTemplate{{Namespace: first.Namespace, Revision: first.Revision, Digest: first.Digest, ExpectedJSON: first.ExpectedJSON}}}
	clone, _ := json.Marshal(base)
	emptyNext := cloneJournal(prior)
	emptyNext.Guards = append(emptyNext.Guards, runtimeGuardTemplate{Namespace: second.Namespace, Revision: second.Revision, Digest: second.Digest, ExpectedJSON: second.ExpectedJSON})
	emptyNext.Sequence++
	emptyRaw, _ := json.Marshal(runtimeJournalEnvelope{Payload: emptyNext, Checksum: journalChecksum(emptyNext)})
	// UUID substitutions have the same canonical byte length. Compute the
	// bounded entry count once, then validate the exact marshaled envelopes.
	count := (runtimeJournalLimit-len(emptyRaw))/(len(clone)+1) + 1
	if count <= 0 || count > 256 {
		t.Fatal("fixture exceeds bounded entry census")
	}
	for i := 0; i < count; i++ {
		var e RuntimeJournalEntry
		if json.Unmarshal(clone, &e) != nil {
			t.Fatal("clone")
		}
		delivery, conn := uuid.New(), uuid.New()
		rebind := func(v *RuntimeJournalEntry) {
			v.DeliveryID = delivery
			v.Allocation.ConnectionID = conn
			for i := range v.Engines {
				v.Engines[i].Binding.ConnectionID = conn
			}
		}
		rebind(&e)
		for i := range e.Restoration.Retired {
			rebind(&e.Restoration.Retired[i].Entry)
		}
		prior.Entries = append(prior.Entries, e)
	}
	candidate := cloneJournal(prior)
	candidate.Guards = append(candidate.Guards, runtimeGuardTemplate{Namespace: second.Namespace, Revision: second.Revision, Digest: second.Digest, ExpectedJSON: second.ExpectedJSON})
	candidate.Sequence++
	priorRaw, _ := json.Marshal(runtimeJournalEnvelope{Payload: prior, Checksum: journalChecksum(prior)})
	nextRaw, _ := json.Marshal(runtimeJournalEnvelope{Payload: candidate, Checksum: journalChecksum(candidate)})
	if len(priorRaw) > runtimeJournalLimit || !validJournalPayload(prior) || !validJournalPayload(candidate) || !validJournalSuccessor(prior, candidate) {
		t.Fatal("writer-cap fixture not a valid bounded successor")
	}
	if len(nextRaw) <= runtimeJournalLimit {
		t.Fatal("fixture failed to exceed bounded envelope budget")
	}
	dir := journalDir(t)
	path := filepath.Join(dir, "journal.json")
	if os.WriteFile(path, priorRaw, 0600) != nil {
		t.Fatal("fixture write")
	}
	j, err := OpenRuntimeJournal(dir, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	before := cloneJournal(j.payload)
	if err = j.prepareGuard(second); err != ErrRuntimeJournal {
		t.Fatal("oversized valid writer envelope accepted")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(priorRaw) || !reflect.DeepEqual(j.payload, before) || j.poisoned {
		t.Fatal("size refusal mutated or poisoned prior durable duty")
	}
	if err = j.finishGuard(first); err != nil {
		t.Fatal("safe bounded prior journal unusable after refused successor", err)
	}
	t.Logf("valid prior envelope=%d, refused temporary successor=%d, entries=%d", len(priorRaw), len(nextRaw), len(prior.Entries))
}
