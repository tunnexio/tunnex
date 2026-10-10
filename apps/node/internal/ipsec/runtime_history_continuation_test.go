package ipsec

import (
	"encoding/json"
	"fmt"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Identity fixtures model independently proved cleanup. The test exercises the
// real durable journal/checksum/successor/reload boundaries, not native deletion.
func TestHistoryProcessFortyDurableGenerations(t *testing.T) {
	e := processStateFixture(t)
	p := e.BGPProcess
	e.BGPProcess = nil
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { j.Close() }()
	e = saveAppliedRestorationFixture(t, j, e)
	e.BGPProcess = p
	for n := uint64(1); n <= 40; n++ {
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatalf("reserve generation%d: %v", n, err)
		}
		cleaned := cloneProcessState(e)
		cleaned.BGPProcess.Stage = "cleaned"
		if err = j.Save([]RuntimeJournalEntry{cleaned}); err != nil {
			t.Fatal(err)
		}
		dir := j.dir
		j.Close()
		j, err = OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := j.Entries()
		if !reflect.DeepEqual(got[0], cleaned) {
			t.Fatal("durable continuation lost")
		}
		if n == 40 {
			if j.payload.Version != 8 || historyCount(cleaned.BGPProcessHistory) != 23 || len(cleaned.BGPProcessRetired) != 16 {
				t.Fatal("not bounded monotonic v8", cleaned.BGPProcessHistory)
			}
			break
		}
		next := cloneProcessState(cleaned)
		if compactBGPProcessHistory(&next) != nil {
			t.Fatal("cleaned prefix compaction refused")
		}
		next.BGPProcessRetired = append(next.BGPProcessRetired, *cleaned.BGPProcess)
		next.BGPProcess.Generation = n + 1
		next.BGPProcess.Stage = "reserved"
		next.BGPProcess.Directory = filepath.Join(filepath.Dir(p.Directory), fmt.Sprintf("bgp-%s-g%d", e.DeliveryID, n+1))
		next.BGPProcess.DirectoryFile.Inode++
		e = next
	}
}
func TestHistoryFortyTrustedRestorations(t *testing.T) {
	for _, bgp := range []bool{false, true} {
		t.Run(fmt.Sprint(bgp), func(t *testing.T) {
			e := restorationFixture()
			if bgp {
				e = bgpEntryFixture(t)
			}
			j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			e = saveAppliedRestorationFixture(t, j, e)
			for n := uint64(1); n <= 40; n++ {
				next := restoredFixture(e)
				if e.Restoration != nil {
					prior := *e.Restoration
					if compactRestorationHistory(&prior) != nil {
						t.Fatal("discharged epoch refused")
					}
					next.Restoration.Compacted = prior.Compacted
					next.Restoration.Retired = append(append([]RuntimeRetiredEpoch{}, prior.Retired...), next.Restoration.Retired[len(next.Restoration.Retired)-1])
				}
				if err = j.Save([]RuntimeJournalEntry{next}); err != nil {
					t.Fatalf("epoch%d: %v", n, err)
				}
				dir := j.dir
				j.Close()
				j, err = OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := j.Entries()
				if !reflect.DeepEqual(got[0], next) {
					t.Fatal("epoch continuity lost")
				}
				e = next
			}
			if j.payload.Version != 8 || e.Restoration.Epoch != 40 || historyCount(e.Restoration.Compacted) != 24 || len(e.Restoration.Retired) != 16 {
				t.Fatal("epoch artificially bounded or lineage lost")
			}
		})
	}
}
func TestHistoryUncertainAndForgedContinuationRefused(t *testing.T) {
	e := processStateFixture(t)
	e.BGPProcessRetired = nil
	for n := uint64(1); n <= 16; n++ {
		p := *e.BGPProcess
		p.Generation = n
		p.Stage = "cleaned"
		p.Directory = fmt.Sprintf("/var/lib/tunnex/bgp-%s-g%d", e.DeliveryID, n)
		e.BGPProcessRetired = append(e.BGPProcessRetired, p)
	}
	e.BGPProcess.Generation = 17
	e.BGPProcess.Directory = fmt.Sprintf("/var/lib/tunnex/bgp-%s-g17", e.DeliveryID)
	e.BGPProcess.Stage = "cleaned"
	uncertain := e
	uncertain.BGPProcessRetired = append([]bgpengine.ProcessIdentity{}, e.BGPProcessRetired...)
	uncertain.BGPProcessRetired[0].Stage = "retired-uncertain"
	if compactBGPProcessHistory(&uncertain) == nil {
		t.Fatal("uncertain duty compacted")
	}
	next := cloneProcessState(e)
	if compactBGPProcessHistory(&next) != nil {
		t.Fatal("cleanup compact failed")
	}
	next.BGPProcessRetired = append(next.BGPProcessRetired, *e.BGPProcess)
	next.BGPProcess.Generation++
	next.BGPProcess.Stage = "reserved"
	next.BGPProcess.Directory = fmt.Sprintf("/var/lib/tunnex/bgp-%s-g18", e.DeliveryID)
	if !validBGPProcessSuccessor(e, next) {
		t.Fatal("legal continuation refused")
	}
	for _, change := range []func(*RuntimeJournalEntry){func(x *RuntimeJournalEntry) {
		h := *x.BGPProcessHistory
		h.Digest = stringDigest([]byte("forged"))
		x.BGPProcessHistory = &h
	}, func(x *RuntimeJournalEntry) { h := *x.BGPProcessHistory; h.Count++; x.BGPProcessHistory = &h }, func(x *RuntimeJournalEntry) { x.BGPProcessHistory = nil }, func(x *RuntimeJournalEntry) { x.BGPProcess.Generation = 1 }} {
		bad := cloneProcessState(next)
		change(&bad)
		if validBGPProcessSuccessor(e, bad) {
			t.Fatal("forged/replayed lineage admitted")
		}
	}
	if _, err := advanceHistory(&RuntimeHistoryContinuation{Count: ^uint64(0), Digest: stringDigest([]byte("max"))}, "x", e); err == nil {
		t.Fatal("count wrapped")
	}
	old := restorationFixture()
	old.Restoration = &RuntimeRestoration{Epoch: ^uint64(0)}
	after := old
	after.Restoration = &RuntimeRestoration{Epoch: 0}
	if restorationAdvanced(old, after) {
		t.Fatal("epoch wrapped")
	}
}
func TestHistoryLegacyBytesAndVersionGate(t *testing.T) {
	e := processStateFixture(t)
	b, _ := json.Marshal(e)
	var fields map[string]any
	json.Unmarshal(b, &fields)
	if _, ok := fields["BGPProcessHistory"]; ok {
		t.Fatal("legacy serialization changed")
	}
	e.BGPProcess = nil
	e.BGPProcessHistory = &RuntimeHistoryContinuation{Count: 1, Digest: stringDigest([]byte("invalid untrusted fixture"))}
	p := runtimeJournalPayload{Version: 7, OwnerID: e.Engines[0].Binding.GatewayID, Entries: []RuntimeJournalEntry{e}}
	if validJournalPayload(p) {
		t.Fatal("v7 admitted continuation")
	}
	// Unsupported readers must reject the new version rather than silently ignore
	// offset lineage. Production Load uses strict decoder + version validation.
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryMixedBGPProcessAndNamespaceFortyCycles(t *testing.T) {
	e := processStateFixture(t)
	template := *e.BGPProcess
	e.BGPProcess = nil
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { j.Close() }()
	e = saveAppliedRestorationFixture(t, j, e)
	for n := uint64(1); n <= 40; n++ {
		p := template
		p.Generation = n
		p.Directory = filepath.Join(filepath.Dir(template.Directory), fmt.Sprintf("bgp-%s-g%d", e.DeliveryID, n))
		p.Namespace = e.Allocation.Namespace
		p.DirectoryFile.Inode += n
		if e.Restoration != nil {
			p.BootID = e.Restoration.BootID
		}
		e.BGPProcess = &p
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatalf("mixed reserve%d:%v", n, err)
		}
		e = cloneProcessState(e)
		e.BGPProcess.Stage = "cleaned"
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
		next := restoredFixture(e)
		next.BGPProcess = nil
		if compactBGPProcessHistory(&next) != nil {
			t.Fatal("mixed process compaction")
		}
		next.BGPProcessRetired = append(next.BGPProcessRetired, *e.BGPProcess)
		if e.Restoration != nil {
			prior := *e.Restoration
			if compactRestorationHistory(&prior) != nil {
				t.Fatal("mixed epoch compaction")
			}
			next.Restoration.Compacted = prior.Compacted
			next.Restoration.Retired = append(append([]RuntimeRetiredEpoch{}, prior.Retired...), next.Restoration.Retired[len(next.Restoration.Retired)-1])
		}
		if err = j.Save([]RuntimeJournalEntry{next}); err != nil {
			t.Fatalf("mixed restoration%d:%v", n, err)
		}
		dir := j.dir
		j.Close()
		j, err = OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := j.Entries()
		e = rows[0]
	}
	if historyCount(e.BGPProcessHistory) != 24 || historyCount(e.Restoration.Compacted) != 24 || e.Restoration.Epoch != 40 || j.payload.Version != 8 {
		t.Fatal("mixed monotonic continuation lost")
	}
}
func TestHistoryCompactionSaveFailurePreservesDurableLineage(t *testing.T) {
	e := restorationFixture()
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	e = saveAppliedRestorationFixture(t, j, e)
	for n := 0; n < 16; n++ {
		e = restoredFixture(e)
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
	next := restoredFixture(e)
	prior := *e.Restoration
	compactRestorationHistory(&prior)
	next.Restoration.Compacted = prior.Compacted
	next.Restoration.Retired = append(append([]RuntimeRetiredEpoch{}, prior.Retired...), next.Restoration.Retired[len(next.Restoration.Retired)-1])
	j.syncDirectory = func() error { return fmt.Errorf("causal fsync failure") }
	if j.Save([]RuntimeJournalEntry{next}) == nil {
		t.Fatal("ambiguous compaction reported success")
	}
	if _, err = j.Entries(); err == nil {
		t.Fatal("failed writer not poisoned")
	}
	dir := j.dir
	j.Close()
	j, err = OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	rows, _ := j.Entries()
	// The rename may already have landed. Reload must see one whole validated
	// lineage, never a dropped prefix without the exact tombstone.
	if !reflect.DeepEqual(rows[0], e) && !reflect.DeepEqual(rows[0], next) {
		t.Fatal("partial lineage recovered")
	}
}
func TestHistoryEpochUncertainAndLineageRewriteRefused(t *testing.T) {
	old := restorationFixture()
	old.Phase = RuntimeApplied
	for n := 0; n < 16; n++ {
		old = restoredFixture(old)
	}
	next := restoredFixture(old)
	prior := *old.Restoration
	if compactRestorationHistory(&prior) != nil {
		t.Fatal("epoch compaction")
	}
	next.Restoration.Compacted = prior.Compacted
	next.Restoration.Retired = append(append([]RuntimeRetiredEpoch{}, prior.Retired...), next.Restoration.Retired[len(next.Restoration.Retired)-1])
	if !validRestorationSuccessor(old, next) {
		t.Fatal("legal epoch continuation")
	}
	for _, change := range []func(*RuntimeRestoration){func(v *RuntimeRestoration) {
		h := *v.Compacted
		h.Digest = stringDigest([]byte("forged"))
		v.Compacted = &h
	}, func(v *RuntimeRestoration) { h := *v.Compacted; h.Count++; v.Compacted = &h }, func(v *RuntimeRestoration) { v.Epoch = 0 }, func(v *RuntimeRestoration) { v.Retired = v.Retired[1:] }} {
		bad := next
		r := *next.Restoration
		r.Retired = append([]RuntimeRetiredEpoch{}, r.Retired...)
		bad.Restoration = &r
		change(&r)
		if validRestorationSuccessor(old, bad) {
			t.Fatal("epoch rewrite/replay admitted")
		}
	}
	blocked := *old.Restoration
	blocked.Retired = append([]RuntimeRetiredEpoch{}, blocked.Retired...)
	blocked.Retired[0].Entry.BGPProcessRetired = []bgpengine.ProcessIdentity{{Stage: "retired-uncertain"}}
	if compactRestorationHistory(&blocked) == nil {
		t.Fatal("uncertain epoch duty erased")
	}
}
