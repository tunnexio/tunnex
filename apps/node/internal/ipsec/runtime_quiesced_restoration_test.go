package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Model only the real boot/native readers; keep the actual durable journal,
// nonce-bound lease authority, validators and reservation transaction.
func coldQuiescedFixture(t *testing.T) (*RuntimeController, []RuntimeJournalEntry, RuntimeJournalEntry, RuntimeMaterial, string, *int) {
	t.Helper()
	old := quiescedFixture(t)
	old.Phase = RuntimeQuiesced
	old.Restoration.Retired = nil
	dir := journalDir(t)
	old.BGPProcess.Directory = filepath.Join(dir, "bgp-"+old.DeliveryID.String()+"-g1")
	payload := runtimeJournalPayload{Version: 12, OwnerID: old.Engines[0].Binding.GatewayID, Sequence: 1, Entries: []RuntimeJournalEntry{old}}
	if !validJournalPayload(payload) {
		t.Fatal("invalid negative checkpoint")
	}
	writeColdQuiescedPayload(t, dir, payload)
	j, err := OpenRuntimeJournal(dir, payload.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	c := &RuntimeController{journal: j, config: RuntimeControllerConfig{JournalDir: dir, GatewayID: payload.OwnerID, OrgID: old.Engines[0].Binding.OrgID}}
	c.namespace = func() (string, error) { return old.Allocation.Namespace, nil }
	denies := 0
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		denies++
		if len(in.Connections) == 0 {
			t.Fatal("missing permanent refusal")
		}
		for _, g := range in.Connections {
			if !g.PrefixOnly || len(g.Grants) != 0 {
				t.Fatal("reservation granted access")
			}
		}
		return GuardManifest{}, nil
	}
	c.client = maintenanceLeaseFunc(func(_ context.Context, id uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
		if denies == 0 || id != old.Allocation.ConnectionID || r.DeliveryID != old.DeliveryID || len(r.Nonce) != 64 {
			t.Fatal("lease precedes denial or wrong identity")
		}
		return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}, nil
	})
	candidate := cloneRuntimeEntries([]RuntimeJournalEntry{old})[0]
	candidate.Phase = RuntimeReserved
	return c, []RuntimeJournalEntry{old}, candidate, RuntimeMaterial{Policy: RuntimePolicy{Hash: strings.Repeat("a", 64)}}, uuid.NewString(), &denies
}
func writeColdQuiescedPayload(t *testing.T, dir string, p runtimeJournalPayload) {
	t.Helper()
	raw, err := json.Marshal(runtimeJournalEnvelope{Payload: p, Checksum: journalChecksum(p)})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func coldCurrent(context.Context, string, string) bool                      { return true }
func coldAbsent(context.Context, RuntimeJournalEntry, string, string) error { return nil }

func TestColdQuiescedRestorationDurableNegativeHistory(t *testing.T) {
	for _, changedNS := range []bool{false, true} {
		t.Run(map[bool]string{false: "reused_namespace", true: "new_namespace"}[changedNS], func(t *testing.T) {
			c, entries, candidate, m, boot, denies := coldQuiescedFixture(t)
			old := cloneRuntimeEntries(entries)[0]
			if changedNS {
				candidate.Allocation.Namespace = "net:[87654]"
			}
			if err := c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, coldCurrent); err != nil {
				t.Fatal(err)
			}
			got := entries[0]
			if *denies != 1 || len(c.active) != 0 || c.journal.payload.Version != 14 || got.Phase != RuntimeApplying || got.Observed != ([2]Ownership{}) || got.BGPProcess != nil || got.BGPRoutes != nil || got.Restoration.Epoch != 1 || got.Restoration.BootID != boot || got.Allocation.Generation == old.Allocation.Generation {
				t.Fatal("unsafe reservation", got.Phase)
			}
			if !reflect.DeepEqual(got.Restoration.Retired[0].Entry, flattenedRestorationEntry(old)) || got.Restoration.Retired[0].BootID != old.Restoration.BootID || !reflect.DeepEqual(got.BGPProcessRetired, append(old.BGPProcessRetired, *old.BGPProcess)) {
				t.Fatal("old negative obligations were changed")
			}
			dir := c.journal.dir
			c.journal.Close()
			reopened, err := OpenRuntimeJournal(dir, c.config.GatewayID)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			durable, _ := reopened.Entries()
			if !reflect.DeepEqual(durable, entries) {
				t.Fatal("reservation not durable")
			}
			// A crash after reservation must not append a second epoch or authorize.
			c.journal = reopened
			if c.reserveColdQuiescedRestoration(t.Context(), m, durable, 0, candidate, boot, coldAbsent, coldCurrent) == nil {
				t.Fatal("reserved Applying replay appended history")
			}
			after, _ := reopened.Entries()
			if !reflect.DeepEqual(after, entries) || len(c.active) != 0 {
				t.Fatal("replay changed duties")
			}
		})
	}
}

func TestColdQuiescedRestorationFailuresPreserveCheckpoint(t *testing.T) {
	for _, mode := range []string{"same_boot", "changed_intent", "denial", "lease_denied", "wrong_nonce", "wrong_hash", "wrong_delivery", "short_lease", "absence", "boot_drift", "namespace_drift", "cancel", "journal_changed", "save_failure", "expired_during_absence"} {
		t.Run(mode, func(t *testing.T) {
			c, entries, candidate, m, boot, _ := coldQuiescedFixture(t)
			before := cloneRuntimeEntries(entries)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			absent := coldAbsent
			current := coldCurrent
			calls := 0
			switch mode {
			case "same_boot":
				boot = entries[0].Restoration.BootID
			case "changed_intent":
				candidate.OwnershipDigest = strings.Repeat("b", 64)
			case "denial":
				c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }
			case "lease_denied", "wrong_nonce", "wrong_hash", "wrong_delivery", "short_lease", "expired_during_absence":
				c.client = maintenanceLeaseFunc(func(_ context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
					if mode == "lease_denied" {
						return RuntimeLease{}, errors.New("CP denied")
					}
					v := RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}
					switch mode {
					case "wrong_nonce":
						v.Nonce = strings.Repeat("b", 64)
					case "wrong_hash":
						v.PolicyHash = strings.Repeat("b", 64)
					case "wrong_delivery":
						v.DeliveryID = uuid.New()
					case "short_lease":
						v.TTLMS = 4000
					case "expired_during_absence":
						v.TTLMS = 5100
					}
					return v, nil
				})
				if mode == "expired_during_absence" {
					absent = func(context.Context, RuntimeJournalEntry, string, string) error {
						time.Sleep(150 * time.Millisecond)
						return nil
					}
				}
			case "absence":
				absent = func(context.Context, RuntimeJournalEntry, string, string) error { return ErrRuntimeController }
			case "boot_drift", "namespace_drift":
				current = func(context.Context, string, string) bool { calls++; return calls == 1 }
			case "cancel":
				absent = func(context.Context, RuntimeJournalEntry, string, string) error { cancel(); return nil }
				current = func(ctx context.Context, _ string, _ string) bool { return ctx.Err() == nil }
			case "journal_changed":
				absent = func(context.Context, RuntimeJournalEntry, string, string) error {
					c.journal.payload.Entries[0].OwnershipDigest = strings.Repeat("b", 64)
					return nil
				}
			case "save_failure":
				c.journal.syncDirectory = func() error { return errors.New("fsync failure") }
			}
			if err := c.reserveColdQuiescedRestoration(ctx, m, entries, 0, candidate, boot, absent, current); err == nil {
				t.Fatal("unsafe cold restoration accepted")
			}
			if len(c.active) != 0 || !reflect.DeepEqual(entries, before) {
				t.Fatal("failed path authorized or changed caller checkpoint")
			}
			if mode == "save_failure" {
				dir := c.journal.dir
				c.journal.Close()
				j, err := OpenRuntimeJournal(dir, c.config.GatewayID)
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				got, _ := j.Entries()
				if got[0].Phase != RuntimeApplying || !reflect.DeepEqual(got[0].Restoration.Retired[0].Entry, flattenedRestorationEntry(before[0])) {
					t.Fatal("ambiguous commit lost duties")
				}
			} else if mode != "journal_changed" {
				got, _ := c.journal.Entries()
				if !reflect.DeepEqual(got, before) {
					t.Fatal("precommit failure rewrote journal")
				}
			}
		})
	}
}

func TestColdQuiescedJournalRejectsUnprovenOrLegacyShape(t *testing.T) {
	c, entries, candidate, m, boot, _ := coldQuiescedFixture(t)
	prior := cloneJournal(c.journal.payload)
	if err := c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, coldCurrent); err != nil {
		t.Fatal(err)
	}
	next := cloneJournal(c.journal.payload)
	for _, v := range []int{12, 13} {
		p := cloneJournal(next)
		p.Version = v
		if validJournalPayload(p) {
			t.Fatal("old version admitted new history")
		}
	}
	for name, mutate := range map[string]func(*runtimeJournalPayload){
		"faked_applied": func(p *runtimeJournalPayload) { p.Entries[0].Restoration.Retired[0].Entry.Phase = RuntimeApplied },
		"same_boot":     func(p *runtimeJournalPayload) { p.Entries[0].Restoration.Retired[0].BootID = boot },
		"supervisor_instead_of_boot": func(p *runtimeJournalPayload) {
			p.Entries[0].Restoration.Retired[0].Termination = "supervisor-confirmed-runtime-stop"
		},
		"missing_observed": func(p *runtimeJournalPayload) { p.Entries[0].Restoration.Retired[0].Entry.Observed = [2]Ownership{} },
		"live_process": func(p *runtimeJournalPayload) {
			p.Entries[0].Restoration.Retired[0].Entry.BGPProcess.Stage = "reserved"
		},
		"foreign_boot": func(p *runtimeJournalPayload) {
			p.Entries[0].Restoration.Retired[0].Entry.BGPProcess.BootID = uuid.NewString()
		},
		"routes_not_withdrawn": func(p *runtimeJournalPayload) { p.Entries[0].Restoration.Retired[0].Entry.BGPRoutes.Withdrawal = false },
		"changed_predecessor": func(p *runtimeJournalPayload) {
			p.Entries[0].Restoration.Retired[0].Entry.OwnershipDigest = strings.Repeat("b", 64)
		},
		"reused_generation": func(p *runtimeJournalPayload) {
			p.Entries[0].Allocation.Generation = prior.Entries[0].Allocation.Generation
		},
		"invented_applied_successor": func(p *runtimeJournalPayload) { p.Entries[0].Phase = RuntimeApplied },
		"lost_process_duty":          func(p *runtimeJournalPayload) { p.Entries[0].BGPProcessRetired = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneJournal(next)
			mutate(&bad)
			if validJournalPayload(bad) && validJournalSuccessor(prior, bad) {
				t.Fatal("unproved transition accepted")
			}
		})
	}
}

func TestColdQuiescedRepeatedBootPreservesHistoryAndVersion(t *testing.T) {
	c, entries, candidate, m, boot, _ := coldQuiescedFixture(t)
	original := cloneRuntimeEntries(entries)[0]
	for generation := 1; generation <= 18; generation++ {
		prior := cloneRuntimeEntries(entries)[0]
		if err := c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, coldCurrent); err != nil {
			t.Fatalf("cold boot %d: %v", generation, err)
		}
		current := entries[0]
		if current.Restoration.Epoch != uint64(generation) || c.journal.payload.Version != 14 || !reflect.DeepEqual(current.Restoration.Retired[len(current.Restoration.Retired)-1].Entry, flattenedRestorationEntry(prior)) {
			t.Fatal("negative history lost", generation)
		}
		// Model later normal authorized staging and graceful quiescence using only
		// the existing legal journal transitions; these writes grant no lease.
		p := *original.BGPProcess
		p.Generation = uint64(generation + 1)
		p.BootID = boot
		p.Namespace = current.Allocation.Namespace
		p.Directory = filepath.Join(c.journal.dir, "bgp-"+current.DeliveryID.String()+"-g"+fmt.Sprint(p.Generation))
		p.DirectoryFile.Inode += uint64(generation)
		p.Stage = "reserved"
		current.BGPProcess = &p
		for i, a := range current.Allocation.Tunnels {
			current.Observed[i] = Ownership{Namespace: current.Allocation.Namespace, InterfaceName: a.Name, InterfaceIndex: 100 + 2*generation + i, XFRMID: a.XFRMID}
		}
		current.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "pending", Withdrawal: false, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
		if err := c.journal.Save([]RuntimeJournalEntry{current}); err != nil {
			t.Fatal("model fresh process reservation", generation, err)
		}
		current.BGPProcess.Stage = "cleaned"
		current.BGPRoutes.Stage = "completed"
		current.Phase = RuntimeApplied
		if err := c.journal.Save([]RuntimeJournalEntry{current}); err != nil {
			t.Fatal("model fresh authorized apply and cleanup", generation, err)
		}
		current.BGPRoutes.Stage = "pending"
		current.BGPRoutes.Sequence++
		current.BGPRoutes.Withdrawal = true
		if err := c.journal.Save([]RuntimeJournalEntry{current}); err != nil {
			t.Fatal("model route withdrawal", generation, err)
		}
		current.BGPRoutes.Stage = "completed"
		if err := c.journal.Save([]RuntimeJournalEntry{current}); err != nil {
			t.Fatal("model route absence", generation, err)
		}
		current.Phase = RuntimeQuiesced
		if err := c.journal.Save([]RuntimeJournalEntry{current}); err != nil {
			t.Fatal("model repeated graceful quiescence", generation, err)
		}
		entries = []RuntimeJournalEntry{current}
		candidate = cloneRuntimeEntries(entries)[0]
		candidate.Phase = RuntimeReserved
		boot = uuid.NewString()
	}
	if c.journal.payload.Version != 14 || entries[0].Restoration.Compacted == nil || entries[0].Restoration.Compacted.Count != 2 || len(entries[0].Restoration.Retired) != 16 || len(c.active) != 0 {
		t.Fatal("version/history not sticky after compaction")
	}
	dir := c.journal.dir
	c.journal.Close()
	j, err := OpenRuntimeJournal(dir, c.config.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, _ := j.Entries()
	if j.payload.Version != 14 || !reflect.DeepEqual(got, entries) {
		t.Fatal("reopen lost compacted cold history")
	}
}

func TestColdQuiescedInterruptedAfterSaveRemainsApplying(t *testing.T) {
	c, entries, candidate, m, boot, _ := coldQuiescedFixture(t)
	old := cloneRuntimeEntries(entries)[0]
	checks := 0
	current := func(context.Context, string, string) bool { checks++; return checks < 4 }
	if err := c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, current); err == nil {
		t.Fatal("post-save drift succeeded")
	}
	if checks != 4 || len(c.active) != 0 || entries[0].Phase != RuntimeApplying {
		t.Fatal("post-save refusal lost reservation")
	}
	got, _ := c.journal.Entries()
	if !reflect.DeepEqual(got, entries) || !reflect.DeepEqual(got[0].Restoration.Retired[0].Entry, flattenedRestorationEntry(old)) {
		t.Fatal("post-save original obligations lost")
	}
}

func TestColdQuiescedEmptyHistoryEncodingAndFreshDescriptorLease(t *testing.T) {
	for _, emptyArray := range []bool{false, true} {
		t.Run(fmt.Sprint(emptyArray), func(t *testing.T) {
			c, entries, candidate, m, boot, _ := coldQuiescedFixture(t)
			if emptyArray {
				c.journal.Close()
				entries[0].Restoration.Retired = []RuntimeRetiredEpoch{}
				p := runtimeJournalPayload{Version: 12, OwnerID: c.config.GatewayID, Sequence: 1, Entries: entries}
				writeColdQuiescedPayload(t, c.config.JournalDir, p)
				j, err := OpenRuntimeJournal(c.config.JournalDir, c.config.GatewayID)
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				c.journal = j
			}
			fixture, _, _ := v2FQDNFixture(t)
			m.Policy.FQDNPolicyVersion = 2
			m.Policy.FQDNGrants = runtimeFQDNLeaseDescriptors(fixture.Policy)
			expected := runtimeFQDNLeaseDescriptors(m.Policy)
			var nonces []string
			c.client = maintenanceLeaseFunc(func(_ context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
				if !reflect.DeepEqual(r.FQDNGrants, expected) {
					t.Fatal("reservation discarded exact FQDN descriptors")
				}
				nonces = append(nonces, r.Nonce)
				if len(nonces) == 1 {
					return RuntimeLease{}, errors.New("temporary CP refusal")
				}
				return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: runtimeFQDNGrantDigest(expected[0]), TTLMS: 20000}}}, nil
			})
			if c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, coldCurrent) == nil {
				t.Fatal("denied CP restored")
			}
			if err := c.reserveColdQuiescedRestoration(t.Context(), m, entries, 0, candidate, boot, coldAbsent, coldCurrent); err != nil {
				t.Fatal(err)
			}
			if len(nonces) != 2 || nonces[0] == nonces[1] || len(c.active) != 0 {
				t.Fatal("replayed authority or manufactured application grant")
			}
		})
	}
}
