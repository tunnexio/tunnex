package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const activeBootFixture = "0259d2d2-1111-4111-8111-111111111111"

func activeBootKernel(e RuntimeJournalEntry) *recoveryKernelFixture {
	f := newRecoveryKernelFixture()
	f.p, f.owned = e.Allocation, e.Observed
	f.routes = [2]map[string]bool{{}, {}}
	if e.ContractVersion == 3 {
		for i, tunnel := range e.Allocation.Tunnels {
			f.routes[i][netip.PrefixFrom(tunnel.BGP.Peer, 32).String()] = true
		}
		for _, route := range bgpRouteUnion(e.BGPRoutes) {
			f.routes[int(route.Slot)-1][route.Prefix.String()] = true
		}
	} else {
		for _, prefix := range e.Allocation.Tunnels[0].RemotePrefixes {
			f.routes[int(selectedRuntimeSlot(e))-1][prefix.String()] = true
		}
	}
	return f
}

// Real boot-record journal transition followed by canonical priority renewal.
// Native FRR/kernel observations and the boot reader are synthetic; the five
// owners, journal, finite authority and rendered native permits are real.
func TestAppliedBootRecordRetainsPriorityOwners(t *testing.T) {
	for _, contract := range []int{2, 3} {
		name := "static"
		if contract == 3 {
			name = "bgp"
		}
		t.Run(name, func(t *testing.T) {
			r, original, process, originalKernel := desktopBGPRenewalRig(t, true)
			target := r.target
			if contract == 3 {
				for id, a := range r.c.active {
					if id != original && a.Entry.ContractVersion == 3 {
						target = id
						break
					}
				}
			}
			prepared := cloneMaintenanceActive(r.c.active[target])
			preparedKernel := activeBootKernel(prepared.Entry)
			r.c.kernel = &KernelApplier{namespace: r.c.namespace, run: func(ctx context.Context, args ...string) ([]byte, error) {
				var joined []any
				for _, native := range []*recoveryKernelFixture{originalKernel, preparedKernel} {
					raw, err := native.run(ctx, args...)
					if err != nil {
						return nil, err
					}
					if len(raw) == 0 {
						continue
					}
					var rows []any
					if err := json.Unmarshal(raw, &rows); err != nil {
						return nil, err
					}
					joined = append(joined, rows...)
				}
				if len(joined) == 0 {
					return []byte("[]"), nil
				}
				return json.Marshal(joined)
			}}
			var material RuntimeMaterial
			for _, m := range r.materials {
				if m.Manifest.ConnectionID == target {
					material = m
				}
			}
			entriesBefore, err := r.c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			pos := -1
			for i, e := range entriesBefore {
				if e.DeliveryID == prepared.Entry.DeliveryID {
					pos = i
				}
			}
			if pos < 0 || material.ID != prepared.Entry.DeliveryID {
				t.Fatal("missing canonical Apply input")
			}
			// Transport preparation is the existing native fixture. Exercise the
			// actual contract-specific Apply body from no process-local owner,
			// including its fresh CP lease and final combined guard publication.
			delete(r.c.active, target)
			if contract == 2 {
				_, err = r.c.applyRecovery(context.Background(), material, entriesBefore, pos, prepared.Environment, prepared.Grants)
			} else {
				if r.c.bgpStaged == nil {
					r.c.bgpStaged = map[uuid.UUID]bool{}
				}
				r.c.bgpStaged[prepared.Entry.DeliveryID] = true
				_, err = r.c.applyBGPProof(context.Background(), material, entriesBefore, pos, prepared.Environment, prepared.Grants, func() bool { return true }, func(context.Context, RuntimeJournalEntry) error { return ErrRuntimeController })
			}
			if err != nil {
				t.Fatal("canonical Apply body", err)
			}
			before := cloneMaintenanceActive(r.c.active[target])
			if before.Entry.ContractVersion != contract || before.Entry.Restoration != nil {
				t.Fatal("fixture must enter the initial post-Apply boot-record boundary")
			}
			originalBefore := cloneMaintenanceActive(r.c.active[original])
			deadline := before.Authority.deadline
			originalDeadline := originalBefore.Authority.deadline
			installed := map[string]time.Duration{}
			for k, v := range r.installed {
				installed[k] = v
			}
			kernel := activeBootKernel(before.Entry)
			r.c.kernel = kernel.applier()
			if err := r.c.recordRuntimeBootObserved(context.Background(), before.Entry.DeliveryID, func() (string, error) { return activeBootFixture, nil }); err != nil {
				t.Fatal("initial boot record", err)
			}
			entries, err := r.c.journal.Entries()
			if err != nil {
				t.Fatal(err)
			}
			var committed RuntimeJournalEntry
			for _, e := range entries {
				if e.DeliveryID == before.Entry.DeliveryID {
					committed = e
				}
			}
			if committed.Restoration == nil || committed.Restoration.BootID != activeBootFixture {
				t.Fatal("boot stamp missing")
			}
			if !reflect.DeepEqual(r.c.active[target].Entry, committed) {
				t.Error("successful boot record left active owner behind its exact committed journal entry")
			}
			want := cloneMaintenanceActive(before)
			want.Entry = committed
			if !reflect.DeepEqual(r.c.active[target], want) || before.Authority.deadline != deadline || !reflect.DeepEqual(r.c.active[original], originalBefore) || originalBefore.Authority.deadline != originalDeadline || !reflect.DeepEqual(installed, r.installed) || kernel.mutations != 0 {
				t.Error("boot metadata synchronization changed authority, native permits or unrelated owner")
			}
			r.c.kernel = originalKernel.applier()
			r.phase = "maintenance"
			if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
				t.Fatalf("first priority renewal after boot record withdrew healthy owners: %v; original process closed=%v", err, process.closed)
			}
			if !allPriorityMembersLive(r) || process.closed || r.c.bgpProcesses[originalBefore.Entry.DeliveryID] != process || before.Authority.deadline != deadline || originalBefore.Authority.deadline != originalDeadline {
				t.Fatal("priority renewal lost unrelated owner or extended old authority")
			}
		})
	}
}

func TestBootRecordRefusesUnprovedSynchronization(t *testing.T) {
	for _, kind := range []string{"missing_owner", "stale_entry", "stale_identity", "expired_before", "boot_changed", "native_changed", "save_failed", "cancelled_after_save", "boot_changed_after_save", "owner_changed_after_save", "authority_replaced_after_save", "expired_after_save", "existing_boot_stale_owner", "existing_foreign_boot"} {
		t.Run(kind, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			id := r.target
			before := cloneMaintenanceActive(r.c.active[id])
			deadline := before.Authority.deadline
			kernel := activeBootKernel(before.Entry)
			r.c.kernel = kernel.applier()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "existing_boot_stale_owner" || kind == "existing_foreign_boot" {
				entries, err := r.c.journal.Entries()
				if err != nil {
					t.Fatal(err)
				}
				for i := range entries {
					if entries[i].DeliveryID == before.Entry.DeliveryID {
						entries[i].Restoration = &RuntimeRestoration{BootID: activeBootFixture}
					}
				}
				if err := r.c.journal.Save(entries); err != nil {
					t.Fatal(err)
				}
				if kind == "existing_foreign_boot" {
					a := r.c.active[id]
					a.Entry.Restoration = &RuntimeRestoration{BootID: activeBootFixture}
					r.c.active[id] = a
				}
			}
			switch kind {
			case "missing_owner":
				delete(r.c.active, id)
			case "stale_entry":
				a := r.c.active[id]
				a.Entry.Phase = RuntimeApplying
				r.c.active[id] = a
			case "stale_identity":
				a := r.c.active[id]
				a.Identity.Binding.DesiredRevision++
				r.c.active[id] = a
			case "expired_before":
				*r.now = deadline
			case "native_changed":
				kernel.owned[0].InterfaceIndex++
			}
			calls, injected := 0, false
			read := func() (string, error) {
				calls++
				if kind == "existing_foreign_boot" {
					return "1259d2d2-1111-4111-8111-111111111111", nil
				}
				if calls == 2 {
					if kind == "boot_changed" {
						injected = true
						return "1259d2d2-1111-4111-8111-111111111111", nil
					}
					if kind == "save_failed" {
						injected = true
						r.c.journal.Close()
					}
				}
				if calls == 3 {
					injected = true
					switch kind {
					case "cancelled_after_save":
						cancel()
					case "boot_changed_after_save":
						return "1259d2d2-1111-4111-8111-111111111111", nil
					case "owner_changed_after_save":
						a := r.c.active[id]
						a.Entry.SiteID[0] ^= 1
						r.c.active[id] = a
					case "authority_replaced_after_save":
						a := r.c.active[id]
						a.Authority = maintenanceAuthority(r)()
						req, err := a.Authority.Begin(a.Identity)
						if err != nil || a.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}) != nil {
							t.Fatal("replacement authority fixture invalid")
						}
						r.c.active[id] = a
					case "expired_after_save":
						*r.now = deadline
					}
				}
				return activeBootFixture, nil
			}
			if err := r.c.recordRuntimeBootObserved(ctx, before.Entry.DeliveryID, read); err == nil {
				t.Fatal("unproved synchronization accepted", kind)
			}
			if kind == "boot_changed" || kind == "save_failed" || kind == "cancelled_after_save" || kind == "boot_changed_after_save" || kind == "owner_changed_after_save" || kind == "authority_replaced_after_save" || kind == "expired_after_save" {
				if !injected {
					t.Fatal("hostile boundary not reached")
				}
			}
			if a, ok := r.c.active[id]; ok && a.Entry.Restoration != nil && kind != "existing_foreign_boot" {
				t.Fatal("failed or stale commit adopted journal metadata")
			}
			if before.Authority.deadline != deadline || kernel.mutations != 0 {
				t.Fatal("failed metadata synchronization changed authority/native state")
			}
		})
	}
}

func TestBootRecordAlreadyCommittedIsExactAndReadOnly(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	a := r.c.active[r.target]
	r.c.kernel = activeBootKernel(a.Entry).applier()
	read := func() (string, error) { return activeBootFixture, nil }
	if err := r.c.recordRuntimeBootObserved(context.Background(), a.Entry.DeliveryID, read); err != nil {
		t.Fatal(err)
	}
	before := cloneMaintenanceActive(r.c.active[r.target])
	entries, err := r.c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	sequence := r.c.journal.payload.Sequence
	if err := r.c.recordRuntimeBootObserved(context.Background(), a.Entry.DeliveryID, read); err != nil {
		t.Fatal(err)
	}
	after, err := r.c.journal.Entries()
	if err != nil || r.c.journal.payload.Sequence != sequence || !reflect.DeepEqual(after, entries) || !reflect.DeepEqual(r.c.active[r.target], before) {
		t.Fatal("idempotent boot recording rewrote/adopted owner")
	}
}

func TestBootRecordClassicKeepsCallerCommitBoundary(t *testing.T) {
	e, _, _, _ := classicProofFixture(t)
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		e.Phase = phase
		if err := j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
	prior := e
	prior.Phase = RuntimeApplying
	f := activeBootKernel(e)
	f.missing = 1
	k := f.applier()
	k.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := f.run(ctx, args...)
		if strings.Contains(strings.Join(args, " "), "addr show") {
			raw = []byte(strings.ReplaceAll(string(raw), `"prefixlen":30`, `"prefixlen":`+strconv.Itoa(e.Allocation.Tunnels[0].InsideAddress.Bits())))
		}
		return raw, err
	}
	c := &RuntimeController{journal: j, kernel: k, namespace: func() (string, error) { return e.Allocation.Namespace, nil }, active: map[uuid.UUID]runtimeActive{e.Allocation.ConnectionID: {Entry: prior}}}
	if err := c.recordRuntimeBootObserved(context.Background(), e.DeliveryID, func() (string, error) { return activeBootFixture, nil }); err != nil {
		t.Fatal(err)
	}
	entries, err := j.Entries()
	if err != nil || !classicCommittedEntryMatches(prior, entries[0], activeBootFixture) || !reflect.DeepEqual(c.active[e.Allocation.ConnectionID].Entry, prior) {
		t.Fatal("Classic recorder bypassed caller's separate exact commit")
	}
}

func TestBootRecordDurableReadbackFailureCannotPublish(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	a := cloneMaintenanceActive(r.c.active[r.target])
	r.c.kernel = activeBootKernel(a.Entry).applier()
	called := false
	r.c.journal.syncDirectory = func() error {
		called = true
		return os.WriteFile(filepath.Join(r.c.journal.dir, "journal.json"), []byte("corrupt readback"), 0600)
	}
	if err := r.c.recordRuntimeBootObserved(context.Background(), a.Entry.DeliveryID, func() (string, error) { return activeBootFixture, nil }); err == nil || !called {
		t.Fatal("failed journal readback accepted or injection missed")
	}
	if !reflect.DeepEqual(r.c.active[r.target], a) {
		t.Fatal("unreadable durable commit changed active snapshot")
	}
}
