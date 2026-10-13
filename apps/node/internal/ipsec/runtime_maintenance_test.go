package ipsec

import (
	"context"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func maintenanceMaterials(r *renewalCycleRig) []RuntimeMaterial {
	// Same logical order after TGW-static: BGP, recreated static, BGP, BGP, TGW.
	out := []RuntimeMaterial{}
	for _, i := range []int{1, 4, 0, 2, 3} {
		out = append(out, r.materials[i])
	}
	return out
}
func maintenanceAuthority(r *renewalCycleRig) func() *PermitLeaseAuthority {
	return func() *PermitLeaseAuthority {
		return &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
	}
}
func TestFiveProviderMaintainedRenewalDeadline(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	// Same initial target renewal/post-lease commit as the serial RED. The next
	// normal page renews all five exact existing owners as one batch.
	a := r.c.active[r.target]
	a.Authority = r.fresh(t, a)
	r.c.active[r.target] = a
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal(err)
	}
	r.charge("observe_report_ack", 600*time.Millisecond)
	old := map[uuid.UUID]runtimeActive{}
	deadlines := map[uuid.UUID]time.Duration{}
	for id, a := range r.c.active {
		old[id] = a
		deadlines[id] = a.Authority.deadline
	}
	replace := r.c.replace
	commits := 0
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		commits++
		for id, a := range r.c.active {
			if a.Authority != old[id].Authority {
				t.Fatal("fresh authority published before guard commit")
			}
		}
		return replace(ctx, in)
	}
	r.heartbeat(t)
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
	r.phase = ""
	// Same ordinary report/ACK seam charge as the frozen serial path.
	r.charge("observe_report_ack", time.Duration(len(results))*600*time.Millisecond)
	t.Logf("elapsed=%s firstTGWExpiry=%s nativeMemberEmpty=%t heartbeatCallbacks=%d samples=%d telemetryNoncesDiscarded=%d freshMaintenanceCPNonces=%d commits=%d work=%v", *r.now, r.firstLapse, r.expiryEmpty, r.heartbeatOK, r.heartbeatSamples, r.telemetryNonces, r.leases, commits, r.charged)
	if err != nil || len(results) != 5 || commits != 1 || len(r.c.active) != 5 {
		t.Fatalf("maintenance results=%d commits=%d active=%d err=%v", len(results), commits, len(r.c.active), err)
	}
	if r.firstLapse != 0 || r.expiryEmpty {
		t.Fatal("native member expired before maintained commit")
	}
	for i, m := range maintenanceMaterials(r) {
		got := results[i]
		if got.Acknowledgement != (RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}) || got.Report.DeliveryID != m.ID || got.Report.DesiredRevision != m.DesiredRevision {
			t.Fatal("exact existing delivery acknowledgement lost")
		}
		a := r.c.active[m.Manifest.ConnectionID]
		if a.Authority == old[m.Manifest.ConnectionID].Authority || !reflect.DeepEqual(a.Entry, old[m.Manifest.ConnectionID].Entry) {
			t.Fatal("candidate changed intent or failed fresh nonce")
		}
		if old[m.Manifest.ConnectionID].Authority.deadline != deadlines[m.Manifest.ConnectionID] {
			t.Fatal("maintenance mutated original deadline")
		}
	}
	for _, process := range r.c.bgpProcesses {
		if process.(*bgpSessionFixture).closed {
			t.Fatal("positive maintained renewal closed an existing BGP session")
		}
	}
}

type maintenanceBlockingEnvironment struct {
	previous         RuntimeEnvironmentInspector
	entered, release chan struct{}
	once             sync.Once
}

func (e *maintenanceBlockingEnvironment) Observe(ctx context.Context, a KernelAllocation, engines [2]EngineTunnel) (RuntimeEnvironment, error) {
	e.once.Do(func() { close(e.entered); <-e.release })
	return e.previous.Observe(ctx, a, engines)
}
func (e *maintenanceBlockingEnvironment) Drain(ctx context.Context, entries []RuntimeJournalEntry) error {
	return e.previous.Drain(ctx, entries)
}

func TestMaintainedChangedDNSInputsWithdrawBeforeEnvironmentIO(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	c := r.c
	m := r.materials[3]
	id := m.Manifest.ConnectionID
	// The published epoch models an in-flight unlocked DNS reader. Revocation,
	// rather than a positive socket/guard claim, is the boundary under test.
	epoch := &runtimeDNSEpoch{}
	c.dnsView.Store(&runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{id: {active: cloneDNSOwnerActive(c.active[id]), epoch: epoch}}})
	m.Policy.Hash = strings.Repeat("c", 64)
	block := &maintenanceBlockingEnvironment{previous: c.config.Environment, entered: make(chan struct{}), release: make(chan struct{})}
	c.config.Environment = block
	var release sync.Once
	defer release.Do(func() { close(block.release) })
	done := make(chan struct{})
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer close(done)
		_, _ = c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{m}, maintenanceAuthority(r), func() bool { return true })
	}()
	select {
	case <-block.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("environment boundary not reached")
	}
	if !epoch.revoked.Load() {
		t.Error("old in-flight DNS epoch remained usable during changed material IO")
	}
	if v := c.dnsView.Load(); v != nil {
		if _, ok := v.entries[id]; ok {
			t.Error("old DNS owner stayed published during changed material IO")
		}
	}
	release.Do(func() { close(block.release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance did not leave blocked boundary")
	}
}

type maintenanceLeaseFunc func(context.Context, uuid.UUID, RuntimeLeaseRequest) (RuntimeLease, error)

func (f maintenanceLeaseFunc) RenewIPsecLease(ctx context.Context, id uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
	return f(ctx, id, r)
}

func TestMaintainedRenewalStrictFallback(t *testing.T) {
	for _, scenario := range []string{"inactive", "new_delivery", "policy", "grants", "prepared_missing", "pending", "missing_members", "native", "namespace", "foreign_table", "original_expired_during_CP", "wrong_nonce", "duplicate_connection", "duplicate_delivery", "startup_gate", "canceled", "bgp_learned_changed", "bgp_qualification_during_CP", "bgp_qualification_during_commit", "candidate_evicted_during_commit"} {
		t.Run(scenario, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			c := r.c
			mats := maintenanceMaterials(r)
			target := r.target
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			qualified := true
			expectError := false
			noResults := false
			switch scenario {
			case "inactive":
				delete(c.active, target)
			case "new_delivery":
				mats[4].ID = uuid.New()
			case "policy":
				mats[4].Policy.Hash = strings.Repeat("c", 64)
			case "grants":
				mats[4].Policy.Grants = []RuntimeGrant{{Source: mats[4].Manifest.LocalPrefixes[0], Destination: mats[4].Manifest.RemotePrefixes[0], Protocol: "tcp", PortLow: 53, PortHigh: 53}}
			case "prepared_missing":
				delete(c.recoveryPrepared, mats[4].ID)
			case "pending":
				a := c.active[target]
				next := *a.Entry.Recovery
				next.Stage = "pending"
				next.PendingFrom = 1
				next.PendingTo = 2
				next.SelectedSlot = 0
				a.Entry.Recovery = &next
				c.active[target] = a
			case "missing_members":
				r.installed[guardLeaseName(target)] = 0
			case "native":
				old := c.prove
				c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
					if e.Allocation.ConnectionID == target {
						return ErrRuntimeController
					}
					return old(ctx, e, env)
				}
			case "namespace":
				c.guard.reader.namespace = func() (string, error) { return "net:[4026532999]", nil }
				noResults = true
			case "foreign_table":
				c.guard.reader.run = func(context.Context, ...string) ([]byte, error) {
					return []byte(strings.ReplaceAll(string(r.native()), "tunnex_ipsec", "foreign_ipsec")), nil
				}
				noResults = true
			case "original_expired_during_CP":
				old := c.client
				c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					out, err := old.RenewIPsecLease(ctx, id, q)
					r.charge("slow_CP", 61*time.Second)
					return out, err
				})
				noResults = true
			case "wrong_nonce":
				old := c.client
				c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					out, err := old.RenewIPsecLease(ctx, id, q)
					out.Nonce = "wrong"
					return out, err
				})
				expectError = true
			case "duplicate_connection":
				mats = append(mats, mats[0])
				expectError = true
			case "duplicate_delivery":
				mats[4].ID = mats[0].ID
				expectError = true
			case "startup_gate":
				c.config.JournalDir = t.TempDir()
				if err := os.WriteFile(filepath.Join(c.config.JournalDir, "restoration-startup-gate"), []byte("held"), 0600); err != nil {
					t.Fatal(err)
				}
				expectError = true
			case "canceled":
				cancel()
				expectError = true
			case "bgp_learned_changed":
				c.bgpProcesses[mats[0].ID].(*bgpSessionFixture).routes = []bgpengine.LearnedRoute{{Prefix: r.entries[1].Allocation.Tunnels[0].RemotePrefixes[0], Slot: 2}}
				target = mats[0].Manifest.ConnectionID
			case "bgp_qualification_during_CP":
				old := c.client
				c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					out, err := old.RenewIPsecLease(ctx, id, q)
					qualified = false
					return out, err
				})
				target = mats[0].Manifest.ConnectionID
			case "bgp_qualification_during_commit":
				old := c.replace
				c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
					m, err := old(ctx, in)
					qualified = false
					return m, err
				}
				expectError = true
			case "candidate_evicted_during_commit":
				// Inject after the actual target CP response, rather than depending
				// on how many equivalent native proofs preceded the installer.
				freshReturned := false
				client := c.client
				c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
					out, err := client.RenewIPsecLease(ctx, id, q)
					if id == target && err == nil {
						freshReturned = true
					}
					return out, err
				})
				old := c.prove
				c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
					if e.Allocation.ConnectionID == target && freshReturned {
						return ErrRuntimeController
					}
					return old(ctx, e, env)
				}
				expectError = true
			}
			epoch := &runtimeDNSEpoch{}
			c.dnsView.Store(&runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{target: {active: cloneDNSOwnerActive(c.active[target]), epoch: epoch}}})
			r.phase = "maintenance"
			out, err := c.maintainIPsecRuntime(ctx, mats, maintenanceAuthority(r), func() bool { return qualified })
			r.phase = ""
			if expectError && (err == nil || len(out) != 0) {
				t.Fatalf("expected closed error, result=%d err=%v", len(out), err)
			}
			if noResults && len(out) != 0 {
				t.Fatalf("ineligible inputs acknowledged=%d", len(out))
			}
			for _, result := range out {
				if result.Acknowledgement.DeliveryID == mats[4].ID && target == r.target {
					t.Fatal("ineligible exact owner acknowledged")
				}
				if result.Acknowledgement.DeliveryID == mats[0].ID && target == mats[0].Manifest.ConnectionID {
					t.Fatal("changed BGP owner acknowledged")
				}
			}
			if scenario == "duplicate_connection" || scenario == "duplicate_delivery" || scenario == "startup_gate" || scenario == "canceled" {
				if r.leases != 0 {
					t.Fatal("invalid page requested fresh authority")
				}
			}
			if expectError && scenario != "canceled" {
				if len(c.active) != 0 || (c.dnsView.Load() != nil && len(c.dnsView.Load().entries) != 0) {
					t.Fatal("unknown/commit failure exposed positive owner")
				}
			}
			if !expectError && !noResults {
				if _, ok := c.active[target]; ok {
					t.Fatal("unsafe old target remained active")
				}
			}
		})
	}
}

func TestMaintainedResultsRecheckFirstDeadlineAfterLastReport(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	c := r.c
	c.config.Daemon = &DaemonClient{}
	// A deliberately unavailable inspector keeps actual reports Unknown; normal
	// persisted static observation sequences are still used, never manufactured Up.
	c.config.IPPath = "/usr/bin/false"
	authorities := []*PermitLeaseAuthority{}
	constructor := func() *PermitLeaseAuthority {
		x := &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
		authorities = append(authorities, x)
		return x
	}
	committed := false
	oldReplace := c.replace
	c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		m, err := oldReplace(ctx, in)
		committed = true
		return m, err
	}
	saves := 0
	syncDir := c.journal.syncDirectory
	c.journal.syncDirectory = func() error {
		if committed {
			saves++
			if saves == 2 {
				*r.now = authorities[0].deadline + time.Millisecond
			}
		}
		return syncDir()
	}
	r.phase = "maintenance"
	out, err := c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), constructor, func() bool { return true })
	if saves < 2 || len(authorities) != 5 {
		t.Fatalf("last actual static report did not execute: saves=%d authorities=%d", saves, len(authorities))
	}
	if err == nil || len(out) != 0 || len(c.active) != 0 {
		t.Fatal("cached first ACK escaped after later report expired its fresh authority")
	}
	if _, err := authorities[4].RemainingForApply(r.candidatesIdentityForTest(r, 4), time.Millisecond); err != nil {
		t.Fatal("negative must expire the first candidate while last remains valid", err)
	}
}
func (r *renewalCycleRig) candidatesIdentityForTest(_ *renewalCycleRig, i int) PermitLeaseIdentity {
	m := maintenanceMaterials(r)[i]
	return PermitLeaseIdentity{DeliveryID: m.ID, Binding: r.entries[[]int{1, 4, 0, 2, 3}[i]].Engines[0].Binding, PolicyHash: m.Policy.Hash}
}

func TestOrdinaryBGPPublicationIsSecretFreeAndBound(t *testing.T) {
	r := newRenewalCycleRigInput(t, true)
	m := r.materials[0]
	c := r.c
	id := m.Manifest.ConnectionID
	a := c.active[id]
	a.Delivery = RuntimeDelivery{}
	c.active[id] = a
	original := a.Authority
	if err := c.rememberAppliedBGPDelivery(context.Background(), m.RuntimeDelivery, m.Policy.Hash, func() bool { return true }); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(c.active[id].Delivery, m.RuntimeDelivery) || c.active[id].Authority != original {
		t.Fatal("normal publication failed exact secret-free context")
	}
	bad := m.RuntimeDelivery
	bad.OwnershipDigest = strings.Repeat("c", 64)
	if c.rememberAppliedBGPDelivery(context.Background(), bad, m.Policy.Hash, func() bool { return true }) == nil {
		t.Fatal("foreign delivery remembered")
	}
	if c.rememberAppliedBGPDelivery(context.Background(), m.RuntimeDelivery, m.Policy.Hash, func() bool { return false }) == nil {
		t.Fatal("stale qualification remembered")
	}
}
