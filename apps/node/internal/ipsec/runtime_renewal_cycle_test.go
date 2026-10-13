package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
)

// The local host cannot qualify native FRR. This drives the production
// post-qualification guard/reconcile/heartbeat seams, not public Apply or a
// native Linux acceptance claim. Every lease and rendered timeout is real.
type renewalCycleEnvironment map[uuid.UUID]RuntimeEnvironment

func (e renewalCycleEnvironment) Observe(_ context.Context, a KernelAllocation, _ [2]EngineTunnel) (RuntimeEnvironment, error) {
	return e[a.ConnectionID], nil
}
func (e renewalCycleEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }

type renewalCycleRig struct {
	c                   *RuntimeController
	materials           []RuntimeMaterial
	entries             []RuntimeJournalEntry
	now                 *time.Duration
	installed           map[string]time.Duration
	applicationDenied   map[uuid.UUID]bool
	expected            []byte
	target              uuid.UUID
	firstLapse          time.Duration
	expiryEmpty         bool
	shortcut            bool
	phase               string
	heartbeatSamples    int
	telemetryNonces     int
	heartbeatOK, leases int
	charged             map[string]time.Duration
	nonces              map[string]bool
}

func newRenewalCycleRig(t *testing.T) *renewalCycleRig { return newRenewalCycleRigInput(t, false) }
func newRenewalCycleRigInput(t *testing.T, canonical bool) *renewalCycleRig {
	t.Helper()
	c, entries, ids := mixedBudgetFixture(t)
	var materials []RuntimeMaterial
	if canonical {
		entries, materials = renewalCanonicalMaterials(t, c, entries)
	}
	r := &renewalCycleRig{c: c, entries: entries, materials: materials, now: budgetClock(t, c), target: ids[0], installed: map[string]time.Duration{}, applicationDenied: map[uuid.UUID]bool{}, charged: map[string]time.Duration{}, nonces: map[string]bool{}}
	c.journal.Close()
	dir := journalDir(t)
	payload := runtimeJournalPayload{Version: 8, OwnerID: c.config.GatewayID, Sequence: 1, Entries: entries}
	if !validJournalPayload(payload) {
		t.Fatal("five-provider fixture invalid")
	}
	raw, _ := json.Marshal(runtimeJournalEnvelope{Payload: payload, Checksum: journalChecksum(payload)})
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenRuntimeJournal(dir, c.config.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	c.journal = j
	c.recoveryClock = func() time.Duration { return *r.now }
	c.client = renewalTelemetryLease{rig: r}
	envs := renewalCycleEnvironment{}
	for id, a := range c.active {
		envs[id] = a.Environment
	}
	c.config.Environment = envs
	c.recoveryHistory = map[uuid.UUID]*recoveryDecision{}
	links := []GuardInterface{}
	for _, e := range entries {
		a := c.active[e.Allocation.ConnectionID]
		for _, o := range e.Observed {
			links = append(links, GuardInterface{Name: o.InterfaceName, Index: o.InterfaceIndex})
		}
		if e.ContractVersion == 3 {
			id := e.Allocation.ConnectionID
			c.bgpProcesses[e.DeliveryID].(*bgpSessionFixture).close = func() {
				if !r.applicationDenied[id] {
					t.Fatal("daemon close before actual rendered application denial")
				}
			}
			c.bgpProcesses[e.DeliveryID].(*bgpSessionFixture).routes = []bgpengine.LearnedRoute{{Prefix: e.Allocation.Tunnels[0].RemotePrefixes[0], Slot: 1}}
		} else {
			one := 1
			if !canonical {
				a.Delivery = RuntimeDelivery{ID: e.DeliveryID, Kind: "apply", OwnershipDigest: e.OwnershipDigest, DesiredRevision: e.Engines[0].Binding.DesiredRevision, Manifest: RuntimeManifest{OrgID: c.config.OrgID, NodeID: c.config.GatewayID, DesiredRevision: e.Engines[0].Binding.DesiredRevision, ProfileID: "aws-static-ipv4-v1", ConnectionID: e.Allocation.ConnectionID, ConfigurationRevision: e.Engines[0].Binding.ConfigurationRevision, RecoveryVersion: &one}}
				for i, v := range e.Engines {
					a.Delivery.Manifest.Tunnels[i] = RuntimeTunnel{ID: v.TunnelID, Slot: i + 1, Selected: i == 0}
				}
			}
			ep := recoveryEpoch{Binding: e.Engines[0].Binding, PolicyHash: a.Identity.PolicyHash, DeliveryID: e.DeliveryID, Namespace: e.Allocation.Namespace, Tunnels: [2]uuid.UUID{e.Engines[0].TunnelID, e.Engines[1].TunnelID}}
			h := &recoveryDecision{}
			h.observe(ep, 0, recoveryObservation{Epoch: ep, Current: 1, Status: [2]string{"up", "up"}, Authorized: true, At: 0})
			c.recoveryHistory[e.Allocation.ConnectionID] = h
		}
		c.active[e.Allocation.ConnectionID] = a
		if e.ContractVersion == 2 {
			if c.recoveryPrepared == nil {
				c.recoveryPrepared = map[uuid.UUID]RuntimeEnvironment{}
			}
			c.recoveryPrepared[e.DeliveryID] = a.Environment
		}
	}
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		m, err := RenderGuard(in)
		if err != nil {
			return m, err
		}
		if err = j.prepareGuard(m); err != nil {
			return m, err
		}
		if err = j.finishGuard(m); err != nil {
			return m, err
		}
		for _, g := range in.Connections {
			r.applicationDenied[g.ID] = g.PrefixOnly || len(g.Grants) == 0
		}
		r.expected = []byte(m.ExpectedJSON)
		r.installed = map[string]time.Duration{}
		var env map[string]any
		json.Unmarshal(r.expected, &env)
		for _, o := range env["nftables"].([]any) {
			s, ok := o.(map[string]any)["set"].(map[string]any)
			if !ok {
				continue
			}
			es, ok := s["elem"].([]any)
			if !ok {
				continue
			}
			for _, v := range es {
				e := v.(map[string]any)["elem"].(map[string]any)
				r.installed[s["name"].(string)] = *r.now + time.Duration(e["timeout"].(float64))*time.Second
			}
		}
		return m, nil
	}
	c.guard = &RuntimeGuard{journal: j, reader: &GuardReader{namespace: c.namespace, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return r.native(), nil }}}
	// Establish an actual rendered guard before charging work.
	if err = c.installActive(context.Background(), entries); err != nil {
		t.Fatal(err)
	}

	if canonical {
		for _, m := range materials {
			if m.Manifest.BGP != nil {
				if c.active[m.Manifest.ConnectionID].Delivery.ID != uuid.Nil {
					t.Fatal("fixture preseeded BGP delivery")
				}
				if err := c.rememberAppliedBGPDelivery(context.Background(), m.RuntimeDelivery, m.Policy.Hash, func() bool { return true }); err != nil {
					t.Fatal("ordinary successful BGP publication seam", err)
				}
			}
		}
	}
	c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error {
		r.charge("native_proof", 250*time.Millisecond)
		return nil
	}
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
		r.charge("native_status", 800*time.Millisecond)
		if r.phase == "heartbeat" {
			r.heartbeatSamples++
		}
		return [2]string{"up", "up"}
	}
	return r
}

type renewalTelemetryLease struct{ rig *renewalCycleRig }

func (l renewalTelemetryLease) RenewIPsecLease(_ context.Context, _ uuid.UUID, req RuntimeLeaseRequest) (RuntimeLease, error) {
	if req.Nonce == "" || l.rig.nonces[req.Nonce] {
		return RuntimeLease{}, ErrRuntimeController
	}
	l.rig.nonces[req.Nonce] = true
	if l.rig.phase == "maintenance" {
		l.rig.leases++
		l.rig.charge("fresh_cp", 100*time.Millisecond)
	} else {
		l.rig.telemetryNonces++
		l.rig.charge("telemetry_cp", 100*time.Millisecond)
	}
	return RuntimeLease{RuntimeLeaseRequest: req, TTLMS: 60000}, nil
}
func (r *renewalCycleRig) charge(stage string, d time.Duration) {
	*r.now += d
	r.charged[stage] += d
	if end, ok := r.installed[guardLeaseName(r.target)]; ok && *r.now >= end && r.firstLapse == 0 {
		r.firstLapse = end
		var env map[string]any
		json.Unmarshal(r.native(), &env)
		for _, o := range env["nftables"].([]any) {
			if set, ok := o.(map[string]any)["set"].(map[string]any); ok && set["name"] == guardLeaseName(r.target) {
				r.expiryEmpty = len(set["elem"].([]any)) == 0
			}
		}
	}
}
func (r *renewalCycleRig) native() []byte {
	var env map[string]any
	json.Unmarshal(r.expected, &env)
	for _, o := range env["nftables"].([]any) {
		s, ok := o.(map[string]any)["set"].(map[string]any)
		if !ok {
			continue
		}
		es, ok := s["elem"].([]any)
		if !ok {
			continue
		}
		remaining := r.installed[s["name"].(string)] - *r.now
		if remaining <= 0 {
			s["elem"] = []any{}
			continue
		}
		for _, v := range es {
			v.(map[string]any)["elem"].(map[string]any)["expires"] = int64((remaining + time.Second - 1) / time.Second)
		}
	}
	raw, _ := json.Marshal(env)
	return raw
}
func (r *renewalCycleRig) heartbeat(t *testing.T) {
	t.Helper()
	before := map[uuid.UUID]*PermitLeaseAuthority{}
	for id, a := range r.c.active {
		before[id] = a.Authority
	}
	nativeBefore := map[string]time.Duration{}
	for k, v := range r.installed {
		nativeBefore[k] = v
	}
	samples := r.heartbeatSamples
	r.phase = "heartbeat"
	_, err := r.c.RefreshIPsecActiveRecovery(context.Background())
	r.phase = ""
	if err != nil {
		t.Fatalf("heartbeat at %s: %v", *r.now, err)
	}
	if r.heartbeatSamples-samples != 2 {
		t.Fatalf("expected two healthy real static heartbeat samples, got %d", r.heartbeatSamples-samples)
	}
	for id, a := range r.c.active {
		if a.Authority != before[id] {
			t.Fatal("heartbeat promoted telemetry authority")
		}
	}
	if !reflect.DeepEqual(nativeBefore, r.installed) {
		t.Fatal("heartbeat renewed installed timeout")
	}
	r.heartbeatOK++
	if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal("inactive refresh", err)
	}
}
func (r *renewalCycleRig) fresh(t *testing.T, a runtimeActive) *PermitLeaseAuthority {
	t.Helper()
	x := &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
	req, err := x.Begin(a.Identity)
	if err != nil || r.nonces[req.Nonce] {
		t.Fatal("nonce authority", err)
	}
	r.nonces[req.Nonce] = true
	r.charge("fresh_cp", 100*time.Millisecond)
	if err = x.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal("fresh CP response", err)
	}
	r.leases++
	t.Logf("fresh lease #%d target=%t requestStart=%s deadline=%s", r.leases, a.Entry.Allocation.ConnectionID == r.target, x.started, x.deadline)
	return x
}
func (r *renewalCycleRig) apply(t *testing.T, index int) error {
	t.Helper()
	e := r.entries[index]
	a := r.c.active[e.Allocation.ConnectionID]
	// These are the unchanged, already-active full-Apply guard/renewal seams.
	if e.ContractVersion == 2 && (!r.shortcut || !r.c.recoveryUnchangedActive(context.Background(), e, a.Environment, a.Identity.PolicyHash, a.Grants)) {
		if err := r.c.installActive(context.Background(), r.entries); err != nil {
			return fmt.Errorf("static guard fallback: %w", err)
		}
	}
	fresh := r.fresh(t, a)
	if err := r.c.proveCurrent(context.Background(), e, a.Environment); err != nil {
		t.Fatal(err)
	}
	if e.ContractVersion == 3 {
		old := a.Authority
		if err := r.c.reconcileActiveBGP(context.Background(), r.entries); err != nil {
			return fmt.Errorf("ordinary BGP reconciliation: %w", err)
		}
		if r.c.active[e.Allocation.ConnectionID].Authority != old {
			t.Fatal("BGP old authority changed before RIB reconciliation")
		}
	} else {
		r.c.observeRecovery(context.Background(), e)
	}
	a.Authority = fresh
	r.c.active[e.Allocation.ConnectionID] = a
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		return fmt.Errorf("ordinary commit: %w", err)
	}
	r.charge("observe_report_ack", 600*time.Millisecond)
	return nil
}
func TestFiveProviderRenewalDeadline(t *testing.T) {
	for _, mode := range []struct {
		name               string
		validate, shortcut bool
	}{
		{"frozen", true, false}, {"skip_validate_only", false, false},
		{"static_continuity_only", true, true}, {"both", false, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			r := newRenewalCycleRigInput(t, true)
			r.shortcut = mode.shortcut
			defer func() {
				t.Logf("elapsed=%s firstTGWExpiry=%s nativeMemberEmpty=%t successfulHeartbeatCallbacks=%d actualStaticSamples=%d telemetryNoncesDiscarded=%d freshApplyCPNonces=%d work=%v", *r.now, r.firstLapse, r.expiryEmpty, r.heartbeatOK, r.heartbeatSamples, r.telemetryNonces, r.leases, r.charged)
			}()
			// Begin immediately after the TGW nonce is accepted; its post-lease commit
			// remains charged. The CP logical order after target444a is
			// 8856(BGP),94335(static),9d9(BGP),163d(BGP),444a(static).
			// Fixture allocation UUIDs remain genuine; these indices pin that exact type/order.
			a := r.c.active[r.target]
			a.Authority = r.fresh(t, a)
			r.c.active[r.target] = a
			if err := r.c.installActive(context.Background(), r.entries); err != nil {
				t.Fatal(err)
			}
			r.charge("observe_report_ack", 600*time.Millisecond)
			for _, index := range []int{1, 4, 0} {
				r.heartbeat(t)
				if err := r.apply(t, index); err != nil {
					if r.firstLapse == 0 || !r.expiryEmpty {
						t.Fatal(err)
					}
					t.Logf("expected ordinary refusal after already measured native expiry: %v", err)
					break
				}
			}
			r.heartbeat(t) // owner-loop status before discovery
			if mode.validate {
				if err := r.c.reconcileActiveBGP(context.Background(), r.entries); err != nil {
					t.Fatal(err)
				}
				if err := r.c.installActive(context.Background(), r.entries); err != nil {
					t.Fatal(err)
				}
			}
			for _, index := range []int{2, 3} {
				if r.firstLapse != 0 {
					break
				}
				r.heartbeat(t)
				if err := r.apply(t, index); err != nil {
					if r.firstLapse == 0 || !r.expiryEmpty {
						t.Fatal(err)
					}
					t.Logf("expected ordinary refusal after already measured native expiry: %v", err)
					break
				}
			}
			if r.firstLapse != 0 {
				if !r.expiryEmpty || r.heartbeatSamples == 0 || r.telemetryNonces != r.heartbeatSamples {
					t.Fatal("missing genuine native expiry/healthy telemetry causal contrast")
				}
				t.Logf("expected legacy causal RED: healthy TGW rendered permit expired before repeat commit at %s", r.firstLapse)
				return
			}
			t.Fatal("legacy contrast unexpectedly avoided expiry under unchanged high-cost seams")
		})
	}
}

// Unlike the earlier seam-only fixture, every maintenance input is valid normal
// authenticated material, and the current entry is exactly its locally completed
// form. Neither a material validator nor native qualification is bypassed.
func renewalCanonicalMaterials(t *testing.T, c *RuntimeController, entries []RuntimeJournalEntry) ([]RuntimeJournalEntry, []RuntimeMaterial) {
	t.Helper()
	materials := make([]RuntimeMaterial, len(entries))
	for n, old := range entries {
		m := runtimeMaterialFixture()
		m.ID, m.DesiredRevision = old.DeliveryID, old.Engines[0].Binding.DesiredRevision
		m.Manifest.OrgID, m.Manifest.NodeID, m.Manifest.SiteID, m.Manifest.ConnectionID = c.config.OrgID, c.config.GatewayID, old.SiteID, old.Allocation.ConnectionID
		m.Manifest.DesiredRevision, m.Manifest.ConfigurationRevision = m.DesiredRevision, old.Engines[0].Binding.ConfigurationRevision
		m.Manifest.LocalPrefixes, m.Manifest.RemotePrefixes = []string{}, []string{}
		for _, p := range old.Engines[0].LocalPrefixes {
			m.Manifest.LocalPrefixes = append(m.Manifest.LocalPrefixes, p.String())
		}
		for _, p := range old.Engines[0].RemotePrefixes {
			m.Manifest.RemotePrefixes = append(m.Manifest.RemotePrefixes, p.String())
		}
		one := 1
		if old.ContractVersion == 3 {
			m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
			m.Manifest.BGP = old.BGP
			m.Manifest.BGPVersion = &one
		} else {
			m.Manifest.RecoveryVersion = &one
		}
		for i, v := range old.Engines {
			inside := old.Allocation.Tunnels[i].InsideAddress
			m.Manifest.Tunnels[i] = RuntimeTunnel{ID: v.TunnelID, Slot: i + 1, SecretRevision: v.SecretRevision, LinkName: KernelTunnelName(v.TunnelID), XFRMID: v.XFRMID, ReqID: v.XFRMID, OutsideAddress: v.RemoteAddress.String(), InsideCIDR: inside.Masked().String(), CustomerInsideAddress: inside.Addr().String(), CloudInsideAddress: inside.Masked().Addr().Next().Next().String(), RouteTable: 254, RouteProtocol: 242, RouteMetric: uint32(50001 + i), Selected: old.ContractVersion != 3 && i == 0}
			m.Secrets[i] = RuntimeSecret{TunnelID: v.TunnelID, Revision: v.SecretRevision, PSK: "Synthetic_PSK_123"}
		}
		runtimeReseal(&m)
		e, grants, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, old.Allocation.Namespace)
		if err != nil {
			t.Fatal("normal maintenance material", err)
		}
		e.Phase, e.Observed, e.Allocation.Generation = old.Phase, old.Observed, old.Allocation.Generation
		for i := range e.Allocation.Tunnels {
			e.Allocation.Tunnels[i].Alias = old.Allocation.Tunnels[i].Alias
			e.Engines[i].LocalAddress = c.active[old.Allocation.ConnectionID].Environment.Underlays[i].LocalAddress
		}
		e.Recovery, e.BGPRoutes = old.Recovery, old.BGPRoutes
		if e.ContractVersion == 3 {
			p := processStateFixture(t).BGPProcess
			p.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g1")
			p.Namespace = e.Allocation.Namespace
			p.Stage = "ready"
			p.Children = []bgpengine.ChildIdentity{{Name: "zebra", PID: 111, StartTicks: 5, Executable: bgpengine.FileIdentity{Device: 1, Inode: 100, Mode: 0755}}, {Name: "bgpd", PID: 112, StartTicks: 6, Executable: bgpengine.FileIdentity{Device: 1, Inode: 101, Mode: 0755}}}
			for i, name := range []string{"bgpd.pid", "zebra.pid", "bgpd.vty", "zebra.vty", "zserv.api"} {
				mode := os.FileMode(0600)
				if i >= 2 {
					mode |= os.ModeSocket
				}
				p.Files = append(p.Files, bgpengine.NamedFileIdentity{Name: name, File: bgpengine.FileIdentity{Device: 1, Inode: uint64(i + 10), Mode: uint32(mode)}})
			}
			sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Name < p.Files[j].Name })
			e.BGPProcess = p
		}
		a := c.active[old.Allocation.ConnectionID]
		a.Entry, a.Delivery, a.Grants = e, m.RuntimeDelivery, grants
		if e.ContractVersion == 3 {
			a.Delivery = RuntimeDelivery{}
		}
		a.Identity = PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding, PolicyHash: m.Policy.Hash}
		c.active[e.Allocation.ConnectionID] = a
		entries[n], materials[n] = e, m
	}
	return entries, materials
}
