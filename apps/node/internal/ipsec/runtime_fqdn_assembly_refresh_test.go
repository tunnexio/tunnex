package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

type assemblyRefreshClient struct {
	base     *fqdnCadenceSubsetClient
	target   uuid.UUID
	material func(*RuntimeMaterial)
	fetched  func()
	lease    func(*RuntimeLease)
	events   *[]string
}

func (c *assemblyRefreshClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	m, err := c.base.IPsecMaterial(ctx, id, rev)
	if err != nil {
		return m, err
	}
	// The transport response owns its slices; clearing response secrets must not
	// mutate the server-side fixture or an earlier authenticated material.
	raw, err := json.Marshal(m)
	if err != nil {
		return RuntimeMaterial{}, err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return RuntimeMaterial{}, err
	}
	*c.events = append(*c.events, "material")
	if id == c.target {
		if c.material != nil {
			c.material(&m)
		}
		if c.fetched != nil {
			c.fetched()
		}
	}
	return m, nil
}
func (c *assemblyRefreshClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	out, err := c.base.RenewIPsecLease(ctx, id, q)
	*c.events = append(*c.events, "lease")
	if id == c.target && c.lease != nil {
		c.lease(&out)
	}
	return out, err
}
func assemblyClone(in map[uuid.UUID]runtimeActive) map[uuid.UUID]runtimeActive {
	out := map[uuid.UUID]runtimeActive{}
	for id, a := range in {
		out[id] = cloneMaintenanceActive(a)
	}
	return out
}

type assemblyRefreshRig struct {
	r                                           *renewalCycleRig
	client                                      *assemblyRefreshClient
	prior, candidates, staged, required, cutoff map[uuid.UUID]runtimeActive
	materials                                   []maintenanceItem
	ids                                         []uuid.UUID
	events                                      []string
	journal                                     []byte
	deadlines                                   map[*PermitLeaseAuthority]time.Duration
	fqdnDeadlines                               map[*PermitLeaseAuthority]map[string]time.Duration
}

func newAssemblyRefreshRig(t *testing.T) *assemblyRefreshRig {
	t.Helper()
	r, base := fqdnMultiOwnerCadenceRig(t)
	x := &assemblyRefreshRig{r: r, prior: assemblyClone(r.c.active), deadlines: map[*PermitLeaseAuthority]time.Duration{}, fqdnDeadlines: map[*PermitLeaseAuthority]map[string]time.Duration{}}
	x.candidates = assemblyClone(x.prior)
	for id, a := range x.candidates {
		// Ordinary maintenance has already obtained a new, bounded candidate lease.
		// It is not published and may still name the earlier FQDN expiry.
		auth := maintenanceAuthority(r)()
		q, err := auth.BeginFQDN(a.Identity, runtimeFQDNLeaseKeys(base.old[id].Policy))
		if err != nil {
			t.Fatal(err)
		}
		permits := []RuntimeFQDNPermit{}
		for _, f := range a.FQDNLeaseDescriptors {
			permits = append(permits, RuntimeFQDNPermit{GrantDigest: runtimeFQDNGrantDigest(f), TTLMS: 23000})
		}
		if err = auth.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: permits}); err != nil {
			t.Fatal(err)
		}
		a.Authority = auth
		x.candidates[id] = a
		if len(a.FQDNLeaseDescriptors) > 0 {
			x.ids = append(x.ids, id)
		}
		x.materials = append(x.materials, maintenanceItem{RuntimeDelivery: a.Delivery, Entry: a.Entry, Grants: append([]GuardGrant(nil), a.Grants...), FQDNLeaseDescriptors: append([]RuntimeFQDNGrant(nil), a.FQDNLeaseDescriptors...), PolicyHash: a.Identity.PolicyHash})
	}
	sort.Slice(x.ids, func(i, j int) bool { return x.ids[i].String() < x.ids[j].String() })
	if len(x.ids) != 2 {
		t.Fatal("expected two static FQDN owners")
	}
	x.staged, x.required, x.cutoff = assemblyClone(x.candidates), assemblyClone(x.candidates), assemblyClone(x.candidates)
	for _, m := range []map[uuid.UUID]runtimeActive{x.prior, x.candidates} {
		for _, a := range m {
			x.deadlines[a.Authority] = a.Authority.deadline
			copy := map[string]time.Duration{}
			for k, v := range a.Authority.fqdnDeadlines {
				copy[k] = v
			}
			x.fqdnDeadlines[a.Authority] = copy
		}
	}
	var err error
	x.journal, err = os.ReadFile(filepath.Join(r.c.journal.dir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.charge("same_answer_publication", 5*time.Second)
	x.client = &assemblyRefreshClient{base: base, target: x.ids[1], events: &x.events}
	r.c.client = x.client
	prove := r.c.prove
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		x.events = append(x.events, "native")
		return prove(ctx, e, env)
	}
	return x
}
func (x *assemblyRefreshRig) checkActiveUntouched(t *testing.T) {
	t.Helper()
	if !reflect.DeepEqual(x.r.c.active, x.prior) {
		t.Fatal("active authority changed before atomic installation")
	}
	raw, err := os.ReadFile(filepath.Join(x.r.c.journal.dir, "journal.json"))
	if err != nil || !reflect.DeepEqual(raw, x.journal) {
		t.Fatal("assembly refresh changed durable journal", err)
	}
	for auth, deadline := range x.deadlines {
		if auth.deadline != deadline || !reflect.DeepEqual(auth.fqdnDeadlines, x.fqdnDeadlines[auth]) {
			t.Fatal("original absolute permit deadline changed")
		}
	}
}
func (x *assemblyRefreshRig) call(ctx context.Context) error {
	return x.r.c.refreshFQDNAssemblyCandidates(ctx, maintenanceAuthority(x.r), func() bool { return true }, x.prior, x.candidates, x.staged, x.required, x.cutoff, x.materials)
}
func TestFQDNAssemblyRefreshStagesOnlyAfterFreshNonceAndNativeProof(t *testing.T) {
	x := newAssemblyRefreshRig(t)
	if err := x.call(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.checkActiveUntouched(t)
	if !reflect.DeepEqual(x.candidates, x.staged) || !reflect.DeepEqual(x.candidates, x.required) {
		t.Fatal("candidate maps diverged")
	}
	for _, id := range x.ids {
		a, old := x.candidates[id], x.prior[id]
		if a.Authority == old.Authority || a.Identity.PolicyHash == old.Identity.PolicyHash || !a.FQDNLeaseDescriptors[0].ExpiresAt.After(old.FQDNLeaseDescriptors[0].ExpiresAt) {
			t.Fatal("missing fresh candidate authority")
		}
		if !reflect.DeepEqual(a.Entry, old.Entry) || !reflect.DeepEqual(a.Delivery, old.Delivery) {
			t.Fatal("expiry refresh changed immutable native intent")
		}
		if _, ok := x.cutoff[id]; ok {
			t.Fatal("refreshed candidate retained an extra cutoff retry")
		}
		if _, err := a.Authority.RemainingFQDNForApply(a.Identity, runtimeFQDNGrantDigest(a.FQDNLeaseDescriptors[0]), 5*time.Second); err != nil {
			t.Fatal("new exact grant has no bounded permit", err)
		}
	}
	if !reflect.DeepEqual(x.events, []string{"material", "material", "lease", "lease", "native", "native"}) {
		t.Fatalf("native proof did not follow fresh nonces: %v", x.events)
	}
}
func TestFQDNAssemblyRefreshRefusalIsAtomic(t *testing.T) {
	for _, mode := range []string{"changed_tuple", "changed_key", "changed_ordinary", "changed_transport", "revoked", "wrong_nonce", "wrong_hash", "fetch_deadline", "parent_cancel", "original_expiry", "native_failure", "desktop_postproof_failure"} {
		t.Run(mode, func(t *testing.T) {
			x := newAssemblyRefreshRig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "changed_tuple":
				x.client.material = func(m *RuntimeMaterial) {
					f := &m.Policy.FQDNGrants[0]
					f.Destination = netip.PrefixFrom(netip.MustParsePrefix(f.Destination).Addr().Next(), 32).String()
				}
			case "changed_key":
				x.client.material = func(m *RuntimeMaterial) {
					m.Policy.FQDNGrants[0].PublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
				}
			case "changed_ordinary":
				x.client.material = func(m *RuntimeMaterial) {
					m.Policy.Grants = append(m.Policy.Grants, RuntimeGrant{Source: m.Manifest.LocalPrefixes[0], Destination: m.Policy.FQDNGrants[0].Destination, Protocol: "tcp", PortLow: 81, PortHigh: 81, RuleID: uuid.NewString()})
				}
			case "changed_transport":
				x.client.material = func(m *RuntimeMaterial) { m.Manifest.Tunnels[0].OutsideAddress = "203.0.113.123" }
			case "revoked":
				x.client.material = func(m *RuntimeMaterial) { m.Policy.FQDNGrants = nil; m.Policy.FQDNPolicyVersion = 0 }
			case "wrong_nonce":
				x.client.lease = func(l *RuntimeLease) { l.Nonce = "not-the-current-request" }
			case "wrong_hash":
				x.client.lease = func(l *RuntimeLease) { l.PolicyHash = stringDigest([]byte("foreign-policy")) }
			case "fetch_deadline":
				x.client.fetched = func() { x.r.charge("slow_material", 2*time.Second) }
			case "parent_cancel":
				x.client.fetched = cancel
			case "original_expiry":
				x.client.fetched = func() { *x.r.now = x.prior[x.ids[0]].Authority.deadline }
			case "native_failure":
				original := x.r.c.prove
				x.r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
					if e.Allocation.ConnectionID == x.ids[1] {
						return ErrRuntimeController
					}
					return original(ctx, e, env)
				}
			case "desktop_postproof_failure":
				original := x.r.c.desktopObserve
				x.r.c.desktopObserve = func(ctx context.Context, g []GuardGrant) ([]GuardGrant, error) {
					if x.client.base.requests >= 2 {
						return nil, ErrRuntimeController
					}
					return original(ctx, g)
				}
			}
			before := assemblyClone(x.candidates)
			beforeMaterials := append([]maintenanceItem(nil), x.materials...)
			if err := x.call(ctx); err == nil {
				t.Fatal("unsafe refresh accepted")
			}
			x.checkActiveUntouched(t)
			if !reflect.DeepEqual(x.candidates, before) || !reflect.DeepEqual(x.staged, before) || !reflect.DeepEqual(x.required, before) || !reflect.DeepEqual(x.cutoff, before) || !reflect.DeepEqual(x.materials, beforeMaterials) {
				t.Fatal("failed later owner left partially updated candidates")
			}
		})
	}
}

// No newer normal publication means no new forwarding authority. The shared
// polling budget may wait briefly, but must preserve every original candidate.
func TestFQDNAssemblyRefreshUnchangedPublicationIsBounded(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_new_publication", true: "cancel_during_wait"}[cancelWait], func(t *testing.T) {
			x := newAssemblyRefreshRig(t)
			x.client.base.publishAt = *x.r.now + time.Hour
			before := assemblyClone(x.candidates)
			beforeMaterials := append([]maintenanceItem(nil), x.materials...)
			started := *x.r.now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waits := 0
			x.r.c.fqdnMaterialWait = func(waitCtx context.Context, delay time.Duration) error {
				waits++
				deadline, bounded := waitCtx.Deadline()
				if !bounded || time.Until(deadline) > 2*time.Second || delay <= 0 || delay > 250*time.Millisecond {
					t.Fatal("poll did not retain the shared two-second bounded context")
				}
				if cancelWait {
					cancel()
					return waitCtx.Err()
				}
				x.r.charge("unchanged_material_wait", delay)
				return waitCtx.Err()
			}
			err := x.call(ctx)
			if (err != nil) != cancelWait {
				t.Fatal("unchanged/cancelled polling result", err)
			}
			if waits < 1 || waits > 8 || *x.r.now-started >= 2*time.Second || x.client.base.requests != 0 {
				t.Fatal("polling exceeded budget or issued a nonce without newer material", waits, *x.r.now-started, x.client.base.requests)
			}
			for _, event := range x.events {
				if event != "material" {
					t.Fatal("unchanged material triggered authority/native work", x.events)
				}
			}
			x.checkActiveUntouched(t)
			if !reflect.DeepEqual(x.candidates, before) || !reflect.DeepEqual(x.staged, before) || !reflect.DeepEqual(x.required, before) || !reflect.DeepEqual(x.cutoff, before) || !reflect.DeepEqual(x.materials, beforeMaterials) {
				t.Fatal("bounded unchanged/cancelled poll mutated candidate collections")
			}
		})
	}
}
