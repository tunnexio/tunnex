package ipsec

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fqdnTurnoverConflict struct{}

func (fqdnTurnoverConflict) Error() string                  { return "conflict" }
func (fqdnTurnoverConflict) IPsecLeaseFailureStage() string { return "http_409_conflict" }

type fqdnTurnoverClient struct {
	base     RuntimeLeaseClient
	material RuntimeMaterial
	target   uuid.UUID
	oldHash  string
	fetched  int
	requests []RuntimeLeaseRequest
	mutate   func(*RuntimeLease)
}

func (c *fqdnTurnoverClient) IPsecMaterial(_ context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	if id != c.target || rev != c.material.DesiredRevision {
		return RuntimeMaterial{}, ErrRuntimeController
	}
	c.fetched++
	return c.material, nil
}
func (c *fqdnTurnoverClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	if id == c.target {
		c.requests = append(c.requests, q)
		if q.PolicyHash == c.oldHash {
			return RuntimeLease{}, fqdnTurnoverConflict{}
		}
		if q.PolicyHash != c.material.Policy.Hash || !reflect.DeepEqual(q.FQDNGrants, c.material.Policy.FQDNGrants) {
			return RuntimeLease{}, ErrRuntimeController
		}
	}
	out, err := c.base.RenewIPsecLease(ctx, id, q)
	if id == c.target {
		for _, g := range q.FQDNGrants {
			out.FQDNPermits = append(out.FQDNPermits, RuntimeFQDNPermit{GrantDigest: runtimeFQDNGrantDigest(g), TTLMS: 25000})
		}
		if c.mutate != nil {
			c.mutate(&out)
		}
	}
	return out, err
}
func fqdnExpiryTurnoverRig(t *testing.T, static ...bool) (*renewalCycleRig, *fqdnTurnoverClient) {
	t.Helper()
	var r *renewalCycleRig
	var target uuid.UUID
	if len(static) > 0 && static[0] {
		r, target = desktopStaticRenewalRig(t)
	} else {
		r, target, _, _ = desktopBGPRenewalRig(t, true)
	}
	r.target = target
	a := r.c.active[r.target]
	var m RuntimeMaterial
	for _, item := range r.materials {
		if item.Manifest.ConnectionID == r.target {
			m = item
		}
	}
	base, _, _ := desktopStaticFQDNFixture(t)
	f := base.Policy.FQDNGrants[0]
	// Keep the exact desktop source, device and public key from the production-shaped fixture.
	f.Destination = netip.PrefixFrom(a.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32).String()
	f.ResolverSourceAddress = ""
	f.SelectedSiteID = m.Manifest.SiteID.String()
	f.SelectedGatewayID = m.Manifest.NodeID.String()
	f.ConnectionID = r.target.String()
	f.ConfigurationRevision = m.Manifest.ConfigurationRevision
	f.ExpiresAt = time.Now().UTC().Add(30 * time.Second)
	m.Policy.FQDNPolicyVersion = 2
	m.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
	_, grants, err := runtimeMaterialEntry(m, r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	grants, err = r.c.observeDesktopGrants(context.Background(), grants)
	if err != nil {
		t.Fatal(err)
	}
	a.Grants = grants
	a.FQDNLeaseDescriptors = runtimeFQDNLeaseDescriptors(m.Policy)
	p := &nodepolicy.Compiled{Version: 9, NodeID: m.Manifest.NodeID.String(), Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{{SrcIP: f.Source, DstCIDR: f.Destination, Protocol: f.Protocol, PortLow: int(f.PortLow), PortHigh: int(f.PortHigh), RuleID: f.RuleID, FQDNManaged: true}}, FQDNGenerations: []nodepolicy.FQDNGeneration{{ResourceID: f.ResourceID, Name: f.Name, Generation: f.Generation, ResolverConfigID: f.ResolverConfigID, ResolverConfigVersion: f.ResolverConfigVersion, Answers: []string{f.Destination}}}, DNSResolverProfiles: []nodepolicy.DNSResolverProfile{{ContextConfigID: f.ResolverConfigID, ContextConfigVersion: f.ResolverConfigVersion, ProfileID: f.ResolverProfileID, ZoneSuffixes: []string{f.ResolverMatchSuffix}, IPsecPath: nodepolicy.DNSResolverIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision, SourceAddress: f.ResolverSourceAddress}}}}
	p.Allow[0].SrcIP = strings.TrimSuffix(f.Source, "/32")
	p.Allow[0].SrcDeviceID = f.DeviceID
	p.Allow[0].FQDNDeviceID = f.DeviceID
	p.FQDNGenerations[0].ApplicationIPsecPath = &nodepolicy.FQDNApplicationIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}
	p.DNSResolverProfiles[0].IPsecPath = nodepolicy.DNSResolverIPsecPath{}
	p.DNSResolverProfiles[0].StaticRecords = []nodepolicy.DNSStaticRecord{{Name: f.Name, Type: "CNAME", Value: "backend.example.net", TTL: 30}}
	r.c.config.FQDNPolicy = &RuntimeFQDNPolicySource{}
	r.c.config.FQDNPolicy.CommittedPolicy(p)
	r.c.qualification.fqdnExpiry = true
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			t.Log(d.Operation, d.Stage)
		}
	}
	auth := maintenanceAuthority(r)()
	q, err := auth.BeginFQDN(a.Identity, runtimeFQDNLeaseKeys(m.Policy))
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: runtimeFQDNGrantDigest(f), TTLMS: 25000}}}); err != nil {
		t.Fatal(err)
	}
	a.Authority = auth
	r.c.active[r.target] = a
	if err = r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("initial exact FQDN guard", err)
	}
	next := m
	next.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
	next.Policy.FQDNGrants[0].ExpiresAt = f.ExpiresAt.Add(15 * time.Second)
	next.Policy.Hash = strings.Repeat("e", 64)
	client := &fqdnTurnoverClient{base: r.c.client, material: next, target: r.target, oldHash: a.Identity.PolicyHash}
	r.c.client = client
	r.phase = "maintenance"
	return r, client
}
func TestPriorityFQDNExpiryOnlyTurnoverFreshMaterialAtomic(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	before := r.c.active[r.target]
	denied := false
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		for _, c := range in.Connections {
			if c.PrefixOnly || (c.ID == r.target && len(c.Grants) == 0) {
				denied = true
				t.Log("denied tuple", c.ID, c.PrefixOnly, len(c.Grants), "target", r.target)
			}
		}
		m, err := replace(ctx, in)
		if err == nil {
			for id := range r.c.active {
				for _, name := range []string{guardLeaseName(id), guardReplyLeaseName(id), guardSALeaseName(id)} {
					if r.installed[name] <= *r.now {
						t.Errorf("empty or expired existing permit set %s", name)
					}
				}
			}
		}
		return m, err
	}
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err != nil {
		t.Fatal("fresh expiry-only rollover refused", err)
	}
	after := r.c.active[r.target]
	if denied || client.fetched != 1 || len(client.requests) != 2 || client.requests[0].Nonce == client.requests[1].Nonce || after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == before.Authority || !reflect.DeepEqual(after.FQDNLeaseDescriptors, client.material.Policy.FQDNGrants) {
		t.Fatal("lost atomic fresh authorization", denied, client.fetched, len(client.requests))
	}
	for _, g := range after.Grants {
		if g.FQDNManaged {
			if _, err := after.Authority.RemainingFQDNForApply(after.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
				t.Fatal("fresh desktop membership lacks matching CP-issued permit", err)
			}
			if _, present := r.installed[guardFQDNSetName(g)]; !present {
				t.Fatal("new FQDN timed set was silently dropped")
			}
		}
	}
	if !reflect.DeepEqual(after.Entry, before.Entry) || !reflect.DeepEqual(after.Delivery, before.Delivery) {
		t.Fatal("expiry-only turnover changed transport")
	}
	for id, a := range r.c.active {
		if (id == r.target && r.applicationDenied[id]) || a.Authority == nil {
			t.Fatal("unrelated ordinary authority denied", id)
		}
	}
	// The committed ordinary policy was not republished: identical wire generation,
	// tuple and ordinary policy survived while only the private expiry/hash changed.
	if before.Grants[len(before.Grants)-1].FQDN.Generation != after.Grants[len(after.Grants)-1].FQDN.Generation {
		t.Fatal("fixture changed generation")
	}
}
func TestPriorityFQDNExpiryTurnoverRejectsFreshLeaseMismatch(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	client.mutate = func(l *RuntimeLease) { l.Nonce = "wrong" }
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err == nil {
		t.Fatal("mismatched fresh nonce authorized")
	}
	if len(r.c.active) != 0 {
		t.Fatal("failed fresh proof preserved authority")
	}
}
func TestPriorityFQDNExpiryTurnoverRejectsChangedAnswer(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	client.material.Policy.FQDNGrants[0].Destination = netip.PrefixFrom(netip.MustParsePrefix(client.material.Policy.FQDNGrants[0].Destination).Addr().Next(), 32).String()
	if err := r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil); err == nil {
		t.Fatal("expiry-only handoff accepted changed answer")
	}
	if len(r.c.active) != 0 {
		t.Fatal("changed current policy did not fail closed")
	}
}

func TestPriorityFQDNExpiryTurnoverRejectsUnsafeFreshMaterial(t *testing.T) {
	for name, mutate := range map[string]func(*renewalCycleRig, *fqdnTurnoverClient){
		"source": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].Source = "10.99.0.8/32"
		},
		"rule": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].RuleID = uuid.NewString()
		},
		"config": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].ResolverConfigVersion++
		},
		"fresh-lease-hash": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.mutate = func(l *RuntimeLease) { l.PolicyHash = strings.Repeat("f", 64) }
		},
		"device": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].DeviceID = uuid.NewString()
		},
		"key": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].PublicKey = desktopGrantFixture().PublicKey + "invalid"
		},
		"delivery": func(_ *renewalCycleRig, c *fqdnTurnoverClient) { c.material.ID = uuid.New() },
		"revision": func(_ *renewalCycleRig, c *fqdnTurnoverClient) { c.material.DesiredRevision++ },
		"expired-expiry": func(_ *renewalCycleRig, c *fqdnTurnoverClient) {
			c.material.Policy.FQDNGrants[0].ExpiresAt = time.Now().Add(-time.Second)
		},
		"missing-current-policy": func(r *renewalCycleRig, _ *fqdnTurnoverClient) { r.c.config.FQDNPolicy.CommittedPolicy(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			r, c := fqdnExpiryTurnoverRig(t)
			mutate(r, c)
			_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
			if len(r.c.active) != 0 {
				t.Fatal("unsafe refresh retained authority")
			}
		})
	}
}
func TestPriorityFQDNExpiryTurnoverDoesNotReviveExpiredOrdinaryAuthority(t *testing.T) {
	r, c := fqdnExpiryTurnoverRig(t)
	a := r.c.active[r.target]
	a.Authority.deadline = *r.now
	r.c.active[r.target] = a
	_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
	if _, ok := r.c.active[r.target]; ok || c.fetched != 0 {
		t.Fatal("expired original authority used as bridge")
	}
}

func TestNormalPageFQDNExpiryOnlyTurnoverFreshMaterialAtomic(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	before := r.c.active[r.target]
	denied := false
	replace := r.c.replace
	r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		for _, owner := range in.Connections {
			if owner.ID == r.target && (owner.PrefixOnly || len(owner.Grants) == 0) {
				denied = true
			}
		}
		return replace(ctx, in)
	}
	result, err := r.c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{client.material}, maintenanceAuthority(r), func() bool { return true })
	after, retained := r.c.active[r.target]
	t.Logf("normal page results=%d err=%v denied=%t targetretained=%t materialfetches=%d leasecalls=%d", len(result), err, denied, retained, client.fetched, len(client.requests))
	if err != nil || len(result) != 1 || denied || !retained || after.Identity.PolicyHash != client.material.Policy.Hash || after.Authority == before.Authority {
		t.Fatal("routine normal-page expiry rollover lost finite ordinary authority")
	}
}

type expiryDuringMaterialClient struct {
	*fqdnTurnoverClient
	rig *renewalCycleRig
}

func (c expiryDuringMaterialClient) IPsecMaterial(ctx context.Context, id uuid.UUID, rev int64) (RuntimeMaterial, error) {
	material, err := c.fqdnTurnoverClient.IPsecMaterial(ctx, id, rev)
	*c.rig.now = c.rig.c.active[c.rig.target].Authority.deadline + time.Millisecond
	return material, err
}
func TestPriorityFQDNExpiryTurnoverRejectsBridgeExpiredDuringFetch(t *testing.T) {
	r, client := fqdnExpiryTurnoverRig(t)
	r.c.client = expiryDuringMaterialClient{client, r}
	_ = r.c.renewActiveIPsecRuntimeObserved(context.Background(), maintenanceAuthority(r), func() bool { return true }, nil, nil)
	_, retained := r.c.active[r.target]
	t.Logf("materialfetches=%d leasecalls=%d targetretained=%t", client.fetched, len(client.requests), retained)
	if client.fetched != 1 || len(client.requests) != 2 || retained {
		t.Fatal("fresh lease revived target after original bridge expired during material fetch")
	}
}
