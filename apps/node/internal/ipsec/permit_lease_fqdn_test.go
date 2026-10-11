package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

// Frozen independent descriptor bytes; neither producer nor consumer self-seals it.
const fqdnLeaseDescriptorGolden = `{"expires_at":"2026-10-11T12:00:30Z","resolver_source_address":"10.1.0.1","source":"10.1.0.2/32","destination":"10.2.0.3/32","protocol":"tcp","port_low":8080,"port_high":8080,"rule_id":"11111111-1111-4111-8111-111111111111","fqdn_managed":true,"resource_id":"22222222-2222-4222-8222-222222222222","name":"app.private.test","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resolver_config_id":"33333333-3333-4333-8333-333333333333","resolver_config_version":3,"selected_site_id":"44444444-4444-4444-8444-444444444444","selected_gateway_id":"55555555-5555-4555-8555-555555555555","resolver_profile_id":"66666666-6666-4666-8666-666666666666","resolver_match_suffix":"private.test","connection_id":"77777777-7777-4777-8777-777777777777","configuration_revision":1}`
const fqdnLeaseDescriptorDigestGolden = "c536d00baa7858437e8ad953576edaaabdd9ac7acdce4c71eb7abcb06b0f0d62"

func TestRuntimeFQDNLeaseDescriptorGolden(t *testing.T) {
	var g RuntimeFQDNGrant
	if json.Unmarshal([]byte(fqdnLeaseDescriptorGolden), &g) != nil {
		t.Fatal("golden decode")
	}
	raw, err := json.Marshal(g)
	if err != nil || string(raw) != fqdnLeaseDescriptorGolden || runtimeFQDNGrantDigest(g) != fqdnLeaseDescriptorDigestGolden {
		t.Fatal("API/node exact descriptor wire changed", err, string(raw))
	}
	for _, mutate := range []func(*RuntimeFQDNGrant){func(g *RuntimeFQDNGrant) { g.ExpiresAt = g.ExpiresAt.Add(time.Second) }, func(g *RuntimeFQDNGrant) { g.ResolverSourceAddress = "10.1.0.4" }, func(g *RuntimeFQDNGrant) { g.Generation = strings.Repeat("b", 64) }, func(g *RuntimeFQDNGrant) { g.PortHigh++ }, func(g *RuntimeFQDNGrant) { g.ResourceID = "88888888-8888-4888-8888-888888888888" }} {
		next := g
		mutate(&next)
		if runtimeFQDNGrantDigest(next) == fqdnLeaseDescriptorDigestGolden {
			t.Fatal("descriptor field omitted from identity")
		}
	}
}

func fqdnTestAuthority(t *testing.T, ttl int64) (*PermitLeaseAuthority, PermitLeaseIdentity, *time.Duration) {
	t.Helper()
	now := time.Duration(0)
	a := &PermitLeaseAuthority{elapsed: func() time.Duration { return now }}
	id := permitIdentity()
	q, e := a.BeginFQDN(id, []string{fqdnLeaseDescriptorDigestGolden})
	if e != nil {
		t.Fatal(e)
	}
	now = 5 * time.Second
	if e = a.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: fqdnLeaseDescriptorDigestGolden, TTLMS: ttl}}}); e != nil {
		t.Fatal(e)
	}
	return a, id, &now
}
func TestPermitLeaseFQDNPreRequestFenceIndependentOrdinaryAndZero(t *testing.T) {
	a, id, now := fqdnTestAuthority(t, 30000)
	d, e := a.RemainingFQDNForApply(id, fqdnLeaseDescriptorDigestGolden, 5*time.Second)
	if e != nil || d != 20*time.Second {
		t.Fatal("transport was not charged", d, e)
	}
	ordinary, e := a.RemainingForApply(id, 5*time.Second)
	if e != nil || ordinary != 50*time.Second {
		t.Fatal("ordinary shortened", ordinary, e)
	}
	*now = 31 * time.Second
	if _, e = a.RemainingFQDNForApply(id, fqdnLeaseDescriptorDigestGolden, time.Millisecond); e == nil {
		t.Fatal("expired grant renewed")
	}
	if _, e = a.RemainingForApply(id, time.Millisecond); e != nil {
		t.Fatal("selective expiry withdrew ordinary")
	}
	zero, identity, _ := fqdnTestAuthority(t, 0)
	if _, e = zero.RemainingFQDNForApply(identity, fqdnLeaseDescriptorDigestGolden, time.Millisecond); e == nil {
		t.Fatal("zero minted authority")
	}
	if _, e = zero.RemainingForApply(identity, time.Millisecond); e != nil {
		t.Fatal("zero withdrew ordinary")
	}
}
func TestPermitLeaseFQDNRejectsMissingDuplicateForeignAndWrongNonce(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "foreign", "negative", "too_long", "nonce", "identity", "late_ordinary"} {
		t.Run(name, func(t *testing.T) {
			now := time.Duration(0)
			a := &PermitLeaseAuthority{elapsed: func() time.Duration { return now }}
			id := permitIdentity()
			q, e := a.BeginFQDN(id, []string{fqdnLeaseDescriptorDigestGolden})
			if e != nil {
				t.Fatal(e)
			}
			r := PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: fqdnLeaseDescriptorDigestGolden, TTLMS: 30000}}}
			switch name {
			case "missing":
				r.FQDNPermits = nil
			case "duplicate":
				r.FQDNPermits = append(r.FQDNPermits, r.FQDNPermits[0])
			case "foreign":
				r.FQDNPermits[0].GrantDigest = strings.Repeat("b", 64)
			case "negative":
				r.FQDNPermits[0].TTLMS = -1
			case "too_long":
				r.FQDNPermits[0].TTLMS = 60001
			case "nonce":
				r.Nonce = strings.Repeat("c", 64)
			case "identity":
				r.Identity.DeliveryID = uuid.New()
			case "late_ordinary":
				now = 60 * time.Second
			}
			if a.Accept(r) == nil {
				t.Fatal("invalid proof accepted")
			}
			if _, e = a.RemainingForApply(id, time.Millisecond); e == nil {
				t.Fatal("refusal adopted ordinary authority")
			}
			if a.Accept(r) == nil {
				t.Fatal("refused attempt replayed")
			}
		})
	}
	a := &PermitLeaseAuthority{elapsed: func() time.Duration { return 0 }}
	for _, keys := range [][]string{{"bad"}, {fqdnLeaseDescriptorDigestGolden, fqdnLeaseDescriptorDigestGolden}} {
		if _, e := a.BeginFQDN(permitIdentity(), keys); e == nil {
			t.Fatal("bad expected keyset")
		}
	}
}
func TestPermitLeaseFQDNFailedRenewalDoesNotExtendOrDropOldDeadline(t *testing.T) {
	a, id, now := fqdnTestAuthority(t, 30000)
	*now = 10 * time.Second
	q, e := a.BeginFQDN(id, []string{fqdnLeaseDescriptorDigestGolden})
	if e != nil {
		t.Fatal(e)
	}
	if a.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000}) == nil {
		t.Fatal("missing evidence accepted")
	}
	if d, e := a.RemainingFQDNForApply(id, fqdnLeaseDescriptorDigestGolden, time.Second); e != nil || d != 19*time.Second {
		t.Fatal("old deadline changed", d, e)
	}
	*now = 9 * time.Second
	if _, e := a.RemainingFQDNForApply(id, fqdnLeaseDescriptorDigestGolden, time.Millisecond); e == nil {
		t.Fatal("backwards monotonic clock accepted")
	}
	*now = 10 * time.Second
	if _, e := a.RemainingForApply(id, time.Millisecond); e == nil {
		t.Fatal("clock refusal retained authority")
	}
}
func TestRuntimeFQDNMonotonicGrantIdentityAndWallSkewRendering(t *testing.T) {
	m, g, _ := v2FQDNFixture(t)
	key := runtimeFQDNGrantDigest(m.Policy.FQDNGrants[0])
	if key != guardFQDNGrantDigest(g) {
		t.Fatal("wire/renderer descriptor mismatch")
	}
	elapsed := time.Duration(0)
	a := &PermitLeaseAuthority{elapsed: func() time.Duration { return elapsed }}
	id := permitIdentity()
	q, e := a.BeginFQDN(id, []string{key})
	if e != nil {
		t.Fatal(e)
	}
	elapsed = 5 * time.Second
	if a.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: 30000}}}) != nil {
		t.Fatal("accept")
	}
	ordinary := g
	ordinary.FQDNManaged = false
	ordinary.FQDN = FQDNGrantBinding{}
	dns := ordinary
	dns.HostOrigin = true
	dns.Protocol = GuardUDP
	dns.PortLow = 53
	dns.PortHigh = 53
	in := GuardIntent{Connections: []GuardConnection{{PermitFor: 60 * time.Second, Grants: []GuardGrant{ordinary, g, dns}}}}
	remaining := func(_ uuid.UUID, g GuardGrant, budget time.Duration) (time.Duration, error) {
		return a.RemainingFQDNForApply(id, guardFQDNGrantDigest(g), budget)
	}
	// A node thirty seconds behind cannot mint a longer CP-issued duration.
	out := limitFQDNGuardIntent(in, g.FQDN.ExpiresAt.Add(-75*time.Second), 5*time.Second, remaining)
	if len(out.Connections[0].Grants) != 3 || out.Connections[0].Grants[1].FQDNPermitFor != 20*time.Second {
		t.Fatal("wall skew extended permission")
	}
	missing := limitFQDNGuardIntent(in, time.Now(), 5*time.Second, nil)
	if len(missing.Connections[0].Grants) != 2 || missing.Connections[0].Grants[0] != ordinary || missing.Connections[0].Grants[1] != dns {
		t.Fatal("missing proof is authority or withdrew ordinary/DNS")
	}
	elapsed = 26 * time.Second
	out = limitFQDNGuardIntent(in, g.FQDN.ExpiresAt.Add(-75*time.Second), 5*time.Second, remaining)
	if len(out.Connections[0].Grants) != 2 {
		t.Fatal("commit budget extended permission")
	}
}
func TestRuntimeFQDNLeaseV1ResponseOmission(t *testing.T) {
	raw, err := json.Marshal(RuntimeLease{TTLMS: 60000})
	if err != nil || strings.Contains(string(raw), "fqdn_permits") {
		t.Fatal("legacy wire changed")
	}
}

func permitIdentity() PermitLeaseIdentity { _, _, id := leaseFixture(); return id }

func TestRuntimeFQDNCommitCutoffPreservesIndependentAuthority(t *testing.T) {
	_, g, _ := v2FQDNFixture(t)
	key := guardFQDNGrantDigest(g)
	ordinary := g
	ordinary.FQDNManaged = false
	ordinary.FQDN = FQDNGrantBinding{}
	dns := ordinary
	dns.HostOrigin = true
	dns.Protocol = GuardUDP
	dns.PortLow = 53
	dns.PortHigh = 53
	for _, seconds := range []int64{6, 10, 11, 20} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			elapsed := time.Duration(0)
			id := permitIdentity()
			a := &PermitLeaseAuthority{elapsed: func() time.Duration { return elapsed }}
			keys := []string{key}
			q, e := a.BeginFQDN(id, keys)
			if e != nil {
				t.Fatal(e)
			}
			keys[0] = "changed caller storage"
			if e = a.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: seconds * 1000}}}); e != nil {
				t.Fatal(e)
			}
			in := GuardIntent{Connections: []GuardConnection{{PermitFor: 55 * time.Second, Grants: []GuardGrant{ordinary, g, dns}}}}
			out := limitFQDNGuardIntent(in, g.FQDN.ExpiresAt.Add(-time.Hour), 5*time.Second, func(_ uuid.UUID, g GuardGrant, b time.Duration) (time.Duration, error) {
				return a.RemainingFQDNForApply(id, guardFQDNGrantDigest(g), b)
			})
			want := 2
			if seconds >= 11 {
				want = 3
			}
			if len(out.Connections[0].Grants) != want {
				t.Fatal("cutoff", seconds, out)
			}
			// Charge the entire original commit/readback budget, including a delayed
			// commit. Short grants were omitted before writes, not owner-wide refusal.
			elapsed = 5 * time.Second
			if d, e := a.RemainingForApply(id, time.Millisecond); e != nil || d != 54999*time.Millisecond {
				t.Fatal("ordinary/DNS authority changed", d, e)
			}
			if want == 3 {
				if d, e := a.RemainingFQDNForApply(id, key, time.Millisecond); e != nil || d <= 0 {
					t.Fatal("included grant expired within original commit", d, e)
				}
			} else {
				if out.Connections[0].Grants[0] != ordinary || out.Connections[0].Grants[1] != dns {
					t.Fatal("selective omission lost independent grants")
				}
			}
		})
	}
}
func TestPermitLeaseFQDNChangedIdentityInvalidKeysClearsAuthority(t *testing.T) {
	a, id, _ := fqdnTestAuthority(t, 30000)
	changed := id
	changed.DeliveryID = uuid.New()
	if _, e := a.BeginFQDN(changed, []string{"invalid"}); e == nil {
		t.Fatal("invalid key accepted")
	}
	if _, e := a.RemainingForApply(id, time.Millisecond); e == nil {
		t.Fatal("old identity survived")
	}
	if _, e := a.RemainingFQDNForApply(id, fqdnLeaseDescriptorDigestGolden, time.Millisecond); e == nil {
		t.Fatal("old grant survived")
	}
}

// The existing five-provider fixture exercises actual maintained authority and
// guard transaction code with synthetic CP durations; this is not native/live proof.
func TestRuntimeFQDNV2MaintenanceFreshAndZeroDuration(t *testing.T) {
	for _, ttl := range []int64{30000, 0} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			r, s, p := fqdnActiveRig(t)
			a := r.c.active[r.target]
			g := a.Grants[len(a.Grants)-1]
			g.FQDN.Version = 2
			g.FQDN.ExpiresAt = time.Now().UTC().Add(45 * time.Second)
			g.FQDN.ResolverSourceAddress = "10.84.2.254"
			p.DNSResolverProfiles[0].IPsecPath.SourceAddress = g.FQDN.ResolverSourceAddress
			s.CommittedPolicy(p)
			r.c.qualification.fqdnExpiry = true
			b := g.FQDN
			f := RuntimeFQDNGrant{ExpiresAt: b.ExpiresAt, ResolverSourceAddress: b.ResolverSourceAddress, RuntimeGrant: RuntimeGrant{Source: g.Source.String(), Destination: g.Destination.String(), Protocol: string(g.Protocol), PortLow: g.PortLow, PortHigh: g.PortHigh, RuleID: b.RuleID.String()}, FQDNManaged: true, ResourceID: b.ResourceID.String(), Name: b.Name, Generation: b.Generation, ResolverConfigID: b.ResolverConfigID.String(), ResolverConfigVersion: b.ResolverConfigVersion, SelectedSiteID: b.SelectedSiteID.String(), SelectedGatewayID: b.SelectedGatewayID.String(), ResolverProfileID: b.ResolverProfileID.String(), ResolverMatchSuffix: b.ResolverMatchSuffix, ConnectionID: b.ConnectionID.String(), ConfigurationRevision: b.ConfigurationRevision}
			for i := range r.materials {
				if r.materials[i].Manifest.ConnectionID == r.target {
					r.materials[i].Policy.FQDNPolicyVersion = 2
					r.materials[i].Policy.FQDNGrants = []RuntimeFQDNGrant{f}
					_, grants, e := runtimeMaterialEntry(r.materials[i], r.c.config.OrgID, r.c.config.GatewayID, a.Environment.Namespace)
					if e != nil {
						t.Fatal(e)
					}
					a.Grants = grants
				}
			}
			key := runtimeFQDNGrantDigest(f)
			old := &PermitLeaseAuthority{elapsed: func() time.Duration { return *r.now }}
			q, e := old.BeginFQDN(a.Identity, []string{key})
			if e != nil {
				t.Fatal(e)
			}
			if e = old.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: 40000}}}); e != nil {
				t.Fatal(e)
			}
			a.Authority = old
			r.c.active[r.target] = a
			r.c.config.Environment.(renewalCycleEnvironment)[r.target] = a.Environment
			r.c.recoveryPrepared[a.Entry.DeliveryID] = a.Environment
			if e = r.c.installActive(context.Background(), r.entries); e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(r.expected), "fqdn_") {
				t.Fatal("initial timed permit absent")
			}
			oldDeadline := old.deadline
			client := r.c.client
			r.c.client = maintenanceLeaseFunc(func(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
				requestRaw, _ := json.Marshal(q)
				var decoded RuntimeLeaseRequest
				if json.Unmarshal(requestRaw, &decoded) != nil {
					return RuntimeLease{}, ErrPermitLease
				}
				out, e := client.RenewIPsecLease(ctx, id, decoded)
				out.RuntimeLeaseRequest = RuntimeLeaseRequest{DeliveryID: q.DeliveryID, DesiredRevision: q.DesiredRevision, PolicyHash: q.PolicyHash, Nonce: q.Nonce}
				if id == r.target {
					out.FQDNPermits = []RuntimeFQDNPermit{{GrantDigest: key, TTLMS: ttl}}
				}
				responseRaw, _ := json.Marshal(out)
				if strings.Contains(string(responseRaw), "fqdn_grants") {
					t.Fatal("response echoed descriptors")
				}
				var decodedResponse RuntimeLease
				if json.Unmarshal(responseRaw, &decodedResponse) != nil {
					return RuntimeLease{}, ErrPermitLease
				}
				return decodedResponse, e
			})
			r.phase = "maintenance"
			results, e := r.c.maintainIPsecRuntime(context.Background(), maintenanceMaterials(r), maintenanceAuthority(r), func() bool { return true })
			r.phase = ""
			if e != nil || len(results) != 5 {
				t.Fatal("maintained renewal", len(results), e)
			}
			current, ok := r.c.active[r.target]
			if !ok || current.Authority == old || old.deadline != oldDeadline {
				t.Fatal("owner lost or previous authority mutated")
			}
			if _, e = current.Authority.RemainingForApply(current.Identity, time.Millisecond); e != nil {
				t.Fatal("ordinary/DNS authority lost", e)
			}
			has := strings.Contains(string(r.expected), "fqdn_")
			if has != (ttl > 0) {
				t.Fatal("selective zero duration", has, ttl)
			}
		})
	}
}
