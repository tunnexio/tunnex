package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func v2FQDNFixture(t *testing.T) (RuntimeMaterial, GuardGrant, *nodepolicy.Compiled) {
	t.Helper()
	m, _, p := fqdnRuntimeFixture(t)
	m.Policy.FQDNPolicyVersion = 2
	f := &m.Policy.FQDNGrants[0]
	f.ExpiresAt = time.Now().UTC().Add(45 * time.Second)
	f.ResolverSourceAddress = "10.10.0.1"
	_, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 {
		t.Fatal("valid v2 descriptor refused", err)
	}
	return m, grants[0], p
}

func TestRuntimeFQDNV2TimedMembershipDoesNotRenewAndPreservesOrdinary(t *testing.T) {
	_, g, _ := v2FQDNFixture(t)
	now := g.FQDN.ExpiresAt.Add(-30 * time.Second)
	ordinary := g
	ordinary.FQDNManaged = false
	ordinary.FQDN = FQDNGrantBinding{}
	dns := ordinary
	dns.HostOrigin = true
	dns.Protocol = GuardUDP
	dns.PortLow = 53
	dns.PortHigh = 53
	dns.DNSResolver = DNSResolverBinding{ContextConfigID: g.FQDN.ResolverConfigID, ContextConfigVersion: g.FQDN.ResolverConfigVersion, ProfileID: g.FQDN.ResolverProfileID, ConnectionID: g.FQDN.ConnectionID, ConfigurationRevision: g.FQDN.ConfigurationRevision}
	in := GuardIntent{Connections: []GuardConnection{{PermitFor: 60 * time.Second, Grants: []GuardGrant{ordinary, g, dns}}}}
	a := limitFQDNGuardIntent(in, now, 5*time.Second, testFQDNRemaining(now))
	if len(a.Connections[0].Grants) != 3 || a.Connections[0].Grants[1].FQDNPermitFor != 25*time.Second || in.Connections[0].Grants[1].FQDNPermitFor != 0 {
		t.Fatal("finite budget or immutable input lost")
	}
	b := limitFQDNGuardIntent(in, now.Add(10*time.Second), 5*time.Second, testFQDNRemaining(now.Add(10*time.Second)))
	if b.Connections[0].Grants[1].FQDNPermitFor != 15*time.Second {
		t.Fatal("absolute cutoff renewed")
	}
	c := limitFQDNGuardIntent(in, g.FQDN.ExpiresAt.Add(-5*time.Second), 5*time.Second, testFQDNRemaining(g.FQDN.ExpiresAt.Add(-5*time.Second)))
	if len(c.Connections[0].Grants) != 2 || c.Connections[0].Grants[0] != ordinary || c.Connections[0].Grants[1] != dns {
		t.Fatal("expiry withdrew ordinary or retained FQDN")
	}
	g = a.Connections[0].Grants[1]
	name := guardFQDNSetName(g)
	for _, reply := range []bool{false, true} {
		r := guardAllow(g, 2, 3, reply, "lease_owned", "oif")
		if !strings.Contains(r.text, "@"+name) || !strings.Contains(r.text, "@lease_owned") || !strings.Contains(r.text, "ct mark") {
			t.Fatal("original/reply lost timed membership, exact lease or mark")
		}
	}
	related := guardRemoteFragmentNeeded(GuardConnection{ID: g.FQDN.ConnectionID}, g, 3, 2, netip.MustParsePrefix("10.20.0.0/24"))
	if !strings.Contains(related.text, "ct original ip daddr @"+name) {
		t.Fatal("derived related reply lost the same absolute-expiry membership")
	}
}

func TestRuntimeFQDNV2RejectsMissingOrForeignAuthorityAndSelectivelyExpires(t *testing.T) {
	m, g, p := v2FQDNFixture(t)
	_, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RuntimeFQDNGrant){func(f *RuntimeFQDNGrant) { f.ExpiresAt = time.Time{} }, func(f *RuntimeFQDNGrant) { f.ResolverSourceAddress = "10.99.0.1" }, func(f *RuntimeFQDNGrant) { f.ExpiresAt = time.Now().Add(2 * time.Hour) }} {
		copy := m
		copy.Policy.FQDNGrants = append([]RuntimeFQDNGrant(nil), m.Policy.FQDNGrants...)
		change(&copy.Policy.FQDNGrants[0])
		if _, _, err := runtimeMaterialEntry(copy, copy.Manifest.OrgID, copy.Manifest.NodeID, "net:[4026531992]"); err == nil {
			t.Fatal("invalid v2 authority admitted")
		}
	}
	m.Policy.FQDNGrants[0].ExpiresAt = time.Now().Add(-time.Second)
	_, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 0 {
		t.Fatal("expired descriptor did not selectively disappear", err)
	}
	p.DNSResolverProfiles[0].IPsecPath.SourceAddress = g.FQDN.ResolverSourceAddress
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(p)
	if !s.view.Load().matches(g) {
		t.Fatal("exact source refused")
	}
	p.DNSResolverProfiles[0].IPsecPath.SourceAddress = "10.10.0.2"
	s.CommittedPolicy(p)
	if s.view.Load().matches(g) {
		t.Fatal("foreign committed source admitted")
	}
}

func TestRuntimeFQDNV1WireOmission(t *testing.T) {
	m, _, _ := fqdnRuntimeFixture(t)
	b, _ := json.Marshal(m.Policy)
	if strings.Contains(string(b), "expires_at") || strings.Contains(string(b), "resolver_source_address") {
		t.Fatal("v1 additive fields not omitted")
	}
}

func TestRuntimeFQDNV2WholeGuardReadbackAndAtomicSetTurnover(t *testing.T) {
	_, g, _ := v2FQDNFixture(t)
	in := guardFixture()
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDN.ConnectionID = in.Connections[0].ID
	in.Connections[0].ReplyIngressIndices = []int{10}
	in.Connections[0].Grants = append(in.Connections[0].Grants, g)
	in = limitFQDNGuardIntent(in, time.Now(), 5*time.Second, testFQDNRemaining(time.Now()))
	m, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)); err != nil {
		t.Fatal("typed v2 full guard refused", err)
	}
	name := guardFQDNSetName(in.Connections[0].Grants[1])
	var env map[string]any
	if json.Unmarshal([]byte(m.ExpectedJSON), &env) != nil {
		t.Fatal("fixture")
	}
	for _, raw := range env["nftables"].([]any) {
		if set, ok := raw.(map[string]any)["set"].(map[string]any); ok && set["name"] == name {
			delete(set, "elem")
		}
	}
	expired, _ := json.Marshal(env)
	links := []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}}
	if VerifyGuardWithdrawal([]byte(m.ExpectedJSON), expired, links) != nil {
		t.Fatal("natural expiry failed structural denial readback")
	}
	if VerifyGuardReadback([]byte(m.ExpectedJSON), expired) == nil {
		t.Fatal("expired member manufactured positive permission")
	}
	tx, err := replaceOwnedFQDNSets(m.NFTJSON, m.ExpectedJSON)
	if err != nil || !strings.Contains(tx, `"delete":{"set":{"family":"inet","name":"`+name+`","table":"tunnex_ipsec"}}`) {
		t.Fatal("old exact set not atomically removed", err)
	}
	if !strings.Contains(tx, `"flush":{"table"`) || strings.Contains(tx, `"delete":{"table"`) {
		t.Fatal("scope widened")
	}
	if _, err := replaceOwnedFQDNSets(m.NFTJSON, strings.Replace(m.ExpectedJSON, "ipv4_addr", "ipv6_addr", 1)); err == nil {
		t.Fatal("foreign prior set type accepted")
	}
	if _, err := replaceOwnedFQDNSets(strings.Replace(m.NFTJSON, `"flush"`, `"delete"`, 1), m.ExpectedJSON); err == nil {
		t.Fatal("unexpected transaction preamble accepted")
	}
}

func TestRuntimeFQDNV2CheckOnlyQualificationCannotBeManufactured(t *testing.T) {
	step := func(context.Context) error { return nil }
	base := runtimePlatformProbe{namespace: func() (string, error) { return "net:[1234]", nil }, clock: func() (runtimeClock, error) { return runtimeClock{Boot: time.Hour, Monotonic: time.Hour}, nil }, alive: func() bool { return true }, packaged: step, daemon: step, kernel: step, xfrm: step, environment: step, nft: step, privilege: step}
	q, err := base.probe(context.Background())
	if err != nil || q.fqdnExpiry {
		t.Fatal("omitted v2 check qualified", err)
	}
	base.fqdn = func(context.Context) error { return ErrRuntimeProbe }
	q, err = base.probe(context.Background())
	if err != nil || q.fqdnExpiry {
		t.Fatal("failed v2 check qualified or broke base qualification", err)
	}
	base.fqdn = step
	q, err = base.probe(context.Background())
	if err != nil || !q.fqdnExpiry || !q.current() {
		t.Fatal("genuine complete check missing", err)
	}
	m, err := runtimeProbeFQDNManifest("net:[1234]")
	if err != nil || !strings.Contains(m.NFTJSON, `"type":"ipv4_addr"`) || !strings.Contains(m.NFT, "ip daddr @fqdn_") || !strings.Contains(m.NFT, "ip saddr @fqdn_") {
		t.Fatal("startup check omitted original/reply expiry grammar", err)
	}
}

func TestRuntimeFQDNV2WithdrawalPreservesSameConnectionOrdinary(t *testing.T) {
	r, s, p := fqdnActiveRig(t)
	a := r.c.active[r.target]
	oldAuthority := a.Authority
	oldDeadline := oldAuthority.deadline
	g := a.Grants[len(a.Grants)-1]
	g.FQDN.Version = 2
	g.FQDN.ExpiresAt = time.Now().UTC().Add(45 * time.Second)
	g.FQDN.ResolverSourceAddress = "10.84.2.254"
	concrete := g
	concrete.FQDNManaged = false
	concrete.FQDN = FQDNGrantBinding{}
	concrete.PortLow = 8443
	concrete.PortHigh = 8443
	a.Grants = append(a.Grants[:len(a.Grants)-1], concrete, g)
	ordinary := append([]GuardGrant(nil), a.Grants[:len(a.Grants)-1]...)
	p.DNSResolverProfiles[0].IPsecPath.SourceAddress = g.FQDN.ResolverSourceAddress
	s.CommittedPolicy(p)
	r.c.qualification.fqdnExpiry = true
	r.c.active[r.target] = a
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("v2 initial native guard", err)
	}
	p.Allow = nil
	if err := s.BeforePolicy(context.Background(), p); err != nil {
		t.Fatal("selective callback", err)
	}
	current, ok := r.c.active[r.target]
	if !ok || current.Authority != oldAuthority || !reflect.DeepEqual(current.Grants, ordinary) || oldAuthority.deadline != oldDeadline {
		t.Fatalf("selective withdrawal mismatch owner_present=%t same_authority=%t remaining_grants=%d expected_grants=%d deadline_unchanged=%t", ok, current.Authority == oldAuthority, len(current.Grants), len(ordinary), oldAuthority.deadline == oldDeadline)
	}
	if _, err := oldAuthority.RemainingForApply(current.Identity, time.Millisecond); err != nil {
		t.Fatal("ordinary authority invalidated", err)
	}
	if strings.Contains(string(r.expected), "fqdn_") {
		t.Fatal("old application permit remains")
	}
}

// Synthetic CP duration evidence for renderer-only fixtures, not production authority.
func testFQDNRemaining(at time.Time) func(uuid.UUID, GuardGrant, time.Duration) (time.Duration, error) {
	return func(_ uuid.UUID, g GuardGrant, budget time.Duration) (time.Duration, error) {
		return g.FQDN.ExpiresAt.Sub(at) - budget, nil
	}
}
