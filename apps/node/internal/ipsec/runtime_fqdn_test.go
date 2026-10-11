package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func fqdnRuntimeFixture(t *testing.T) (RuntimeMaterial, GuardGrant, *nodepolicy.Compiled) {
	t.Helper()
	m := runtimeMaterialFixture()
	f := RuntimeFQDNGrant{RuntimeGrant: RuntimeGrant{Source: "10.10.0.8/32", Destination: "10.20.0.9/32", Protocol: "tcp", PortLow: 8081, PortHigh: 8081, RuleID: uuid.NewString()}, FQDNManaged: true, ResourceID: uuid.NewString(), Name: "private.example.test", Generation: strings.Repeat("a", 64), ResolverConfigID: uuid.NewString(), ResolverConfigVersion: 5, SelectedSiteID: m.Manifest.SiteID.String(), SelectedGatewayID: m.Manifest.NodeID.String(), ResolverProfileID: uuid.NewString(), ResolverMatchSuffix: "example.test", ConnectionID: m.Manifest.ConnectionID.String(), ConfigurationRevision: m.Manifest.ConfigurationRevision}
	m.Policy.FQDNPolicyVersion = 1
	m.Policy.FQDNGrants = []RuntimeFQDNGrant{f}
	_, g, e := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if e != nil || len(g) != 1 {
		t.Fatal(e, g)
	}
	p := &nodepolicy.Compiled{Version: 9, NodeID: m.Manifest.NodeID.String(), Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{{SrcIP: f.Source, DstCIDR: f.Destination, Protocol: f.Protocol, PortLow: 8081, PortHigh: 8081, RuleID: f.RuleID, FQDNManaged: true}}, FQDNGenerations: []nodepolicy.FQDNGeneration{{ResourceID: f.ResourceID, Name: f.Name, Generation: f.Generation, ResolverConfigID: f.ResolverConfigID, ResolverConfigVersion: 5, Answers: []string{"10.20.0.9"}}}, DNSResolverProfiles: []nodepolicy.DNSResolverProfile{{ContextConfigID: f.ResolverConfigID, ContextConfigVersion: 5, ProfileID: f.ResolverProfileID, ZoneSuffixes: []string{"example.test"}, IPsecPath: nodepolicy.DNSResolverIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}}}}
	return m, g[0], p
}

func TestRuntimeFQDNOnlyCopiedCommittedGenerationQualifies(t *testing.T) {
	_, g, p := fqdnRuntimeFixture(t)
	s := &RuntimeFQDNPolicySource{}
	if s.view.Load().matches(g) {
		t.Fatal("cold desired state granted")
	}
	if e := s.BeforePolicy(context.Background(), p); e != nil || s.view.Load().matches(g) {
		t.Fatal("pending state granted", e)
	}
	s.CommittedPolicy(p)
	if !s.view.Load().matches(g) {
		t.Fatal("exact committed tuple refused")
	}
	// Ownership-safe copies: changing desired slices after actual apply cannot
	// corrupt or silently supersede the successfully applied view.
	p.Allow[0].DstCIDR = "invalid"
	p.FQDNGenerations[0].Answers[0] = "10.20.0.99"
	p.DNSResolverProfiles[0].ZoneSuffixes[0] = "other.test"
	if !s.view.Load().matches(g) {
		t.Fatal("mutable desired policy changed committed authority")
	}
}

func TestRuntimeFQDNDesiredWithdrawalNeverPublishesReplacement(t *testing.T) {
	_, g, p := fqdnRuntimeFixture(t)
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(p)
	p.FQDNGenerations[0].Generation = strings.Repeat("b", 64)
	if e := s.BeforePolicy(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if s.view.Load().matches(g) {
		t.Fatal("old answer survived pre-commit generation withdrawal")
	}
	// A failed ordinary apply invokes no CommittedPolicy callback, and cannot
	// recover old answer authority or adopt the desired new generation.
	newg := g
	newg.FQDN.Generation = strings.Repeat("b", 64)
	if s.view.Load().matches(newg) {
		t.Fatal("failed candidate granted")
	}
	s.CommittedPolicy(p)
	if !s.view.Load().matches(newg) || s.view.Load().matches(g) {
		t.Fatal("commit did not bind one exact generation")
	}
}

func TestRuntimeFQDNMaterialRejectsPrefixAndProvenanceBypass(t *testing.T) {
	changes := map[string]func(*RuntimeMaterial){
		"outside-local-WG":   func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Source = "10.99.0.2/32" },
		"outside-remote":     func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Destination = "8.8.8.8/32" },
		"answer-subnet":      func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Destination = "10.20.0.0/24" },
		"unmanaged":          func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].FQDNManaged = false },
		"version":            func(m *RuntimeMaterial) { m.Policy.FQDNPolicyVersion = 0 },
		"foreign-connection": func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ConnectionID = uuid.NewString() },
		"foreign-site":       func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].SelectedSiteID = uuid.NewString() },
		"foreign-node":       func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].SelectedGatewayID = uuid.NewString() },
		"revision":           func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ConfigurationRevision++ },
		"resource":           func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ResourceID = "" },
		"generation":         func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Generation = "" },
		"profile":            func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ResolverProfileID = "" },
		"suffix":             func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ResolverMatchSuffix = "foreign.test" },
		"wildcard":           func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Name = "*.example.test" },
		"port":               func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].PortLow = 0 },
		"duplicate":          func(m *RuntimeMaterial) { m.Policy.FQDNGrants = append(m.Policy.FQDNGrants, m.Policy.FQDNGrants[0]) },
	}
	for n, change := range changes {
		t.Run(n, func(t *testing.T) {
			m, _, _ := fqdnRuntimeFixture(t)
			change(&m)
			if _, _, e := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); e == nil {
				t.Fatal("invalid FQDN authority accepted")
			}
		})
	}
}

func TestRuntimeFQDNGuardMarkedOriginalLeaseAndExactReply(t *testing.T) {
	_, g, _ := fqdnRuntimeFixture(t)
	i := guardFixture()
	i.OwnerID = g.FQDN.SelectedGatewayID
	i.Connections[0].ID = g.FQDN.ConnectionID
	i.Connections[0].Grants = []GuardGrant{g}
	i.Connections[0].ReplyIngressIndices = []int{10}
	m, e := RenderGuard(i)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"ct mark set ((ct mark & 0xf0ffffff) | 0x01000000)", "ct mark & 0x0f000000 == 0x01000000", "ip saddr 10.10.0.8/32 ip daddr 10.20.0.9/32", "tcp dport 8081", "meta oif @lease_"} {
		if !strings.Contains(m.NFT, s) {
			t.Fatal("missing strict grant", s)
		}
	}
	if e := VerifyGuardReadback([]byte(m.ExpectedJSON), []byte(m.ExpectedJSON)); e != nil {
		t.Fatal("unverifiable FQDN native document", e)
	}
	i.Connections[0].PermitFor = 0
	expired, e := RenderGuard(i)
	if e != nil || strings.Contains(expired.NFT, "counter accept") || strings.Contains(expired.NFT, "ct mark set") {
		t.Fatal("expired lease permitted FQDN", e)
	}
	i = guardFixture()
	i.Connections[0].Grants[0].FQDNManaged = true
	if _, e := RenderGuard(i); e == nil {
		t.Fatal("bare legacy bit adopted as authority")
	}
}

func TestRuntimeFQDNLegacyPolicyAndOrdinaryGuardRemainUnchanged(t *testing.T) {
	b, e := json.Marshal(runtimeMaterialFixture().Policy)
	if e != nil || strings.Contains(string(b), "fqdn_") {
		t.Fatal("legacy wire changed", e, string(b))
	}
	i := guardFixture()
	m, e := RenderGuard(i)
	if e != nil || strings.Contains(m.NFT, "ct mark") {
		t.Fatal("ordinary grants gained FQDN ownership", e)
	}
	_, g, _ := fqdnRuntimeFixture(t)
	g.Source = netip.MustParsePrefix("10.99.0.2/32")
	i.OwnerID = g.FQDN.SelectedGatewayID
	i.Connections[0].ID = g.FQDN.ConnectionID
	i.Connections[0].Grants = []GuardGrant{g}
	if _, e := RenderGuard(i); e == nil {
		t.Fatal("renderer bypassed configured local prefix")
	}
}

func TestRuntimeFQDNCommittedViewRejectsForeignOrIncompleteProvenance(t *testing.T) {
	for name, mutate := range map[string]func(*nodepolicy.Compiled){
		"node":            func(p *nodepolicy.Compiled) { p.NodeID = uuid.NewString() },
		"unsupported":     func(p *nodepolicy.Compiled) { p.Version = nodepolicy.MaxSupportedVersion + 1 },
		"legacy-unmarked": func(p *nodepolicy.Compiled) { p.Version = 8 },
		"mesh":            func(p *nodepolicy.Compiled) { p.Mesh = true },
		"off":             func(p *nodepolicy.Compiled) { p.Mode = nodepolicy.ModeOff },
		"generation":      func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].Generation = strings.Repeat("b", 64) },
		"resource":        func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ResourceID = uuid.NewString() },
		"name":            func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].Name = "other.example.test" },
		"answer":          func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].Answers = []string{"10.20.0.99"} },
		"config":          func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ResolverConfigID = uuid.NewString() },
		"config-version":  func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ResolverConfigVersion++ },
		"rule":            func(p *nodepolicy.Compiled) { p.Allow[0].RuleID = uuid.NewString() },
		"unmarked-tuple":  func(p *nodepolicy.Compiled) { p.Allow[0].FQDNManaged = false },
		"source":          func(p *nodepolicy.Compiled) { p.Allow[0].SrcIP = "10.99.0.2/32" },
		"destination":     func(p *nodepolicy.Compiled) { p.Allow[0].DstCIDR = "10.20.0.99/32" },
		"protocol":        func(p *nodepolicy.Compiled) { p.Allow[0].Protocol = "udp" },
		"port":            func(p *nodepolicy.Compiled) { p.Allow[0].PortHigh++ },
		"profile":         func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].ProfileID = uuid.NewString() },
		"connection":      func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].IPsecPath.ConnectionID = uuid.NewString() },
		"revision":        func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].IPsecPath.ConfigurationRevision++ },
		"suffix":          func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].ZoneSuffixes = []string{"other.test"} },
	} {
		t.Run(name, func(t *testing.T) {
			_, g, p := fqdnRuntimeFixture(t)
			mutate(p)
			s := &RuntimeFQDNPolicySource{}
			s.CommittedPolicy(p)
			if s.view.Load().matches(g) {
				t.Fatal("incomplete committed provenance granted")
			}
		})
	}
}

func fqdnActiveRig(t *testing.T) (*renewalCycleRig, *RuntimeFQDNPolicySource, *nodepolicy.Compiled) {
	t.Helper()
	r := newRenewalCycleRigInput(t, true)
	a := r.c.active[r.target]
	_, g, p := fqdnRuntimeFixture(t)
	g.Source = netip.MustParsePrefix("10.84.2.10/32")
	g.Destination = netip.PrefixFrom(a.Entry.Engines[0].RemotePrefixes[0].Addr().Next(), 32)
	g.FQDN.SelectedGatewayID = r.c.config.GatewayID
	g.FQDN.SelectedSiteID = a.Entry.SiteID
	g.FQDN.ConnectionID = r.target
	g.FQDN.ConfigurationRevision = a.Entry.Engines[0].Binding.ConfigurationRevision
	p.NodeID = r.c.config.GatewayID.String()
	p.Allow[0].SrcIP, p.Allow[0].DstCIDR = g.Source.String(), g.Destination.String()
	p.FQDNGenerations[0].Answers = []string{g.Destination.Addr().String()}
	p.DNSResolverProfiles[0].IPsecPath.ConnectionID = r.target.String()
	p.DNSResolverProfiles[0].IPsecPath.ConfigurationRevision = g.FQDN.ConfigurationRevision
	a.Grants = append(a.Grants, g)
	a.Environment.LocalIngressIndices = []int{2}
	r.c.active[r.target] = a
	kernel := newRecoveryKernelFixture()
	kernel.p, kernel.owned = a.Entry.Allocation, a.Entry.Observed
	kernel.routes = [2]map[string]bool{{}, {}}
	for _, prefix := range a.Entry.Engines[0].RemotePrefixes {
		kernel.routes[0][prefix.String()] = true
	}
	r.c.kernel = kernel.applier()
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(p)
	s.Attach(r.c)
	r.c.config.FQDNPolicy = s
	if !s.view.Load().matches(g) {
		t.Fatalf("fixture committed provenance invalid: %+v", g.FQDN)
	}
	r.c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			t.Logf("refused stage=%s", d.Stage)
		}
	}
	if err := r.c.installActive(context.Background(), r.entries); err != nil {
		t.Fatal("actual finite marked guard install", err)
	}
	return r, s, p
}

func TestRuntimeFQDNWithdrawalDeniesOnlyAffectedOwnerBeforeOrdinarySwap(t *testing.T) {
	r, s, p := fqdnActiveRig(t)
	original := r.c.active[r.target]
	deadline := original.Authority.deadline
	others := map[uuid.UUID]runtimeActive{}
	for id, a := range r.c.active {
		if id != r.target {
			others[id] = a
		}
	}
	p.Allow = p.Allow[:0]
	if err := s.BeforePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.active[r.target]; ok {
		t.Fatal("withdrawn generation retained active authority")
	}
	if _, err := original.Authority.RemainingForApply(original.Identity, time.Millisecond); err == nil {
		t.Fatal("original lease survived policy withdrawal")
	}
	if original.Authority.deadline > deadline {
		t.Fatal("withdrawal extended deadline")
	}
	for id, a := range others {
		if !reflect.DeepEqual(a, r.c.active[id]) {
			t.Fatal("unrelated applied owner changed")
		}
	}
	var document map[string]any
	if err := json.Unmarshal(r.expected, &document); err != nil {
		t.Fatal(err)
	}
	for _, row := range document["nftables"].([]any) {
		if rule, ok := row.(map[string]any)["rule"].(map[string]any); ok {
			raw, _ := json.Marshal(rule)
			if strings.Contains(string(raw), original.Grants[len(original.Grants)-1].Destination.String()) && strings.Contains(string(raw), "accept") {
				t.Fatal("withdrawn marked tuple still accepted")
			}
		}
	}
	if !r.applicationDenied[r.target] {
		t.Fatal("no actual rendered target denial")
	}
}

func TestRuntimeFQDNWithdrawalIntersectsBeforeOwnerWait(t *testing.T) {
	r, s, p := fqdnActiveRig(t)
	grant := r.c.active[r.target].Grants[len(r.c.active[r.target].Grants)-1]
	r.c.mu.Lock()
	p.FQDNGenerations = nil
	done := make(chan error, 1)
	go func() { done <- s.BeforePolicy(context.Background(), p) }()
	limit := time.After(time.Second)
	for s.view.Load().matches(grant) {
		select {
		case <-limit:
			r.c.mu.Unlock()
			t.Fatal("owner lock delayed permission retraction")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	// Native withdrawal waits for the serialized owner, but no validator can
	// reenter the egress lock or adopt the pending generation in the meantime.
	select {
	case <-done:
		r.c.mu.Unlock()
		t.Fatal("native owner withdrawal bypassed its lock")
	default:
	}
	r.c.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFQDNOriginalExpiryNativeFailureAndCommitRaceNeverPermit(t *testing.T) {
	for _, mode := range []string{"expired-before", "expired-during-native", "native-refused", "policy-during-replace", "commit-failed"} {
		t.Run(mode, func(t *testing.T) {
			r, s, _ := fqdnActiveRig(t)
			old := r.c.active[r.target]
			deadline := old.Authority.deadline
			replacedPositive := false
			replace := r.c.replace
			r.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if g.ID == r.target && !g.PrefixOnly {
						replacedPositive = true
					}
				}
				if mode == "commit-failed" {
					return GuardManifest{}, ErrGuardReadback
				}
				m, e := replace(ctx, in)
				if mode == "policy-during-replace" {
					s.view.Store(nil)
				}
				return m, e
			}
			prove := r.c.prove
			r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
				if e.Allocation.ConnectionID == r.target {
					if mode == "expired-during-native" {
						*r.now = deadline + time.Second
					}
					if mode == "native-refused" {
						return ErrRuntimeController
					}
				}
				return prove(ctx, e, env)
			}
			if mode == "expired-before" {
				*r.now = deadline + time.Second
			}
			err := r.c.installActive(context.Background(), r.entries)
			if mode == "policy-during-replace" || mode == "commit-failed" {
				if err == nil {
					t.Fatal("failed atomic commit accepted")
				}
			} else if replacedPositive {
				t.Fatal("invalid source/native authority installed positively")
			}
			if old.Authority.deadline != deadline {
				t.Fatal("finite original authority extended")
			}
			if view := r.c.dnsView.Load(); view != nil {
				if _, ok := view.entries[r.target]; ok {
					t.Fatal("failed/expired owner published positive DNS view")
				}
			}
		})
	}
}

func TestRuntimeFQDNChangedMaterialWithdrawsBeforeBlockingEnvironment(t *testing.T) {
	r, _, _ := fqdnActiveRig(t)
	c := r.c
	m := r.materials[3]
	if m.Manifest.ConnectionID != r.target {
		t.Fatal("fixture logical target order")
	}
	old := c.active[r.target]
	deadline := old.Authority.deadline
	initialLeases := r.leases
	// Removing the authenticated FQDN grant changes intent; ordinary material
	// remains validated and cannot re-use its previous marked permission.
	m.Policy.Hash = strings.Repeat("e", 64)
	block := &maintenanceBlockingEnvironment{previous: c.config.Environment, entered: make(chan struct{}), release: make(chan struct{})}
	c.config.Environment = block
	done := make(chan struct{})
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer close(done)
		_, _ = c.maintainIPsecRuntime(context.Background(), []RuntimeMaterial{m}, maintenanceAuthority(r), func() bool { return true })
	}()
	// Build17 may perform deny-only inactive recovery IO after withdrawal.
	// At the first Environment call all three real rendered target sets must
	// already be empty, and the old marked application authority must be gone.
	beforeIO := func() bool {
		_, active := c.active[r.target]
		setsEmpty := true
		for _, name := range []string{guardLeaseName(r.target), guardReplyLeaseName(r.target), guardSALeaseName(r.target)} {
			if _, present := r.installed[name]; present {
				setsEmpty = false
			}
		}
		_, leaseErr := old.Authority.RemainingForApply(old.Identity, time.Millisecond)
		denial := c.recoveryGuardDenied(context.Background(), old.Entry)
		unchangedNonceCount := r.leases == initialLeases
		t.Logf("before first Environment: active=%t applicationDenied=%t all3RenderedSetsEmpty=%t strictNativeDenial=%t oldAuthorityInvalid=%t originalDeadlineNotExtended=%t freshApplyNonceUnchanged=%t", active, r.applicationDenied[r.target], setsEmpty, denial, leaseErr != nil, old.Authority.deadline <= deadline, unchangedNonceCount)
		return !active && r.applicationDenied[r.target] && setsEmpty && denial && leaseErr != nil && old.Authority.deadline <= deadline && unchangedNonceCount
	}
	select {
	case <-block.entered:
		safe := beforeIO()
		close(block.release)
		<-done
		if !safe {
			t.Fatal("old marked owner or finite native authority survived first Environment IO")
		}
	case <-done:
		if !beforeIO() {
			t.Fatal("old marked owner retained without Environment IO")
		}
	case <-time.After(2 * time.Second):
		close(block.release)
		t.Fatal("changed intent did not finish refusal/fallback")
	}
	if _, ok := c.active[r.target]; ok || !r.applicationDenied[r.target] {
		t.Fatal("old native marked owner retained")
	}
	if _, err := old.Authority.RemainingForApply(old.Identity, time.Millisecond); err == nil {
		t.Fatal("changed material kept old lease")
	}
}

func TestRuntimeFQDNCapabilityRequiresCommittedOwnerAndNativePlatform(t *testing.T) {
	m, _, p := fqdnRuntimeFixture(t)
	s := &RuntimeFQDNPolicySource{}
	c := &RuntimeController{started: true, qualification: testRuntimeQualification("net:[4026531992]"), config: RuntimeControllerConfig{GatewayID: m.Manifest.NodeID, FQDNPolicy: s, Daemon: &DaemonClient{}, DaemonAlive: func() bool { return true }}}
	if c.fqdnPolicyCapabilityFor("linux", "amd64") != 0 {
		t.Fatal("cold desired capability manufactured")
	}
	s.CommittedPolicy(p)
	if c.fqdnPolicyCapabilityFor("linux", "amd64") != 1 {
		t.Fatal("actual qualified committed feature not advertised")
	}
	for _, platform := range []string{"darwin", "windows"} {
		if c.fqdnPolicyCapabilityFor(platform, "amd64") != 0 {
			t.Fatal("unsupported platform advertised FQDN capability")
		}
	}
	c.qualification = nil
	if c.fqdnPolicyCapabilityFor("linux", "amd64") != 0 {
		t.Fatal("unqualified native controller advertised")
	}
	c.qualification = testRuntimeQualification("net:[4026531992]")
	p.NodeID = uuid.NewString()
	s.CommittedPolicy(p)
	if c.fqdnPolicyCapabilityFor("linux", "amd64") != 0 {
		t.Fatal("foreign applied view advertised")
	}
	c.closed = true
	if c.fqdnPolicyCapabilityFor("linux", "amd64") != 0 {
		t.Fatal("closed owner advertised")
	}
}

// This crosses the actual additive JSON boundary rather than merely seeding a
// native GuardGrant. A pre-feature agent decodes no FQDN authority and must
// not mistake this material for a completed positive application grant.
func TestRuntimeFQDNWireMaterialProducesSeparateProvenance(t *testing.T) {
	m, _, _ := fqdnRuntimeFixture(t)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var received RuntimeMaterial
	if err = json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	entry, grants, err := runtimeMaterialEntry(received, received.Manifest.OrgID, received.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 || !grants[0].FQDNManaged || grants[0].FQDN.ResourceID.String() != m.Policy.FQDNGrants[0].ResourceID {
		t.Fatal("authenticated FQDN JSON lost its distinct authority", err)
	}
	if entry.Allocation.ConnectionID != m.Manifest.ConnectionID || len(received.Policy.Grants) != 0 {
		t.Fatal("FQDN source silently converted to ordinary grant")
	}
}
