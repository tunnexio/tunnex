//go:build linux

package egress

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	conntrack "github.com/florianl/go-conntrack"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// AI-SEC-2: the artifact's explicit denies (v16) close the direct path from an agent device to its MCP
// server. They are rendered ahead of the mesh accepts and ahead of the compiled allows, in both families
// and both modes, and a deny that arrives cuts the flow the device already holds.

var (
	testDeny4 = nodepolicy.DenyEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000, Reason: "mcp_gateway_only"}
	testDeny6 = nodepolicy.DenyEntry{SrcIP: "fd42:99::7", DstCIDR: "2001:db8::10/128", Protocol: "tcp", PortLow: 9000, PortHigh: 9000, Reason: "mcp_gateway_only"}
)

func denyTestPolicies() map[string]nodepolicy.Compiled {
	allow := []nodepolicy.AllowEntry{
		// The very path the deny names, and a wider one that covers it: the deny must win over both.
		{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000},
		{SrcIP: "10.99.0.7", DstCIDR: "0.0.0.0/0", Protocol: "any"},
		{SrcIP: "fd42:99::7", DstCIDR: "::/0", Protocol: "any"},
	}
	return map[string]nodepolicy.Compiled{
		"mesh":      {Version: 16, Mode: nodepolicy.ModeOff, Mesh: true},
		"enforcing": {Version: 16, Mode: nodepolicy.ModeEnforcing, Allow: allow},
	}
}

func TestDeniesRenderBeforeTheMeshAndBeforeTheAllowsInBothFamilies(t *testing.T) {
	for mode, base := range denyTestPolicies() {
		t.Run(mode, func(t *testing.T) {
			m := New("wg0")
			without := base
			plain4, plain6 := m.forwardRules(&without, true)
			if strings.Contains(plain4+plain6, policyDenyComment) {
				t.Fatalf("an artifact without denies rendered one:\n%s%s", plain4, plain6)
			}
			with := base
			with.Deny = []nodepolicy.DenyEntry{testDeny4, testDeny6}
			v4, v6 := m.forwardRules(&with, true)
			deny4, deny6, ok := renderDenies(with.Deny, 0)
			if !ok || deny4 == "" || deny6 == "" {
				t.Fatalf("fixture denies did not render: %q %q", deny4, deny6)
			}
			// The denies are the FIRST lines of the chain body, and everything after them is exactly
			// what the artifact renders without them: every accept, mesh or allow, comes later.
			if v4 != deny4+plain4 {
				t.Fatalf("ip forward:\n%s\nwant the denies, then:\n%s", v4, plain4)
			}
			if v6 != deny6+plain6 {
				t.Fatalf("ip6 forward:\n%s\nwant the denies, then:\n%s", v6, plain6)
			}
			for _, rules := range []string{v4, v6} {
				firstAccept := strings.Index(rules, " accept")
				lastDeny := strings.LastIndex(rules, policyDenyComment)
				if firstAccept < 0 || lastDeny < 0 || lastDeny > firstAccept {
					t.Fatalf("an accept precedes a deny:\n%s", rules)
				}
			}
			if strings.Contains(v4, "2001:db8::10") || strings.Contains(v6, "172.30.0.10") {
				t.Fatalf("a deny crossed address families:\n%s\n%s", v4, v6)
			}
		})
	}
}

// The whole ruleset of an artifact without denies is what it was: no deny line and, on a VM gateway, no
// input chain. With denies, removing exactly the deny lines and the VM input chain gives it back.
func TestRulesetWithoutDeniesIsUnchanged(t *testing.T) {
	for mode, base := range denyTestPolicies() {
		t.Run(mode, func(t *testing.T) {
			m := New("wg0")
			without := base
			m.SetPolicy(&without)
			plain := m.rulesetWith("10.99.0.0/24", &without)
			if strings.Contains(plain, policyDenyComment) || strings.Contains(plain, "chain input") {
				t.Fatalf("an artifact without denies changed the ruleset:\n%s", plain)
			}
			with := base
			with.Deny = []nodepolicy.DenyEntry{testDeny4, testDeny6}
			m.SetPolicy(&with)
			denied := m.rulesetWith("10.99.0.0/24", &with)
			deny4, deny6, _ := renderDenies(with.Deny, 0)
			input := func(denies string) string {
				return "  chain input {\n    type filter hook input priority filter; policy accept;\n" + denies + "  }\n"
			}
			stripped := strings.Replace(strings.Replace(denied, input(deny4), "", 1), input(deny6), "", 1)
			stripped = strings.Replace(strings.Replace(stripped, deny4, "", 1), deny6, "", 1)
			if stripped != plain {
				t.Fatalf("the denies changed more than their own lines:\n%s\nwant:\n%s", stripped, plain)
			}
		})
	}
}

// A denied server that runs on the gateway host is delivered locally and never meets the forward chain, so
// a VM gateway renders the same drops on the input hook while the artifact carries denies. An in-cluster
// gateway keeps its fixed input chain, which already drops everything a device sends to the node.
func TestVMGatewayRendersDeniesOnTheInputHook(t *testing.T) {
	pol := &nodepolicy.Compiled{Version: 16, Mode: nodepolicy.ModeEnforcing, Deny: []nodepolicy.DenyEntry{testDeny4}}
	m := New("wg0")
	m.SetPolicy(pol)
	v4, v6 := inputChains(t, m.rulesetWith("10.99.0.0/24", pol))
	deny4, _, _ := renderDenies(pol.Deny, 0)
	want := "  chain input {\n    type filter hook input priority filter; policy accept;\n" + deny4 + "  }\n"
	if v4 != want {
		t.Fatalf("ip input:\n%s\nwant:\n%s", v4, want)
	}
	if v6 != "" {
		t.Fatalf("an IPv4 deny rendered an ip6 input chain:\n%s", v6)
	}
	k := inputTestManager(true)
	k.SetPolicy(pol)
	if k4, k6 := inputChains(t, k.rulesetWith("10.99.0.0/24", pol)); k4 != wantInputChainV4 || k6 != wantInputChainV4 {
		t.Fatalf("the in-cluster input chain followed the policy:\n%s\n%s", k4, k6)
	}
	// Before the first delivery and under a refusal the forward chain is deny-all; no input chain appears.
	cold := New("wg0")
	if c4, c6 := inputChains(t, cold.rulesetWith("10.99.0.0/24", pol)); c4 != "" || c6 != "" {
		t.Fatalf("cold start rendered an input chain:\n%s%s", c4, c6)
	}
}

// A v16 artifact is refused by a gateway whose ceiling is 15 (deny-all, reported), and applied at 16.
func TestDenyArtifactIsRefusedAtCeiling15AndAppliedAt16(t *testing.T) {
	if nodepolicy.MaxSupportedVersion < 16 || !nodepolicy.RendersDeny {
		t.Fatalf("MaxSupportedVersion=%d RendersDeny=%v: the ceiling and the render move together", nodepolicy.MaxSupportedVersion, nodepolicy.RendersDeny)
	}
	pol := &nodepolicy.Compiled{Version: 16, Mesh: true, Deny: []nodepolicy.DenyEntry{testDeny4}}
	old := New("wg0")
	old.maxPolicyVersion = 15
	old.SetPolicy(pol)
	if old.RefusedVersion() != 16 {
		t.Fatalf("a gateway at ceiling 15 accepted a v16 artifact: refused=%d", old.RefusedVersion())
	}
	rs := old.ruleset("10.99.0.1/24")
	if strings.Contains(rs, blanketV4) || strings.Contains(rs, policyDenyComment) || !strings.Contains(rs, "tunnex_default_drop") {
		t.Fatalf("a refused v16 artifact must be deny-all:\n%s", rs)
	}
	current := New("wg0")
	current.SetPolicy(pol)
	if current.RefusedVersion() != 0 {
		t.Fatalf("this gateway refused v16: %d", current.RefusedVersion())
	}
	rs = current.ruleset("10.99.0.1/24")
	deny := strings.Index(rs, policyDenyComment)
	mesh := strings.Index(rs, blanketV4)
	if deny < 0 || mesh < 0 || deny > mesh {
		t.Fatalf("v16 mesh artifact: the deny must precede the mesh accept:\n%s", rs)
	}
}

// A deny that cannot be rendered exactly is never skipped: the chain is deny-all.
func TestUnrenderableDenyIsDenyAll(t *testing.T) {
	for mode, base := range denyTestPolicies() {
		t.Run(mode, func(t *testing.T) {
			pol := base
			pol.Deny = []nodepolicy.DenyEntry{testDeny4, {SrcIP: "10.99.0.8", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000}}
			m := New("wg0")
			v4, v6 := m.forwardRules(&pol, true)
			if v4 != dropCounter || v6 != dropCounter {
				t.Fatalf("a malformed deny was skipped:\n%s\n%s", v4, v6)
			}
		})
	}
}

func TestDeniedRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	deny := []nodepolicy.DenyEntry{testDeny4, testDeny6,
		{SrcIP: "10.99.0.8", DstCIDR: "172.30.0.0/24", Protocol: "any"},
		{SrcIP: "10.99.0.9", DstCIDR: "172.30.0.11/32", Protocol: "udp"},
		{SrcIP: "10.99.0.9", DstCIDR: "172.30.0.11/32", Protocol: "udp", PortLow: 5000, PortHigh: 5010},
	}
	for mode, base := range denyTestPolicies() {
		for _, k8s := range []bool{false, true} {
			for _, group := range []int{0, 5} {
				pol := base
				pol.Deny = deny
				m := inputTestManager(k8s)
				m.SetFlowLogGroup(group)
				m.SetPolicy(&pol)
				rs := m.rulesetWith("10.99.0.0/24", &pol)
				if !strings.Contains(rs, policyDenyComment) {
					t.Fatalf("%s: the probe would not exercise a deny:\n%s", mode, rs)
				}
				cmd := exec.Command("nft", "-c", "-f", "-")
				cmd.Stdin = strings.NewReader(rs)
				if out, err := cmd.CombinedOutput(); err != nil {
					if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "cache initialization") {
						t.Skipf("nft cannot init netlink here (needs NET_ADMIN):\n%s", out)
					}
					t.Fatalf("%s k8s=%v group=%d: nft rejected the rendered ruleset (%v):\n%s\n--- RULESET ---\n%s", mode, k8s, group, err, out, rs)
				}
			}
		}
	}
}

func denyFlushManager(flushed *[][]flowTuple, flushErr *error) *Manager {
	m := &Manager{
		apply: func(context.Context, string) error { return nil },
		now:   time.Now,
		ctFlush: func(_ context.Context, tuples []flowTuple) (int, error) {
			*flushed = append(*flushed, append([]flowTuple(nil), tuples...))
			return len(tuples), *flushErr
		},
	}
	m.policyReceived.Store(true)
	return m
}

// A deny that enters the applied set cuts the flows of exactly its tuple, once, in both modes. With no
// baseline (the first apply after a start) every deny is cut.
func TestNewDenyCutsItsEstablishedFlowsOnceInBothModes(t *testing.T) {
	for mode, base := range denyTestPolicies() {
		t.Run(mode, func(t *testing.T) {
			var flushed [][]flowTuple
			var flushErr error
			m := denyFlushManager(&flushed, &flushErr)
			ctx := context.Background()
			without := base
			if err := m.applyAndTrack(ctx, "plain", &without); err != nil {
				t.Fatal(err)
			}
			m.drainFlush(ctx)
			if len(flushed) != 0 {
				t.Fatalf("an artifact without denies flushed: %+v", flushed)
			}
			with := base
			with.Deny = []nodepolicy.DenyEntry{testDeny4}
			if err := m.applyAndTrack(ctx, "denied", &with); err != nil {
				t.Fatal(err)
			}
			m.drainFlush(ctx)
			if len(flushed) != 1 || len(flushed[0]) != 1 {
				t.Fatalf("the new deny was not cut exactly once: %+v", flushed)
			}
			tuple := flushed[0][0]
			if !tuple.denied || tuple.proto != 6 || tuple.portLow != 9000 || tuple.portHigh != 9000 ||
				tuple.src.String() != "10.99.0.7/32" || tuple.dst.String() != "172.30.0.10/32" {
				t.Fatalf("cut tuple is not the deny's: %+v", tuple)
			}
			// The steady state re-applies the same artifact: nothing more to cut.
			if err := m.applyAndTrack(ctx, "denied", &with); err != nil {
				t.Fatal(err)
			}
			m.drainFlush(ctx)
			if len(flushed) != 1 {
				t.Fatalf("an unchanged deny was cut again: %+v", flushed)
			}
			// A second deny cuts only itself.
			more := base
			more.Deny = []nodepolicy.DenyEntry{testDeny4, testDeny6}
			if err := m.applyAndTrack(ctx, "more", &more); err != nil {
				t.Fatal(err)
			}
			m.drainFlush(ctx)
			if len(flushed) != 2 || len(flushed[1]) != 1 || flushed[1][0].dst.String() != "2001:db8::10/128" {
				t.Fatalf("the second deny: %+v", flushed)
			}
		})
	}
}

// A failed apply leaves the previous ruleset in force and cuts nothing; a failed cut is retried.
func TestDenyCutFollowsTheApplyAndIsRetriedUntilItSucceeds(t *testing.T) {
	var flushed [][]flowTuple
	var flushErr error
	m := denyFlushManager(&flushed, &flushErr)
	ctx := context.Background()
	pol := &nodepolicy.Compiled{Version: 16, Mode: nodepolicy.ModeEnforcing, Deny: []nodepolicy.DenyEntry{testDeny4}}
	boom := errors.New("nft rejected")
	m.apply = func(context.Context, string) error { return boom }
	if err := m.applyAndTrack(ctx, "denied", pol); !errors.Is(err, boom) {
		t.Fatalf("apply = %v", err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 0 {
		t.Fatalf("a deny that is not in force cut a flow: %+v", flushed)
	}
	m.apply = func(context.Context, string) error { return nil }
	flushErr = errors.New("netlink unavailable")
	if err := m.applyAndTrack(ctx, "denied", pol); err != nil {
		t.Fatal(err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 1 || !m.ConntrackFlushFailing() {
		t.Fatalf("first cut attempt: %+v failing=%v", flushed, m.ConntrackFlushFailing())
	}
	flushErr = nil
	if err := m.applyAndTrack(ctx, "denied", pol); err != nil {
		t.Fatal(err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 2 || len(flushed[1]) != 1 || !flushed[1][0].denied || m.ConntrackFlushFailing() {
		t.Fatalf("a failed cut was not retried: %+v", flushed)
	}
	m.drainFlush(ctx)
	if len(flushed) != 2 {
		t.Fatalf("a successful cut ran again: %+v", flushed)
	}
}

// Under a version refusal the chain is deny-all and the last-good artifact's denies are not in force as
// rendered rules; when a supported artifact returns, its denies are cut again.
func TestDenyBaselineIsDroppedWhileTheChainIsDenyAll(t *testing.T) {
	var flushed [][]flowTuple
	var flushErr error
	m := denyFlushManager(&flushed, &flushErr)
	ctx := context.Background()
	pol := &nodepolicy.Compiled{Version: 16, Mode: nodepolicy.ModeEnforcing, Deny: []nodepolicy.DenyEntry{testDeny4}}
	if err := m.applyAndTrack(ctx, "denied", pol); err != nil {
		t.Fatal(err)
	}
	m.drainFlush(ctx)
	m.refusedVersion.Store(99)
	if err := m.applyAndTrack(ctx, "deny-all", pol); err != nil {
		t.Fatal(err)
	}
	m.drainFlush(ctx)
	m.refusedVersion.Store(0)
	if err := m.applyAndTrack(ctx, "denied", pol); err != nil {
		t.Fatal(err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 2 {
		t.Fatalf("cuts = %+v, want one before the refusal and one after it", flushed)
	}
}

// The cut is scoped to the deny's tuple: the device's other flows and other devices' flows survive. A flow
// the device opened to another address that is DNATed to the denied server is cut too.
func TestDeniedTupleMatchesOnlyItsOwnFlows(t *testing.T) {
	tuple, ok := tupleFromDeny(testDeny4)
	if !ok {
		t.Fatal("deny tuple refused")
	}
	if !matchesTuple(con("10.99.0.7", "172.30.0.10", 6, 9000), tuple) {
		t.Fatal("the denied flow was not matched")
	}
	for name, c := range map[string]conntrack.Con{
		"another device":      con("10.99.0.8", "172.30.0.10", 6, 9000),
		"another port":        con("10.99.0.7", "172.30.0.10", 6, 5432),
		"another server":      con("10.99.0.7", "172.30.0.11", 6, 9000),
		"another protocol":    con("10.99.0.7", "172.30.0.10", 17, 9000),
		"the gateway's proxy": con("10.99.0.1", "172.30.0.10", 6, 9000),
	} {
		if matchesTuple(c, tuple) {
			t.Fatalf("%s: an innocent flow would be cut", name)
		}
	}
	dnat := con("10.99.0.7", "100.64.0.5", 6, 80)
	dnat.Reply = &conntrack.IPTuple{Src: ipp("172.30.0.10"), Dst: ipp("10.99.0.7"), Proto: &conntrack.ProtoTuple{Number: u8p(6), SrcPort: u16p(9000)}}
	if !matchesTuple(dnat, tuple) {
		t.Fatal("a flow DNATed to the denied server was not matched")
	}
	other := con("10.99.0.7", "100.64.0.5", 6, 80)
	other.Reply = &conntrack.IPTuple{Src: ipp("172.30.0.10"), Dst: ipp("10.99.0.7"), Proto: &conntrack.ProtoTuple{Number: u8p(6), SrcPort: u16p(5432)}}
	if matchesTuple(other, tuple) {
		t.Fatal("a flow DNATed to another port of the server would be cut")
	}
	// The reply match belongs to denies only: a withdrawn grant keeps its origin-tuple scope.
	grant, _ := tupleFromAllow(nodepolicy.AllowEntry{SrcIP: "10.99.0.7", DstCIDR: "172.30.0.10/32", Protocol: "tcp", PortLow: 9000, PortHigh: 9000})
	if matchesTuple(dnat, grant) {
		t.Fatal("a withdrawn grant's flush widened to the reply tuple")
	}
}
