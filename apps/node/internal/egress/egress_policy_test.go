//go:build linux

package egress

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Fail-closed + staleness (decisions 4b / #1): a FAILED apply must NOT advance the
// applied status — the kernel keeps the previous ruleset in force, so applied stays at
// the last-good version while desired moves ahead (STALE, and surfaced via applyErr).
// The applier is injected so this is provable without a real nft/kernel; the kernel's
// transactional rollback itself is a box proof (runbook #7).
func TestApplyFailureLeavesAppliedStale(t *testing.T) {
	m := New("wg0")
	m.apply = func(context.Context, string) error { return nil } // inject: nft not present in CI unit env

	// First: a good apply of policy version 1 records applied=1 + the CANONICAL policy
	// hash (nodepolicy.CanonicalHash — the same bytes the control plane hashes; NEVER
	// the ruleset text, which carries node-local subnet state).
	v1 := &nodepolicy.Compiled{Version: 1, Mode: nodepolicy.ModeEnforcing, Mesh: false}
	m.SetPolicy(v1)
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), v1); err != nil {
		t.Fatalf("good apply: %v", err)
	}
	if v, h, fs, e := m.AppliedStatus(); v != 1 || h != nodepolicy.CanonicalHash(v1) || e != nil || !fs.IsZero() {
		t.Fatalf("after good apply want v=1, canonical hash, nil err; got v=%d h=%q e=%v", v, h, e)
	}
	goodHash := nodepolicy.CanonicalHash(v1)

	// Now: desired advances to version 2, but the apply FAILS (bad ruleset / no nft).
	boom := errors.New("nft apply: rejected")
	m.apply = func(context.Context, string) error { return boom }
	v2 := &nodepolicy.Compiled{Version: 2, Mode: nodepolicy.ModeEnforcing, Mesh: false}
	m.SetPolicy(v2)
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), v2); !errors.Is(err, boom) {
		t.Fatalf("failed apply must return the error; got %v", err)
	}
	v, h, fs, e := m.AppliedStatus()
	_ = fs
	if v != 1 || h != goodHash {
		t.Fatalf("applied must stay at the last-good (v=1) on failure; got v=%d h=%q", v, h)
	}
	if !errors.Is(e, boom) {
		t.Fatalf("apply error must be surfaced for staleness; got %v", e)
	}
	// desired (2) != applied (1) => STALE, visible to the control plane.
	if m.desiredVersion() == v {
		t.Fatal("desired should have advanced past applied (stale not detectable)")
	}
}

const blanketV4 = `iifname "wg0" oifname "wg0" counter accept`

// Mesh / nil policy renders the LEGACY blanket mesh — no behavior change when Zero
// Trust is off (or in the open build, which never sets a policy).
func TestRulesetMeshIsBlanket(t *testing.T) {
	for _, pol := range []*nodepolicy.Compiled{nil, {Mode: nodepolicy.ModeOff, Mesh: true}} {
		m := New("wg0")
		m.SetPolicy(pol)
		rs := m.ruleset("10.99.0.1/24")
		if !strings.Contains(rs, blanketV4) {
			t.Fatalf("mesh must keep the wg0<->wg0 blanket accept; got:\n%s", rs)
		}
		if !strings.Contains(rs, `iifname "wg0" oifname != "wg0" counter accept`) {
			t.Fatalf("mesh must keep the egress blanket accept; got:\n%s", rs)
		}
	}
}

// TestMeshSymmetricSiteForward — S8.2c D1: mesh mode must forward a behind-gateway host's LAN→tunnel
// traffic to APPROVED REMOTE SITE SUBNETS (the Routes), symmetric with the wg0-ingress accepts — mesh
// means "no doors". SCOPED to the routes so the S3.7 spoke-isolation HOLDS: the device pool (10.99.x)
// is NEVER a Route, so the egress LAN still cannot initiate into device spokes.
func TestMeshSymmetricSiteForward(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{
		Mode: nodepolicy.ModeOff, Mesh: true,
		Routes: []nodepolicy.Route{{DstCIDR: "172.31.0.0/16"}, {DstCIDR: "10.2.0.0/24"}},
	})
	rs := m.ruleset("10.99.0.1/24")
	// LAN→tunnel now accepted, scoped to each remote site subnet.
	if !strings.Contains(rs, `iifname != "wg0" oifname "wg0" ip daddr 172.31.0.0/16 counter accept`) {
		t.Fatalf("mesh must forward LAN->tunnel to the approved site subnet 172.31.0.0/16; got:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname != "wg0" oifname "wg0" ip daddr 10.2.0.0/24 counter accept`) {
		t.Fatalf("mesh must forward LAN->tunnel to 10.2.0.0/24; got:\n%s", rs)
	}
	// SPOKE-ISOLATION HOLDS: no BLANKET LAN->tunnel (the device pool 10.99.x must stay unreachable from
	// the egress LAN — the S3.7 stance). Only route-scoped daddr rules, never a bare LAN->tunnel accept.
	if strings.Contains(rs, `iifname != "wg0" oifname "wg0" counter accept`) {
		t.Fatalf("mesh must NOT open a BLANKET LAN->tunnel (spoke-isolation) — only route-scoped; got:\n%s", rs)
	}
	// A gateway with NO routes (no remote sites) emits NO LAN->tunnel rule (nothing to reach).
	m2 := New("wg0")
	m2.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true})
	if strings.Contains(m2.ruleset("10.99.0.1/24"), `iifname != "wg0" oifname "wg0"`) {
		t.Fatal("mesh with no routes must emit no LAN->tunnel rule")
	}
}

// Enforcing renders DEFAULT-DENY: the compiled allows, in order, and CRUCIALLY no
// wg0<->wg0 blanket accept anywhere (the S7.1 structural guard, now on the wire — 3c).
func TestRulesetEnforcingDefaultDenyNoBlanket(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{
		Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
			{SrcIP: "10.99.0.10", DstCIDR: "10.99.0.20/32", Protocol: "any"},
		},
	})
	rs := m.ruleset("10.99.0.1/24")

	if strings.Contains(rs, blanketV4) {
		t.Fatalf("enforcing must NOT emit the wg0<->wg0 blanket accept; got:\n%s", rs)
	}
	if !strings.Contains(rs, "policy drop") {
		t.Fatal("enforcing must keep the forward policy drop base")
	}
	if !strings.Contains(rs, "ip saddr 10.99.0.10 ct original ip daddr 10.0.5.0/24 tcp dport 5432 counter accept") {
		t.Fatalf("missing the resource allow; got:\n%s", rs)
	}
	if !strings.Contains(rs, "ip saddr 10.99.0.10 ct original ip daddr 10.99.0.20/32 counter accept") {
		t.Fatalf("missing the device-to-device allow; got:\n%s", rs)
	}
	// The masquerade still NATs allowed egress.
	if !strings.Contains(rs, "masquerade") {
		t.Fatal("masquerade must remain for allowed egress")
	}
}

// Enforcing with ZERO allows = deny-all: drop base, no allows, no blanket (empty !=
// permissive, on the wire).
func TestRulesetEnforcingEmptyIsDenyAll(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Mesh: false})
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, blanketV4) {
		t.Fatal("empty enforcing must not be permissive (no blanket)")
	}
	if !strings.Contains(rs, "policy drop") {
		t.Fatal("empty enforcing must still drop by default")
	}
	if strings.Contains(rs, "ip daddr") { // allow rules carry `ip daddr`; the masquerade (ip saddr) does not
		t.Fatalf("empty enforcing must emit no allow rules; got:\n%s", rs)
	}
}

// Idempotence (4c): the same Compiled renders byte-identical ruleset text, so a
// steady-state reconcile is a no-op.
func TestRulesetDeterministic(t *testing.T) {
	pol := &nodepolicy.Compiled{
		Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "0.0.0.0/0", Protocol: "any"},
			{SrcIP: "10.99.0.11", DstCIDR: "10.0.5.0/24", Protocol: "udp", PortLow: 53, PortHigh: 53},
		},
	}
	m := New("wg0")
	m.SetPolicy(pol)
	a := m.ruleset("10.99.0.1/24")
	b := m.ruleset("10.99.0.1/24")
	if a != b {
		t.Fatal("ruleset must be deterministic for equal input")
	}
	// Order is preserved from the (already-sorted) compiler output.
	iA := strings.Index(a, "10.99.0.10")
	iB := strings.Index(a, "10.99.0.11")
	if iA < 0 || iB < 0 || iA > iB {
		t.Fatalf("allow order not preserved:\n%s", a)
	}
}

// renderAllow re-emits every field through netip (canonical numeric) so nothing can
// inject nft statements, and skips what it can't safely render.
// rule_id (v2, S7.5.1) is OBSERVABILITY metadata. SPLIT assertion (the A-1 law at FULL
// strength on the packet-fate part, NOT a loosening):
//
//	(i)  the ENFORCEMENT clause (match + counter + verdict) is BYTE-IDENTICAL with and
//	     without rule_id — the part that decides accept/drop never depends on rule_id;
//	(ii) rule_id appears ONLY inside the log clause, which is the SOLE delta of the logged
//	     variant and is NON-TERMINAL (the accept verdict is unchanged).
func TestRenderAllowRuleIDOnlyInLogClause(t *testing.T) {
	base := nodepolicy.AllowEntry{SrcIP: "10.99.0.7", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432}
	withID := base
	withID.RuleID = "019f6400-0000-7000-8000-000000000a01"

	// (i) enforcement byte-identical regardless of rule_id, ending in the verdict.
	enf1, ok1 := renderAllow(base)
	enf2, ok2 := renderAllow(withID)
	if !ok1 || !ok2 || enf1 != enf2 {
		t.Fatalf("enforcement clause must be byte-identical w/ and w/o rule_id: %q vs %q", enf1, enf2)
	}
	if !strings.HasSuffix(enf1, " accept\n") {
		t.Fatalf("enforcement clause must end in the accept verdict: %q", enf1)
	}
	if strings.Contains(enf1, "019f6400-0000-7000-8000-000000000a01") {
		t.Fatalf("enforcement clause must NOT carry rule_id (observability never touches packet fate): %q", enf1)
	}

	// (ii) the logged variant keeps the accept verdict and carries rule_id ONLY in the log
	// clause, which is the SOLE delta vs the enforcement line.
	logged, ok := renderAllowLogged(withID, 5)
	if !ok {
		t.Fatal("renderAllowLogged skipped a valid entry")
	}
	if !strings.HasSuffix(logged, " accept\n") {
		t.Fatalf("logged line must keep the accept verdict (log is non-terminal): %q", logged)
	}
	delta := logClause(flowlog.EncodePrefix("019f6400-0000-7000-8000-000000000a01"), 5)
	if !strings.Contains(delta, "019f6400-0000-7000-8000-000000000a01") {
		t.Fatalf("the delta (log clause) must carry rule_id: %q", delta)
	}
	if strings.Replace(logged, delta, "", 1) != enf1 {
		t.Fatalf("the log clause must be the SOLE delta vs enforcement:\n logged=%q\n enf=%q\n delta=%q", logged, enf1, delta)
	}
}

// forwardRules: flow logging OFF (default) renders NO log clause — the enforcement ruleset
// is exactly pre-S7.5.1 (safety default). Logging ON adds the rule_id + deny log clauses
// while every verdict line still ends accept/drop.
func TestForwardRulesFlowLogGrouping(t *testing.T) {
	// rule_id must be a canonical UUID — renderAllowLogged validates it (fold-2 #7), so a fake
	// "rid-1" would (correctly) render NO log clause. Use a real uuid, matching what the
	// compiler always stamps.
	const rid = "019f645f-0f5b-74a7-ba0a-fdaca4fca917"
	pol := &nodepolicy.Compiled{Version: 2, Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{
		{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: rid},
	}}
	m := New("wg0")

	v4off, _ := m.forwardRules(pol, true)
	if strings.Contains(v4off, "log prefix") {
		t.Fatalf("flow logging OFF must render NO log clause (safety default): %q", v4off)
	}

	m.SetFlowLogGroup(5)
	v4on, _ := m.forwardRules(pol, true)
	if !strings.Contains(v4on, `log prefix "tnx:`+rid+` " group 5`) {
		t.Fatalf("logging ON must carry the rule_id log clause: %q", v4on)
	}
	if !strings.Contains(v4on, `log prefix "tnx:deny " group 5`) {
		t.Fatalf("logging ON must log denies (flow-start): %q", v4on)
	}
	if !strings.Contains(v4on, " accept\n") {
		t.Fatalf("allow verdict must be preserved with logging on: %q", v4on)
	}
	// The deny tail's verdict must come BEFORE the trailing comment. nft requires `comment`
	// to be the LAST token in a rule; the box-walk caught the inverted `counter comment ...
	// drop` form as a hard syntax error that made the whole atomic apply fail (stranding the
	// gateway at cold-start deny-all). Asserting `drop\n` (as this test once did) ENCODED the
	// bug — it only matched the invalid ordering. Parse-validated by TestEnforcingLoggedRulesetIsValidNft.
	if !strings.Contains(v4on, "counter drop comment \"tunnex_default_drop\"\n") {
		t.Fatalf("deny verdict must precede the trailing comment (valid nft): %q", v4on)
	}
	// The enforcement match is present with and without logging (packet fate unchanged).
	const match = "ip saddr 10.99.0.10 ct original ip daddr 10.0.5.0/24"
	if !strings.Contains(v4off, match) || !strings.Contains(v4on, match) {
		t.Fatalf("the enforcement match must be present regardless of logging:\n off=%q\n on=%q", v4off, v4on)
	}
}

// TestEnforcingLoggedRulesetIsValidNft is the regression guard for the box-walk finding:
// the logged deny tail rendered `counter comment "..." drop`, which nft REJECTS (`comment`
// must be the last token in a rule). Because the whole ruleset is ONE atomic `nft -f -`
// transaction, that one bad line failed EVERY enforcing apply — silently stranding the
// gateway at its cold-start deny-all (fail-closed, but the policy never landed). The other
// egress tests string-check the render but never PARSE it, so the class slipped. This test
// shells `nft -c` (check/parse only — no commit) on the rendered enforcing+logging ruleset.
// It fails ONLY on a detected syntax error; where nft is absent or refuses without privilege
// it SKIPS (the box-walk host applies the real ruleset, the ultimate proof).
func TestEnforcingLoggedRulesetIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not present; parse-guard runs on the box-walk host / nftables-equipped CI")
	}
	m := New("wg0")
	m.SetFlowLogGroup(100)
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 2, Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.2", DstCIDR: "10.99.0.3/32", Protocol: "any", RuleID: "019f6400-0000-7000-8000-000000000b01"},
			{SrcIP: "10.99.0.2", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: "019f6400-0000-7000-8000-000000000b02"},
		},
	})
	rs := m.ruleset("10.99.0.1/24")
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return // parses clean
	}
	if strings.Contains(strings.ToLower(string(out)), "syntax error") {
		t.Fatalf("rendered enforcing+logging ruleset is invalid nft (box-walk regression):\n%s\nRULESET:\n%s", out, rs)
	}
	t.Skipf("nft check inconclusive (likely needs privilege in this env): %v: %s", err, out)
}

// review #7: rule_id (the one non-numeric renderer field) is validated to the canonical UUID
// shape before entering the root nft ruleset. A valid uuid rides the log prefix; a malformed
// / injection-shaped rule_id renders the accept WITHOUT a log clause — never an empty prefix
// (which EncodePrefix encodes as the DENY sentinel, misclassifying the accepted flow) and
// never a raw interpolation. Enforcement (accept) is unaffected either way.
func TestRenderAllowLoggedValidatesRuleID(t *testing.T) {
	base := nodepolicy.AllowEntry{SrcIP: "10.99.0.2", DstCIDR: "10.0.5.0/24", Protocol: "any"}

	good := base
	good.RuleID = "019f645f-0f5b-74a7-ba0a-fdaca4fca917"
	line, ok := renderAllowLogged(good, 100)
	if !ok || !strings.Contains(line, `log prefix "tnx:019f645f-0f5b-74a7-ba0a-fdaca4fca917 " group 100`) {
		t.Fatalf("valid rule_id must ride the log prefix: %q", line)
	}

	bad := base
	bad.RuleID = `x" ; add rule ip tunnex forward accept ; log prefix "y`
	line, ok = renderAllowLogged(bad, 100)
	if !ok {
		t.Fatal("a bad rule_id must not skip the rule (enforcement unaffected)")
	}
	if strings.Contains(line, "log prefix") {
		t.Fatalf("malformed rule_id must render NO log clause, never interpolate: %q", line)
	}
	if strings.Contains(line, "tnx:deny") {
		t.Fatalf("a malformed ALLOW rule_id must NOT collapse to the deny sentinel: %q", line)
	}
	if !strings.HasSuffix(line, " accept\n") {
		t.Fatalf("verdict must stay accept: %q", line)
	}
}

func TestRenderAllowSanitizesAndSkips(t *testing.T) {
	// Injection attempt in SrcIP -> skipped (not parseable as an IP).
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1; add rule ip tunnex forward accept", DstCIDR: "10.0.0.0/24"}); ok {
		t.Fatal("a non-IP SrcIP (injection) must be skipped")
	}
	// v6 destination -> skipped (v4 spokes; v6 stays default-deny).
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "2001:db8::/32"}); ok {
		t.Fatal("a v6 destination must be skipped")
	}
	// Bad CIDR -> skipped.
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "not-a-cidr"}); ok {
		t.Fatal("a malformed CIDR must be skipped")
	}
	// Valid any-proto egress grant.
	line, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.99.0.7", DstCIDR: "0.0.0.0/0", Protocol: "any"})
	if !ok || !strings.Contains(line, "ip saddr 10.99.0.7 ct original ip daddr 0.0.0.0/0 counter accept") {
		t.Fatalf("valid egress grant mis-rendered: %q", line)
	}
	// Host bits in dst are masked (defense-in-depth; the service already canonicalizes).
	line, _ = renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.5/24", Protocol: "any"})
	if !strings.Contains(line, "ip daddr 10.0.5.0/24") {
		t.Fatalf("dst not canonicalized: %q", line)
	}
	// tcp with no ports -> ip protocol clause.
	line, _ = renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp"})
	if !strings.Contains(line, "ip protocol tcp counter accept") {
		t.Fatalf("tcp-no-ports mis-rendered: %q", line)
	}
	// port range.
	line, _ = renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 8000, PortHigh: 9000})
	if !strings.Contains(line, "tcp dport 8000-9000 counter accept") {
		t.Fatalf("port range mis-rendered: %q", line)
	}
}

// failingSince (finding #3) is the mismatch ONSET: zero while apply is healthy, set
// on the FIRST failure, cleared on the next success. This is what the control plane's
// stale window measures — so a normal push that applies never registers stale.
func TestFailingSinceMismatchOnset(t *testing.T) {
	m := New("wg0")
	tick := time.Unix(1000, 0)
	m.now = func() time.Time { return tick }

	// Healthy apply -> no failingSince (a normal push is never stale).
	m.apply = func(context.Context, string) error { return nil }
	m.SetPolicy(&nodepolicy.Compiled{Version: 1, Mode: nodepolicy.ModeEnforcing})
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), m.policy.Load()); err != nil {
		t.Fatal(err)
	}
	if _, _, fs, _ := m.AppliedStatus(); !fs.IsZero() {
		t.Fatalf("healthy apply must leave failingSince zero, got %v", fs)
	}

	// First failure stamps the onset.
	m.apply = func(context.Context, string) error { return errFail }
	tick = time.Unix(2000, 0)
	m.SetPolicy(&nodepolicy.Compiled{Version: 2, Mode: nodepolicy.ModeEnforcing})
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), m.policy.Load())
	_, _, fs1, _ := m.AppliedStatus()
	if !fs1.Equal(time.Unix(2000, 0)) {
		t.Fatalf("first failure must stamp onset=2000, got %v", fs1)
	}
	// A SECOND failure does NOT move the onset (measures duration from first fail).
	tick = time.Unix(2050, 0)
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), m.policy.Load())
	if _, _, fs2, _ := m.AppliedStatus(); !fs2.Equal(time.Unix(2000, 0)) {
		t.Fatalf("onset must not advance on repeated failure, got %v", fs2)
	}
	// Recovery clears it.
	m.apply = func(context.Context, string) error { return nil }
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), m.policy.Load()); err != nil {
		t.Fatal(err)
	}
	if _, _, fs3, e := m.AppliedStatus(); !fs3.IsZero() || e != nil {
		t.Fatalf("recovery must clear failingSince, got fs=%v err=%v", fs3, e)
	}
}

var errFail = fmtErr("nft apply: rejected")

type fmtErr string

func (e fmtErr) Error() string { return string(e) }

// Finding #2 (three states): a Manager that has NEVER received a policy renders
// DENY-ALL (drop + ct only), NOT the blanket mesh — fail-closed cold start. This is
// distinct from nil-in-received (= mesh, asserted by TestRulesetMeshIsBlanket, which
// calls SetPolicy). The absent=Mesh contract is thus SPLIT: nil-in-received=mesh,
// never-received=deny.
func TestNeverReceivedIsDenyAllNotMesh(t *testing.T) {
	m := New("wg0") // no SetPolicy call -> policyReceived is false
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, blanketV4) {
		t.Fatalf("cold start (no policy received) must NOT render the blanket mesh; got:\n%s", rs)
	}
	if !strings.Contains(rs, "policy drop") || !strings.Contains(rs, "tunnex_default_drop") {
		t.Fatal("cold start must be deny-all (policy drop + default_drop counter)")
	}
	if strings.Contains(rs, "ip daddr") {
		t.Fatal("cold start must emit no allow rules")
	}
	// Once a nil policy is RECEIVED (an off org's first fetch), it becomes the mesh.
	m.SetPolicy(nil)
	if !strings.Contains(m.ruleset("10.99.0.1/24"), blanketV4) {
		t.Fatal("nil-in-received must render the blanket mesh")
	}
}

// S8.1 D1 fail-closed gate: an artifact whose Version exceeds MaxSupportedVersion is REFUSED —
// the agent goes DENY-ALL (never a best-effort apply of a shape it can't interpret, and NEVER a
// fall-through to the legacy mesh — fail-OPEN) and reports the refused version. The Mesh:true here
// is deliberate: a too-new artifact that WOULD open the blanket must still deny-all. A subsequent
// supported version clears the refusal and renders normally.
func TestUnsupportedVersionRefusedIsDenyAll(t *testing.T) {
	m := New("wg0")
	tooNew := &nodepolicy.Compiled{
		Version: nodepolicy.MaxSupportedVersion + 1,
		Mode:    "enforcing",
		Mesh:    true, // would normally open the blanket mesh — the refusal MUST override this
		Allow:   []nodepolicy.AllowEntry{{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "any"}},
	}
	m.SetPolicy(tooNew)
	if m.RefusedVersion() != nodepolicy.MaxSupportedVersion+1 {
		t.Fatalf("RefusedVersion = %d, want %d", m.RefusedVersion(), nodepolicy.MaxSupportedVersion+1)
	}
	// Note-2 pin: the agent must NEVER report the refused artifact's hash as applied — that would
	// read synced-and-healthy to the CP desync detector, contradicting the degraded kind. Structural:
	// SetPolicy does not STORE the refused artifact, so applyAndTrack only ever hashes the last-good
	// (or nil) policy — the refused artifact is never passed to CanonicalHash. Here (never applied) the
	// applied hash is empty, and specifically not the refused artifact's hash.
	if _, h, _, _ := m.AppliedStatus(); h == nodepolicy.CanonicalHash(tooNew) {
		t.Fatal("refused artifact's hash must not be reported as applied (would read synced-healthy)")
	}
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, blanketV4) {
		t.Fatalf("a refused (unsupported-version) artifact must NOT render the mesh, even with Mesh:true; got:\n%s", rs)
	}
	if strings.Contains(rs, "ip daddr") {
		t.Fatal("a refused artifact must emit NO allow rules")
	}
	if !strings.Contains(rs, "policy drop") || !strings.Contains(rs, "tunnex_default_drop") {
		t.Fatal("a refused artifact must be deny-all (policy drop + default_drop counter)")
	}
	// A supported version CLEARS the refusal and renders normally.
	m.SetPolicy(&nodepolicy.Compiled{Version: nodepolicy.MaxSupportedVersion, Mesh: true})
	if m.RefusedVersion() != 0 {
		t.Fatal("a supported version must CLEAR the refusal")
	}
	if !strings.Contains(m.ruleset("10.99.0.1/24"), blanketV4) {
		t.Fatal("after clearing the refusal, a mesh policy must render the blanket mesh")
	}
}

// TestInterlockOldMaxAgentRefusesSitesBump is the S8.1 Slice-3 INTERLOCK red (distinct from Slice 1's
// SYNTHETIC max+1 red). It simulates a GATED agent PINNED at the pre-sites maxSupported (3) — the
// go-forward guarantee — receiving the REAL current-version sites artifact (Version =
// nodepolicy.MaxSupportedVersion, which Slice 3 bumped to 4): it deny-alls + records the refusal.
//
// It CATCHES A NON-BUMP: if Slice 3 forgot to increment the version (MaxSupportedVersion stayed 3), the
// fed version would equal the pinned max, `4 > 3` becomes `3 > 3` (false), the old agent would ACCEPT
// the sites artifact, and the guard below fails loudly. (This simulates a GATED old binary; a genuinely
// UNGATED pre-S8.1 binary has no gate and silently accepts — the go-forward-only residual, papered in
// D1, owed the upgrade-order sentence in the S8 upgrade docs.)
func TestInterlockOldMaxAgentRefusesSitesBump(t *testing.T) {
	const preSitesMax = 3 // the pre-S8.1 maxSupported — this test simulates THAT exact gated agent
	if nodepolicy.MaxSupportedVersion <= preSitesMax {
		t.Fatalf("NON-BUMP: Slice 3 must increment MaxSupportedVersion above the pre-sites max %d (got %d) — "+
			"otherwise the sites artifact is applied unbumped and the version gate never fires", preSitesMax, nodepolicy.MaxSupportedVersion)
	}
	m := New("wg0")
	m.maxPolicyVersion = preSitesMax // pin the OLD-max gated agent
	// The REAL current sites artifact (Mesh:true — a would-open shape, to prove refusal overrides it).
	m.SetPolicy(&nodepolicy.Compiled{Version: nodepolicy.MaxSupportedVersion, Mode: "enforcing", Mesh: true})
	if m.RefusedVersion() != nodepolicy.MaxSupportedVersion {
		t.Fatalf("a gated agent at the pre-sites max (%d) must REFUSE the current v%d sites artifact; RefusedVersion=%d",
			preSitesMax, nodepolicy.MaxSupportedVersion, m.RefusedVersion())
	}
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, blanketV4) || strings.Contains(rs, "ip daddr") {
		t.Fatal("the refused sites artifact must render DENY-ALL, not mesh/allows")
	}
}

// TestSiteSourceCIDRRendersAndRoutedButDropped — S8.2 Slice-1 SECURITY SPINE (D3 routed-but-dropped) +
// the LAN-source render. An enforcing v5 artifact with a site→site grant renders a CIDR-SOURCE accept
// (`ip saddr <LAN-CIDR>`) — the v4 renderer's ParseAddr would have skipped it. The SAME enforcing gateway
// WITHOUT the grant renders default-deny: a routed site subnet with no grant is DROPPED at the forward
// chain (routing ≠ permission), provable at the enforcement layer BEFORE any propagation plumbing exists.
func TestSiteSourceCIDRRendersAndRoutedButDropped(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 5, Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24", Protocol: "any"}},
	})
	if rs := m.ruleset("10.99.0.1/24"); !strings.Contains(rs, "ip saddr 10.1.0.0/24 ct original ip daddr 10.2.0.0/24 counter accept") {
		t.Fatalf("a v5 site→site (CIDR source) grant must render a LAN-source accept; got:\n%s", rs)
	}
	// Routed-but-DROPPED: the same enforcing gateway WITHOUT the grant → no accept for that subnet.
	m.SetPolicy(&nodepolicy.Compiled{Version: 4, Mode: nodepolicy.ModeEnforcing, Mesh: false})
	rs2 := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs2, "10.2.0.0/24") {
		t.Fatalf("a routed site subnet with NO grant must be DROPPED (no accept); got:\n%s", rs2)
	}
	if !strings.Contains(rs2, "policy drop") {
		t.Fatal("routed-but-dropped must keep the default-deny drop")
	}
}

// TestMSSClampOnIntraTunnelForward — S8.2 D9 (Slice 3): the forward chain clamps intra-tunnel (wg0→wg0)
// TCP SYN MSS to the path MTU — the double-encapsulation "ping works, large transfer freezes" fix.
// Node-local rendered rule, scoped to wg0→wg0 so device internet egress is untouched.
func TestMSSClampOnIntraTunnelForward(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Mesh: false})
	rs := m.ruleset("10.99.0.1/24")
	if !strings.Contains(rs, `iifname "wg0" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu`) {
		t.Fatalf("forward chain must clamp intra-tunnel TCP MSS to path MTU; got:\n%s", rs)
	}
}

// TestSiteToSiteNotMasqueraded — S8.2 Item 8 PINNED INVARIANT: site-to-site traffic (wg0→wg0) is NEVER
// NATed. The masquerade rule is scoped `oifname != "wg0"` (internet egress only), so a future scope
// change can't silently start NATing site traffic (which would break return routing — both LANs need
// their real addresses). Structural pin on the rendered rule.
func TestSiteToSiteNotMasqueraded(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Mesh: false})
	rs := m.ruleset("10.99.0.1/24")
	if !strings.Contains(rs, `oifname != "wg0" masquerade`) {
		t.Fatalf("masquerade must be scoped oifname != wg0 (wg0→wg0 site traffic never NATed); got:\n%s", rs)
	}
}

// TestInterlockV4AgentRefusesV5 — S8.2 Slice-1 interlock: a GATED agent pinned at the pre-S8.2 max (4)
// receiving the REAL v5 LAN-source artifact REFUSES it (deny-all + records the refusal) rather than
// silently SKIPPING the CIDR source (which the old allowMatch would do → office-to-office blackholes
// while green). This is the go-forward guarantee on the exact v4→v5 event the box-walk's Leg-1 proves
// live. Catches a non-bump: if S8.2 forgot to bump above 4, the v5 feature would ride v4 and the old
// agent would accept it.
func TestInterlockV4AgentRefusesV5(t *testing.T) {
	const preS82Max = 4
	if nodepolicy.MaxSupportedVersion <= preS82Max {
		t.Fatalf("NON-BUMP: S8.2 must bump MaxSupportedVersion above %d (got %d)", preS82Max, nodepolicy.MaxSupportedVersion)
	}
	m := New("wg0")
	m.maxPolicyVersion = preS82Max // pin the pre-S8.2 gated agent
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 5, Mode: "enforcing", Mesh: false,
		Allow: []nodepolicy.AllowEntry{{SrcIP: "10.1.0.0/24", DstCIDR: "10.2.0.0/24", Protocol: "any"}},
	})
	if m.RefusedVersion() != 5 {
		t.Fatalf("a v4-max agent must REFUSE a v5 artifact; RefusedVersion=%d", m.RefusedVersion())
	}
	if rs := m.ruleset("10.99.0.1/24"); strings.Contains(rs, "ip daddr") {
		t.Fatal("a refused v5 artifact must render DENY-ALL (no accepts)")
	}
}

// S10.3 v7 interlock (F3 condition 2a): an agent pinned at the pre-S10.3 max (6) REFUSES a v7 artifact
// carrying a VIP map, keeping DENY-ALL (fail-static) rather than mis-serving an exposed Service it has no
// DNAT/DNS-rewrite render for. The CP surfacing half (unsupported_ver) is the agent-reported RefusedVersion
// flowing to policyhealth's KindUnsupportedPolicyVersion — version-agnostic, so v7 rides the existing path.
func TestInterlockV6AgentRefusesV7VIPMap(t *testing.T) {
	const preK8sMax = 6
	if nodepolicy.MaxSupportedVersion <= preK8sMax {
		t.Fatalf("NON-BUMP: S10.3 must bump MaxSupportedVersion above %d (got %d)", preK8sMax, nodepolicy.MaxSupportedVersion)
	}
	m := New("wg0")
	m.maxPolicyVersion = preK8sMax // pin the pre-S10.3 gated agent
	m.SetPolicy(&nodepolicy.Compiled{
		Version: 7, Mode: "enforcing", Mesh: false,
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "100.64.0.5", Namespace: "prod", Service: "api"}},
	})
	if m.RefusedVersion() != 7 {
		t.Fatalf("a v6-max agent must REFUSE a v7 VIP-map artifact; RefusedVersion=%d", m.RefusedVersion())
	}
	if rs := m.ruleset("10.99.0.1/24"); strings.Contains(rs, "ip daddr") {
		t.Fatal("a refused v7 artifact must render DENY-ALL (fail-static, no accepts)")
	}
}

// Finding #1: a half-set / inverted port range fails CLOSED (rule skipped), never
// widening to all-ports.
func TestRenderAllowHalfSetPortRangeFailsClosed(t *testing.T) {
	// only port_high set (port_low == 0) -> the old bug emitted `ip protocol tcp` (all ports).
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortHigh: 443}); ok {
		t.Fatal("port_high without port_low must be SKIPPED (fail-closed), not widened to all-ports")
	}
	// only port_low set -> also skipped.
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 443}); ok {
		t.Fatal("port_low without port_high must be skipped")
	}
	// inverted range -> skipped.
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 500, PortHigh: 400}); ok {
		t.Fatal("inverted range must be skipped")
	}
	// both unset -> any-port (valid).
	if line, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "tcp"}); !ok || !strings.Contains(line, "ip protocol tcp") {
		t.Fatalf("both-unset must be any-port, got %q ok=%v", line, ok)
	}
}

// Finding #6: an unknown/empty protocol fails CLOSED (rule skipped), never a silent
// all-protocol widen — symmetric with the half-set-port refusal. "any" is the only
// intended all-protocol grant.
func TestRenderAllowUnknownProtocolFailsClosed(t *testing.T) {
	// empty protocol -> the old switch left clause="" and emitted an all-protocol accept.
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: ""}); ok {
		t.Fatal("empty protocol must be SKIPPED (fail-closed), not widened to all-protocols")
	}
	// garbage / future protocol -> skipped.
	if _, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "sctp"}); ok {
		t.Fatal("unrecognized protocol must be skipped")
	}
	// "any" -> the intended all-protocol accept (no protocol clause).
	line, ok := renderAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1", DstCIDR: "10.0.5.0/24", Protocol: "any"})
	if !ok || strings.Contains(line, "ip protocol") || strings.Contains(line, "dport") {
		t.Fatalf("'any' must render an all-protocol accept with no protocol clause, got %q ok=%v", line, ok)
	}
}

// Finding #6: an apply failure while the policy is NOT enforcing (mesh/nil/off/open)
// is an egress-arm problem, NOT policy staleness -> must not set failingSince/applyErr.
func TestNonEnforcingApplyFailureIsNotPolicyStale(t *testing.T) {
	m := New("wg0")
	m.apply = func(context.Context, string) error { return errFail }
	// mesh policy (off org) whose nft apply fails:
	mesh := &nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true}
	m.SetPolicy(mesh)
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), mesh)
	if _, _, fs, e := m.AppliedStatus(); !fs.IsZero() || e != nil {
		t.Fatalf("non-enforcing apply failure must NOT set policy failingSince/err; got fs=%v e=%v", fs, e)
	}
	// nil policy (open build) apply failure: same.
	m.SetPolicy(nil)
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), nil)
	if _, _, fs, e := m.AppliedStatus(); !fs.IsZero() || e != nil {
		t.Fatalf("nil-policy apply failure must NOT set policy failingSince/err; got fs=%v e=%v", fs, e)
	}
}

// Finding #B: a gateway that WAS enforcing and then fails to apply the new mesh/off
// ruleset is STUCK enforcing a disabled policy — the kernel keeps the enforcing chain.
// That must be VISIBLE (applyErr surfaced), unlike a never-enforced gateway's egress-arm
// failure (#6). "silent stale policy = violation in slow motion", found live.
func TestFailedEnforcingToOffApplySurfacesStuckEnforcing(t *testing.T) {
	m := New("wg0")
	m.apply = func(context.Context, string) error { return nil }
	// Enforcing is applied and in force.
	enf := &nodepolicy.Compiled{Version: 1, Mode: nodepolicy.ModeEnforcing, Mesh: false}
	m.SetPolicy(enf)
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), enf); err != nil {
		t.Fatalf("enforcing apply: %v", err)
	}

	// Admin disables ZT -> control plane pushes mesh (off) -> but the apply FAILS.
	m.apply = func(context.Context, string) error { return errFail }
	mesh := &nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true}
	m.SetPolicy(mesh)
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), mesh)

	// The kernel still enforces the disabled policy -> applyErr MUST be surfaced (not
	// silently cleared as a benign non-enforcing apply).
	if _, _, _, e := m.AppliedStatus(); e == nil {
		t.Fatal("a failed enforcing->off apply must surface applyErr (gateway stuck enforcing a disabled policy)")
	}

	// Once the mesh apply SUCCEEDS, the gateway is no longer enforcing -> status clears,
	// and a later mesh-apply failure is quiet again (no longer stuck-enforcing).
	m.apply = func(context.Context, string) error { return nil }
	if err := m.applyAndTrack(context.Background(), m.ruleset(""), mesh); err != nil {
		t.Fatalf("mesh apply recovery: %v", err)
	}
	if _, _, _, e := m.AppliedStatus(); e != nil {
		t.Fatalf("successful mesh apply must clear applyErr; got %v", e)
	}
	m.apply = func(context.Context, string) error { return errFail }
	_ = m.applyAndTrack(context.Background(), m.ruleset(""), mesh)
	if _, _, fs, e := m.AppliedStatus(); !fs.IsZero() || e != nil {
		t.Fatalf("a non-enforcing gateway's later apply failure must stay quiet; got fs=%v e=%v", fs, e)
	}
}

// TestB1EnforcingGrantHasNoInterfacePredicate (S9.1, Slice 1) LOCKS the D-S9.1-4 pre-verification:
// the enforcing per-grant accept adjudicates by ADDRESS (ip saddr / ip daddr), NEVER by interface.
// This is what makes B1 free for OpenVPN — an OVPN client's packet arriving on `tun` (not wg0)
// meets the IDENTICAL rule a WireGuard device meets, because the rule names the /32, not the wire.
// If a future change re-keys an enforcing grant on iifname/oifname (the S8.6b orientation-predicate
// trap), OVPN enforcement parity silently breaks. See docs/S9.1-decisions.md (D-S9.1-4).
//
// RENDER-level proof (the harness stubs m.apply — no nft/netns, so it asserts the ruleset SHAPE,
// not kernel packet fate). The kernel-fate + live-client proof is OWED, trigger = the S9.1 walk.
func TestB1EnforcingGrantHasNoInterfacePredicate(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{
		Mode: nodepolicy.ModeEnforcing, Mesh: false,
		Allow: []nodepolicy.AllowEntry{
			{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432},
		},
	})
	rs := m.ruleset("10.99.0.1/24")

	// the grant is present, address-keyed.
	if !strings.Contains(rs, "ip saddr 10.99.0.10 ct original ip daddr 10.0.5.0/24 tcp dport 5432 counter accept") {
		t.Fatalf("enforcing grant must be address-keyed; got:\n%s", rs)
	}
	// no line carrying this grant's source may be scoped by an interface predicate.
	for _, ln := range strings.Split(rs, "\n") {
		if strings.Contains(ln, "ip saddr 10.99.0.10") &&
			(strings.Contains(ln, "iifname") || strings.Contains(ln, "oifname")) {
			t.Fatalf("B1: an enforcing grant must NOT carry an interface predicate "+
				"(would miss OVPN tun ingress); offending line:\n%s", ln)
		}
	}
}

// TestB1EnforcingUngrantedPoolIPDropped (S9.1, Slice 1) LOCKS the B1 deliberate-red at render
// level: an enforcing gateway with a pool /32 present but NO grant for it emits no accept for that
// /32 — it falls to the default-deny drop, exactly as WireGuard would. The wire form (a real
// OpenVPN Connect client, enforcing + zero grants, DROPPED byte-for-byte) is OWED, trigger = the
// S9.1 box-walk after Slices 2-3 (docs/S9.1-decisions.md, B1 SUBSTITUTES != SATISFIES).
func TestB1EnforcingUngrantedPoolIPDropped(t *testing.T) {
	m := New("wg0")
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Mesh: false}) // zero grants
	rs := m.ruleset("10.99.0.1/24")
	if strings.Contains(rs, "ip daddr") { // allow rules carry ip daddr; the masquerade (ip saddr) does not
		t.Fatalf("enforcing zero-grants must emit no accept for any /32 (default-deny); got:\n%s", rs)
	}
	if !strings.Contains(rs, "policy drop") {
		t.Fatal("enforcing must keep the default-deny drop base")
	}
}

// TestOVPNTunJoinsTunnelSet_MeshAntiSpoof (S9.1 Slice 3, D-S9.3-MESH) is the MANDATORY anti-spoof
// centerpiece. Adding the co-terminated OVPN tun to the tunnel-ingress set must NOT open the S3.7
// spoke-isolation boundary: an eth0-ingress packet claiming a pool source has NO matching mesh
// accept — both blanket accepts REQUIRE tunnel-set ingress ({wg0, ovpn}, never eth0), and the only
// non-tunnel-ingress accept (LAN→tunnel) is route-daddr-scoped while the device pool is never a
// route — so the packet hits the policy-drop base. This re-proves S3.7 under the new keying.
func TestOVPNTunJoinsTunnelSet_MeshAntiSpoof(t *testing.T) {
	m := New("wg0")
	m.SetOVPNTun("tunnex-ovpn")
	m.SetPolicy(&nodepolicy.Compiled{
		Mode: nodepolicy.ModeOff, Mesh: true,
		Routes: []nodepolicy.Route{{DstCIDR: "10.2.0.0/24"}},
	})
	rs := m.ruleset("10.99.0.1/24")

	// both blanket accepts require tunnel-SET ingress — the set is {wg0, ovpn}, NOT eth0.
	if !strings.Contains(rs, `iifname { "wg0", "tunnex-ovpn" } oifname { "wg0", "tunnex-ovpn" } counter accept`) {
		t.Fatalf("device↔device accept must require tunnel-set ingress; got:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname { "wg0", "tunnex-ovpn" } oifname != { "wg0", "tunnex-ovpn" } counter accept`) {
		t.Fatalf("spoke→egress accept must require tunnel-set ingress; got:\n%s", rs)
	}
	// no BARE wg0 ingress accept survives — the tunnel set is the sole ingress key (grep-proof).
	if strings.Contains(rs, `iifname "wg0" oifname`) {
		t.Fatalf("a bare `iifname wg0` accept survived — set is not the sole ingress key:\n%s", rs)
	}
	// A native->native CNI pass-through is permitted so a host-networked Kubernetes
	// connector cannot become the node's CNI firewall. Every native->tunnel accept
	// remains route-daddr-scoped and never reaches the device pool.
	for _, ln := range strings.Split(rs, "\n") {
		if strings.Contains(ln, `iifname != {`) && strings.Contains(ln, "accept") &&
			!strings.Contains(ln, "tunnex_native_forward_passthrough") {
			if !strings.Contains(ln, "ip daddr 10.2.0.0/24") {
				t.Fatalf("native-to-tunnel accept is not route-scoped (anti-spoof hole):\n%s", ln)
			}
			if strings.Contains(ln, "10.99.") {
				t.Fatalf("non-tunnel-ingress accept reaches the pool (spoof hole):\n%s", ln)
			}
		}
	}
	if !strings.Contains(rs, "policy drop") {
		t.Fatal("mesh must keep the policy-drop base")
	}
}

// TestZeroOVPNConfigByteIdentical (S9.1 Slice 3) is the zero-config golden: with NO OVPN tun set,
// tunnelIfaces()={wg0}, ifClause renders the BARE legacy form, and a WireGuard-only deployment sees
// NOT ONE rule change from this slice (the S8.6 zero-config pattern).
func TestZeroOVPNConfigByteIdentical(t *testing.T) {
	m := New("wg0") // no SetOVPNTun
	m.SetPolicy(&nodepolicy.Compiled{Mode: nodepolicy.ModeOff, Mesh: true})
	rs := m.ruleset("10.99.0.1/24")

	if !strings.Contains(rs, `iifname "wg0" oifname "wg0" counter accept`) {
		t.Fatalf("zero-config must render the bare legacy device↔device accept; got:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname "wg0" oifname != "wg0" counter accept`) {
		t.Fatalf("zero-config must render the bare legacy spoke→egress accept; got:\n%s", rs)
	}
	if !strings.Contains(rs, `oifname != "wg0" masquerade`) {
		t.Fatalf("zero-config masquerade must be bare `oifname != wg0`; got:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname "wg0" oifname "wg0" tcp flags syn`) {
		t.Fatalf("zero-config MSS clamp must be bare wg0↔wg0; got:\n%s", rs)
	}
	// NO nft interface-set syntax anywhere — byte-identical to pre-OVPN.
	if strings.Contains(rs, "iifname {") || strings.Contains(rs, "oifname {") {
		t.Fatalf("zero-config must emit NO interface-set syntax; got:\n%s", rs)
	}
}
