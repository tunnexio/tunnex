//go:build linux

// Package egress manages the gateway's NAT + forwarding for full-tunnel egress (S3.7):
// it enables IP forwarding and installs nftables tables that source-NAT tunnel traffic
// out the host's egress interface(s) and forward spoke↔spoke + spoke↔egress. It also
// PROBES whether egress NAT is achievable (a locked-down / route-less host can't) and
// reports that as the node's egress_nat capability — the control plane refuses full-tunnel
// devices against a gateway that lacks it (gateway_no_egress).
//
// IMPLEMENTATION NOTE (deviation from the paper's "Go netlink" preference): we shell to
// `nft` with a declarative ruleset rather than build expression trees via google/nftables.
// The paper explicitly allowed "the nft binary as a fallback"; a declarative ruleset is far
// easier to get correct + review for a root data-plane primitive, at the cost of adding
// nftables to the node image (deploy/docker/node.Dockerfile). The S3.7 decisions doc is
// updated to reflect this.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// ifaceRE bounds an interface name to what the kernel allows (Linux IFNAMSIZ-1 = 15,
// alphanumeric + . _ -). wgIface comes from an operator env var and is interpolated into
// the root nft ruleset, so it MUST be validated or a crafted name could inject nft
// statements (review #4).
var ifaceRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

var (
	// IPv4 rules may carry the renderer's synthetic-VIP exclusion between the
	// interface boundary and the terminal counter. That exclusion only makes the
	// native path narrower; accept it while keeping the tunnel-boundary and
	// terminal verdict checks exact.
	nativeForwardReadbackRE = regexp.MustCompile(`^\s*iifname\s+!=\s+(\{\s*"[A-Za-z0-9._-]{1,15}"(?:\s*,\s*"[A-Za-z0-9._-]{1,15}")*\s*\}|"[A-Za-z0-9._-]{1,15}")\s+oifname\s+!=\s+(\{\s*"[A-Za-z0-9._-]{1,15}"(?:\s*,\s*"[A-Za-z0-9._-]{1,15}")*\s*\}|"[A-Za-z0-9._-]{1,15}")(?:\s+ct\s+original\s+ip\s+daddr\s+!=\s+(?:\d{1,3}\.){3}\d{1,3}|\s+ct\s+original\s+ip\s+daddr\s+!=\s+\{\s*(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3})*\s*\})?\s+counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+accept\s+comment\s+"tunnex_native_forward_passthrough"\s*$`)
	quotedIfaceRE           = regexp.MustCompile(`"([A-Za-z0-9._-]{1,15})"`)
)

// ruleIDRE bounds a rule_id (observability metadata) to the canonical UUID shape before it is
// interpolated into the root nft ruleset — the A-1 discipline applied to the one renderer
// field that isn't numeric (review #7). A non-match drops the id rather than widening trust.
var ruleIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// FQDNConntrackMarkMask reserves bits 24..27 of ct mark for S21 FQDN
// ownership. FQDNConntrackMark uses value 1 in that field. The nft expression
// clears and sets only this mask, preserving every unrelated mark bit.
const (
	FQDNConntrackMarkMask uint32 = 0x0f000000
	FQDNConntrackMark     uint32 = 0x01000000
)

// Manager reconciles the tunnex nft tables for one WG interface. It also holds the
// latest compiled Zero Trust policy (S7.2): the reconcile loop feeds it via SetPolicy
// on every desired-state fetch, and the forward chain is rendered from it — nil or
// Mesh=true keeps the legacy blanket mesh, enforcing renders default-deny + the
// compiled allow rules.
type Manager struct {
	wgIface string
	// ovpnTun is the co-terminated OpenVPN server's tun interface name (S9.1 Slice 3), threaded
	// from the OVPN server lifecycle's config — the ONE truth for the tunnel-ingress set, never
	// re-derived. Empty when no OVPN server is configured (a WireGuard-only deployment), in which
	// case tunnelIfaces() = {wg0} and every rendered rule is byte-identical to the pre-OVPN ruleset
	// (the zero-config golden).
	// ovpnTun (review #3): atomic — WRITTEN by SetOVPNTun on the reconcile goroutine every tick (OVPN
	// up/down) and READ by tunnelIfaces() on the egress-loop goroutine. A bare string was a data race
	// (-race flags it; a torn two-word read could render a garbage iifname and fail the atomic nft apply).
	// Every sibling mutable field is atomic for the same reason.
	ovpnTun atomic.Pointer[string]
	policy  atomic.Pointer[nodepolicy.Compiled]
	// dnsVIPs is the SET of cluster DNS VIPs currently assigned as /32 on the wg interface (S10.3 A1). The
	// gateway must OWN each reserved DNS VIP locally so (a) the client's DNS query to it is delivered locally
	// (not forwarded) and (b) the dnsforward bind-reconcile binds :53 on it (it enumerates wg0's addresses).
	// ReconcileDNSVIPs drives this to match the policy's K8sDNSZones; the last-applied set here lets it remove
	// a departed VIP. runIP is the injectable `ip` runner (nil → the real exec) for the reconcile red.
	dnsVIPs atomic.Pointer[[]string]
	runIP   func(ctx context.Context, args ...string) error
	// runIPOutput is the actual kernel readback path for candidate DNS VIPs.
	// It is separate from the mutation runner so a successful write can never be
	// mistaken for observation.
	runIPOutput func(ctx context.Context, args ...string) (string, error)
	// log surfaces K8s VIP resolution outcomes (WF-K-OBS-1). nil = silent (tests). Set via SetLogger.
	log *slog.Logger
	// policyReceived distinguishes "no policy fetched YET" (cold start, before the first
	// desired-state delivery) from "policy fetched, value nil = legacy mesh". THREE states
	// (finding #2): (a) received + mesh/nil -> blanket; (b) received + enforcing -> grants;
	// (c) NEVER received -> DENY-ALL regardless of mode. The initial synchronous Reconcile
	// runs before OnPolicy is wired, so without this the forward chain would render the
	// blanket mesh (fail-OPEN) on every restart of an enforcing gateway until the first
	// fetch lands. Deny-until-first-policy is fail-CLOSED; an off-mode org's brief
	// restart blip (denied until the first fetch) is the correct trade for a security
	// boundary. This SPLITS the chunk-1 absent=Mesh decision: nil-WITHIN-a-received-policy
	// = mesh (unchanged); NEVER-received != mesh = deny.
	policyReceived atomic.Bool
	// refusedVersion is the compiled-artifact Version the agent last REFUSED because it
	// exceeds nodepolicy.MaxSupportedVersion (S8.1 D1 fail-closed gate). 0 = none refused.
	// A refusal forces the forward chain to DENY-ALL (never a best-effort apply of a shape
	// the agent can't interpret, never a fall-through to legacy mesh) and is reported so the
	// control plane surfaces `unsupported_policy_version`. Cleared when a supported version
	// arrives.
	refusedVersion atomic.Int64
	// maxPolicyVersion is the highest compiled-artifact Version this agent applies (defaults to
	// nodepolicy.MaxSupportedVersion). A field, not the const directly, so the interlock red can pin
	// an OLD-max agent (S8.1 Slice 3) and feed it the current-version artifact.
	maxPolicyVersion int
	// S10.3 WF-K5 — the K8s VIP DNAT (endpoint DNAT). source reads READY pod endpoints for a Service from a
	// read-only EndpointSlice+Service watch (injectable for the classifier reds; nil on a non-cluster gateway
	// or when the in-cluster watcher failed to build — both fail closed: no view → no DNAT). resolvedVIPs is
	// the LAST-RESOLVED VIP->endpoints map the pure render reads (decoupled from the apply path so the watch
	// never stalls an nft apply); k8sUnavailable is the k8s_endpoints_unavailable health kind; refusedK8sVIPs
	// holds the fail-closed refusals for surfacing.
	source         endpointSource
	resolvedVIPs   atomic.Pointer[[]resolvedVIP]
	refusedK8sVIPs atomic.Pointer[[]refusedVIP]
	k8sUnavailable atomic.Bool
	// localIPs (WF-K5 M6) returns THIS gateway's own addresses; classify refuses a DNAT target in this set (a
	// hostNetwork endpoint on this node would DNAT->local->INPUT, bypassing the forward grant chain).
	// Injectable so the M6 red drives the refusal without real host interfaces.
	localIPs func() map[netip.Addr]struct{}
	// apply performs the atomic nft transaction; injectable so the fail-closed +
	// staleness behavior is unit-testable without a real nft/kernel.
	apply func(context.Context, string) error
	// ctFlush deletes the conntrack entries matching a removed-grant tuple set (S8.7 Slice 2), scoped exactly
	// to those tuples; injectable so the innocent-neighbor red asserts the scope without a live conntrack.
	ctFlush func(context.Context, []flowTuple) (int, error)
	// ctFlushRecovery deletes only S21-owned FQDN conntrack entries. It is used
	// after deny-all when a proven prior FQDN baseline is absent/corrupt; unrelated
	// host/CNI/CIDR flows retain their existing conntrack marks and survive.
	ctFlushRecovery func(context.Context) (int, error)
	// nftRun runs an arbitrary `nft <args...>` (list/insert/delete) and returns stdout;
	// injectable for the DOCKER-USER foreign-chain reconcile tests (WF-4). Distinct from
	// `apply` (the atomic `-f -` full-table replace) — the Docker-owned chain can't be
	// flushed, so its rules are managed one at a time by handle.
	nftRun func(context.Context, ...string) (string, error)
	// k8sNetPrep owns provider-neutral host/CNI mechanism reconciliation. Its
	// runner closes over nftRun so existing kernel-test seams remain authoritative.
	k8sNetPrep       k8sNetPrepReconciler
	k8sNetPrepStatus atomic.Pointer[string]
	k8sNetPrepReady  atomic.Bool
	kubernetesMode   atomic.Bool
	// forwardBlocked (WF-4 / D-WF4-d): true when this is a Docker host (DOCKER-USER exists),
	// FORWARD is policy-drop, there ARE remote routes to carry, yet the agent could NOT place
	// its DOCKER-USER accept — so forwarded site traffic is silently dropped by Docker's chain.
	// Surfaced as site_subnet_unreachable (the advertised subnet is not reachable via this
	// gateway) so the health surface shows it LOUD rather than blackholing green.
	forwardBlocked atomic.Bool

	mu sync.Mutex
	// applied* is the status of the LAST SUCCESSFUL apply — what is actually in force
	// on the wire. On an apply FAILURE these are left unchanged (the kernel keeps the
	// previous ruleset), so applied != desired signals STALE policy to the control
	// plane (decision 4b / staleness-visible, chunk-1 status field).
	appliedVersion int
	appliedHash    string
	// appliedSubjects belongs to the same LAST SUCCESSFUL apply as appliedHash.
	// It changes only after the atomic nft transaction succeeds, so a failed
	// candidate can never stamp next-policy identity beside a last-good hash.
	appliedSubjects map[string]nodepolicy.SubjectAttribution
	// appliedVIPMappings belongs to the same last successful atomic nft apply.
	// UID reporting must never let a failed desired policy choose identities.
	appliedVIPMappings []nodepolicy.VIPMapping
	// appliedEnforcing is whether the policy CURRENTLY IN FORCE (last successful apply) is
	// an ENFORCING one. It distinguishes the two non-enforcing apply-failure cases
	// (finding #B): a gateway that was enforcing and FAILS to apply the new mesh/off
	// ruleset is STUCK enforcing a disabled policy (surface it — silent stale policy is a
	// violation in slow motion), whereas a gateway that was never enforcing (open build /
	// off) whose egress-NAT arm fails is not a policy concern (#6 — stays quiet).
	appliedEnforcing bool
	applyErr         error
	// failingSince is the instant apply FIRST started failing (the mismatch onset),
	// cleared the moment an apply SUCCEEDS. The control plane's stale alarm measures
	// (now - failingSince), NOT the applied-hash age — so a NORMAL push that applies
	// cleanly never registers stale, and the 90s window measures the real mismatch
	// duration (box-proof finding #3). now() is injectable for tests.
	failingSince time.Time
	now          func() time.Time
	// flowLogGroup is the nflog group the forward-chain accept/deny rules log to (S7.5.1
	// flow observation). The agent defaults this to a positive group; 0 is the
	// explicit OFF value and renders no log clauses, byte-for-byte preserving
	// enforcement verdicts while disabling observation.
	flowLogGroup int
	// appliedAllow is the Allow set of the last SUCCESSFUL enforcing apply (under mu). S8.7 Slice 2: the
	// conntrack flush diffs the NEW allow set against this to find REMOVED grants (expired/deleted); a
	// removed entry's established flows are torn down. nil after a non-enforcing (mesh/off) apply — mesh is
	// more permissive, nothing to kill.
	appliedAllow []nodepolicy.AllowEntry
	// pendingFlush is the removed-grant tuple set captured under mu at apply-success, drained + flushed by
	// Reconcile OUTSIDE the lock (a netlink dump must not block status reads). This is the LIVE flush: a grant
	// leaving the applied allow set while the agent is UP. The boot-time restart reconcile (a grant revoked
	// while the agent was DOWN) was deferred to S8.7b — see the NOTE in conntrack_linux.go.
	pendingFlush []flowTuple
	// flushErr is the last conntrack-flush error (CAP_NET_ADMIN absent / netlink fault), surfaced never
	// silent — the rule removal already succeeded, the lingering flows are degraded-not-broken.
	flushErr error
	// fqdnBaselinePath stores a committed active FQDN generation and its exact
	// enforcement tuples. A pending/missing/corrupt file is never trusted.
	fqdnBaselinePath       string
	fqdnRecoveryRequired   bool
	fqdnHistoryKnown       bool
	fqdnHistorySeen        bool
	fqdnRecoveryImpossible bool
}

type k8sNetPrepReconciler interface {
	Reconcile(context.Context, string) (k8snetprep.ReconcileStatus, error)
	Withdraw(context.Context) (k8snetprep.ReconcileStatus, error)
}

// New builds a Manager for the given WireGuard interface (e.g. wg0).
func New(wgIface string) *Manager {
	m := &Manager{wgIface: wgIface, apply: nftApply, nftRun: nftRun, now: time.Now, maxPolicyVersion: nodepolicy.MaxSupportedVersion}
	m.k8sNetPrep = k8snetprep.New(wgIface, func(ctx context.Context, args ...string) (string, error) {
		if m.nftRun == nil {
			return "", fmt.Errorf("nft runner unavailable")
		}
		return m.nftRun(ctx, args...)
	})
	// The real conntrack flusher (S8.7 Slice 2); injectable so the scoped-flush wiring is unit-testable
	// without a live conntrack table (the innocent-neighbor red).
	m.ctFlush = flushTuples
	m.ctFlushRecovery = flushFQDNMarkedConntrack
	m.runIP = runIP              // S10.3 A1: the real `ip addr` runner; injectable for the DNS-VIP reconcile red
	m.runIPOutput = runIPOutput  // v3: actual post-apply address enumeration, never desired-state echo
	m.localIPs = defaultLocalIPs // WF-K5 M6: the real gateway-local address set; injectable for the local-endpoint refusal red
	m.log = slog.Default()
	// source is left nil here (WF-K5): a non-cluster gateway has no K8s endpoint watch, and a K8s gateway
	// injects the real in-cluster watcher via SetEndpointSource once it is built. nil source → every VIP
	// classify sees sourceOK=false → no DNAT (fail-closed), which is exactly right for a gateway that can't
	// read endpoints.
	return m
}

// SetFQDNBaselinePath restores the last committed FQDN tuple baseline. This
// must be called before the first policy reconcile. The sibling history marker
// distinguishes a new/CIDR-only gateway from a gateway that has proven prior
// FQDN enforcement. Only the latter needs selective marked-flow recovery.
func (m *Manager) SetFQDNBaselinePath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fqdnBaselinePath = path
	if path == "" {
		return
	}
	m.fqdnHistorySeen, m.fqdnHistoryKnown = readFQDNHistory(path + ".history")
	state, err := readFQDNBaseline(path)
	if err != nil {
		m.fqdnRecoveryRequired = m.fqdnHistoryKnown && m.fqdnHistorySeen
		m.fqdnRecoveryImpossible = !m.fqdnHistoryKnown || hasUnversionedFQDNBaseline(path)
		return
	}
	m.appliedAllow = append([]nodepolicy.AllowEntry(nil), state.Allow...)
	m.fqdnRecoveryRequired = false
	m.fqdnRecoveryImpossible = false
}

// SetEndpointSource injects the K8s ready-endpoint view (WF-K5). Called once at wiring time by a K8s gateway
// after the in-cluster watcher is built; a non-cluster gateway never calls it (source stays nil → no VIP
// DNAT). Injectable so the classifier/render reds drive every fail-closed branch with a fake source.
func (m *Manager) SetEndpointSource(s endpointSource) { m.source = s }

// SetOVPNTun records the co-terminated OpenVPN server's tun interface name (S9.1 Slice 3). Called
// once at wiring time from the OVPN server lifecycle's config (the ONE truth). Setting it adds that
// interface to the tunnel-ingress set so OVPN clients forward like WireGuard devices; leaving it
// unset keeps the ruleset byte-identical to a WireGuard-only deployment.
func (m *Manager) SetOVPNTun(name string) { m.ovpnTun.Store(&name) }

func (m *Manager) AppliedOVPNTun() string {
	if value := m.ovpnTun.Load(); value != nil {
		return *value
	}
	return ""
}

// ReconcileOVPNTunnel atomically threads the desired OpenVPN interface through
// the real nft owners. Publishing the marker alone is never applied state.
func (m *Manager) ReconcileOVPNTunnel(ctx context.Context, name string) error {
	if name != "" && !ifaceRE.MatchString(name) {
		return fmt.Errorf("invalid OpenVPN interface name %q", name)
	}
	m.SetOVPNTun(name)
	if _, _, err := m.Reconcile(ctx); err != nil {
		return err
	}
	_, err := m.ReadAppliedOVPNTunnel(ctx)
	return err
}

// ReadAppliedOVPNTunnel verifies the live IPv4 and IPv6 nft forward chains,
// not the atomic desired marker. The native-forward rule is always rendered
// from the complete authenticated tunnel set, so both tables must name the
// exact expected interfaces before ownership readback can succeed.
func (m *Manager) ReadAppliedOVPNTunnel(ctx context.Context) (string, error) {
	if m.nftRun == nil {
		return "", fmt.Errorf("OpenVPN tunnel-ingress kernel readback is unavailable")
	}
	want := m.tunnelIfaces()
	sort.Strings(want)
	for _, family := range []string{"ip", "ip6"} {
		listing, err := m.nftRun(ctx, "list", "table", family, "tunnex")
		if err != nil {
			return "", fmt.Errorf("read %s OpenVPN tunnel-ingress rules: %w", family, err)
		}
		got, err := parseTunnelIngressInterfaces(listing)
		if err != nil {
			return "", fmt.Errorf("read %s OpenVPN tunnel-ingress rules: %w", family, err)
		}
		if !slices.Equal(got, want) {
			return "", fmt.Errorf("%s OpenVPN tunnel-ingress interfaces=%v want=%v", family, got, want)
		}
	}
	return m.AppliedOVPNTun(), nil
}

func parseTunnelIngressInterfaces(listing string) ([]string, error) {
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, `comment "tunnex_native_forward_passthrough"`) {
			continue
		}
		match := nativeForwardReadbackRE.FindStringSubmatch(line)
		if len(match) != 3 {
			return nil, fmt.Errorf("native-forward tunnel-ingress rule semantics are invalid")
		}
		parseSet := func(raw string) []string {
			matches := quotedIfaceRE.FindAllStringSubmatch(raw, -1)
			values := make([]string, 0, len(matches))
			for _, value := range matches {
				values = append(values, value[1])
			}
			sort.Strings(values)
			return values
		}
		iifaces, oifaces := parseSet(match[1]), parseSet(match[2])
		if len(iifaces) == 0 || !slices.Equal(iifaces, oifaces) {
			return nil, fmt.Errorf("native-forward ingress and egress tunnel sets differ")
		}
		return iifaces, nil
	}
	return nil, fmt.Errorf("native-forward tunnel-ingress rule is absent")
}

// tunnelIfaces returns the crypto-authenticated tunnel-ingress interfaces. MEMBERSHIP IN THIS SET
// MEANS THE PACKET ARRIVED THROUGH AN AUTHENTICATED TUNNEL; adding a LAN-facing interface here
// breaks S3.7 spoke-isolation (an eth0-side host claiming a pool source could then reach spokes —
// the anti-spoof anchor the mesh accepts rely on). Order is stable (wg first) for readable goldens;
// the ip tunnex chain is an atomic full-replace so nft's set-canonicalization is irrelevant there.
func (m *Manager) tunnelIfaces() []string {
	if t := m.ovpnTun.Load(); t != nil && *t != "" {
		return []string{m.wgIface, *t}
	}
	return []string{m.wgIface}
}

// ifClause renders an `iifname`/`oifname` match over the tunnel set: the BARE form for a single
// member (byte-identical to the pre-OVPN ruleset — the zero-config golden) and an nft anonymous set
// for many. neg=true renders the negated form (`!= "x"` / `!= { ... }`).
func ifClause(field string, ifaces []string, neg bool) string {
	op := ""
	if neg {
		op = "!= "
	}
	if len(ifaces) == 1 {
		return fmt.Sprintf("%s %s\"%s\"", field, op, ifaces[0])
	}
	quoted := make([]string, len(ifaces))
	for i, n := range ifaces {
		quoted[i] = fmt.Sprintf("\"%s\"", n)
	}
	return fmt.Sprintf("%s %s{ %s }", field, op, strings.Join(quoted, ", "))
}

// ForwardBlocked reports the WF-4 / D-WF4-d condition: a Docker host whose FORWARD DROP is
// swallowing forwarded site traffic the agent couldn't clear. The reconcile loop feeds this
// into the site_subnet_unreachable health signal so it never blackholes green.
func (m *Manager) ForwardBlocked() bool { return m.forwardBlocked.Load() }

// ConntrackFlushFailing reports whether the last expired-grant conntrack flush FAILED and hasn't recovered
// (S8.7 Slice 2) — no CAP_NET_ADMIN in this deployment shape, or a netlink fault. The agent surfaces it as
// the conntrack_flush_unavailable health kind so an operator sees expiry-flush is degraded on the health
// plane, never just a log line. Cleared by the next successful flush (recovery). The reactive capability
// signal (D-gap-2): an EPERM from the netlink op IS the CAP_NET_ADMIN-absent evidence — no proactive read.
func (m *Manager) ConntrackFlushFailing() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushErr != nil
}

// SetFlowLogGroup enables flow logging by pointing the forward-chain log clauses at an
// nflog group (>0). 0 disables it. Non-terminal + best-effort: the log clause NEVER changes
// a packet's accept/drop fate (kernel semantics), so this cannot affect enforcement.
func (m *Manager) SetFlowLogGroup(group int) { m.flowLogGroup = group }

// SetPolicy stores the latest compiled policy (nil = legacy mesh) and marks that a
// policy has now been received — flipping the forward chain out of the cold-start
// deny-all state. Called on EVERY desired-state delivery (including nil for off orgs).
func (m *Manager) SetPolicy(p *nodepolicy.Compiled) {
	// S8.1 D1 fail-closed gate: an artifact whose Version exceeds what this agent can apply
	// is REFUSED — the agent does NOT store it as the active policy (rendering its fields
	// would be a best-effort apply of a shape it can't interpret) and does NOT fall through
	// to legacy mesh (fail-OPEN). It records the refused version (forcing DENY-ALL in
	// forwardRules) and reports it. The last-good policy is left in place but overridden by
	// the deny-all refusal; a supported version clears the refusal.
	if p != nil && p.Version > m.maxPolicyVersion {
		m.refusedVersion.Store(int64(p.Version))
		m.policyReceived.Store(true) // past cold-start: the refusal, not the cold deny, is the reason
		return
	}
	m.refusedVersion.Store(0)
	m.policy.Store(p)
	m.policyReceived.Store(true)
}

// FlowAttribution returns one locked snapshot of the successfully applied
// policy hash/version and subject metadata. Missing subjects stay empty; the
// caller must never infer them from the source address.
func (m *Manager) FlowAttribution(srcIP string) flowlog.Attribution {
	// An unsupported artifact forces a synthetic deny-all interlock. That ruleset
	// is not the last-good artifact and has no canonical policy hash/subject
	// snapshot of its own, so carrying last-good attribution would rewrite the
	// refusal as an ordinary policy decision. Absence is the truthful record.
	if m.refusedVersion.Load() != 0 {
		return flowlog.Attribution{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.appliedSubjects[srcIP]
	return flowlog.Attribution{
		PolicyHash: m.appliedHash, PolicyVersion: m.appliedVersion,
		SrcDeviceID: s.DeviceID, SrcDeviceKind: s.Kind,
		ConfigRevision: s.ConfigRevision,
	}
}

// DeviceForIP preserves the existing narrow helper for callers/tests while
// reading the successfully applied subject map.
func (m *Manager) DeviceForIP(srcIP string) string {
	return m.FlowAttribution(srcIP).SrcDeviceID
}

// installAppliedSubjects must be called with m.mu held after a successful
// policy apply. The map is complete and grant-independent.
func (m *Manager) installAppliedSubjects(pol *nodepolicy.Compiled) {
	m.appliedSubjects = map[string]nodepolicy.SubjectAttribution{}
	if pol == nil {
		return
	}
	for _, s := range pol.Subjects {
		if s.SrcIP != "" && s.DeviceID != "" {
			m.appliedSubjects[s.SrcIP] = s
		}
	}
}

// AppliedStatus reports the version + canonical hash of the policy CURRENTLY IN FORCE
// (last successful apply), the last apply error, and failingSince — the mismatch
// onset (zero when apply is healthy). The reconcile loop puts these on the status
// channel so the control plane can surface a gateway running STALE policy.
func (m *Manager) AppliedStatus() (version int, hash string, failingSince time.Time, applyErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.appliedVersion, m.appliedHash, m.failingSince, m.applyErr
}

// AppliedVIPMap returns a value copy from the last successful apply. It is a
// scope bound for the UID producer, not Kubernetes identity authority.
func (m *Manager) AppliedVIPMap() []nodepolicy.VIPMapping {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]nodepolicy.VIPMapping(nil), m.appliedVIPMappings...)
}

// RefusedVersion returns the compiled-artifact Version the agent last REFUSED as
// unsupported (S8.1 D1), or 0 when none. The reconcile loop reports this so the control
// plane surfaces `unsupported_policy_version` (remedy: upgrade the agent).
func (m *Manager) RefusedVersion() int { return int(m.refusedVersion.Load()) }

// desiredVersion returns the version of the policy the loop last handed us (0 = mesh/
// none). The control plane compares this to AppliedStatus to detect staleness.
func (m *Manager) desiredVersion() int {
	if p := m.policy.Load(); p != nil {
		return p.Version
	}
	return 0
}

// Reconcile is idempotent (safe to call every interval) and DOUBLES as the egress_nat
// capability probe. Ordering matters: it enables ip_forward FIRST and unconditionally, so
// spoke↔spoke forwarding works even on a host that can't egress (review #2), then applies
// the tunnex tables. egress_nat is true ONLY when a default route exists (an egress path)
// AND the IPv4 NAT table applied — so a route-less or NAT-incapable host reports false and
// full-tunnel is refused there rather than silently blackholing.
func (m *Manager) Reconcile(ctx context.Context) (v4Ready, v6Ready bool, err error) {
	// Keep the last-good Kubernetes posture visible while a new pass is still
	// observing/reconciling it. Slow successful passes must not create a false
	// readiness flap. An actual pass error retracts the previous result, while
	// reconcileK8sNetPrep publishes its final blocked/ready result only after the
	// adapter has returned a complete observation.
	defer func() {
		if err != nil && m.kubernetesMode.Load() {
			m.k8sNetPrepReady.Store(false)
		}
	}()
	if !ifaceRE.MatchString(m.wgIface) {
		return false, false, fmt.Errorf("invalid wg interface name %q", m.wgIface)
	}
	// Ensure ip_forward FIRST + unconditionally: a later egress failure must not leave
	// forwarding off. In a Docker container /proc/sys is READ-ONLY, so the agent can't
	// write it — the compose `sysctls: net.ipv4.ip_forward=1` sets it at boot and we just
	// VERIFY here; on a bare-metal agent we write it directly.
	if err := ensureIPForward(); err != nil {
		return false, false, err
	}
	// The masquerade is scoped by SOURCE (the WG pool CIDR), read from the wg interface
	// address — `iifname` is NOT reliable in the nat postrouting hook, whereas `ip saddr`
	// is (and it restores the pool-source scoping the POC had). Until wg0 exists (the WG
	// backend brings it up), there is no pool to scope, so egress isn't ready yet.
	subnet, err := m.observeWGSubnet(ctx)
	if err != nil {
		return false, false, fmt.Errorf("observe WireGuard IPv4 subnet: %w", err)
	}
	// Apply the tables. The whole ruleset is ONE `nft -f -` transaction (add;flush;
	// redefine per family) — an atomic full-chain replace, so there is no empty-chain
	// window (flush + repopulate commit together), it self-heals a table a prior crashed
	// agent left or a manual flush, and a FAILED apply is rejected wholesale by the
	// kernel → the PREVIOUS ruleset stays in force (decision 4a/4b). On failure we DO NOT
	// update applied* (staleness stays visible); on success we record what is in force.
	pol := m.policy.Load() // load ONCE: the ruleset rendered and the status recorded are the same policy
	if err := m.recoverFQDNBaseline(ctx, subnet, pol); err != nil {
		return false, false, err
	}
	if err := m.applyAndTrack(ctx, m.rulesetWith(subnet, pol), pol); err != nil {
		return false, false, err // no nftables / IPv4 NAT support, or a bad ruleset → not egress-capable
	}
	if m.kubernetesMode.Load() {
		if err := m.reconcileK8sNetPrep(ctx, subnet); err != nil {
			return false, false, err
		}
	}
	m.drainFlush(ctx) // S8.7 Slice 2: tear down established flows of any grant that just left the allow set
	// WF-4: on a Docker host, clear Docker's `filter FORWARD` DROP for the approved site routes
	// (a Routes-scoped DOCKER-USER accept) so site-to-site forwarding works with zero gateway touch.
	// Best-effort + idempotent; a Docker-blocked forward it can't clear is surfaced via ForwardBlocked().
	var routeCIDRs, localSubnets []string
	var poolCIDR string
	if pol != nil {
		for _, rt := range pol.Routes {
			routeCIDRs = append(routeCIDRs, rt.DstCIDR)
		}
		// WF-4-local: this gateway's OWN advertised subnets (LocalSubnets) also need a DOCKER-USER accept —
		// a split-tunnel device reaching the LAN BEHIND this gateway is forwarded wg0→eth0 and Docker's
		// FORWARD DROP swallows it exactly as it did remote routes. Same union, mirrored orientation.
		localSubnets = append(localSubnets, pol.LocalSubnets...)
		// A3b (v6): the org device pool — the pool-class accepts (relaxed, wg0↔wg0 included) so Docker
		// never structurally drops device transit or device↔device; the ip tunnex chain adjudicates.
		poolCIDR = pol.PoolCIDR
	}
	// A gateway must still lift Docker's structural FORWARD DROP for its own
	// WireGuard device pool when policy delivery is absent or predates PoolCIDR.
	// The live wg subnet is the authoritative deployment pool in that case; an
	// empty policy value must not turn an otherwise working NAT path into a
	// blackhole.
	poolCIDR = poolCIDRForForward(poolCIDR, subnet)
	m.reconcileDockerForward(ctx, routeCIDRs, localSubnets, poolCIDR)
	// egress_nat is true only when the pool is known (wg0 up) AND an egress path exists
	// (default route) — otherwise full-tunnel would blackhole, so report NOT capable.
	if subnet == "" || !hasDefaultRoute(ctx) {
		return false, false, nil
	}
	// IPv6 is advertised independently. It is only considered usable when the
	// WireGuard interface has an IPv6 address, the host has an IPv6 default route,
	// and the same atomic nft ruleset contains the NAT66 path. Existing IPv4-only
	// gateways therefore retain their current capability and never claim v6.
	subnet6 := wgSubnet6(ctx, m.wgIface)
	v6Ready = subnet6 != "" && hasDefaultRoute6(ctx) && ensureIPForward6() == nil
	return true, v6Ready, nil
}

func (m *Manager) recoverFQDNBaseline(ctx context.Context, subnet string, pol *nodepolicy.Compiled) error {
	if m.fqdnRecoveryImpossible && policyHasFQDN(pol) {
		return fmt.Errorf("fqdn baseline history is unversioned or corrupt: controlled operator recovery required")
	}
	if !m.requiresFQDNRecovery(pol) {
		return nil
	}
	// Do not let ct established,related keep unknown retired answers alive.
	// The denial is atomic and precedes the selective S21-marked recovery sweep.
	deny := &nodepolicy.Compiled{Version: pol.Version, Mode: nodepolicy.ModeEnforcing}
	if err := m.apply(ctx, m.rulesetWith(subnet, deny)); err != nil {
		return fmt.Errorf("fqdn restart deny-all apply: %w", err)
	}
	if _, err := m.ctFlushRecovery(ctx); err != nil {
		return fmt.Errorf("fqdn restart conntrack recovery: %w", err)
	}
	m.mu.Lock()
	m.fqdnRecoveryRequired = false
	m.mu.Unlock()
	return nil
}

func (m *Manager) requiresFQDNRecovery(pol *nodepolicy.Compiled) bool {
	if pol == nil || pol.Mode != nodepolicy.ModeEnforcing {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fqdnBaselinePath != "" && m.fqdnRecoveryRequired
}

func policyHasFQDN(pol *nodepolicy.Compiled) bool {
	return pol != nil && len(pol.FQDNGenerations) > 0
}

func poolCIDRForForward(policyPool, wgPool string) string {
	if strings.TrimSpace(policyPool) != "" {
		return policyPool
	}
	return wgPool
}

// Teardown removes legacy gateway-owned state. Kubernetes host-posture mode is
// different: the per-node manager owns wg0 plus the nft table markers across a
// gateway rollout. A terminating gateway withdraws its CNI/Docker rules and
// atomically reduces the exact manager-owned tables to marker-only state; it
// never deletes the manager's ownership receipts.
func (m *Manager) Teardown(ctx context.Context) {
	if !m.kubernetesMode.Load() {
		if m.apply != nil {
			_ = m.apply(ctx, "delete table ip tunnex\ndelete table ip6 tunnex\n")
		}
		return
	}
	m.k8sNetPrepReady.Store(false)
	if m.k8sNetPrep != nil {
		status, err := m.k8sNetPrep.Withdraw(ctx)
		m.logK8sNetPrepStatus(status)
		if err != nil && m.log != nil {
			m.log.Warn("k8s_netprep_withdraw_failed", "error", err)
		}
	}
	// DOCKER-USER belongs to Docker. Reconcile an empty desired set so only
	// exact comment-marked Tunnex rules are withdrawn; unknown shapes remain for
	// the manager's bounded, fail-closed last-owner cleanup.
	m.reconcileDockerForward(ctx, nil, nil, "")
	if err := m.reduceToHostPostureMarkers(ctx); err != nil && m.log != nil {
		m.log.Warn("k8s_host_posture_shutdown_blocked", "error", err)
	}
}

func (m *Manager) reduceToHostPostureMarkers(ctx context.Context) error {
	if m.nftRun == nil || m.apply == nil {
		return fmt.Errorf("nft lifecycle runners are unavailable")
	}
	for _, family := range []string{"ip", "ip6"} {
		out, err := m.nftRun(ctx, "-a", "list", "chain", family, "tunnex", "tunnex_posture_owner")
		if err != nil {
			return fmt.Errorf("read %s tunnex posture marker: %w", family, err)
		}
		if err := hostposture.ValidateNFTMarkerChain(out, hostposture.NFTMarkerComment); err != nil {
			return fmt.Errorf("refuse ambiguous %s tunnex posture table: %w", family, err)
		}
	}
	return m.apply(ctx, hostPostureMarkerOnlyRuleset())
}

func hostPostureMarkerOnlyRuleset() string {
	return fmt.Sprintf(`add table ip tunnex
flush table ip tunnex
table ip tunnex {
  chain tunnex_posture_owner {
    counter comment "%[1]s"
  }
}
add table ip6 tunnex
flush table ip6 tunnex
table ip6 tunnex {
  chain tunnex_posture_owner {
    counter comment "%[1]s"
  }
}
`, hostposture.NFTMarkerComment)
}

// ruleset is the atomic desired state. IPv4 (table ip): masquerade tunnel→egress + a
// forward chain with policy DROP so the ct-state return-path guard is real (review #0) —
// only spoke-initiated (iifname wg0) new flows + established return traffic are accepted,
// so the egress LAN can NEVER initiate into spokes. The masquerade is scoped by SOURCE
// (`ip saddr <pool>` — reliable in the postrouting hook, unlike `iifname`) out ANY
// non-tunnel iface (`oifname != wg0` — multi-homed/ECMP-safe, review #8), so it never
// masquerades spoke↔spoke (which stays wg0→wg0) or off-pool sources (review #5). IPv6
// uses the same fail-closed forward policy and adds NAT66 only when a global IPv6
// address is actually present on wg0; capability reporting gates full-tunnel minting.
// The SNAT hook runs ONE priority before the conventional `srcnat` priority used by
// Kubernetes CNIs. NAT uses the first binding created for a connection; leaving both
// hooks at the same priority makes their order undefined and lets a CNI own the
// device-pool flow before Tunnex. That breaks the paired VIP DNAT's reverse-source
// restoration on the return path. `srcnat - 1` keeps Tunnex ownership limited to the
// already source- and interface-scoped masquerade rule; every non-matching native CNI
// flow continues to the CNI's ordinary `srcnat` hook unchanged.
func (m *Manager) ruleset(subnet string) string {
	return m.rulesetWith(subnet, m.policy.Load())
}

// rulesetWith renders the ruleset for an EXPLICIT policy — Reconcile loads the policy
// once and passes it here AND to applyAndTrack, so the rendered rules and the recorded
// status can never be two different policies (no torn read across a SetPolicy).
func (m *Manager) rulesetWith(subnet string, pol *nodepolicy.Compiled) string {
	// Masquerade line present only when the pool subnet is known (wg0 up). Scoped by
	// SOURCE (ip saddr) — reliable in postrouting, unlike iifname — out ANY non-tunnel
	// iface (ECMP/multi-homed-safe). nft masks e.g. 10.99.0.1/24 to the /24 network.
	tun := m.tunnelIfaces()
	masq := ""
	masq6 := ""
	if subnet != "" {
		// Masquerade tunnel-sourced egress out any NON-tunnel iface. Scoped by SOURCE (ip saddr,
		// reliable in postrouting) and by `oifname != <tunnel set>` — so traffic destined to ANY
		// tunnel (spoke↔spoke, incl. device↔device ACROSS wg0/OVPN) stays un-NAT'd (the ZT chain
		// needs the un-mangled source /32), and only true internet egress is masqueraded.
		masq = fmt.Sprintf("    ip saddr %s %s masquerade\n", subnet, ifClause("oifname", tun, true))
	}
	if subnet6 := wgSubnet6(context.Background(), m.wgIface); subnet6 != "" {
		masq6 = fmt.Sprintf("    ip6 saddr %s %s masquerade\n", subnet6, ifClause("oifname", tun, true))
	}
	v4fwd, v6fwd := m.forwardRules(pol, m.policyReceived.Load())
	// This chain is installed in the host network namespace for an in-cluster
	// connector. It must adjudicate every packet that enters or leaves a Tunnex
	// tunnel, but it must not become a second CNI firewall for ordinary native
	// node forwarding (pod<->CoreDNS/API/egress). Requiring BOTH interfaces to
	// be outside the tunnel set keeps the default-deny boundary intact for every
	// tunnel ingress and egress path. The IPv4 rule also excludes a conntrack
	// original destination that is an active synthetic Service VIP: native CNI
	// traffic must never use that bypass to reach a Tunnex-exposed Service.
	nativeForward4 := fmt.Sprintf("    %s %s%s counter accept comment \"tunnex_native_forward_passthrough\"\n",
		ifClause("iifname", tun, true), ifClause("oifname", tun, true), m.resolvedVIPOriginalDstExclusion())
	nativeForward6 := fmt.Sprintf("    %s %s counter accept comment \"tunnex_native_forward_passthrough\"\n",
		ifClause("iifname", tun, true), ifClause("oifname", tun, true))
	postureOwnerChain := ""
	if m.kubernetesMode.Load() {
		postureOwnerChain = fmt.Sprintf("  chain tunnex_posture_owner {\n    counter comment \"%s\"\n  }\n", hostposture.NFTMarkerComment)
	}
	// S8.2 D9 MSS clamp: on the INTRA-TUNNEL forward path (wg0→wg0 — device-to-device and site-to-site,
	// where a client-WG session can ride a site-WG link and PMTUD fails silently inside the tunnels),
	// clamp each TCP SYN's MSS down to the path MTU. This is the classic "ping works, large transfer
	// freezes" fix. HONEST SCOPE (reassuring-comment law): it clamps TCP ONLY (UDP/ICMP-dependent PMTUD
	// is unaffected — those rely on the link MTU / fragmentation) and only NEW connections (the SYN);
	// it does not otherwise change forwarding. Node-local rendered rule, OUTSIDE CanonicalHash (the
	// masquerade class, D2) — no version bump, twin goldens untouched. Non-terminal: it modifies then
	// continues to the grant/drop below.
	// MSS clamp on the intra-tunnel forward path: iif AND oif are both tunnel interfaces (wg0→wg0,
	// and with OVPN co-terminated, tun↔wg0 device↔device across protocols).
	mssClamp := fmt.Sprintf("    %s %s tcp flags syn tcp option maxseg size set rt mtu",
		ifClause("iifname", tun, false), ifClause("oifname", tun, false))
	return fmt.Sprintf(`add table ip tunnex
flush table ip tunnex
table ip tunnex {
%[9]s
%[5]s  chain postrouting {
    type nat hook postrouting priority srcnat - 1; policy accept;
%[1]s  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid counter drop comment "tunnex_ct_invalid_drop"
%[7]s
%[4]s
%[2]s  }
}
add table ip6 tunnex
flush table ip6 tunnex
table ip6 tunnex {
%[9]s
  chain postrouting {
    type nat hook postrouting priority srcnat - 1; policy accept;
%[6]s  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid counter drop comment "tunnex_ct_invalid_drop"
%[8]s
%[3]s  }
}
`, masq, v4fwd, v6fwd, mssClamp, m.preroutingDNAT(), masq6, nativeForward4, nativeForward6, postureOwnerChain)
}

// resolvedVIPOriginalDstExclusion returns a fail-closed, nft-safe match suffix
// for native forwarding. The forward hook sees the post-DNAT destination, so
// the original conntrack tuple is the only stable way to reserve an exposed
// Tunnex VIP for the grant chain. resolvedVIPs are already classifier-validated;
// parse and re-emit anyway because this is root ruleset text.
func (m *Manager) resolvedVIPOriginalDstExclusion() string {
	rs := m.resolvedVIPs.Load()
	if rs == nil || len(*rs) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(*rs))
	for _, r := range *rs {
		a, err := netip.ParseAddr(r.vip)
		if err != nil || !a.Is4() {
			continue
		}
		seen[a.String()] = struct{}{}
	}
	if len(seen) == 0 {
		return ""
	}
	vips := make([]string, 0, len(seen))
	for vip := range seen {
		vips = append(vips, vip)
	}
	sort.Strings(vips)
	if len(vips) == 1 {
		return " ct original ip daddr != " + vips[0]
	}
	return " ct original ip daddr != { " + strings.Join(vips, ", ") + " }"
}

// forwardRules renders the forward-chain accept lines (after the base policy-drop +
// ct-accept) for the ip and ip6 tables, from the compiled policy:
//
//   - nil policy or Mesh=true (Zero Trust off / open build): the LEGACY blanket mesh —
//     wg0<->wg0 (device↔device) + wg0→egress in v4, wg0<->wg0 in v6. No behavior change.
//   - enforcing: DEFAULT-DENY. Only the compiled allows are emitted, in the compiler's
//     already-sorted order (byte-stable → steady-state reconcile is a no-op). There is
//     NO wg0<->wg0 blanket — device↔device is permitted only by an explicit rule (the
//     S7.1 structural guard, now on the wire). Egress is likewise gated: a device reaches
//     off-pool/internet only via an allow whose dst covers it (e.g. a 0.0.0.0/0 resource),
//     which the masquerade then NATs. Native IPv6 source/destination tuples render in
//     the ip6 table; this is required for an FQDN generation that resolves to a /128.
//     Mixed-family tuples are not meaningful packets and stay default-denied.
//
// Every forward rule carries a `counter` (S7.2): per-rule packet/byte counts, near-free
// (a native nft primitive). REPORTING is deferred (the flow-log candidate); emitting now
// reserves the seam and gives the box proof its positive (allow-count) + negative
// (dropCounter) observations for free. counter is in the rendered RULESET only — it is
// NOT part of the canonical Compiled JSON, so the pushed/applied CanonicalHash is
// untouched (no version bump, twin goldens unchanged).
const dropCounter = "    counter comment \"tunnex_default_drop\"\n" // counts unmatched -> policy drop

func (m *Manager) forwardRules(pol *nodepolicy.Compiled, received bool) (v4, v6 string) {
	if !received {
		// COLD START, no policy fetched yet -> DENY-ALL (drop + ct only, no accepts).
		// Fail-closed until the first desired-state delivery, so an enforcing gateway is
		// never briefly wide-open on restart (finding #2). NOT the same as nil-in-received.
		return dropCounter, dropCounter
	}
	if m.refusedVersion.Load() > 0 {
		// S8.1 D1: an unsupported-version artifact was refused -> DENY-ALL (the same
		// fail-closed shape as cold start). NEVER fall through to the mesh/enforcing render
		// below, which would apply a shape the agent can't interpret or open the mesh.
		return dropCounter, dropCounter
	}
	tun := m.tunnelIfaces()
	if pol == nil || pol.Mesh {
		// The blanket mesh accepts. iifname over the TUNNEL SET is the S3.7 anti-spoof anchor:
		// only traffic that arrived through an authenticated tunnel (wg0 or the co-terminated OVPN
		// tun) forwards — an eth0-side host spoofing a pool source is dropped by the policy-drop
		// base (never matched by an `iifname <tunnel-set>` accept). Device↔device = tunnel→tunnel;
		// spoke→egress = tunnel→non-tunnel.
		v4 = fmt.Sprintf("    %[1]s %[2]s counter accept\n    %[1]s %[3]s counter accept\n",
			ifClause("iifname", tun, false), ifClause("oifname", tun, false), ifClause("oifname", tun, true))
		// S8.2c D1: SYMMETRIC site forwarding in mesh. Mesh means "no doors" — a behind-gateway host must
		// be able to INITIATE to a remote site (LAN→tunnel), not just receive. The wg0-ingress accepts
		// above cover tunnel→LAN + spoke↔spoke but NOT LAN→tunnel (the S3.7 "egress LAN can never initiate
		// into spokes" stance). We open LAN→tunnel SCOPED TO THE REMOTE SITE SUBNETS (pol.Routes) only —
		// so the S3.7 spoke-isolation HOLDS (the device pool 10.99.x is never a Route, so the egress LAN
		// still can't reach device spokes; only approved site-to-site subnets). Canonically re-emitted
		// (netip) so nothing injects nft statements. Enforcing keeps its grant-gated forward (allowMatch).
		if pol != nil {
			for _, rt := range pol.Routes {
				if p, err := netip.ParsePrefix(rt.DstCIDR); err == nil && p.Addr().Is4() {
					// LAN→tunnel = non-tunnel ingress → tunnel egress, scoped to the remote site subnet.
					v4 += fmt.Sprintf("    %s %s ip daddr %s counter accept\n",
						ifClause("iifname", tun, true), ifClause("oifname", tun, false), p.Masked().String())
				}
			}
		}
		v6 = fmt.Sprintf("    %s %s counter accept\n    %s %s counter accept\n",
			ifClause("iifname", tun, false), ifClause("oifname", tun, false),
			ifClause("iifname", tun, false), ifClause("oifname", tun, true))
		return v4, v6
	}
	var v4Rules, v6Rules strings.Builder
	g := m.flowLogGroup
	for _, e := range pol.Allow {
		// Render each tuple in its one applicable family. The other family rejects it
		// before emitting text, so an address can never be accepted by both tables.
		var v4Line, v6Line string
		var ok bool
		if e.FQDNManaged {
			v4Line, ok = renderFQDNManagedAllow(e, g, false)
		} else if g > 0 {
			v4Line, ok = renderAllowLogged(e, g)
		} else {
			v4Line, ok = renderAllow(e)
		}
		if ok {
			v4Rules.WriteString(v4Line)
		}
		if e.FQDNManaged {
			v6Line, ok = renderFQDNManagedAllow(e, g, true)
		} else if g > 0 {
			v6Line, ok = renderAllowLoggedFamily(e, g, true)
		} else {
			v6Line, ok = renderAllowFamily(e, true)
		}
		if ok {
			v6Rules.WriteString(v6Line)
		}
	}
	v4Rules.WriteString(denyDrop(g))
	v6Rules.WriteString(denyDrop(g))
	return v4Rules.String(), v6Rules.String()
}

func fqdnMarkClause() string {
	return fmt.Sprintf(" ct mark set ((ct mark & 0x%08x) | 0x%08x)", ^FQDNConntrackMarkMask, FQDNConntrackMark)
}

// renderFQDNManagedAllow marks only a new flow accepted by an FQDN-expanded
// tuple. The mark is connection state, so later established packets retain it
// and selective restart recovery can identify only S21-owned flows.
func renderFQDNManagedAllow(e nodepolicy.AllowEntry, group int, v6 bool) (string, bool) {
	m, ok := allowMatchFamily(e, v6)
	if !ok {
		return "", false
	}
	line := m + fqdnMarkClause()
	if group > 0 && ruleIDRE.MatchString(e.RuleID) {
		line += logClause(flowlog.EncodePrefix(e.RuleID), group)
	}
	return line + " accept\n", true
}

// denyDrop is the default-deny tail. g==0: the original counter (relies on the chain's
// policy drop) — byte-identical to pre-S7.5.1. g>0: additionally LOG the unmatched NEW
// flow (flow-start deny, D1) with the deny sentinel, then count + drop. The verdict is
// drop either way; the log is the sole addition (non-terminal). The deny-log is the
// port-scan amplification point — aggregated CP-side (4/n), nflog socket sized for it.
func denyDrop(group int) string {
	if group <= 0 {
		return dropCounter
	}
	return fmt.Sprintf("    ct state new%s counter drop comment \"tunnex_default_drop\"\n", logClause(flowlog.EncodePrefix(""), group))
}

// allowMatch turns one compiled allow into the ENFORCEMENT clause (match + counter, NO
// verdict) for the ip (v4) forward chain, or reports ok=false to SKIP it. This is the
// rule_id-INDEPENDENT part that decides packet fate — renderAllow / renderAllowLogged
// append the verdict (and, for the logged form, an observation clause) to it. Every field
// is re-emitted through netip as a canonical NUMERIC string (never the raw control-plane
// string) so nothing can inject nft statements into this root ruleset — the same hardening
// as ifaceRE. Ports are integers. Each invocation targets exactly one nft address family.
func allowMatch(e nodepolicy.AllowEntry) (string, bool) { return allowMatchFamily(e, false) }

// allowMatchFamily renders one address family. v6 selects native IPv6; IPv4-mapped
// IPv6 is rejected rather than being rendered in the wrong nft family.
func allowMatchFamily(e nodepolicy.AllowEntry, v6 bool) (string, bool) {
	// SOURCE match: a DEVICE source is a bare host ("10.99.0.7"); a SITE source (v5, S8.2) is a LAN CIDR
	// ("10.1.0.0/24"). Accept BOTH, fail closed on anything else. Re-emit canonically (never the raw CP
	// string) so nothing can inject nft statements. The v4 renderer used ParseAddr only — a CIDR source
	// was SKIPPED (silent under-enforcement), which is exactly why a CIDR source triggers the v5 gate.
	var srcMatch string
	if strings.Contains(e.SrcIP, "/") {
		p, err := netip.ParsePrefix(e.SrcIP)
		if err != nil || p.Addr().Is6() != v6 || (!v6 && !p.Addr().Is4()) {
			return "", false
		}
		srcMatch = p.Masked().String()
	} else {
		a, err := netip.ParseAddr(e.SrcIP)
		if err != nil || a.Is6() != v6 || (!v6 && !a.Is4()) {
			return "", false
		}
		srcMatch = a.String()
	}
	dst, err := netip.ParsePrefix(e.DstCIDR)
	if err != nil || dst.Addr().Is6() != v6 || (!v6 && !dst.Addr().Is4()) {
		return "", false
	}
	// CONVENTION (fail-closed rendering): this renderer REFUSES any unknown or half-
	// specified field — it skips the rule (-> no match -> default-deny) and NEVER widens
	// on it. validateResource is the first gate, but a compromised or future control
	// plane could still emit a malformed artifact, so the renderer never trusts it. This
	// has bitten twice (port range #1, protocol #6); it is a checklist line for every new
	// field added to AllowEntry. ALSO (A-1, S7.5.1): classify every new field
	// enforcement-vs-observability — enforcement fields go into CanonicalHash's projection
	// (nodepolicy/policyspec hash.go); observability fields (e.g. rule_id) stay OUT of it
	// AND out of this renderer, so the hash and the packet fate ignore them alike.
	clause := ""
	switch e.Protocol {
	case "any":
		// All protocols for this src/dst — the intended wide grant; clause stays empty.
	case "tcp", "udp":
		lowSet, highSet := e.PortLow > 0, e.PortHigh > 0
		switch {
		case !lowSet && !highSet:
			// Both unset = any port of this protocol (the "no port range" case).
			clause = fmt.Sprintf(" meta l4proto %s", e.Protocol)
		case lowSet && highSet && e.PortHigh >= e.PortLow:
			if e.PortHigh > e.PortLow {
				clause = fmt.Sprintf(" meta l4proto %s ct original proto-dst %d-%d", e.Protocol, e.PortLow, e.PortHigh)
			} else {
				clause = fmt.Sprintf(" meta l4proto %s ct original proto-dst %d", e.Protocol, e.PortLow)
			}
		default:
			// A HALF-SET or inverted range (only low, only high, or high<low) is
			// malformed. FAIL CLOSED: skip the rule -> default-deny, NEVER widen to
			// all-ports (finding #1).
			return "", false
		}
	default:
		// Unknown/empty protocol. The compiler only emits any/tcp/udp, but the renderer
		// does not rely on that: an unrecognized value FAILS CLOSED (skip -> default-deny),
		// symmetric with the half-set-port refusal — never a silent all-protocol widen
		// (finding #6).
		return "", false
	}
	// WF-K5 C1: match the CONNTRACK ORIGINAL destination, not the current packet dst. The K8s VIP DNAT
	// (prerouting nat, priority -101) rewrites dst VIP->podIP BEFORE this filter-forward chain (priority 0)
	// runs — conntrack (priority -200) already recorded the ORIGINAL tuple (pre-DNAT dst = the VIP), so
	// `ct original ip daddr <VIP>` matches the address the client actually dialed. For NON-DNAT'd grants
	// (device/site) the original dst == the current dst, so this is a semantic no-op off the DNAT path. This
	// makes enforcement key on the SAME tuple space as the S8.7 conntrack flush (which keys on ct-original
	// src): a flow is adjudicated and torn down on one tuple, never two that can disagree (the one-truth law).
	// An UNTRACKED packet has no ct entry so `ct original` cannot match → it falls to policy-drop (fail-closed);
	// `ct state invalid` is dropped explicitly ahead of the grants (rulesetWith) so an invalid packet carrying
	// a stale ct entry can never be adjudicated by this match.
	family := "ip"
	if v6 {
		family = "ip6"
	}
	return fmt.Sprintf("    %s saddr %s ct original %s daddr %s%s counter", family, srcMatch, family, dst.Masked().String(), clause), true
}

// renderAllow is the ENFORCEMENT-ONLY accept line (no observation). rule_id-INDEPENDENT.
func renderAllow(e nodepolicy.AllowEntry) (string, bool) {
	return renderAllowFamily(e, false)
}

func renderAllowFamily(e nodepolicy.AllowEntry, v6 bool) (string, bool) {
	m, ok := allowMatchFamily(e, v6)
	if !ok {
		return "", false
	}
	return m + " accept\n", true
}

// renderAllowLogged is renderAllow PLUS an nflog observation clause carrying the grant's
// rule_id (S7.5.1, decision (a)). The log clause is the SOLE delta vs renderAllow and is
// NON-TERMINAL — `log` cannot change the accept verdict (kernel semantics). Scoping: the
// established-accept line above short-circuits established flows, so this per-rule accept
// only sees a flow's FIRST packet → one log per flow-start (D1). group is the nflog group
// the flowlog reader listens on.
func renderAllowLogged(e nodepolicy.AllowEntry, group int) (string, bool) {
	return renderAllowLoggedFamily(e, group, false)
}

func renderAllowLoggedFamily(e nodepolicy.AllowEntry, group int, v6 bool) (string, bool) {
	// rule_id is the ONE renderer field that isn't a number — validate it to the canonical UUID
	// shape before it enters the root nft ruleset (the A-1 fail-closed discipline, review #7).
	// A non-conforming rule_id renders the accept WITHOUT a log clause: NOT an empty prefix
	// (EncodePrefix("") is the DENY sentinel, which would misclassify this ACCEPTED flow as a
	// deny) and NOT a raw interpolation. Fail-closed on OBSERVABILITY only — the packet is still
	// correctly accepted. In practice the compiler always stamps a DB uuid; this defends a
	// future/compromised artifact, matching allowMatch's netip re-emission of src/dst/port.
	if !ruleIDRE.MatchString(e.RuleID) {
		return renderAllowFamily(e, v6)
	}
	m, ok := allowMatchFamily(e, v6)
	if !ok {
		return "", false
	}
	return m + logClause(flowlog.EncodePrefix(e.RuleID), group) + " accept\n", true
}

// logClause renders a non-terminal nflog statement. prefix names the grant (or the deny
// sentinel); group is the nflog group. Placed BEFORE the verdict so the kernel logs the
// matched packet then proceeds to accept/drop unchanged.
func logClause(prefix string, group int) string {
	return fmt.Sprintf(" log prefix %q group %d", prefix, group)
}

// applyAndTrack performs the atomic apply and records the fail-closed status: on
// SUCCESS it records the applied policy's version + CANONICAL content hash (what is in
// force); on FAILURE it records only the error and leaves applied version/hash
// UNCHANGED — so the kernel's preserved previous ruleset is reflected as
// applied != desired (STALE), never as a silent success. Extracted from Reconcile so
// the fail-closed behavior is unit-testable with an injected applier (the kernel-level
// rollback itself is a box proof).
//
// HASH DISCIPLINE: the hash is nodepolicy.CanonicalHash(pol) — SHA-256 over the
// canonical Compiled JSON, the SAME bytes the control plane hashes on its side
// (policyspec.CanonicalHash, twin-golden-pinned). NEVER hash the rendered ruleset
// text: it contains node-local state (the masquerade subnet line) the control plane
// cannot reproduce, which would false-positive the staleness alarm permanently.
func (m *Manager) applyAndTrack(ctx context.Context, ruleset string, pol *nodepolicy.Compiled) error {
	// POLICY staleness applies ONLY to an ENFORCING policy. A failure while rendering the
	// mesh/off/open ruleset is an S3.7 EGRESS-NAT arm problem (surfaced via egress_nat=false
	// + logs), NOT Zero Trust policy staleness — so it must NOT set policy_error/failingSince
	// (finding #6: a nftless open-build gateway must not report itself policy-stale).
	isPolicy := pol != nil && pol.Mode == nodepolicy.ModeEnforcing
	// Write a pending marker before nft. If this process dies before the
	// matching committed marker, the next process performs restart recovery
	// instead of trusting an ambiguous tuple baseline.
	if isPolicy {
		m.mu.Lock()
		baselinePath := m.fqdnBaselinePath
		m.mu.Unlock()
		if err := writeFQDNBaseline(baselinePath, "pending", pol); err != nil {
			return err
		}
	}
	err := m.apply(ctx, ruleset)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !isPolicy {
		// Desired state is NON-enforcing (mesh / off / open build).
		if err == nil {
			// Applied cleanly: mesh/off is now in force. Clear all policy status.
			m.appliedVersion = 0
			m.appliedHash = nodepolicy.CanonicalHash(pol) // "" for nil, mesh hash otherwise
			m.installAppliedSubjects(pol)
			m.setAppliedVIPMap(pol)
			m.appliedEnforcing = false
			m.applyErr = nil
			m.failingSince = time.Time{}
			// S8.7: mesh/off has no grants — nothing to diff/flush against next. NOTE (S8.7b gap): this drops the
			// enforcing baseline, so if the org toggles ZT OFF→ON and the new enforcing policy no longer grants a
			// destination, an established flow opened during the mesh window is NOT flushed on re-enable
			// (removedTuples diffs from nil → empty). This is the SAME no-continuous-baseline class as the deferred
			// boot reconcile — carried by S8.7b, stated in its named limitation. NEW connections are denied at once.
			m.appliedAllow = nil
			return nil
		}
		// The apply FAILED, so the kernel keeps the PREVIOUS ruleset in force.
		if m.appliedEnforcing {
			// STUCK ENFORCING: the org disabled Zero Trust (or reverted to mesh) but the
			// gateway could not swap out the enforcing chain — it is still enforcing a
			// DISABLED policy, invisibly denying traffic. Surface it via applyErr (an
			// immediate policy_error), the "silent stale policy = violation in slow motion"
			// DoD (finding #B). appliedHash/appliedEnforcing stay (enforcing is what's in
			// force). failingSince stays enforcing-scoped — applyErr is the signal here.
			m.applyErr = err
			return err
		}
		// Never enforcing (open build / off egress-arm failure): NOT a policy concern —
		// the egress-capability path (egress_nat=false + logs) carries this. Stay quiet so
		// a nftless open-build gateway never reports itself policy-stale (finding #6).
		m.applyErr = nil
		m.failingSince = time.Time{}
		return err
	}
	if err != nil {
		m.applyErr = err
		if m.failingSince.IsZero() { // stamp the mismatch ONSET, once
			m.failingSince = m.now()
		}
		return err
	}
	m.appliedVersion = pol.Version
	m.appliedHash = nodepolicy.CanonicalHash(pol)
	m.installAppliedSubjects(pol)
	m.setAppliedVIPMap(pol)
	m.appliedEnforcing = true
	m.applyErr = nil
	m.failingSince = time.Time{} // apply succeeded -> no mismatch -> not stale
	// S8.7 Slice 2 (LIVE flush): capture the grants that LEFT the allow set (expired/deleted) since the last
	// applied enforcing set, under the lock; Reconcile flushes their established flows OUTSIDE the lock. The
	// apply already removed the ACCEPT rule above, so the flush cannot race a re-accept. On the FIRST enforcing
	// apply appliedAllow is nil → removedTuples yields nothing (there is no prior baseline to diff) — that
	// while-DOWN gap (a grant revoked before this baseline existed) is the S8.7b boot-reconcile deferral.
	m.pendingFlush = removedTuples(m.appliedAllow, pol.Allow)
	m.appliedAllow = pol.Allow
	if err := writeFQDNBaseline(m.fqdnBaselinePath, "committed", pol); err != nil {
		// nft has already atomically installed the policy. Leaving the pending
		// marker forces the next boot through deny-all + recovery rather than
		// treating a possibly stale tuple file as current.
		m.applyErr = err
		return err
	}
	if policyHasFQDN(pol) && m.fqdnBaselinePath != "" {
		if err := writeFQDNHistory(m.fqdnBaselinePath + ".history"); err != nil {
			m.applyErr = err
			return err
		}
		m.fqdnHistorySeen, m.fqdnHistoryKnown = true, true
	}
	return nil
}

// setAppliedVIPMap must run while m.mu is held, after the atomic apply has
// succeeded. VIPMapping currently contains value fields, so the slice copy is
// a complete ownership-safe snapshot.
func (m *Manager) setAppliedVIPMap(pol *nodepolicy.Compiled) {
	if pol == nil {
		m.appliedVIPMappings = nil
		return
	}
	m.appliedVIPMappings = append([]nodepolicy.VIPMapping(nil), pol.VIPMappings...)
}

// removedTuples returns the flush specs for grants present in the OLD applied allow set but ABSENT from the
// NEW one — the expired/deleted grants whose established flows must be torn down (S8.7 Slice 2). Keyed on the
// exact enforcement tuple (src/dst/proto/ports); a malformed entry that can't be parsed is skipped (never
// flushed on a bad tuple). ONE function — it is agnostic to WHY a grant left (expiry vs manual delete both
// arrive here as an absent entry), which is exactly D5's "one function, two triggers".
func removedTuples(old, current []nodepolicy.AllowEntry) []flowTuple {
	inCurrent := make(map[string]bool, len(current))
	for _, e := range current {
		inCurrent[allowKey(e)] = true
	}
	var out []flowTuple
	for _, e := range old {
		if inCurrent[allowKey(e)] {
			continue
		}
		if t, ok := tupleFromAllow(e); ok {
			out = append(out, t)
		}
	}
	return out
}

// allowKey is the canonical identity of an AllowEntry for the removed-set diff (enforcement fields only —
// RuleID/SrcDeviceID are observability and excluded).
func allowKey(e nodepolicy.AllowEntry) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d", e.SrcIP, e.DstCIDR, e.Protocol, e.PortLow, e.PortHigh)
}

// drainFlush runs the pending conntrack flush OUTSIDE the status lock, after a successful apply. Best-effort:
// a flush error (CAP_NET_ADMIN absent / netlink fault) is LOGGED + recorded in flushErr (surfaced, never
// silent) — the rule removal already succeeded, so lingering flows are the pre-existing degraded-not-broken
// behavior, not a new failure.
func (m *Manager) drainFlush(ctx context.Context) {
	m.mu.Lock()
	tuples := m.pendingFlush
	m.pendingFlush = nil
	m.mu.Unlock()

	// LIVE removed-grant flush. Recovery is PROBE-LESS: conntrack_flush_unavailable clears on the next
	// SUCCESSFUL actual flush — no synthetic probe. The trade (the kind may over-persist when no flushes occur)
	// is the standing over-report preference: annoyance heals, silence doesn't.
	if len(tuples) == 0 {
		return
	}
	if m.ctFlush == nil { // no flusher wired (a directly-constructed Manager) → skip
		return
	}
	// These `tuples` are EXPLICIT src/dst pairs derived from the removed Allow entries themselves (tupleFromAllow),
	// independent of the WG pool — no pool gate needed.
	killed, err := m.ctFlush(ctx, tuples)
	m.mu.Lock()
	m.flushErr = err
	m.mu.Unlock()
	if err != nil {
		slog.Error("conntrack_flush_failed", "error", err.Error(), "tuples", len(tuples))
		return
	}
	if killed > 0 {
		slog.Info("conntrack_flushed", "flows", killed, "tuples", len(tuples))
	}
}

// nftApply pipes a ruleset to `nft -f -` (a single atomic netlink transaction: every
// command in the input commits together or the whole batch is rejected).
func nftApply(ctx context.Context, ruleset string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// nftRun runs `nft <args...>` and returns stdout. Used by the DOCKER-USER foreign-chain
// reconcile (WF-4) for list/insert/delete, which — unlike the atomic tunnex-table replace —
// must edit a Docker-owned chain one rule at a time (never flush it).
func nftRun(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return string(out), nil
}

func (m *Manager) reconcileK8sNetPrep(ctx context.Context, subnet string) error {
	if m.k8sNetPrep == nil {
		m.k8sNetPrepReady.Store(false)
		return fmt.Errorf("Kubernetes network preparation is unavailable")
	}
	status, err := m.k8sNetPrep.Reconcile(ctx, subnet)
	m.logK8sNetPrepStatus(status)
	ready := subnet != "" && err == nil && status.Host.State == k8snetprep.StateReady
	for _, adapter := range status.Adapters {
		ready = ready && adapter.State == k8snetprep.StateReady
	}
	if len(status.Adapters) == 0 {
		ready = false
	}
	m.k8sNetPrepReady.Store(ready)
	return err
}

// K8sNetPrepReady is the finite readiness signal for common host posture plus
// every observed CNI adapter. Withdrawal and blocked observation are never green.
func (m *Manager) K8sNetPrepReady() bool { return m.k8sNetPrepReady.Load() }

// SetKubernetesMode enables the Kubernetes-only host/CNI contract. It is set
// once from the closed agent configuration before the first reconcile; absence
// preserves the legacy VM/site data plane exactly.
func (m *Manager) SetKubernetesMode(enabled bool) {
	m.kubernetesMode.Store(enabled)
	if !enabled {
		m.k8sNetPrepReady.Store(false)
	}
}

// ReconcileK8sNetPrep refreshes common host/CNI truth independently of the
// slower full egress repair. The caller serializes it with other data-plane
// commands; this method owns only the current WireGuard subnet observation.
func (m *Manager) ReconcileK8sNetPrep(ctx context.Context) error {
	if !m.kubernetesMode.Load() {
		return nil
	}
	subnet, err := m.observeWGSubnet(ctx)
	if err != nil {
		m.k8sNetPrepReady.Store(false)
		return fmt.Errorf("observe WireGuard IPv4 subnet: %w", err)
	}
	return m.reconcileK8sNetPrep(ctx, subnet)
}

func (m *Manager) logK8sNetPrepStatus(status k8snetprep.ReconcileStatus) {
	summary := status.Summary()
	previous := m.k8sNetPrepStatus.Swap(&summary)
	if m.log == nil || (previous != nil && *previous == summary) {
		return
	}
	adapter := k8snetprep.ComponentStatus{Name: "none", State: k8snetprep.StateNotApplicable}
	if len(status.Adapters) > 0 {
		adapter = status.Adapters[0]
	}
	m.log.Info("k8s_netprep_state",
		"host_state", status.Host.State,
		"host_reason", status.Host.Reason,
		"adapter", adapter.Name,
		"adapter_state", adapter.State,
		"adapter_reason", adapter.Reason,
		"owned_rules", adapter.OwnedRules,
	)
}

const dockerUserComment = "tunnex-site-fwd" // marks the agent's own DOCKER-USER rules for idempotent find + full-sweep

// captures direction (s|d addr) + the address + the handle, for a comment-marked rule. BOTH directions
// are Route-scoped (forward: daddr=route; return: saddr=route) — the return path is why a single-direction
// accept passed the forward ping but dropped the reply on the re-walk.
// captures: (1) the iif/oif orientation prefix (for drift-detection, S8.6b), (2) direction s|d, (3) the addr,
// (4) the handle. The orientation prefix distinguishes an old iif!=wg0-predicated rule from the relaxed form
// under the same daddr/saddr key.
var dockerUserRuleRE = regexp.MustCompile(`((?:iifname|oifname)[^\n]*?)?ip ([sd])addr (\S+).*comment "` + dockerUserComment + `".*# handle (\d+)`)

// orientSig canonicalizes a rule's iif/oif match predicates (spaces + quotes stripped) so nft's printed form
// and our insert-args form normalize identically — the drift-detection comparator (S8.6b D-transit-2).
func orientSig(s string) string { return strings.NewReplacer(" ", "", `"`, "").Replace(s) }

// ifaceFromOrient extracts the tunnel interface name from a rule's iif/oif orientation prefix
// (e.g. `oifname "wg0"` -> "wg0", or the insert-args form `oifname wg0`). It is how the per-interface
// pool key (S9.1 Slice 3) is rebuilt from a listed DOCKER-USER rule. Pool rules always carry exactly one
// interface token; returns "" defensively if none is present.
func ifaceFromOrient(orient string) string {
	fields := strings.Fields(orient)
	for i, f := range fields {
		if (f == "iifname" || f == "oifname") && i+1 < len(fields) {
			return strings.Trim(fields[i+1], `"`)
		}
	}
	return ""
}

// argOrientSig derives the orientation signature from an insert-args vector: the tokens BEFORE "ip" (the
// iifname/oifname clause), normalized the same way as orientSig.
func argOrientSig(args []string) string {
	var pre []string
	for _, t := range args {
		if t == "ip" {
			break
		}
		pre = append(pre, t)
	}
	return orientSig(strings.Join(pre, " "))
}

// reconcileDockerForward makes forwarding work on a DOCKER host with ZERO gateway touch (WF-4).
// Docker sets `filter FORWARD` policy DROP + a DOCKER-USER hook; the agent's `ip tunnex` forward
// accept is a SEPARATE base chain, so Docker's drop terminally kills the forwarded packet even
// after the ZT chain accepted it. This inserts SCOPED accepts into DOCKER-USER (jumped FIRST from
// FORWARD; an accept there clears the hook's drop) — mirroring the tunnex rule, NEVER a blanket
// ACCEPT. TWO scoped sets: remote Routes (site-to-site, S8.2c) AND this gateway's own LocalSubnets
// (WF-4-local, S8.5 — a split-tunnel device reaching the LAN behind its gateway is forwarded
// wg0→eth0 and Docker's drop swallowed it; the ZT chain accepted it, proven on the wire). The `ip
// tunnex` chain still ENFORCES the grant (enforcing with no grant stays 100% loss even with the
// DOCKER-USER accept), so this only lifts Docker's structural isolation, never the policy.
//
// Idempotent (list → insert only what's missing) + full-sweep (delete comment-marked rules whose
// addr left Routes∪LocalSubnets) → re-run every reconcile tick, so a dockerd reload that recreates
// DOCKER-USER self-heals within one interval (D-WF4-a). Docker-CONDITIONAL: no DOCKER-USER chain
// (bare metal / the D4 bare-metal path) → no-op, forwarding rides the host's own FORWARD (D-WF4-c).
// Returns forwardBlocked when we have subnets to carry, FORWARD is policy-drop, yet we could not
// place the accept — the D-WF4-d loud signal.
func (m *Manager) reconcileDockerForward(ctx context.Context, routes, localSubnets []string, poolCIDR string) (forwardBlocked bool) {
	wg := m.wgIface
	// Probe DOCKER-USER. Absent → not a Docker-managed FORWARD host; nothing to satisfy.
	if _, err := m.nftRun(ctx, "list", "chain", "ip", "filter", "DOCKER-USER"); err != nil {
		m.forwardBlocked.Store(false)
		return false
	}
	// Desired = TWO accepts per v4 CIDR — forward (daddr) AND return (saddr) — keyed "d:"/"s:" + the CANONICAL
	// address nft PRINTS (host route bare, else masked). Both directions are needed: a forward-only accept
	// passed the ping's echo-request but Docker's FORWARD DROP killed the reply (re-walk). #1: nft drops the
	// /32 from a host addr, so keying on Masked() "x/32" would never match the listed bare "x" and thrash —
	// canonDaddr keys both sides the same way. args are built from canonical prefixes (no operator/CP string
	// reaches nft raw). Routes and LocalSubnets are DISJOINT by construction (remote vs this-gateway), so the
	// "d:"/"s:" address keying never collides across the two orientations.
	desired := map[string]bool{}
	insertArgs := map[string][]string{}
	desiredSig := map[string]string{} // key -> iif/oif orientation signature (drift-detection, S8.6b D-transit-2)
	comment := `"` + dockerUserComment + `"`
	set := func(k string, args []string) {
		desired[k] = true
		insertArgs[k] = args
		desiredSig[k] = argOrientSig(args)
	}
	// REMOTE routes (S8.6b D-transit-1, RELAXED): Docker must not structurally drop traffic whose daddr/saddr
	// is a Route — the ZT chain adjudicates. The old iif!=wg0/oif!=wg0 predicates were "the direction the walk
	// proved" (eth0→wg0), never a security predicate (see docs/S8.6-decisions.md — narrowing-was-incidental).
	// Relaxed, ONE rule covers eth0→wg0 (route) AND wg0→wg0 (device→remote-site hub transit). Forward =
	// oif=wg0, daddr=route; return = iif=wg0, saddr=route. A future PR must NOT re-add the iif/oif predicates.
	//
	// S9.1: this wg0 is the SITE-LINK peer interface (remote sites are reached over WG site links; sites stay
	// WireGuard by S9.3), NOT client ingress — so the tunnel-ingress SET does NOT apply here and this is NOT a
	// "bare wg0" grep-proof violation. An OVPN client→remote-site rides the pool class (tun→wg0 transit) then
	// this rule (wg0→site); `oifname <ovpn-tun> daddr remote-site` would be nonsensical (no route egresses a
	// client tun). Do not thread the set through this class.
	for _, c := range routes {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			a := canonDaddr(p)
			set("d:"+a, []string{"oifname", wg, "ip", "daddr", a, "counter", "accept", "comment", comment})
			set("s:"+a, []string{"iifname", wg, "ip", "saddr", a, "counter", "accept", "comment", comment})
		}
	}
	// WF-4-local (S8.5) + S9.1 Slice 3 PER-INTERFACE: this gateway's OWN advertised subnets. A tunnel client
	// (a WG device OR a co-terminated OVPN client — the PRIMARY OpenVPN use case: laptop dials in, reaches the
	// office file server) initiates IN to the local LAN. Without a DOCKER-USER accept, Docker's FORWARD DROP
	// swallows the tunnel→own-LAN forward even though the ZT chain accepted it (WF-4-local, wire-proven).
	//
	// Keyed `iifname <tif> daddr=localsubnet` (forward) / `oifname <tif> saddr=localsubnet` (return), ONE pair
	// PER tunnel interface — the SAME one-truth as the pool class (D-S9.3-DOCKER (a)). The old `oifname != wg0`
	// / `iifname != wg0` NEGATION is DROPPED (founder-ruled): a packet destined for the gateway's OWN LAN
	// subnet cannot egress a tunnel — the routing table sends it out the LAN interface, and the disjointness
	// validator guarantees NO site subnet overlaps a local subnet, so no other tunnel could legitimately own
	// that destination. So `iifname <tif> daddr=localsub` is sufficient and the negation added nothing.
	for _, c := range localSubnets {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			a := canonDaddr(p)
			if desired["d:"+a] || desired["s:"+a] {
				continue // a route already claimed this addr (disjoint-by-construction guard); do not overwrite
			}
			for _, tif := range m.tunnelIfaces() {
				set("d:"+tif+":"+a, []string{"iifname", tif, "ip", "daddr", a, "counter", "accept", "comment", comment})
				set("s:"+tif+":"+a, []string{"oifname", tif, "ip", "saddr", a, "counter", "accept", "comment", comment})
			}
		}
	}
	// POOL class (A3b v6; S9.1 Slice 3 PER-INTERFACE): the org device pool. Docker must not structurally
	// drop pool traffic to/from ANY crypto-authenticated tunnel-ingress interface — so we emit ONE accept
	// pair (forward oif=tif daddr=pool; return iif=tif saddr=pool) PER tunnel interface (wg0, and the
	// co-terminated OVPN tun when present). The ip tunnex chain (tunnel-set keyed) does the real
	// adjudication; this only lifts Docker's blanket drop (the D-transit-3 boundary).
	//
	// PER-INTERFACE, NOT an nft set: this chain reconciles INCREMENTALLY, and nft canonicalizes set member
	// order — so the drift-detection comparator (orientSig, which compares insert-args to nft's PRINTED
	// form) could never match a set's printed order and would thrash every tick (empirically confirmed via
	// a direct nft probe). This consumes the SAME one-truth as the ip tunnex chain, tunnelIfaces(); the ip
	// tunnex chain renders that set atomically, DOCKER-USER renders it per-interface because its incremental
	// comparator cannot match nft's set canonicalization — same truth, two renderings (D-S9.3-DOCKER (a)).
	//
	// Key = "dir:iface:addr" so the wg0 and tun rules COEXIST and full-sweep INDEPENDENTLY (a departed tun
	// leaves → its rules leave). Routes/localSubnets keep the addr-only "dir:addr" key; the listing side
	// disambiguates by the pool CIDR (poolCanon), which is DISJOINT from routes/locals by construction. The
	// existing-key guard checks the addr-only key so a pool colliding with a route/local never double-places.
	if poolCIDR != "" {
		if p, err := netip.ParsePrefix(poolCIDR); err == nil && p.Addr().Is4() {
			a := canonDaddr(p)
			if !desired["d:"+a] && !desired["s:"+a] { // never overwrite a route/local at this addr (disjoint guard)
				for _, tif := range m.tunnelIfaces() {
					set("d:"+tif+":"+a, []string{"oifname", tif, "ip", "daddr", a, "counter", "accept", "comment", comment})
					set("s:"+tif+":"+a, []string{"iifname", tif, "ip", "saddr", a, "counter", "accept", "comment", comment})
				}
			}
		}
	}
	// Current tunnex-marked rules: "dir:addr" -> handle. A LIST ERROR (not just empty) means we can't know
	// what's in force → SKIP add/sweep this tick and keep the prior signal (#2: blindly inserting on an
	// unread list duplicates accepts the sweep can't reap, since they ARE in desired). Next tick retries.
	listing, err := m.nftRun(ctx, "-a", "list", "chain", "ip", "filter", "DOCKER-USER")
	if err != nil {
		return m.forwardBlocked.Load()
	}
	// current: key -> {handle, orientation signature}. The SIGNATURE (drift-detection, S8.6b D-transit-2) lets
	// a reconcile REPLACE an old orientation-predicated rule with the relaxed form under the SAME daddr/saddr
	// key — key-only idempotence would skip it (key present) and strand the old rule, breaking transit forever.
	type curRule struct {
		handle string
		sig    string
	}
	// perIfaceAddr (S9.1 Slice 3): the canonical addresses whose DOCKER-USER rules are PER-INTERFACE keyed
	// (dir:iface:addr) rather than addr-only — the pool + this gateway's local subnets (both keyed on the
	// tunnel-ingress interface). Routes stay addr-only (site-link keyed, class comment above). Built from the
	// SAME inputs the desired rules were, so the listing side rebuilds the identical key. Disjoint by
	// construction, so an address is in exactly one class.
	perIfaceAddr := map[string]bool{}
	if poolCIDR != "" {
		if p, e := netip.ParsePrefix(poolCIDR); e == nil && p.Addr().Is4() {
			perIfaceAddr[canonDaddr(p)] = true
		}
	}
	for _, c := range localSubnets {
		if p, e := netip.ParsePrefix(c); e == nil && p.Addr().Is4() {
			perIfaceAddr[canonDaddr(p)] = true
		}
	}
	current := map[string]curRule{}
	for _, mt := range dockerUserRuleRE.FindAllStringSubmatch(listing, -1) {
		orient, dir, addr, handle := mt[1], mt[2], mt[3], mt[4]
		canon := ""
		if p, e := netip.ParsePrefix(addr); e == nil {
			canon = canonDaddr(p)
		} else if a, e := netip.ParseAddr(addr); e == nil {
			canon = a.String() // nft prints a host route as a bare address
		}
		if canon == "" {
			continue
		}
		key := dir + ":" + canon
		if perIfaceAddr[canon] { // pool + local-subnet rules are per-interface keyed; derive the iface from orient
			key = dir + ":" + ifaceFromOrient(orient) + ":" + canon
		}
		current[key] = curRule{handle: handle, sig: orientSig(orient)}
	}
	placeErr := false
	// Add missing OR REPLACE drifted — INSERT (prepend) so it precedes DOCKER-USER's trailing RETURN. A key
	// present with a MATCHING signature is idempotent (skip); present with a DIFFERENT signature (an old
	// orientation-predicated rule vs the relaxed desired) is deleted first, then re-inserted — one pass, no
	// orphan window (D-transit-2 sweep-hygiene).
	for key, args := range insertArgs {
		if cur, have := current[key]; have {
			if cur.sig == desiredSig[key] {
				continue // idempotent — same rule already in force
			}
			// drifted: remove the stale-orientation rule before placing the relaxed one (same key)
			if _, err := m.nftRun(ctx, "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", cur.handle); err != nil {
				placeErr = true
				continue // couldn't remove the old rule → don't stack a second; retry next tick
			}
			delete(current, key) // it's gone; the sweep must not try to delete it again by the old handle
		}
		if _, err := m.nftRun(ctx, append([]string{"insert", "rule", "ip", "filter", "DOCKER-USER"}, args...)...); err != nil {
			placeErr = true
		}
	}
	// Full-sweep: delete comment-marked rules whose daddr left Routes. #5: surface a failed delete (a
	// lingering foreign-chain accept is retried next tick, but a persistent failure must not be silent).
	for key, cur := range current {
		if desired[key] {
			continue
		}
		if _, err := m.nftRun(ctx, "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", cur.handle); err != nil {
			slog.Warn("docker_user_sweep_failed", "handle", cur.handle, "daddr", key, "error", err.Error())
		}
	}
	// D-WF4-d: routes to carry + FORWARD policy-drop + our accept couldn't be placed → blocked (loud).
	blocked := len(desired) > 0 && placeErr && forwardPolicyIsDrop(ctx, m.nftRun)
	m.forwardBlocked.Store(blocked)
	return blocked
}

// canonDaddr returns the daddr string nft PRINTS for a prefix: a host route (/32 v4, /128 v6) as the BARE
// address, any other prefix as the masked CIDR. Keying idempotence on this form makes the /32 case match
// (nft drops the /32) instead of thrashing insert+delete every tick.
func canonDaddr(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.Masked().String()
}

// forwardPolicyIsDrop reports whether the `ip filter FORWARD` base chain is policy drop (the
// Docker default that swallows forwarded traffic). Best-effort: an unreadable chain → false
// (don't manufacture a blocked signal we can't substantiate).
func forwardPolicyIsDrop(ctx context.Context, run func(context.Context, ...string) (string, error)) bool {
	out, err := run(ctx, "list", "chain", "ip", "filter", "FORWARD")
	if err != nil {
		return false
	}
	return strings.Contains(out, "policy drop")
}

// observeWGSubnet returns the WG interface's IPv4 address+prefix (for example
// "10.99.0.1/24"), used to scope masquerade by source. A successful empty
// read is known absence; a command or parse failure is unknown and must never
// be collapsed into the empty string consumed as explicit withdrawal.
func (m *Manager) observeWGSubnet(ctx context.Context) (string, error) {
	if !ifaceRE.MatchString(m.wgIface) {
		return "", fmt.Errorf("invalid wg interface name %q", m.wgIface)
	}
	if m.runIPOutput == nil {
		return "", fmt.Errorf("WireGuard address readback is unavailable")
	}
	out, err := m.runIPOutput(ctx, "-o", "-4", "addr", "show", "dev", m.wgIface)
	if err != nil {
		return "", err
	}
	return parseWGSubnet(out)
}

func parseWGSubnet(out string) (string, error) {
	// `ip -o` emits one address per line and keeps the interface's primary
	// tunnel address first. Later lines can be Tunnex DNS VIP /32 secondaries;
	// they are deliberately not competing tunnel-subnet observations.
	out = strings.TrimSpace(out)
	if out == "" {
		return "", nil
	}
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0]) // "N: wg0 inet 10.99.0.1/24 ..."
	for i, field := range fields {
		if field != "inet" {
			continue
		}
		if i+1 >= len(fields) {
			return "", fmt.Errorf("WireGuard IPv4 address readback is malformed")
		}
		prefix, err := netip.ParsePrefix(fields[i+1])
		if err != nil || !prefix.Addr().Is4() {
			return "", fmt.Errorf("WireGuard IPv4 address readback is malformed")
		}
		return prefix.String(), nil
	}
	return "", fmt.Errorf("WireGuard IPv4 address readback is malformed")
}

// wgSubnet6 returns the WireGuard interface's IPv6 address+prefix. It is kept
// separate from observeWGSubnet so an IPv4-only deployment never accidentally reports
// dual-stack capability.
func wgSubnet6(ctx context.Context, iface string) string {
	out, err := exec.CommandContext(ctx, "ip", "-o", "-6", "addr", "show", "dev", iface, "scope", "global").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "inet6" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// hasDefaultRoute reports whether the host has an IPv4 default route (an egress path).
func hasDefaultRoute(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "default")
}

func hasDefaultRoute6(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "default")
}

// ensureIPForward enables IPv4 forwarding. It tries to WRITE the sysctl (bare-metal
// agent); if /proc/sys is read-only (Docker default — the container can't write it), it
// falls back to VERIFYING it's already 1 (set by the compose sysctl at boot). Only a
// not-writable-AND-not-already-enabled state is a real failure.
func ensureIPForward() error {
	if err := writeSysctl("net/ipv4/ip_forward", "1"); err == nil {
		return nil
	}
	v, rerr := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if rerr == nil && strings.TrimSpace(string(v)) == "1" {
		return nil // already enabled (compose/host set it) — read-only fs is expected in a container
	}
	return fmt.Errorf("ip_forward not enabled and not writable (set sysctls net.ipv4.ip_forward=1 on the node-agent)")
}

// ensureIPForward6 mirrors the IPv4 forwarding check but is optional: an
// IPv4-only gateway must remain healthy when the host has IPv6 disabled. It is
// called only after a global IPv6 address is present on wg0.
func ensureIPForward6() error {
	if err := writeSysctl("net/ipv6/conf/all/forwarding", "1"); err == nil {
		return nil
	}
	v, rerr := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if rerr == nil && strings.TrimSpace(string(v)) == "1" {
		return nil
	}
	return fmt.Errorf("ipv6 forwarding not enabled and not writable")
}

func writeSysctl(key, val string) error {
	return os.WriteFile("/proc/sys/"+key, []byte(val), 0o644)
}
