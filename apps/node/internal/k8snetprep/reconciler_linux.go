//go:build linux

package k8snetprep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	ipMasqAdapterName = "ip_masq_agent"
	ipMasqTable       = "nat"
	ipMasqChain       = "IP-MASQ-AGENT"
	ownedRuleComment  = "tunnex_k8s_ip_masq_bypass"
	legacyRuleComment = "tunnex_ha_cni_masq_bypass"
)

var (
	interfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)
	handleRE        = regexp.MustCompile(`# handle ([0-9]+)\s*$`)
	destinationRE   = regexp.MustCompile(`\bip daddr ([^[:space:]]+)`)
	legacySourceRE  = regexp.MustCompile(`\bip saddr ([^[:space:]]+)`)
	outInterfaceRE  = regexp.MustCompile(`\boifname "?([A-Za-z0-9._-]{1,15})"?`)
)

// NFTRunner executes a closed nft argument vector. It exists so mechanism
// state and mutation can be proven without root/kernel access in unit tests.
type NFTRunner func(context.Context, ...string) (string, error)

// Reconciler continuously verifies the manager-owned WireGuard rp_filter
// posture and owns only Tunnex-commented rules in registered CNI mechanisms.
type Reconciler struct {
	mu      sync.Mutex
	iface   string
	procSys string
	runNFT  NFTRunner
}

// New returns a provider-neutral reconciler for one WireGuard interface.
func New(iface string, runNFT NFTRunner) *Reconciler {
	if runNFT == nil {
		runNFT = realNFTRunner
	}
	return &Reconciler{iface: iface, procSys: "/proc/sys", runNFT: runNFT}
}

func realNFTRunner(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, bounded(string(bytes.TrimSpace(out)), maxReasonBytes))
	}
	return string(out), nil
}

// Reconcile converges the exact current tunnel CIDR. An empty CIDR is an
// explicit withdrawal and removes every obsolete owned adapter rule.
func (r *Reconciler) Reconcile(ctx context.Context, tunnelCIDR string) (ReconcileStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tunnelCIDR == "" {
		return r.withdrawLocked(ctx)
	}
	if !interfaceNameRE.MatchString(r.iface) {
		return blockedStatus("wireguard_rp_filter", "invalid WireGuard interface", ipMasqAdapterName), fmt.Errorf("invalid WireGuard interface")
	}
	prefix, err := netip.ParsePrefix(tunnelCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return blockedStatus("wireguard_rp_filter", "invalid IPv4 tunnel CIDR", ipMasqAdapterName), fmt.Errorf("invalid IPv4 tunnel CIDR")
	}
	tunnelCIDR = prefix.Masked().String()

	host := ComponentStatus{Name: "wireguard_rp_filter", State: StateReady}
	if err := readAndVerifySysctl(r.procSys, filepath.Join("net/ipv4/conf", r.iface, "rp_filter"), "0"); err != nil {
		host.State = StateBlocked
		host.Reason = bounded(err.Error(), maxReasonBytes)
		status := ReconcileStatus{Host: host, Adapters: []ComponentStatus{{Name: ipMasqAdapterName, State: StateBlocked, Reason: "host posture blocked"}}}
		return status, fmt.Errorf("WireGuard rp_filter: %s", host.Reason)
	}

	adapter, err := r.reconcileIPMasqLocked(ctx, tunnelCIDR)
	status := ReconcileStatus{Host: host, Adapters: []ComponentStatus{adapter}}
	if err != nil {
		return status, err
	}
	return status, nil
}

func readAndVerifySysctl(procSys, key, desired string) error {
	path := filepath.Join(procSys, filepath.FromSlash(key))
	value, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read back %s: %w", key, err)
	}
	live := strings.TrimSpace(string(value))
	if live != desired {
		return fmt.Errorf("%s readback=%q desired=%q", key, live, desired)
	}
	return nil
}

// Withdraw removes every Tunnex-owned CNI adapter rule and preserves all
// foreign state. It is safe when the mechanism has already disappeared.
func (r *Reconciler) Withdraw(ctx context.Context) (ReconcileStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.withdrawLocked(ctx)
}

func (r *Reconciler) withdrawLocked(ctx context.Context) (ReconcileStatus, error) {
	host := ComponentStatus{Name: "wireguard_rp_filter", State: StateNotApplicable, Reason: "no active tunnel CIDR"}
	adapter, err := r.withdrawIPMasqLocked(ctx)
	status := ReconcileStatus{Host: host, Adapters: []ComponentStatus{adapter}}
	if err != nil {
		return status, err
	}
	return status, nil
}

func blockedStatus(hostName, reason, adapterName string) ReconcileStatus {
	return ReconcileStatus{
		Host:     ComponentStatus{Name: hostName, State: StateBlocked, Reason: bounded(reason, maxReasonBytes)},
		Adapters: []ComponentStatus{{Name: adapterName, State: StateBlocked, Reason: "host input blocked"}},
	}
}

type ownedRule struct {
	handle    uint64
	cidr      string
	iface     string
	marker    string
	direction string
}

// OwnedRuleReceipt is the bounded, non-secret identity of one live CNI rule
// carrying a recognized Tunnex ownership marker. Callers must still use
// Withdraw for mutation; this readback exists so the host-posture journal can
// refuse an ambiguous pre-Tunnex baseline without duplicating the parser.
type OwnedRuleReceipt struct {
	Handle    uint64 `json:"handle"`
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	Marker    string `json:"marker"`
	Direction string `json:"direction"`
}

// OwnedArtifacts observes only the exact registered IP-MASQ-AGENT seam. A
// Tunnex-marked rule with an unknown shape returns StateBlocked and no partial
// receipt set, preserving the reconciler's existing fail-closed behavior.
func (r *Reconciler) OwnedArtifacts(ctx context.Context) ([]OwnedRuleReceipt, State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rules, state, err := r.readIPMasqOwnedRules(ctx)
	if err != nil {
		return nil, state, err
	}
	out := make([]OwnedRuleReceipt, len(rules))
	for i, rule := range rules {
		out[i] = OwnedRuleReceipt{Handle: rule.handle, CIDR: rule.cidr, Interface: rule.iface, Marker: rule.marker, Direction: rule.direction}
	}
	return out, state, nil
}

func (r *Reconciler) reconcileIPMasqLocked(ctx context.Context, cidr string) (ComponentStatus, error) {
	rules, state, err := r.readIPMasqOwnedRules(ctx)
	if err != nil {
		return ComponentStatus{Name: ipMasqAdapterName, State: state, Reason: reasonForAdapterState(state, err)}, err
	}
	if state == StateNotApplicable {
		return ComponentStatus{Name: ipMasqAdapterName, State: StateBlocked, Reason: ReasonNoRegisteredAdapter},
			fmt.Errorf("%s: %s chain is absent", ReasonNoRegisteredAdapter, ipMasqChain)
	}

	keptDesired := false
	for _, rule := range rules {
		if rule.cidr == cidr && rule.iface == r.iface && rule.marker == ownedRuleComment && rule.direction == "daddr" && !keptDesired {
			keptDesired = true
			continue
		}
		if err := r.deleteIPMasqRule(ctx, rule.handle); err != nil {
			return blockedAdapter(fmt.Errorf("remove obsolete owned rule: %w", err))
		}
	}
	if !keptDesired {
		// IP-MASQ-AGENT exemptions describe destinations that must retain the pod
		// source address. For pod-to-client returns the tunnel pool is therefore a
		// destination match, narrowed to the WireGuard egress interface.
		if _, err := r.runNFT(ctx,
			"insert", "rule", "ip", ipMasqTable, ipMasqChain,
			"ip", "daddr", cidr, "oifname", r.iface, "return", "comment", ownedRuleComment,
		); err != nil {
			return blockedAdapter(fmt.Errorf("install owned rule: %w", err))
		}
	}

	readback, state, err := r.readIPMasqOwnedRules(ctx)
	if err != nil {
		return blockedAdapter(fmt.Errorf("read back owned rule: %w", err))
	}
	if state != StateReady {
		return blockedAdapter(fmt.Errorf("mechanism disappeared before readback"))
	}
	if len(readback) != 1 || readback[0].cidr != cidr || readback[0].iface != r.iface || readback[0].marker != ownedRuleComment || readback[0].direction != "daddr" {
		return blockedAdapter(fmt.Errorf("owned rule readback mismatch"))
	}
	return ComponentStatus{Name: ipMasqAdapterName, State: StateReady, OwnedRules: 1}, nil
}

func (r *Reconciler) withdrawIPMasqLocked(ctx context.Context) (ComponentStatus, error) {
	rules, state, err := r.readIPMasqOwnedRules(ctx)
	if err != nil || state == StateNotApplicable {
		return ComponentStatus{Name: ipMasqAdapterName, State: state, Reason: reasonForAdapterState(state, err)}, err
	}
	for _, rule := range rules {
		if err := r.deleteIPMasqRule(ctx, rule.handle); err != nil {
			return blockedAdapter(fmt.Errorf("withdraw owned rule: %w", err))
		}
	}
	readback, state, err := r.readIPMasqOwnedRules(ctx)
	if err != nil {
		return blockedAdapter(fmt.Errorf("read back withdrawal: %w", err))
	}
	if state == StateNotApplicable {
		return ComponentStatus{Name: ipMasqAdapterName, State: StateNotApplicable, Reason: "mechanism absent after withdrawal"}, nil
	}
	if len(readback) != 0 {
		return blockedAdapter(fmt.Errorf("owned rules remain after withdrawal"))
	}
	return ComponentStatus{Name: ipMasqAdapterName, State: StateReady}, nil
}

func reasonForAdapterState(state State, err error) string {
	if state == StateNotApplicable {
		return "exact chain absent"
	}
	if err != nil {
		return bounded(err.Error(), maxReasonBytes)
	}
	return ""
}

func blockedAdapter(err error) (ComponentStatus, error) {
	reason := bounded(err.Error(), maxReasonBytes)
	return ComponentStatus{Name: ipMasqAdapterName, State: StateBlocked, Reason: reason}, fmt.Errorf("%s adapter: %s", ipMasqAdapterName, reason)
}

func (r *Reconciler) readIPMasqOwnedRules(ctx context.Context) ([]ownedRule, State, error) {
	listing, err := r.runNFT(ctx, "-a", "list", "chain", "ip", ipMasqTable, ipMasqChain)
	if err != nil {
		if exactChainAbsent(err) {
			return nil, StateNotApplicable, nil
		}
		return nil, StateBlocked, fmt.Errorf("observe exact chain: %s", bounded(err.Error(), maxReasonBytes))
	}
	rules, err := parseOwnedRules(listing)
	if err != nil {
		return nil, StateBlocked, err
	}
	return rules, StateReady, nil
}

func exactChainAbsent(err error) bool {
	if err == nil {
		return false
	}
	// This classifier is called only for the exact chain-list operation above,
	// but ENOENT can also mean the nft executable disappeared. First prove that
	// the command ran and returned an exit status, then accept nft's missing-rule
	// diagnostic (whose prefix differs across nft releases).
	type exitStatus interface{ ExitCode() int }
	var exited exitStatus
	if !errors.As(err, &exited) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "error: no such file or directory") ||
		strings.Contains(message, "could not process rule: no such file or directory")
}

func parseOwnedRules(listing string) ([]ownedRule, error) {
	var rules []ownedRule
	for _, line := range strings.Split(listing, "\n") {
		marker := ""
		for _, candidate := range []string{ownedRuleComment, legacyRuleComment} {
			if strings.Contains(line, `comment "`+candidate+`"`) {
				marker = candidate
				break
			}
		}
		if marker == "" {
			continue
		}
		handleMatch := handleRE.FindStringSubmatch(line)
		addressMatch := destinationRE.FindStringSubmatch(line)
		direction := "daddr"
		if len(addressMatch) != 2 && marker == legacyRuleComment {
			addressMatch = legacySourceRE.FindStringSubmatch(line)
			direction = "saddr"
		}
		ifaceMatch := outInterfaceRE.FindStringSubmatch(line)
		if len(handleMatch) != 2 || len(addressMatch) != 2 || len(ifaceMatch) != 2 || !strings.Contains(line, " return") {
			return nil, fmt.Errorf("owned rule has an unrecognized shape")
		}
		handle, err := strconv.ParseUint(handleMatch[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("owned rule handle is invalid")
		}
		prefix, err := netip.ParsePrefix(addressMatch[1])
		if err != nil || !prefix.Addr().Is4() || !interfaceNameRE.MatchString(ifaceMatch[1]) {
			return nil, fmt.Errorf("owned rule scope is invalid")
		}
		rules = append(rules, ownedRule{handle: handle, cidr: prefix.Masked().String(), iface: ifaceMatch[1], marker: marker, direction: direction})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].handle > rules[j].handle })
	return rules, nil
}

func (r *Reconciler) deleteIPMasqRule(ctx context.Context, handle uint64) error {
	_, err := r.runNFT(ctx, "delete", "rule", "ip", ipMasqTable, ipMasqChain, "handle", strconv.FormatUint(handle, 10))
	return err
}
