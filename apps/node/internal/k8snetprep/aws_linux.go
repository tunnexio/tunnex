//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	awsAdapterName      = "aws_vpc_snat"
	awsChain            = "AWS-SNAT-CHAIN-0"
	maxCNISnapshotBytes = 8 << 20
)

// NewWithAWS registers the closed AWS mechanism in addition to IP-MASQ. Unlike
// New, every operation needs journal authority. A nil guard is useful ONLY for
// the manager's read-only baseline census; it never permits a mutation.
func NewWithAWS(iface string, nft NFTRunner, iptables IPTablesRunner, guard AuthorityGuard) *Reconciler {
	r := New(iface, nft)
	if iptables == nil {
		iptables = realIPTablesRunner
	}
	r.awsAware, r.runIPTables, r.guard = true, iptables, guard
	return r
}

func realIPTablesRunner(ctx context.Context, args ...string) (string, error) {
	// No alternative-selected wrapper and no restore/write command is allowed.
	if strings.Join(args, " ") != "-V" && strings.Join(args, " ") != "-t nat" {
		return "", errors.New("unsupported iptables-nft-save inspection")
	}
	out, err := exec.CommandContext(ctx, "iptables-nft-save", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("iptables-nft-save inspection: %w", err)
	}
	if len(out) > maxCNISnapshotBytes {
		return "", errors.New("iptables-nft-save inspection exceeds bound")
	}
	return string(out), nil
}

func awsBlocked(err error) (ReconcileStatus, error) {
	reason := bounded(err.Error(), maxReasonBytes)
	return ReconcileStatus{
		Host:     ComponentStatus{Name: "wireguard_rp_filter", State: StateBlocked, Reason: reason},
		Adapters: []ComponentStatus{{Name: ipMasqAdapterName, State: StateBlocked, Reason: reason}, {Name: awsAdapterName, State: StateBlocked, Reason: reason}},
	}, err
}

func (r *Reconciler) reconcileWithAuthority(ctx context.Context, cidr string) (ReconcileStatus, error) {
	// Acquisition time counts against the operation, not just subprocess time.
	ctx, cancelBudget := context.WithTimeout(ctx, CNIOperationBudget)
	defer cancelBudget()
	if r.guard == nil {
		return awsBlocked(errors.New("CNI authority guard is required"))
	}
	// Global lock order is node operation guard BEFORE this process-local mutex.
	// The manager uses a static guard only while it already holds that same lock.
	grant, release, err := r.guard(ctx)
	if release != nil {
		defer release()
	}
	if err != nil {
		return awsBlocked(fmt.Errorf("CNI authority: %w", err))
	}
	if release == nil || (grant.Scope != ScopeIPMasqOnly && grant.Scope != ScopeIPMasqAndAWS) {
		return awsBlocked(errors.New("CNI authority scope or release is invalid"))
	}
	if grant.NotAfter.IsZero() || !time.Now().Before(grant.NotAfter) {
		return awsBlocked(errors.New("CNI authority expiry is missing or elapsed"))
	}
	ctx, cancelGrant := context.WithDeadline(ctx, grant.NotAfter)
	defer cancelGrant()
	if err := r.lockOperation(ctx); err != nil {
		return awsBlocked(err)
	}
	defer r.mu.Unlock()
	if cidr == "" {
		// Legacy epoch cleanup must not even enumerate the new ownership space.
		if grant.Scope == ScopeIPMasqOnly {
			status, err := r.withdrawLocked(ctx)
			if expired := operationContextErr(ctx); expired != nil {
				return awsBlocked(expired)
			}
			return status, err
		}
		return r.withdrawAWSAwareLocked(ctx)
	}
	if !interfaceNameRE.MatchString(r.iface) {
		return awsBlocked(errors.New("invalid WireGuard interface"))
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return awsBlocked(errors.New("invalid IPv4 tunnel CIDR"))
	}
	cidr = prefix.Masked().String()
	if err := readAndVerifySysctl(r.procSys, filepath.Join("net/ipv4/conf", r.iface, "rp_filter"), "0"); err != nil {
		return awsBlocked(fmt.Errorf("WireGuard rp_filter: %w", err))
	}
	snapshot, err := r.observeRegisteredMechanisms(ctx, cidr)
	if err != nil {
		return awsBlocked(err)
	}
	if snapshot.hasChain(awsChain) && grant.Scope != ScopeIPMasqAndAWS {
		return awsBlocked(errors.New("AWS CNI requires a new journal epoch with AWS authority"))
	}
	if !snapshot.hasChain(ipMasqChain) && !snapshot.hasChain(awsChain) {
		return awsBlocked(errors.New(ReasonNoRegisteredAdapter))
	}
	status := ReconcileStatus{Host: ComponentStatus{Name: "wireguard_rp_filter", State: StateReady}}
	for _, adapter := range []struct{ name, chain, marker string }{{ipMasqAdapterName, ipMasqChain, ownedRuleComment}, {awsAdapterName, awsChain, AWSOwnedRuleComment}} {
		if !snapshot.hasChain(adapter.chain) {
			status.Adapters = append(status.Adapters, ComponentStatus{Name: adapter.name, State: StateNotApplicable, Reason: "exact chain absent"})
			continue
		}
		if err := r.convergeScopedChain(ctx, snapshot, adapter.chain, adapter.marker, cidr); err != nil {
			return awsBlocked(err)
		}
		status.Adapters = append(status.Adapters, ComponentStatus{Name: adapter.name, State: StateReady, OwnedRules: 1})
	}
	// Re-prove both adapters and hook ordering after ALL mutations. One adapter's
	// success cannot hide another mechanism or a controller replacement.
	after, err := r.observeRegisteredMechanisms(ctx, cidr)
	if err != nil {
		return awsBlocked(fmt.Errorf("CNI final readback: %w", err))
	}
	for _, chain := range []string{ipMasqChain, awsChain} {
		if snapshot.hasChain(chain) != after.hasChain(chain) {
			return awsBlocked(errors.New("CNI mechanism changed during reconciliation"))
		}
		if !after.hasChain(chain) {
			continue
		}
		owned := after.owned[chain]
		if len(owned) != 1 || owned[0].cidr != cidr || owned[0].iface != r.iface || owned[0].direction != "daddr" ||
			owned[0].marker != markerForChain(chain) || len(after.rules[nftKey("ip", "nat", chain)]) == 0 ||
			after.rules[nftKey("ip", "nat", chain)][0].Handle != owned[0].handle {
			return awsBlocked(errors.New("CNI exact owned rule or prepend readback mismatch"))
		}
	}
	if err := operationContextErr(ctx); err != nil {
		return awsBlocked(err)
	}
	return status, nil
}

// Also compare the absolute deadline: a fake runner may ignore cancellation,
// and the context timer goroutine need not have run before a final readback.
func operationContextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (r *Reconciler) lockOperation(ctx context.Context) error {
	for {
		if err := operationContextErr(ctx); err != nil {
			return err
		}
		if r.mu.TryLock() {
			if err := operationContextErr(ctx); err != nil {
				r.mu.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func markerForChain(chain string) string {
	if chain == awsChain {
		return AWSOwnedRuleComment
	}
	return ownedRuleComment
}

func (r *Reconciler) convergeScopedChain(ctx context.Context, snapshot *cniSnapshot, chain, marker, cidr string) error {
	owned := snapshot.owned[chain]
	all := snapshot.rules[nftKey("ip", "nat", chain)]
	keep := uint64(0)
	// The bypass must be the first executable rule. Matching bytes after a
	// terminal foreign rule are not readiness; remove/reinsert ONLY our rule.
	if len(all) != 0 {
		for _, rule := range owned {
			if rule.handle == all[0].Handle && rule.cidr == cidr && rule.iface == r.iface && rule.marker == marker && rule.direction == "daddr" {
				keep = rule.handle
			}
		}
	}
	for _, rule := range owned {
		if rule.handle == keep {
			continue
		}
		if err := r.deleteScopedRule(ctx, chain, rule.handle); err != nil {
			return err
		}
	}
	if keep == 0 {
		if err := operationContextErr(ctx); err != nil {
			return err
		}
		_, err := r.runNFT(ctx, "insert", "rule", "ip", "nat", chain, "ip", "daddr", cidr, "oifname", r.iface, "return", "comment", marker)
		if err != nil {
			return fmt.Errorf("insert scoped CNI return: %w", err)
		}
	}
	return nil
}

func (r *Reconciler) deleteScopedRule(ctx context.Context, chain string, handle uint64) error {
	if err := operationContextErr(ctx); err != nil {
		return err
	}
	_, err := r.runNFT(ctx, "delete", "rule", "ip", "nat", chain, "handle", strconv.FormatUint(handle, 10))
	if err != nil {
		return fmt.Errorf("delete exact owned CNI handle: %w", err)
	}
	return nil
}

func (r *Reconciler) withdrawAWSAwareLocked(ctx context.Context) (ReconcileStatus, error) {
	snapshot, err := r.readOwnedCNISnapshot(ctx)
	if err != nil {
		return awsBlocked(err)
	}
	for _, chain := range []string{ipMasqChain, awsChain} {
		for _, rule := range snapshot.owned[chain] {
			if err := r.deleteScopedRule(ctx, chain, rule.handle); err != nil {
				return awsBlocked(err)
			}
		}
	}
	after, err := r.readOwnedCNISnapshot(ctx)
	if err != nil {
		return awsBlocked(err)
	}
	if len(after.owned[ipMasqChain])+len(after.owned[awsChain]) != 0 {
		return awsBlocked(errors.New("owned CNI rules remain after withdrawal"))
	}
	status := ReconcileStatus{Host: ComponentStatus{Name: "wireguard_rp_filter", State: StateNotApplicable, Reason: "no active tunnel CIDR"}}
	for _, chain := range []string{ipMasqChain, awsChain} {
		name := ipMasqAdapterName
		if chain == awsChain {
			name = awsAdapterName
		}
		state := StateNotApplicable
		if after.hasChain(chain) {
			state = StateReady
		}
		status.Adapters = append(status.Adapters, ComponentStatus{Name: name, State: state})
	}
	if err := operationContextErr(ctx); err != nil {
		return awsBlocked(err)
	}
	return status, nil
}

func (r *Reconciler) ownedAWSAwareArtifacts(ctx context.Context) ([]OwnedRuleReceipt, State, error) {
	snapshot, err := r.readOwnedCNISnapshot(ctx)
	if err != nil {
		return nil, StateBlocked, err
	}
	var out []OwnedRuleReceipt
	for _, chain := range []string{ipMasqChain, awsChain} {
		for _, rule := range snapshot.owned[chain] {
			out = append(out, OwnedRuleReceipt{Handle: rule.handle, CIDR: rule.cidr, Interface: rule.iface, Marker: rule.marker, Direction: rule.direction})
		}
	}
	if !snapshot.hasChain(ipMasqChain) && !snapshot.hasChain(awsChain) {
		return out, StateNotApplicable, nil
	}
	return out, StateReady, nil
}

type nftChainView struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Handle   uint64 `json:"handle"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority int    `json:"prio"`
	Policy   string `json:"policy"`
}
type nftRuleView struct {
	Family  string           `json:"family"`
	Table   string           `json:"table"`
	Chain   string           `json:"chain"`
	Handle  uint64           `json:"handle"`
	Comment string           `json:"comment"`
	Expr    []map[string]any `json:"expr"`
}
type cniSnapshot struct {
	chains map[string]nftChainView
	rules  map[string][]nftRuleView
	owned  map[string][]ownedRule
}

func nftKey(family, table, chain string) string { return family + "/" + table + "/" + chain }
func (s *cniSnapshot) hasChain(chain string) bool {
	_, ok := s.chains[nftKey("ip", "nat", chain)]
	return ok
}

func (r *Reconciler) readCNISnapshot(ctx context.Context) (*cniSnapshot, error) {
	if err := operationContextErr(ctx); err != nil {
		return nil, err
	}
	listing, err := r.runNFT(ctx, "-j", "-a", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("observe CNI nft ruleset: %w", err)
	}
	if err := operationContextErr(ctx); err != nil {
		return nil, err
	}
	return parseCNISnapshot(listing)
}

// Ownership census is deliberately weaker than runtime qualification: foreign
// topology may be broken during teardown, but opaque ownership cannot authorize
// deletion or a new clean baseline. Correlate native handles and compat markers
// across a stable snapshot without requiring any foreign rule's packet meaning.
func (r *Reconciler) readOwnedCNISnapshot(ctx context.Context) (*cniSnapshot, error) {
	before, err := r.readCNISnapshot(ctx)
	if err != nil || !before.hasChain(awsChain) {
		return before, err
	}
	listing, err := r.readAWSCompat(ctx)
	if err != nil {
		return nil, err
	}
	if err := before.validateAWSOwnedCompat(listing); err != nil {
		return nil, err
	}
	after, err := r.readCNISnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if before.fingerprint() != after.fingerprint() {
		return nil, errors.New("CNI rules changed across ownership census")
	}
	return after, nil
}

func (r *Reconciler) readAWSCompat(ctx context.Context) (string, error) {
	if err := operationContextErr(ctx); err != nil {
		return "", err
	}
	version, err := r.runIPTables(ctx, "-V")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(version), "iptables-nft-save v") || !strings.Contains(version, "(nf_tables)") {
		return "", errors.New("explicit nft-backed iptables-nft-save is unavailable or incompatible")
	}
	if err := operationContextErr(ctx); err != nil {
		return "", err
	}
	listing, err := r.runIPTables(ctx, "-t", "nat")
	if err != nil {
		return "", fmt.Errorf("observe AWS compat rule semantics: %w", err)
	}
	if err := operationContextErr(ctx); err != nil {
		return "", err
	}
	return listing, nil
}

func (s *cniSnapshot) validateAWSOwnedCompat(listing string) error {
	chains, err := parseNFTSaveNAT(listing)
	if err != nil {
		return err
	}
	native := s.rules[nftKey("ip", "nat", awsChain)]
	compat, exists := chains[awsChain]
	if !exists || len(native) != len(compat) {
		return errors.New("AWS ownership census nft/compat chain or rule count differs")
	}
	for chain, rules := range chains {
		if strings.Contains(chain, "tunnex_k8s_aws_snat") {
			return errors.New("AWS compat ownership marker is outside its exact namespace")
		}
		for i, line := range rules {
			reserved := strings.Contains(line, "tunnex_k8s_aws_snat")
			if chain != awsChain {
				if reserved {
					return errors.New("AWS compat ownership marker is outside its exact namespace")
				}
				continue
			}
			if native[i].Comment != AWSOwnedRuleComment {
				if reserved {
					return errors.New("AWS compat ownership marker lacks an exact native owned rule")
				}
				continue
			}
			if err := validateOwnedAWSCompatRule(native[i], line); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOwnedAWSCompatRule(rule nftRuleView, line string) error {
	owned, err := parseExactOwnedNFTRule(rule)
	if err != nil {
		return err
	}
	plain := fmt.Sprintf("-A %s -d %s -o %s -j RETURN", awsChain, owned.cidr, owned.iface)
	marked := fmt.Sprintf("-A %s -d %s -o %s -m comment --comment %s -j RETURN", awsChain, owned.cidr, owned.iface, AWSOwnedRuleComment)
	if line != plain && line != marked {
		return errors.New("owned AWS rule compat readback is not exact")
	}
	return nil
}

func parseCNISnapshot(listing string) (*cniSnapshot, error) {
	if len(listing) > maxCNISnapshotBytes {
		return nil, errors.New("CNI ruleset exceeds inspection bound")
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(listing), &doc); err != nil || doc.NFTables == nil {
		return nil, errors.New("invalid nft CNI ruleset JSON")
	}
	s := &cniSnapshot{chains: map[string]nftChainView{}, rules: map[string][]nftRuleView{}, owned: map[string][]ownedRule{}}
	handles := map[string]bool{}
	for _, entry := range doc.NFTables {
		if raw, ok := entry["chain"]; ok {
			var chain nftChainView
			if err := json.Unmarshal(raw, &chain); err != nil || chain.Handle == 0 {
				return nil, errors.New("invalid nft chain or handle")
			}
			key := nftKey(chain.Family, chain.Table, chain.Name)
			if _, exists := s.chains[key]; exists {
				return nil, errors.New("duplicate nft chain")
			}
			s.chains[key] = chain
		}
		if raw, ok := entry["rule"]; ok {
			var rule nftRuleView
			if err := json.Unmarshal(raw, &rule); err != nil || rule.Handle == 0 {
				return nil, errors.New("invalid nft rule or missing handle")
			}
			key := nftKey(rule.Family, rule.Table, rule.Chain)
			handleKey := nftKey(rule.Family, rule.Table, strconv.FormatUint(rule.Handle, 10))
			if handles[handleKey] {
				return nil, errors.New("duplicate nft rule handle")
			}
			handles[handleKey] = true
			s.rules[key] = append(s.rules[key], rule)
			reserved := strings.Contains(string(raw), ownedRuleComment) || strings.Contains(string(raw), legacyRuleComment) || strings.Contains(string(raw), "tunnex_k8s_aws_snat")
			if !reserved {
				continue
			}
			if rule.Family != "ip" || rule.Table != "nat" ||
				!((rule.Chain == ipMasqChain && (rule.Comment == ownedRuleComment || rule.Comment == legacyRuleComment)) || (rule.Chain == awsChain && rule.Comment == AWSOwnedRuleComment)) {
				return nil, errors.New("CNI ownership marker is malformed or outside its exact namespace")
			}
			owned, err := parseExactOwnedNFTRule(rule)
			if err != nil {
				return nil, err
			}
			s.owned[rule.Chain] = append(s.owned[rule.Chain], owned)
		}
	}
	for key := range s.rules {
		if _, ok := s.chains[key]; !ok {
			return nil, errors.New("nft rule references an undeclared chain")
		}
	}
	return s, nil
}

func parseExactOwnedNFTRule(rule nftRuleView) (ownedRule, error) {
	expr := withoutCounters(rule.Expr)
	if len(expr) != 3 || !reflect.DeepEqual(expr[2], map[string]any{"return": nil}) {
		return ownedRule{}, errors.New("owned CNI rule has an unknown expression")
	}
	direction := "daddr"
	cidr, ok := nftAddressMatch(expr[0], direction)
	if !ok && rule.Comment == legacyRuleComment {
		direction = "saddr"
		cidr, ok = nftAddressMatch(expr[0], direction)
	}
	iface, ifaceOK := nftInterfaceMatch(expr[1], "==")
	if !ok || !ifaceOK || !interfaceNameRE.MatchString(iface) {
		return ownedRule{}, errors.New("owned CNI rule has an invalid exact scope")
	}
	return ownedRule{handle: rule.Handle, cidr: cidr, iface: iface, marker: rule.Comment, direction: direction}, nil
}

func withoutCounters(expr []map[string]any) []map[string]any {
	var out []map[string]any
	for _, item := range expr {
		if len(item) == 1 {
			if count, ok := item["counter"].(map[string]any); ok && len(count) == 2 {
				p, pok := count["packets"].(float64)
				b, bok := count["bytes"].(float64)
				if pok && bok && p >= 0 && b >= 0 && p == float64(uint64(p)) && b == float64(uint64(b)) {
					continue
				}
			}
		}
		out = append(out, item)
	}
	return out
}

// nft 1.0.4 emits xt:null; the runtime's 1.0.9 formatter exposes this exact
// typed descriptor. Accept the latter only at a position whose specific match
// or target is independently proved by explicit iptables-nft-save semantics.
// Never erase arbitrary typed expressions into the old opaque representation.
func nftXT(expr map[string]any, kind, name string) bool {
	if reflect.DeepEqual(expr, map[string]any{"xt": nil}) {
		return true
	}
	return reflect.DeepEqual(expr, map[string]any{"xt": map[string]any{"type": kind, "name": name}})
}

func nftMatch(expr map[string]any, op string, left any) (any, bool) {
	match, ok := expr["match"].(map[string]any)
	if len(expr) != 1 || !ok || len(match) != 3 || match["op"] != op || !reflect.DeepEqual(match["left"], left) {
		return nil, false
	}
	right, ok := match["right"]
	return right, ok
}

func nftAddressMatch(expr map[string]any, direction string) (string, bool) {
	right, ok := nftMatch(expr, "==", map[string]any{"payload": map[string]any{"protocol": "ip", "field": direction}})
	if !ok {
		return "", false
	}
	if address, ok := right.(string); ok {
		addr, err := netip.ParseAddr(address)
		return addr.String() + "/32", err == nil && addr.Is4() && addr.String() == address
	}
	object, ok := right.(map[string]any)
	if !ok || len(object) != 1 {
		return "", false
	}
	prefix, ok := object["prefix"].(map[string]any)
	if !ok || len(prefix) != 2 {
		return "", false
	}
	addr, ok := prefix["addr"].(string)
	bits, bitsOK := prefix["len"].(float64)
	if !ok || !bitsOK || bits < 0 || bits > 32 || bits != float64(int(bits)) {
		return "", false
	}
	value := addr + "/" + strconv.Itoa(int(bits))
	p, err := netip.ParsePrefix(value)
	return value, err == nil && p.Addr().Is4() && p.Masked().String() == value
}

func nftInterfaceMatch(expr map[string]any, op string) (string, bool) {
	right, ok := nftMatch(expr, op, map[string]any{"meta": map[string]any{"key": "oifname"}})
	iface, stringOK := right.(string)
	return iface, ok && stringOK
}

// Counter values and JSON formatting may advance during observation, but every
// executable foreign expression, ownership field and handle must remain exact.
func (s *cniSnapshot) fingerprint() string {
	copyRules := map[string][]nftRuleView{}
	for key, rules := range s.rules {
		for _, rule := range rules {
			rule.Expr = withoutCounters(rule.Expr)
			copyRules[key] = append(copyRules[key], rule)
		}
	}
	encoded, _ := json.Marshal(struct {
		Chains map[string]nftChainView
		Rules  map[string][]nftRuleView
	}{s.chains, copyRules})
	return string(encoded)
}

func (r *Reconciler) observeRegisteredMechanisms(ctx context.Context, cidr string) (*cniSnapshot, error) {
	before, err := r.readCNISnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err := before.validateHookCoverage(r.iface, cidr); err != nil {
		return nil, err
	}
	if before.hasChain(ipMasqChain) {
		if err := before.validateIPMasqForeignRules(); err != nil {
			return nil, err
		}
	}
	if before.hasChain(awsChain) {
		listing, err := r.readAWSCompat(ctx)
		if err != nil {
			return nil, err
		}
		if err := before.validateAWSOwnedCompat(listing); err != nil {
			return nil, err
		}
		if err := before.validateAWSCompat(listing); err != nil {
			return nil, err
		}
	}
	after, err := r.readCNISnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if before.fingerprint() != after.fingerprint() {
		return nil, errors.New("CNI rules changed across semantic observation")
	}
	return after, nil
}

func (s *cniSnapshot) validateHookCoverage(iface, cidr string) error {
	postKey := nftKey("ip", "nat", "POSTROUTING")
	for key, rules := range s.rules {
		for _, rule := range rules {
			for _, expr := range rule.Expr {
				for _, verdict := range []string{"jump", "goto"} {
					target, ok := expr[verdict].(map[string]any)
					if !ok {
						continue
					}
					if (target["target"] == awsChain || target["target"] == ipMasqChain) && (key != postKey || verdict != "jump") {
						return errors.New("registered CNI has another or conditional entry path")
					}
				}
			}
		}
	}
	post, postOK := s.chains[postKey]
	if s.hasChain(ipMasqChain) || s.hasChain(awsChain) {
		if !postOK || post.Type != "nat" || post.Hook != "postrouting" || post.Priority != 100 || post.Policy != "accept" {
			return errors.New("registered CNI lacks exact IPv4 source-NAT hook coverage")
		}
	}
	for key, chain := range s.chains {
		if chain.Family != "ip" && chain.Family != "inet" {
			continue
		}
		if chain.Hook != "postrouting" {
			continue
		}
		if key == postKey {
			continue
		}
		if chain.Family == "ip" && chain.Table == "tunnex" && chain.Name == "postrouting" && chain.Type == "nat" && chain.Priority == 99 && chain.Policy == "accept" {
			if err := s.validateTunnexPostrouting(iface, cidr); err != nil {
				return err
			}
			continue
		}
		// A foreign postrouting filter can set marks that select an earlier NAT
		// binding too; merely checking its type would miss that coverage.
		return errors.New("unknown IPv4 postrouting hook coverage")
	}
	seen := map[string]bool{}
	for _, rule := range s.rules[postKey] {
		expr := withoutCounters(rule.Expr)
		// The explicit compat readback below proves xt comment semantics for AWS.
		if len(expr) == 2 && nftXT(expr[0], "match", "comment") && s.hasChain(awsChain) {
			expr = expr[1:]
		}
		if len(expr) != 1 || len(expr[0]) != 1 {
			return errors.New("unknown NAT POSTROUTING rule coverage")
		}
		jump, ok := expr[0]["jump"].(map[string]any)
		if !ok || len(jump) != 1 {
			return errors.New("NAT POSTROUTING is not an unconditional registered jump")
		}
		target, ok := jump["target"].(string)
		if !ok || seen[target] || (target != ipMasqChain && target != awsChain && !(target == "KUBE-POSTROUTING" && s.hasChain(awsChain))) {
			return errors.New("unknown or duplicate NAT jump target")
		}
		seen[target] = true
	}
	for _, chain := range []string{ipMasqChain, awsChain} {
		if s.hasChain(chain) != seen[chain] {
			return errors.New("registered CNI chain has ambiguous reachability")
		}
		if s.hasChain(chain) {
			view := s.chains[nftKey("ip", "nat", chain)]
			if view.Hook != "" || view.Type != "" || view.Policy != "" {
				return errors.New("registered CNI chain unexpectedly owns a hook")
			}
		}
	}
	return nil
}

func (s *cniSnapshot) validateTunnexPostrouting(iface, cidr string) error {
	ownerKey := nftKey("ip", "tunnex", "tunnex_posture_owner")
	owner, ok := s.chains[ownerKey]
	markers := s.rules[ownerKey]
	if !ok || owner.Hook != "" || len(markers) != 1 || markers[0].Comment != "tunnex_host_posture_v1" || len(markers[0].Expr) != 1 || len(withoutCounters(markers[0].Expr)) != 0 {
		return errors.New("Tunnex NAT hook lacks its exact posture ownership marker")
	}
	for _, rule := range s.rules[nftKey("ip", "tunnex", "postrouting")] {
		expr := withoutCounters(rule.Expr)
		if len(expr) != 3 || rule.Comment != "" || !reflect.DeepEqual(expr[2], map[string]any{"masquerade": nil}) {
			return errors.New("unknown Tunnex source-NAT rule")
		}
		if actual, ok := nftAddressMatch(expr[0], "saddr"); !ok || actual != cidr {
			return errors.New("Tunnex source-NAT CIDR differs from current tunnel")
		}
		right, ok := nftMatch(expr[1], "!=", map[string]any{"meta": map[string]any{"key": "oifname"}})
		if !ok {
			return errors.New("Tunnex source-NAT lacks exact tunnel egress exclusion")
		}
		excluded := right == iface
		if set, ok := right.(map[string]any); ok && len(set) == 1 {
			members, ok := set["set"].([]any)
			if !ok || len(members) == 0 || len(members) > 16 {
				return errors.New("Tunnex NAT interface set is unsupported")
			}
			for _, member := range members {
				name, ok := member.(string)
				if !ok || !interfaceNameRE.MatchString(name) {
					return errors.New("Tunnex NAT interface set is invalid")
				}
				if name == iface {
					excluded = true
				}
			}
		}
		if !excluded {
			return errors.New("Tunnex NAT could bind traffic returning to WireGuard")
		}
	}
	return nil
}

func (s *cniSnapshot) validateIPMasqForeignRules() error {
	var foreign []nftRuleView
	for _, rule := range s.rules[nftKey("ip", "nat", ipMasqChain)] {
		if rule.Comment != ownedRuleComment && rule.Comment != legacyRuleComment {
			foreign = append(foreign, rule)
		}
	}
	if len(foreign) == 0 {
		return errors.New("IP-MASQ chain has no registered masquerade mechanism")
	}
	for i, rule := range foreign {
		expr := withoutCounters(rule.Expr)
		if i == len(foreign)-1 && len(expr) == 1 && reflect.DeepEqual(expr[0], map[string]any{"masquerade": nil}) {
			continue
		}
		if i == len(foreign)-1 || len(expr) != 2 || !reflect.DeepEqual(expr[1], map[string]any{"return": nil}) {
			return errors.New("unsupported IP-MASQ foreign rule topology")
		}
		if _, ok := nftAddressMatch(expr[0], "daddr"); !ok {
			return errors.New("unsupported IP-MASQ destination exemption")
		}
	}
	return nil
}

// The AWS registration deliberately covers chain-0's observed single VPC
// return + terminal SNAT form, not arbitrary AWS-named chains or future modes.
func (s *cniSnapshot) validateAWSCompat(listing string) error {
	chains, err := parseNFTSaveNAT(listing)
	if err != nil {
		return err
	}
	for name := range chains {
		if strings.HasPrefix(name, "AWS-SNAT-CHAIN-") && name != awsChain {
			return errors.New("unsupported AWS SNAT chain topology")
		}
	}
	for _, chain := range s.chains {
		if chain.Family == "ip" && chain.Table == "nat" && strings.HasPrefix(chain.Name, "AWS-SNAT-CHAIN-") && chain.Name != awsChain {
			return errors.New("unsupported nft AWS SNAT chain topology")
		}
	}
	post := chains["POSTROUTING"]
	expectedPost := []string{"-A POSTROUTING -m comment --comment \"kubernetes postrouting rules\" -j KUBE-POSTROUTING"}
	for _, rule := range s.rules[nftKey("ip", "nat", "POSTROUTING")] {
		expr := withoutCounters(rule.Expr)
		last := expr[len(expr)-1]
		jump, _ := last["jump"].(map[string]any)
		if jump["target"] == ipMasqChain {
			expectedPost = append(expectedPost, "-A POSTROUTING -j "+ipMasqChain)
		}
	}
	expectedPost = append(expectedPost, "-A POSTROUTING -m comment --comment \"AWS SNAT CHAIN\" -j "+awsChain)
	if !reflect.DeepEqual(post, expectedPost) {
		return errors.New("unsupported AWS/Kubernetes postrouting order or semantics")
	}
	kube := []string{
		"-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN",
		"-A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0",
		"-A KUBE-POSTROUTING -m comment --comment \"kubernetes service traffic requiring SNAT\" -j MASQUERADE --random-fully",
	}
	if !reflect.DeepEqual(chains["KUBE-POSTROUTING"], kube) || len(s.rules[nftKey("ip", "nat", "KUBE-POSTROUTING")]) != len(kube) {
		return errors.New("unsupported earlier Kubernetes masquerade path")
	}
	kubeNFT := s.rules[nftKey("ip", "nat", "KUBE-POSTROUTING")]
	markReturn := []map[string]any{
		{"match": map[string]any{"op": "!=", "left": map[string]any{"&": []any{map[string]any{"meta": map[string]any{"key": "mark"}}, float64(16384)}}, "right": float64(16384)}},
		{"return": nil},
	}
	markExpr, masqueradeExpr := withoutCounters(kubeNFT[1].Expr), withoutCounters(kubeNFT[2].Expr)
	if !reflect.DeepEqual(withoutCounters(kubeNFT[0].Expr), markReturn) ||
		len(markExpr) != 1 || !nftXT(markExpr[0], "target", "MARK") ||
		len(masqueradeExpr) != 2 || !nftXT(masqueradeExpr[0], "match", "comment") || !nftXT(masqueradeExpr[1], "target", "MASQUERADE") {
		return errors.New("Kubernetes nft/compat masquerade semantics disagree")
	}
	aws := chains[awsChain]
	nftRules := s.rules[nftKey("ip", "nat", awsChain)]
	if len(aws) != len(nftRules) {
		return errors.New("AWS nft and compat rule counts differ")
	}
	var foreign []string
	var foreignNFT []nftRuleView
	for i, rule := range nftRules {
		if rule.Comment == AWSOwnedRuleComment {
			// nft native comments are metadata; iptables-nft-save may print the
			// semantic return without that metadata, but never an unknown rule.
			if err := validateOwnedAWSCompatRule(rule, aws[i]); err != nil {
				return err
			}
			continue
		}
		foreign = append(foreign, aws[i])
		foreignNFT = append(foreignNFT, rule)
	}
	if len(foreign) != 2 {
		return errors.New("unsupported AWS foreign rule topology")
	}
	first := strings.Fields(foreign[0])
	if len(first) != 12 || first[0] != "-A" || first[1] != awsChain || first[2] != "-d" {
		return errors.New("unsupported AWS VPC return")
	}
	prefix, err := netip.ParsePrefix(first[3])
	if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != first[3] ||
		foreign[0] != fmt.Sprintf("-A %s -d %s -m comment --comment \"AWS SNAT CHAIN\" -j RETURN", awsChain, first[3]) {
		return errors.New("unsupported AWS VPC return scope")
	}
	parts := strings.Fields(foreign[1])
	if len(parts) != 20 {
		return errors.New("unsupported AWS terminal SNAT")
	}
	ip := parts[18]
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() || addr.String() != ip || !prefix.Contains(addr) ||
		foreign[1] != fmt.Sprintf("-A %s ! -o vlan+ -m comment --comment \"AWS, SNAT\" -m addrtype ! --dst-type LOCAL -j SNAT --to-source %s --random-fully", awsChain, ip) {
		return errors.New("unsupported AWS terminal SNAT scope")
	}
	// Cross-check every visible native expression. xt opacity is accepted only
	// at the exact locations whose semantics the explicit save proved above.
	firstExpr := withoutCounters(foreignNFT[0].Expr)
	actualCIDR, ok := "", false
	if len(firstExpr) == 3 {
		actualCIDR, ok = nftAddressMatch(firstExpr[0], "daddr")
	}
	if !ok || actualCIDR != first[3] || !nftXT(firstExpr[1], "match", "comment") || !reflect.DeepEqual(firstExpr[2], map[string]any{"return": nil}) {
		return errors.New("AWS VPC nft/compat semantics disagree")
	}
	lastExpr := withoutCounters(foreignNFT[1].Expr)
	actualIface, ok := "", false
	if len(lastExpr) == 4 {
		actualIface, ok = nftInterfaceMatch(lastExpr[0], "!=")
	}
	if !ok || actualIface != "vlan*" || !nftXT(lastExpr[1], "match", "comment") || !nftXT(lastExpr[2], "match", "addrtype") || !nftXT(lastExpr[3], "target", "SNAT") {
		return errors.New("AWS SNAT nft/compat semantics disagree")
	}
	return nil
}

func parseNFTSaveNAT(listing string) (map[string][]string, error) {
	if len(listing) > maxCNISnapshotBytes {
		return nil, errors.New("compat CNI snapshot exceeds bound")
	}
	chains := map[string][]string{}
	inNAT, found, complete := false, false, false
	for _, raw := range strings.Split(listing, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# Generated by iptables") || strings.HasPrefix(line, "# Completed on ") {
				continue
			}
			return nil, errors.New("unrecognized compat inspection warning")
		}
		if strings.HasPrefix(line, "*") {
			if inNAT || (line == "*nat" && found) {
				return nil, errors.New("ambiguous compat NAT table")
			}
			inNAT = line == "*nat"
			if inNAT {
				found = true
			}
			continue
		}
		if line == "COMMIT" {
			if inNAT {
				complete = true
			}
			inNAT = false
			continue
		}
		if !inNAT {
			continue
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, ":") {
			if len(fields) != 3 {
				return nil, errors.New("malformed compat chain declaration")
			}
			name := strings.TrimPrefix(fields[0], ":")
			if _, ok := chains[name]; ok {
				return nil, errors.New("duplicate compat chain")
			}
			chains[name] = []string{}
			continue
		}
		if len(fields) < 3 || fields[0] != "-A" {
			return nil, errors.New("unknown compat NAT record")
		}
		if _, ok := chains[fields[1]]; !ok {
			return nil, errors.New("compat rule has undeclared chain")
		}
		chains[fields[1]] = append(chains[fields[1]], line)
	}
	if !found || !complete || inNAT {
		return nil, errors.New("incomplete compat NAT inspection")
	}
	return chains, nil
}
