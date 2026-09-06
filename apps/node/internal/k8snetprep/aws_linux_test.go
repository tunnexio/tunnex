//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// These are the actual, unmodified read-only worker snapshots committed in the
// walk ledger, including opaque xt expressions. The mutation fake below models
// ONLY our closed nft insert/delete calls; it does not invent foreign semantics.
func nativeAWSFixture(t *testing.T) (string, string) {
	t.Helper()
	root := "testdata"
	nft, err := os.ReadFile(filepath.Join(root, "native-nft-ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := os.ReadFile(filepath.Join(root, "native-iptables-nft-save.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(nft), string(ip)
}

type awsTestKernel struct {
	doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	save          string
	version       string
	next          uint64
	mutations     []string
	commands      []string
	inspectErr    error
	checkGuard    func()
	deleteFailure bool
	discardInsert bool
}

func newAWSTestKernel(t *testing.T) *awsTestKernel {
	t.Helper()
	nft, save := nativeAWSFixture(t)
	f := &awsTestKernel{save: save, version: "iptables-nft-save v1.8.8 (nf_tables)", next: 10000}
	if err := json.Unmarshal([]byte(nft), &f.doc); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *awsTestKernel) listing() string { out, _ := json.Marshal(f.doc); return string(out) }
func rawEntry(kind string, value any) map[string]json.RawMessage {
	out, _ := json.Marshal(value)
	return map[string]json.RawMessage{kind: out}
}

func (f *awsTestKernel) addRule(rule nftRuleView, first bool) {
	if rule.Handle == 0 {
		f.next++
		rule.Handle = f.next
	}
	entry := rawEntry("rule", rule)
	if first {
		for i, item := range f.doc.NFTables {
			var old nftRuleView
			if json.Unmarshal(item["rule"], &old) == nil && nftKey(old.Family, old.Table, old.Chain) == nftKey(rule.Family, rule.Table, rule.Chain) {
				f.doc.NFTables = append(f.doc.NFTables[:i], append([]map[string]json.RawMessage{entry}, f.doc.NFTables[i:]...)...)
				return
			}
		}
	}
	f.doc.NFTables = append(f.doc.NFTables, entry)
}

func nftAddr(direction, cidr string) map[string]any {
	parts := strings.Split(cidr, "/")
	bits, _ := strconv.Atoi(parts[1])
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": direction}}, "right": map[string]any{"prefix": map[string]any{"addr": parts[0], "len": float64(bits)}}}}
}
func nftIface(op, iface string) map[string]any {
	return map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": iface}}
}
func nftOwned(chain, cidr, iface, marker string) nftRuleView {
	return nftRuleView{Family: "ip", Table: "nat", Chain: chain, Comment: marker, Expr: []map[string]any{nftAddr("daddr", cidr), nftIface("==", iface), {"return": nil}}}
}

func (f *awsTestKernel) nft(_ context.Context, args ...string) (string, error) {
	if f.checkGuard != nil {
		f.checkGuard()
	}
	command := strings.Join(args, " ")
	f.commands = append(f.commands, "nft "+command)
	if command == "-j -a list ruleset" {
		if f.inspectErr != nil {
			return "", f.inspectErr
		}
		return f.listing(), nil
	}
	if command == "-a list chain ip nat IP-MASQ-AGENT" {
		return "", fakeNftExitError{message: "Error: No such file or directory"}
	}
	if len(args) == 13 && args[0] == "insert" && args[1] == "rule" && args[2] == "ip" && args[3] == "nat" &&
		(args[4] == awsChain || args[4] == ipMasqChain) && args[5] == "ip" && args[6] == "daddr" && args[8] == "oifname" && args[10] == "return" && args[11] == "comment" {
		f.mutations = append(f.mutations, command)
		if !f.discardInsert {
			f.addRule(nftOwned(args[4], args[7], args[9], args[12]), true)
		}
		return "", nil
	}
	if len(args) == 15 && args[0] == "insert" && args[1] == "rule" && args[2] == "ip" && args[3] == "nat" &&
		args[4] == awsChain && args[5] == "ip" && args[6] == "saddr" && args[8] == "iifname" && args[10] == "oifname" &&
		args[12] == "return" && args[13] == "comment" && args[14] == AWSTransitOwnedRuleComment {
		f.mutations = append(f.mutations, command)
		if !f.discardInsert {
			ingress := map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": args[9]}}
			f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: awsChain, Comment: args[14], Expr: []map[string]any{
				nftAddr("saddr", args[7]), ingress, nftIface("==", args[11]), {"return": nil},
			}}, true)
		}
		return "", nil
	}
	if len(args) == 7 && args[0] == "delete" && args[1] == "rule" && args[2] == "ip" && args[3] == "nat" &&
		(args[4] == awsChain || args[4] == ipMasqChain) && args[5] == "handle" {
		f.mutations = append(f.mutations, command)
		if f.deleteFailure {
			return "", errors.New("injected exact delete failure")
		}
		handle, _ := strconv.ParseUint(args[6], 10, 64)
		for i, item := range f.doc.NFTables {
			var rule nftRuleView
			if json.Unmarshal(item["rule"], &rule) == nil && rule.Family == "ip" && rule.Table == "nat" && rule.Chain == args[4] && rule.Handle == handle {
				f.doc.NFTables = append(f.doc.NFTables[:i], f.doc.NFTables[i+1:]...)
				return "", nil
			}
		}
		return "", errors.New("unknown delete handle")
	}
	return "", fmt.Errorf("unexpected nft command %q", command)
}

func (f *awsTestKernel) iptables(_ context.Context, args ...string) (string, error) {
	if f.checkGuard != nil {
		f.checkGuard()
	}
	f.commands = append(f.commands, "iptables-nft-save "+strings.Join(args, " "))
	if strings.Join(args, " ") == "-V" {
		return f.version, nil
	}
	if strings.Join(args, " ") != "-t nat" {
		return "", errors.New("unexpected compat command")
	}
	if f.inspectErr != nil {
		return "", f.inspectErr
	}
	// Model native owned rules in their actual chain positions, while leaving
	// the saved FOREIGN AWS bytes untouched. A real-tool witness is separate.
	snapshot, err := parseCNISnapshot(f.listing())
	if err != nil {
		return "", err
	}
	base, err := parseNFTSaveNAT(f.save)
	if err != nil {
		return "", err
	}
	var rendered []string
	foreignIndex := 0
	for _, rule := range snapshot.rules[nftKey("ip", "nat", awsChain)] {
		if rule.Comment != AWSOwnedRuleComment && rule.Comment != AWSTransitOwnedRuleComment {
			if foreignIndex >= len(base[awsChain]) {
				return "", errors.New("fake lacks exact foreign rule bytes")
			}
			rendered = append(rendered, base[awsChain][foreignIndex])
			foreignIndex++
			continue
		}
		owned, err := parseExactOwnedNFTRule(rule)
		if err != nil {
			return "", err
		}
		if owned.marker == AWSTransitOwnedRuleComment {
			rendered = append(rendered, fmt.Sprintf("-A %s -s %s -i %s -o %s -j RETURN", awsChain, owned.cidr, owned.ingress, owned.iface))
		} else {
			rendered = append(rendered, fmt.Sprintf("-A %s -d %s -o %s -j RETURN", awsChain, owned.cidr, owned.iface))
		}
	}
	var lines []string
	emitted := false
	for _, line := range strings.Split(f.save, "\n") {
		if strings.HasPrefix(line, "-A "+awsChain+" ") {
			if !emitted {
				lines = append(lines, rendered...)
				emitted = true
			}
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}

func awsTestReconciler(t *testing.T, f *awsTestKernel, scope AuthorityScope) *Reconciler {
	t.Helper()
	r := NewWithAWS("wg0", f.nft, f.iptables, func(context.Context) (AuthorityGrant, func(), error) { return awsTestGrant(scope), func() {}, nil })
	r.procSys = t.TempDir()
	path := filepath.Join(r.procSys, "net", "ipv4", "conf", "wg0", "rp_filter")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	return r
}

func awsTestGrant(scope AuthorityScope) AuthorityGrant {
	return AuthorityGrant{Scope: scope, NotAfter: time.Now().Add(time.Minute)}
}

func TestAWSActualWorkerSnapshotsProveRegisteredMechanism(t *testing.T) {
	nft, save := nativeAWSFixture(t)
	s, err := parseCNISnapshot(nft)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validateHookCoverage("wg0", "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := s.validateAWSCompat(save); err != nil {
		t.Fatal(err)
	}
	if !s.hasChain(awsChain) || s.hasChain(ipMasqChain) {
		t.Fatal("actual worker mechanism census changed")
	}
}

// Model only the formatter change at the explicitly witnessed compat positions.
// Packet semantics still come from the unchanged explicit iptables-nft-save.
func awsTypedFormatterFixture(t *testing.T, f *awsTestKernel) {
	t.Helper()
	positions := map[string][][2]string{
		"POSTROUTING/0":      {{"match", "comment"}},
		"POSTROUTING/1":      {{"match", "comment"}},
		"KUBE-POSTROUTING/1": {{"target", "MARK"}},
		"KUBE-POSTROUTING/2": {{"match", "comment"}, {"target", "MASQUERADE"}},
		"AWS-SNAT-CHAIN-0/0": {{"match", "comment"}},
		"AWS-SNAT-CHAIN-0/1": {{"match", "comment"}, {"match", "addrtype"}, {"target", "SNAT"}},
	}
	indexes := map[string]int{}
	for i, entry := range f.doc.NFTables {
		var rule nftRuleView
		if json.Unmarshal(entry["rule"], &rule) != nil || rule.Family != "ip" || rule.Table != "nat" {
			continue
		}
		key := rule.Chain + "/" + strconv.Itoa(indexes[rule.Chain])
		indexes[rule.Chain]++
		want, ok := positions[key]
		if !ok {
			continue
		}
		matched := 0
		for _, expr := range rule.Expr {
			if reflect.DeepEqual(expr, map[string]any{"xt": nil}) {
				if matched >= len(want) {
					t.Fatalf("extra compat expression in %s", key)
				}
				expr["xt"] = map[string]any{"type": want[matched][0], "name": want[matched][1]}
				matched++
			}
		}
		if matched != len(want) {
			t.Fatalf("compat fixture %s has %d expressions, want %d", key, matched, len(want))
		}
		f.doc.NFTables[i] = rawEntry("rule", rule)
		delete(positions, key)
	}
	if len(positions) != 0 {
		t.Fatalf("missing formatter positions: %v", positions)
	}
}

func TestAWSExplicitTypedFormatterReconcilesWithoutForeignRewrite(t *testing.T) {
	f := newAWSTestKernel(t)
	awsTypedFormatterFixture(t, f)
	before := f.listing()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), "10.98.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.listing() != before {
		t.Fatal("typed foreign compatibility expressions were rewritten")
	}
}

func TestAWSActualAlpineRuntimeBeforeAndOwnedSnapshotsConverge(t *testing.T) {
	load := func(name string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	baselineNFT := load("runtime-alpine-baseline.nft.json")
	baselineSave := load("runtime-alpine-baseline.iptables.txt")
	ownedNFT := load("runtime-alpine-owned.nft.json")
	ownedSave := load("runtime-alpine-owned.iptables.txt")
	// Feed the complete actual before/after readbacks, not a reformatted fake.
	// The isolated real witness produced native handle 21 from this one insert.
	ownsRule := false
	mutations := 0
	r := awsTestReconciler(t, newAWSTestKernel(t), ScopeIPMasqAndAWS)
	r.runNFT = func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-j -a list ruleset":
			if ownsRule {
				return ownedNFT, nil
			}
			return baselineNFT, nil
		case "insert rule ip nat AWS-SNAT-CHAIN-0 ip daddr 10.99.0.0/24 oifname wg0 return comment tunnex_k8s_aws_snat_bypass":
			if ownsRule {
				t.Fatal("duplicate native insertion")
			}
			ownsRule = true
			mutations++
			return "", nil
		case "delete rule ip nat AWS-SNAT-CHAIN-0 handle 21":
			if !ownsRule {
				t.Fatal("duplicate native deletion")
			}
			ownsRule = false
			mutations++
			return "", nil
		default:
			t.Fatalf("command outside real witness scope: %v", args)
			return "", errors.New("unreachable")
		}
	}
	r.runIPTables = func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "-V":
			return "iptables-nft-save v1.8.10 (nf_tables)", nil
		case "-t nat":
			if ownsRule {
				return ownedSave, nil
			}
			return baselineSave, nil
		default:
			t.Fatalf("unknown explicit save command: %v", args)
			return "", errors.New("unreachable")
		}
	}
	if receipts, state, err := r.OwnedArtifacts(t.Context()); err != nil || state != StateReady || len(receipts) != 0 {
		t.Fatalf("actual runtime baseline: %v %s %v", receipts, state, err)
	}
	for range 2 {
		status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
		if err != nil || status.Host.State != StateReady || status.Adapters[0].State != StateNotApplicable || status.Adapters[1].State != StateReady {
			t.Fatalf("actual runtime convergence/readback: %+v %v", status, err)
		}
	}
	if mutations != 1 {
		t.Fatalf("actual readback was not idempotent: %d writes", mutations)
	}
	if receipts, _, err := r.OwnedArtifacts(t.Context()); err != nil || len(receipts) != 1 || receipts[0].Handle != 21 {
		t.Fatalf("actual runtime owned receipt: %v %v", receipts, err)
	}
	for range 2 {
		if _, err := r.Withdraw(t.Context()); err != nil {
			t.Fatalf("actual runtime withdrawal: %v", err)
		}
	}
	if ownsRule || mutations != 2 {
		t.Fatalf("actual runtime withdrawal was not exact/idempotent: owned=%v writes=%d", ownsRule, mutations)
	}
}

func TestAWSTypedCompatUnknownDescriptorsRefuseAtEveryProvenPosition(t *testing.T) {
	base := newAWSTestKernel(t)
	awsTypedFormatterFixture(t, base)
	positions := 0
	for entryIndex, entry := range base.doc.NFTables {
		var rule nftRuleView
		if json.Unmarshal(entry["rule"], &rule) != nil {
			continue
		}
		for expressionIndex, expr := range rule.Expr {
			if _, typed := expr["xt"].(map[string]any); !typed {
				continue
			}
			positions++
			for _, mutation := range []string{"unknown type", "unknown name", "wrong known position", "extra field"} {
				t.Run(fmt.Sprintf("%s/%d/%d/%s", rule.Chain, entryIndex, expressionIndex, mutation), func(t *testing.T) {
					f := newAWSTestKernel(t)
					awsTypedFormatterFixture(t, f)
					var changed nftRuleView
					if err := json.Unmarshal(f.doc.NFTables[entryIndex]["rule"], &changed); err != nil {
						t.Fatal(err)
					}
					descriptor := changed.Expr[expressionIndex]["xt"].(map[string]any)
					switch mutation {
					case "unknown type":
						descriptor["type"] = "future"
					case "unknown name":
						descriptor["name"] = "future"
					case "wrong known position":
						if descriptor["name"] == "SNAT" {
							descriptor["type"], descriptor["name"] = "match", "comment"
						} else {
							descriptor["type"], descriptor["name"] = "target", "SNAT"
						}
					case "extra field":
						descriptor["flags"] = "unknown"
					}
					f.doc.NFTables[entryIndex] = rawEntry("rule", changed)
					r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
					if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil || len(f.mutations) != 0 {
						t.Fatalf("unknown typed descriptor accepted or mutated: %v %v", descriptor, err)
					}
				})
			}
		}
	}
	if positions != 9 {
		t.Fatalf("typed negative coverage changed: %d positions", positions)
	}
}

func TestAWSScopedInsertReadbackIdempotenceReplacementAndWithdrawal(t *testing.T) {
	f := newAWSTestKernel(t)
	before := f.listing()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	for i := 0; i < 2; i++ {
		status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Adapters) != 2 || status.Adapters[0].State != StateNotApplicable || status.Adapters[1].State != StateReady {
			t.Fatalf("adapter selection: %+v", status)
		}
	}
	if len(f.mutations) != 1 || f.mutations[0] != "insert rule ip nat AWS-SNAT-CHAIN-0 ip daddr 10.99.0.0/24 oifname wg0 return comment tunnex_k8s_aws_snat_bypass" {
		t.Fatalf("closed insert=%v", f.mutations)
	}
	if _, err := r.Reconcile(t.Context(), "10.98.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 3 {
		t.Fatalf("replacement mutations=%v", f.mutations)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.listing() != before {
		t.Fatal("foreign fixture bytes/order changed after owned withdrawal")
	}
}

func TestAWSAuthorityGuardIsHeldAcrossAllObservationAndMutation(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	held, acquired, released := false, 0, 0
	r.guard = func(context.Context) (AuthorityGrant, func(), error) {
		held = true
		acquired++
		return awsTestGrant(ScopeIPMasqAndAWS), func() { held = false; released++ }, nil
	}
	f.checkGuard = func() {
		if !held {
			t.Fatal("command outside guard")
		}
	}
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if held || acquired != 2 || released != 2 {
		t.Fatalf("guard lifecycle %t/%d/%d", held, acquired, released)
	}
}

func TestAWSGuardReleaseRunsOnObservationFailure(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	released := 0
	r.guard = func(context.Context) (AuthorityGrant, func(), error) {
		return awsTestGrant(ScopeIPMasqAndAWS), func() { released++ }, nil
	}
	f.inspectErr = errors.New("denied readback")
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("failed inspection accepted")
	}
	if released != 1 || len(f.mutations) != 0 {
		t.Fatalf("failure leaked guard or mutated: release=%d mutations=%v", released, f.mutations)
	}
}

func TestAWSGuardAcquiresBeforeProcessMutexAndHonorsCancellation(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	entered := make(chan struct{})
	r.guard = func(ctx context.Context) (AuthorityGrant, func(), error) {
		close(entered)
		<-ctx.Done()
		return AuthorityGrant{}, nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := r.Reconcile(ctx, "10.99.0.0/24"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("guard waited for process mutex: lock order inversion")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("guard cancellation=%v", err)
	}
	if len(f.commands) != 0 {
		t.Fatal("cancelled guard reached inspection")
	}
}

func TestAWSNilUnknownAndFailedGuardsRefuseBeforeCommands(t *testing.T) {
	for name, guard := range map[string]AuthorityGuard{
		"nil":     nil,
		"unknown": func(context.Context) (AuthorityGrant, func(), error) { return awsTestGrant("future"), func() {}, nil },
		"nil release": func(context.Context) (AuthorityGrant, func(), error) {
			return awsTestGrant(ScopeIPMasqAndAWS), nil, nil
		},
		"error": func(context.Context) (AuthorityGrant, func(), error) {
			return AuthorityGrant{}, nil, errors.New("stale authority")
		},
		"no expiry": func(context.Context) (AuthorityGrant, func(), error) {
			return AuthorityGrant{Scope: ScopeIPMasqAndAWS}, func() {}, nil
		},
		"expired": func(context.Context) (AuthorityGrant, func(), error) {
			return AuthorityGrant{Scope: ScopeIPMasqAndAWS, NotAfter: time.Now().Add(-time.Second)}, func() {}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			r.guard = guard
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
				t.Fatal("invalid guard reconciled")
			}
			if _, err := r.Withdraw(t.Context()); err == nil {
				t.Fatal("invalid guard withdrew")
			}
			if len(f.commands) != 0 {
				t.Fatal("invalid guard executed commands")
			}
		})
	}
}

func TestAWSLegacyEpochCannotWriteOrCleanAWSNamespace(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	r := awsTestReconciler(t, f, ScopeIPMasqOnly)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("legacy epoch became AWS-ready")
	}
	before := f.listing()
	f.commands = nil
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.listing() != before || len(f.mutations) != 0 {
		t.Fatal("legacy scope mutated AWS")
	}
	if !reflect.DeepEqual(f.commands, []string{"nft -a list chain ip nat IP-MASQ-AGENT"}) {
		t.Fatalf("legacy cleanup inspected new namespace: %v", f.commands)
	}
}

func TestAWSBaselineCensusNeedsNoGuardAndRefusesMalformedOwnership(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	r := NewWithAWS("wg0", f.nft, f.iptables, nil)
	owned, state, err := r.OwnedArtifacts(t.Context())
	if err != nil || state != StateReady || len(owned) != 1 || owned[0].Marker != AWSOwnedRuleComment {
		t.Fatalf("baseline census: %+v %s %v", owned, state, err)
	}
	foreign := nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment+"_unknown")
	f.addRule(foreign, true)
	if _, state, err := r.OwnedArtifacts(t.Context()); err == nil || state != StateBlocked {
		t.Fatal("unknown ownership accepted")
	}
	if len(f.mutations) != 0 {
		t.Fatal("baseline wrote CNI")
	}
}

func TestAWSControllerLossBlocksAndNaturalReturnHeals(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	controller, _ := nativeAWSFixture(t)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	// Controller graph recreation loses our child without a product withdrawal.
	f.doc.NFTables = nil // replacement, not json.Unmarshal's reuse/merge of old entry maps
	if err := json.Unmarshal([]byte(controller), &f.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 2 {
		t.Fatal("controller-owned child deletion did not heal")
	}
	f.removeChain(awsChain)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("missing controller chain retained readiness")
	}
	if len(f.mutations) != 2 {
		t.Fatal("missing controller mechanism was manufactured")
	}
	f.doc.NFTables = nil
	if err := json.Unmarshal([]byte(controller), &f.doc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	f.inspectErr = errors.New("controller observation unavailable")
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("controller uncertainty became ready")
	}
	if len(f.mutations) != 3 {
		t.Fatal("uncertain inspection mutated")
	}
}

func TestAWSUnknownForeignTopologyAndBackendRefuseWithoutMutation(t *testing.T) {
	for name, mutate := range map[string]func(*awsTestKernel){
		"legacy backend": func(f *awsTestKernel) { f.version = "iptables-nft-save v1.8.8 (legacy)" },
		"tool missing":   func(f *awsTestKernel) { f.version = "" },
		"unknown jump":   func(f *awsTestKernel) { f.save = strings.Replace(f.save, "-j AWS-SNAT-CHAIN-0", "-j FOREIGN", 1) },
		"unconditional kube NAT": func(f *awsTestKernel) {
			f.save = strings.Replace(f.save, "-m mark ! --mark 0x4000/0x4000 -j RETURN", "-j RETURN", 1)
		},
		"foreign SNAT address": func(f *awsTestKernel) {
			f.save = strings.Replace(f.save, "--to-source 10.240.10.204", "--to-source 192.0.2.2", 1)
		},
		"future AWS chain": func(f *awsTestKernel) {
			f.save = strings.Replace(f.save, ":AWS-SNAT-CHAIN-0 - [0:0]", ":AWS-SNAT-CHAIN-0 - [0:0]\n:AWS-SNAT-CHAIN-1 - [0:0]", 1)
		},
		"opaque warning": func(f *awsTestKernel) { f.save += "\n# Warning: unknown nft rule\n" },
		"another hook": func(f *awsTestKernel) {
			f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", nftChainView{Family: "inet", Table: "other", Name: "post", Handle: 5000, Hook: "postrouting", Type: "nat", Priority: 90, Policy: "accept"}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			mutate(f)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			before := f.listing()
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
				t.Fatal("unknown mechanism accepted")
			}
			if len(f.mutations) != 0 || before != f.listing() {
				t.Fatal("unknown mechanism was mutated")
			}
		})
	}
}

func TestAWSMalformedOwnedExpressionsRefuseWithdrawal(t *testing.T) {
	for name, mutate := range map[string]func(*nftRuleView){
		"source":            func(r *nftRuleView) { r.Expr[0] = nftAddr("saddr", "10.99.0.0/24") },
		"wrong verdict":     func(r *nftRuleView) { r.Expr[2] = map[string]any{"accept": nil} },
		"extra condition":   func(r *nftRuleView) { r.Expr = append([]map[string]any{{"xt": nil}}, r.Expr...) },
		"wrong namespace":   func(r *nftRuleView) { r.Chain = "KUBE-POSTROUTING" },
		"unmasked":          func(r *nftRuleView) { r.Expr[0] = nftAddr("daddr", "10.99.0.2/24") },
		"invalid interface": func(r *nftRuleView) { r.Expr[1] = nftIface("==", "bad iface") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			rule := nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment)
			mutate(&rule)
			f.addRule(rule, true)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if _, err := r.Withdraw(t.Context()); err == nil {
				t.Fatal("ambiguous ownership cleaned")
			}
			if len(f.mutations) != 0 {
				t.Fatal("ambiguous owned rule mutated")
			}
		})
	}
}

func TestAWSCleanupIsIndependentOfForeignMechanismReadiness(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	// Unknown foreign packet semantics are not an ownership ambiguity: inspect
	// them for hidden reserved markers, but do not require runtime qualification.
	f.save = strings.ReplaceAll(f.save, "--random-fully", "--random")
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 1 || !strings.HasPrefix(f.mutations[0], "delete rule ip nat AWS-SNAT-CHAIN-0 handle ") {
		t.Fatalf("wrong cleanup: %v", f.mutations)
	}
}

func TestAWSInsertAndDeleteReadbackFailuresStayBlocked(t *testing.T) {
	f := newAWSTestKernel(t)
	f.discardInsert = true
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("lost insert reported ready")
	}
	f.discardInsert = false
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	f.deleteFailure = true
	if _, err := r.Withdraw(t.Context()); err == nil {
		t.Fatal("failed withdrawal reported clean")
	}
}

func TestAWSAuthoritySerializesCompetingReconciles(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	var guard sync.Mutex
	r.guard = func(ctx context.Context) (AuthorityGrant, func(), error) {
		guard.Lock()
		return awsTestGrant(ScopeIPMasqAndAWS), guard.Unlock, nil
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() { _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); errs <- err }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if len(f.mutations) != 1 {
		t.Fatalf("concurrent insertion=%v", f.mutations)
	}
}

func (f *awsTestKernel) removeChain(chain string) {
	var kept []map[string]json.RawMessage
	for _, entry := range f.doc.NFTables {
		var c nftChainView
		if json.Unmarshal(entry["chain"], &c) == nil && c.Family == "ip" && c.Table == "nat" && c.Name == chain {
			continue
		}
		var r nftRuleView
		if json.Unmarshal(entry["rule"], &r) == nil && r.Family == "ip" && r.Table == "nat" {
			if r.Chain == chain {
				continue
			}
			if r.Chain == "POSTROUTING" {
				last := r.Expr[len(r.Expr)-1]
				if jump, ok := last["jump"].(map[string]any); ok && jump["target"] == chain {
					continue
				}
			}
		}
		kept = append(kept, entry)
	}
	f.doc.NFTables = kept
}

func (f *awsTestKernel) addIPMasq() {
	f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", nftChainView{Family: "ip", Table: "nat", Name: ipMasqChain, Handle: 7000}))
	f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: ipMasqChain, Expr: []map[string]any{nftAddr("daddr", "10.240.0.0/16"), {"return": nil}}}, false)
	f.addRule(nftRuleView{Family: "ip", Table: "nat", Chain: ipMasqChain, Expr: []map[string]any{{"masquerade": nil}}}, false)
	jump := nftRuleView{Family: "ip", Table: "nat", Chain: "POSTROUTING", Handle: 7001, Expr: []map[string]any{{"jump": map[string]any{"target": ipMasqChain}}}}
	for i, entry := range f.doc.NFTables {
		var r nftRuleView
		if json.Unmarshal(entry["rule"], &r) == nil && r.Family == "ip" && r.Table == "nat" && r.Chain == "POSTROUTING" {
			last := r.Expr[len(r.Expr)-1]
			if target, ok := last["jump"].(map[string]any); ok && target["target"] == awsChain {
				f.doc.NFTables = append(f.doc.NFTables[:i], append([]map[string]json.RawMessage{rawEntry("rule", jump)}, f.doc.NFTables[i:]...)...)
				break
			}
		}
	}
	f.save = strings.Replace(f.save, ":AWS-SNAT-CHAIN-0 - [0:0]", ":AWS-SNAT-CHAIN-0 - [0:0]\n:IP-MASQ-AGENT - [0:0]", 1)
	f.save = strings.Replace(f.save, "-A POSTROUTING -m comment --comment \"AWS SNAT CHAIN\"", "-A POSTROUTING -j IP-MASQ-AGENT\n-A POSTROUTING -m comment --comment \"AWS SNAT CHAIN\"", 1)
}

func TestAWSBothMechanismsMustConvergeAndNeitherCanHideTheOther(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addIPMasq()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	before := f.listing()
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Adapters) != 2 || status.Adapters[0].State != StateReady || status.Adapters[1].State != StateReady || len(f.mutations) != 2 {
		t.Fatalf("both mechanisms: %+v %v", status, f.mutations)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.listing() != before {
		t.Fatal("dual cleanup changed foreign rules")
	}
	f.save = strings.Replace(f.save, "--random-fully", "--random", 1)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
		t.Fatal("IP-MASQ hid unsupported AWS semantics")
	}
	if len(f.mutations) != 4 {
		t.Fatal("one adapter mutated before other adapter observation was proved")
	}
}

func TestAWSAwareIPMasqOnlyHostDoesNotRequireAbsentAWSMechanism(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addIPMasq()
	f.removeChain(awsChain)
	f.removeChain("KUBE-POSTROUTING")
	r := awsTestReconciler(t, f, ScopeIPMasqOnly)
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if status.Adapters[0].State != StateReady || status.Adapters[1].State != StateNotApplicable {
		t.Fatalf("wrong applicable set: %+v", status)
	}
	for _, command := range f.commands {
		if strings.HasPrefix(command, "iptables") {
			t.Fatal("absent AWS requires unnecessary compat inspection")
		}
	}
	if len(f.mutations) != 1 || !strings.Contains(f.mutations[0], "IP-MASQ-AGENT") {
		t.Fatalf("wrong scope: %v", f.mutations)
	}
}

func TestAWSNoRecognizedMechanismAndDetachedAWSChainRemainBlocked(t *testing.T) {
	for _, detached := range []bool{false, true} {
		t.Run(strconv.FormatBool(detached), func(t *testing.T) {
			f := newAWSTestKernel(t)
			if detached {
				// Remove only the hook jump, leaving the AWS-named chain: its name
				// cannot manufacture reachability or make the mechanism applicable.
				for i, entry := range f.doc.NFTables {
					var r nftRuleView
					if json.Unmarshal(entry["rule"], &r) == nil && r.Family == "ip" && r.Table == "nat" && r.Chain == "POSTROUTING" && r.Handle == 35 {
						f.doc.NFTables = append(f.doc.NFTables[:i], f.doc.NFTables[i+1:]...)
						break
					}
				}
			} else {
				f.removeChain(awsChain)
				f.removeChain("KUBE-POSTROUTING")
			}
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
				t.Fatal("absent/detached CNI became ready")
			}
			if len(f.mutations) != 0 {
				t.Fatal("absent/detached mechanism mutated")
			}
			if _, err := r.Withdraw(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAWSDuplicateOwnedRulesAreSweptWithoutForeignMutation(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.98.0.0/24", "old0", AWSOwnedRuleComment), true)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 2 {
		t.Fatalf("duplicate cleanup: %v", f.mutations)
	}
	owned, _, err := r.OwnedArtifacts(t.Context())
	if err != nil || len(owned) != 1 || owned[0].CIDR != "10.99.0.0/24" {
		t.Fatalf("dedupe receipt: %+v %v", owned, err)
	}
}

func TestAWSOwnedReturnAfterSNATIsMovedWithoutForeignReordering(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), false)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 2 || !strings.HasPrefix(f.mutations[0], "delete rule ") || !strings.HasPrefix(f.mutations[1], "insert rule ") {
		t.Fatalf("misordered bypass was not replaced: %v", f.mutations)
	}
}

func TestAWSTunnexEarlierNATHookRequiresExactMarkerAndWireGuardExclusion(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(strconv.FormatBool(valid), func(t *testing.T) {
			f := newAWSTestKernel(t)
			f.doc.NFTables = append(f.doc.NFTables, rawEntry("chain", nftChainView{Family: "ip", Table: "tunnex", Name: "postrouting", Handle: 8000, Type: "nat", Hook: "postrouting", Priority: 99, Policy: "accept"}), rawEntry("chain", nftChainView{Family: "ip", Table: "tunnex", Name: "tunnex_posture_owner", Handle: 8001}))
			f.addRule(nftRuleView{Family: "ip", Table: "tunnex", Chain: "tunnex_posture_owner", Comment: "tunnex_host_posture_v1", Expr: []map[string]any{{"counter": map[string]any{"packets": float64(0), "bytes": float64(0)}}}}, false)
			iface := "wg0"
			if !valid {
				iface = "eth0"
			}
			f.addRule(nftRuleView{Family: "ip", Table: "tunnex", Chain: "postrouting", Expr: []map[string]any{nftAddr("saddr", "10.99.0.0/24"), nftIface("!=", iface), {"masquerade": nil}}}, false)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			_, err := r.Reconcile(t.Context(), "10.99.0.0/24")
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && (err == nil || len(f.mutations) != 0) {
				t.Fatalf("earlier tunnel-return NAT was accepted/mutated: %v", err)
			}
		})
	}
}

func TestAWSOperationDeadlineIsEarliestAdmissionCallerAndBudget(t *testing.T) {
	for _, test := range []struct {
		name        string
		callerLimit time.Duration
		grantLimit  time.Duration
	}{
		{"operation budget", time.Minute, time.Minute},
		{"caller", time.Second, time.Minute},
		{"authority", time.Minute, 2 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			start := time.Now()
			callerDeadline := start.Add(test.callerLimit)
			grantDeadline := start.Add(test.grantLimit)
			ctx, cancel := context.WithDeadline(t.Context(), callerDeadline)
			defer cancel()
			var acquisitionDeadline time.Time
			r.guard = func(ctx context.Context) (AuthorityGrant, func(), error) {
				acquisitionDeadline, _ = ctx.Deadline()
				return AuthorityGrant{Scope: ScopeIPMasqAndAWS, NotAfter: grantDeadline}, func() {}, nil
			}
			var commandDeadline time.Time
			r.runNFT = func(ctx context.Context, args ...string) (string, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("unbounded command")
				}
				if commandDeadline.IsZero() {
					commandDeadline = deadline
				} else if !commandDeadline.Equal(deadline) {
					t.Fatal("deadline refreshed between commands")
				}
				return f.nft(ctx, args...)
			}
			if _, err := r.Reconcile(ctx, "10.99.0.0/24"); err != nil {
				t.Fatal(err)
			}
			want := acquisitionDeadline
			if grantDeadline.Before(want) {
				want = grantDeadline
			}
			if !commandDeadline.Equal(want) || acquisitionDeadline.After(callerDeadline) || acquisitionDeadline.After(start.Add(CNIOperationBudget+100*time.Millisecond)) {
				t.Fatalf("deadline caller=%s grant=%s acquisition=%s command=%s", callerDeadline, grantDeadline, acquisitionDeadline, commandDeadline)
			}
		})
	}
}

func TestAWSExpiredInspectionOrMutationCannotContinueOrPublishReady(t *testing.T) {
	for _, test := range []struct {
		name          string
		scope         AuthorityScope
		readToExpire  int
		deleteExpires bool
		withdraw      bool
		wantMutations int
	}{
		{name: "first inspection", readToExpire: 1},
		{name: "final readback", readToExpire: 4, wantMutations: 1},
		{name: "transit final readback", scope: ScopeIPMasqAndAWSTransit, readToExpire: 4, wantMutations: 2},
		{name: "between replacement deletes", deleteExpires: true, wantMutations: 1},
		{name: "withdrawal inspection", readToExpire: 1, withdraw: true},
		{name: "withdrawal final readback", readToExpire: 4, withdraw: true, wantMutations: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := test.scope
			if scope == "" {
				scope = ScopeIPMasqAndAWS
			}
			f := newAWSTestKernel(t)
			if test.deleteExpires || test.withdraw {
				f.addRule(nftOwned(awsChain, "10.98.0.0/24", "old0", AWSOwnedRuleComment), true)
			}
			if test.deleteExpires {
				f.addRule(nftOwned(awsChain, "10.97.0.0/24", "old0", AWSOwnedRuleComment), true)
			}
			r := awsTestReconciler(t, f, scope)
			released := 0
			r.guard = func(context.Context) (AuthorityGrant, func(), error) {
				return AuthorityGrant{Scope: scope, NotAfter: time.Now().Add(100 * time.Millisecond)}, func() { released++ }, nil
			}
			reads, deletes := 0, 0
			r.runNFT = func(ctx context.Context, args ...string) (string, error) {
				out, err := f.nft(ctx, args...)
				if args[0] == "-j" {
					reads++
				}
				if args[0] == "delete" {
					deletes++
				}
				if (args[0] == "-j" && reads == test.readToExpire) || (test.deleteExpires && args[0] == "delete" && deletes == 1) {
					deadline, _ := ctx.Deadline()
					// Deliberately ignore cancellation and return a successful result.
					time.Sleep(time.Until(deadline) + time.Millisecond)
				}
				return out, err
			}
			cidr := "10.99.0.0/24"
			if test.withdraw {
				cidr = ""
			}
			status, err := r.Reconcile(t.Context(), cidr)
			if !errors.Is(err, context.DeadlineExceeded) || status.Host.State != StateBlocked || released != 1 || len(f.mutations) != test.wantMutations {
				t.Fatalf("late result: %+v err=%v release=%d mutations=%v", status, err, released, f.mutations)
			}
		})
	}
}

func TestAWSLegacyScopedWithdrawalAlsoRejectsExpiredFakeRead(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqOnly)
	r.guard = func(context.Context) (AuthorityGrant, func(), error) {
		return AuthorityGrant{Scope: ScopeIPMasqOnly, NotAfter: time.Now().Add(20 * time.Millisecond)}, func() {}, nil
	}
	commands := 0
	r.runNFT = func(ctx context.Context, args ...string) (string, error) {
		commands++
		deadline, _ := ctx.Deadline()
		time.Sleep(time.Until(deadline) + time.Millisecond)
		return `table ip nat { chain IP-MASQ-AGENT {
ip daddr 10.99.0.0/24 oifname "wg0" return comment "tunnex_k8s_ip_masq_bypass" # handle 41
} }`, nil
	}
	status, err := r.Withdraw(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) || status.Host.State != StateBlocked || commands != 1 {
		t.Fatalf("legacy scoped late read: %+v %v commands=%d", status, err, commands)
	}
}

func TestAWSProcessMutexWaitIsBoundedAndReleasesGuard(t *testing.T) {
	f := newAWSTestKernel(t)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	released := 0
	r.guard = func(context.Context) (AuthorityGrant, func(), error) {
		return awsTestGrant(ScopeIPMasqAndAWS), func() { released++ }, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := r.Reconcile(ctx, "10.99.0.0/24")
	if !errors.Is(err, context.DeadlineExceeded) || released != 1 || len(f.commands) != 0 {
		t.Fatalf("mutex wait=%v release=%d commands=%v", err, released, f.commands)
	}
}

func TestAWSCompatOwnershipCensusRejectsOpaqueOrUncorrelatedMarkersBeforeMutation(t *testing.T) {
	for name, corrupt := range map[string]func(string) string{
		"opaque reserved comment": func(s string) string {
			return strings.Replace(s, `--comment "AWS SNAT CHAIN" -j RETURN`, "--comment "+AWSOwnedRuleComment+" -j RETURN", 1)
		},
		"opaque unknown marker": func(s string) string {
			return strings.Replace(s, `--comment "AWS SNAT CHAIN" -j RETURN`, "--comment "+AWSOwnedRuleComment+"_future -j RETURN", 1)
		},
		"wrong compat chain": func(s string) string {
			return strings.Replace(s, `--comment "kubernetes postrouting rules"`, "--comment "+AWSOwnedRuleComment, 1)
		},
		"native owned scope differs": func(s string) string {
			return strings.Replace(s, "-d 10.99.0.0/24 -o wg0", "-d 0.0.0.0/0 -o wg0", 1)
		},
		"native owned unknown comment": func(s string) string {
			return strings.Replace(s, "-d 10.99.0.0/24 -o wg0 -j RETURN", "-d 10.99.0.0/24 -o wg0 -m comment --comment "+AWSOwnedRuleComment+"_future -j RETURN", 1)
		},
		"rule count differs": func(s string) string {
			return strings.Replace(s, "-A AWS-SNAT-CHAIN-0 -d 10.99.0.0/24 -o wg0 -j RETURN\n", "", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
			before := f.listing()
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			r.runIPTables = func(ctx context.Context, args ...string) (string, error) {
				out, err := f.iptables(ctx, args...)
				if len(args) == 2 {
					changed := corrupt(out)
					if changed == out {
						t.Fatal("corruption fixture did not change compat snapshot")
					}
					out = changed
				}
				return out, err
			}
			if receipts, state, err := r.OwnedArtifacts(t.Context()); err == nil || state != StateBlocked || len(receipts) != 0 {
				t.Fatalf("ambiguous baseline accepted: %+v %s %v", receipts, state, err)
			}
			if _, err := r.Withdraw(t.Context()); err == nil {
				t.Fatal("ambiguous ownership authorized withdrawal")
			}
			if len(f.mutations) != 0 || f.listing() != before {
				t.Fatal("ambiguous compat ownership changed native state")
			}
		})
	}
}

func TestAWSCompatCensusRequiresExplicitToolAndAcceptsNativeMarkedReadback(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
	f.version = "missing tool"
	if _, _, err := r.OwnedArtifacts(t.Context()); err == nil {
		t.Fatal("AWS census accepted unavailable semantic tool")
	}
	if _, err := r.Withdraw(t.Context()); err == nil || len(f.mutations) != 0 {
		t.Fatal("AWS withdrawal skipped unavailable semantic tool")
	}
	f.version = "iptables-nft-save v1.8.10 (nf_tables)"
	r.runIPTables = func(ctx context.Context, args ...string) (string, error) {
		out, err := f.iptables(ctx, args...)
		if len(args) == 2 {
			out = strings.Replace(out, "-d 10.99.0.0/24 -o wg0 -j RETURN", "-d 10.99.0.0/24 -o wg0 -m comment --comment "+AWSOwnedRuleComment+" -j RETURN", 1)
		}
		return out, err
	}
	if receipts, _, err := r.OwnedArtifacts(t.Context()); err != nil || len(receipts) != 1 {
		t.Fatalf("real-tool-compatible native marked readback rejected: %+v %v", receipts, err)
	}
	if _, err := r.Withdraw(t.Context()); err != nil {
		t.Fatal(err)
	}
}
