//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeChainRule struct {
	handle    uint64
	direction string
	cidr      string
	iface     string
	comment   string
}

type fakeNftExitError struct{ message string }

func (e fakeNftExitError) Error() string { return e.message }
func (e fakeNftExitError) ExitCode() int { return 1 }

type fakeIPMasqChain struct {
	present     bool
	listErr     error
	nextHandle  uint64
	rules       []fakeChainRule
	insertCalls int
	deleteCalls int
	otherCalls  []string
	calls       []string
	rawListing  string
}

func (f *fakeIPMasqChain) run(_ context.Context, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, joined)
	switch {
	case joined == "-a list chain ip nat IP-MASQ-AGENT":
		if f.listErr != nil {
			return "", f.listErr
		}
		if !f.present {
			return "", fakeNftExitError{message: "Error: No such file or directory"}
		}
		if f.rawListing != "" {
			return f.rawListing, nil
		}
		var out strings.Builder
		out.WriteString("chain IP-MASQ-AGENT {\n")
		for _, rule := range f.rules {
			direction := rule.direction
			if direction == "" {
				direction = "daddr"
			}
			fmt.Fprintf(&out, "  ip %s %s oifname \"%s\" return comment \"%s\" # handle %d\n", direction, rule.cidr, rule.iface, rule.comment, rule.handle)
		}
		out.WriteString("}\n")
		return out.String(), nil

	case strings.HasPrefix(joined, "insert rule ip nat IP-MASQ-AGENT ip daddr "):
		f.insertCalls++
		f.nextHandle++
		f.rules = append(f.rules, fakeChainRule{
			handle:    f.nextHandle,
			direction: args[6],
			cidr:      args[7],
			iface:     args[9],
			comment:   args[12],
		})
		return "", nil

	case strings.HasPrefix(joined, "delete rule ip nat IP-MASQ-AGENT handle "):
		f.deleteCalls++
		handle, err := strconv.ParseUint(args[len(args)-1], 10, 64)
		if err != nil {
			return "", err
		}
		for i, rule := range f.rules {
			if rule.handle == handle {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
				return "", nil
			}
		}
		return "", fmt.Errorf("handle %d absent", handle)
	default:
		f.otherCalls = append(f.otherCalls, joined)
		return "", fmt.Errorf("unexpected nft command: %s", joined)
	}
}

func newTestReconciler(t *testing.T, chain *fakeIPMasqChain, iface string) *Reconciler {
	t.Helper()
	procSys := t.TempDir()
	path := filepath.Join(procSys, "net/ipv4/conf", iface, "rp_filter")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := New(iface, chain.run)
	r.procSys = procSys
	return r
}

func ownedRules(chain *fakeIPMasqChain) []fakeChainRule {
	var out []fakeChainRule
	for _, rule := range chain.rules {
		if rule.comment == ownedRuleComment || rule.comment == legacyRuleComment {
			out = append(out, rule)
		}
	}
	return out
}

func TestIPMasqExactChainAbsenceBlocksActiveTunnelWithoutRegisteredAdapter(t *testing.T) {
	chain := &fakeIPMasqChain{}
	r := newTestReconciler(t, chain, "wg0")
	status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
	if err == nil || status.Adapters[0].State != StateBlocked || status.Adapters[0].Reason != ReasonNoRegisteredAdapter {
		t.Fatalf("active tunnel without a registered adapter must block: status=%+v err=%v", status, err)
	}
}

func TestIPMasqPermissionFailureIsBlockedNotAbsent(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, listErr: errors.New("nft: Operation not permitted")}
	r := newTestReconciler(t, chain, "wg0")
	status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
	if err == nil || status.Adapters[0].State != StateBlocked {
		t.Fatalf("permission failure must block: status=%+v err=%v", status, err)
	}
	if chain.insertCalls != 0 || chain.deleteCalls != 0 {
		t.Fatalf("blocked observation mutated chain: insert=%d delete=%d", chain.insertCalls, chain.deleteCalls)
	}
}

func TestIPMasqCommandAbsenceIsBlockedNotChainAbsence(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, listErr: errors.New("fork/exec /usr/sbin/nft: no such file or directory")}
	r := newTestReconciler(t, chain, "wg0")
	status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
	if err == nil || status.Adapters[0].State != StateBlocked {
		t.Fatalf("command absence must block: status=%+v err=%v", status, err)
	}
	if chain.insertCalls != 0 || chain.deleteCalls != 0 {
		t.Fatalf("blocked command absence mutated chain: insert=%d delete=%d", chain.insertCalls, chain.deleteCalls)
	}
}

func TestIPMasqUnparseableOwnedRuleIsBlockedNotRewritten(t *testing.T) {
	chain := &fakeIPMasqChain{
		present:    true,
		rawListing: `chain IP-MASQ-AGENT { ip saddr 10.99.0.0/24 return comment "tunnex_k8s_ip_masq_bypass" }`,
	}
	r := newTestReconciler(t, chain, "wg0")
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err == nil || status.Adapters[0].State != StateBlocked {
		t.Fatalf("parse failure must block: status=%+v err=%v", status, err)
	}
	if chain.insertCalls != 0 || chain.deleteCalls != 0 {
		t.Fatalf("unrecognized owned rule was mutated: insert=%d delete=%d", chain.insertCalls, chain.deleteCalls)
	}
}

func TestIPMasqOwnedRuleIsIdempotentAndSelfHealsControllerRewrite(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, nextHandle: 20}
	r := newTestReconciler(t, chain, "wg0")
	for i := 0; i < 2; i++ {
		status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
		if err != nil || status.Adapters[0].State != StateReady {
			t.Fatalf("reconcile %d: status=%+v err=%v", i, status, err)
		}
	}
	if chain.insertCalls != 1 || len(ownedRules(chain)) != 1 {
		t.Fatalf("idempotence failed: inserts=%d rules=%+v", chain.insertCalls, chain.rules)
	}
	// Simulate the CNI controller rebuilding its foreign chain.
	chain.rules = nil
	if _, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err != nil {
		t.Fatal(err)
	}
	if chain.insertCalls != 2 || len(ownedRules(chain)) != 1 {
		t.Fatalf("controller rewrite was not healed: inserts=%d rules=%+v", chain.insertCalls, chain.rules)
	}
}

func TestIPMasqControllerChainLossBlocksUntilMechanismReturns(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, nextHandle: 20}
	r := newTestReconciler(t, chain, "wg0")
	if status, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err != nil || status.Adapters[0].State != StateReady {
		t.Fatalf("initial adapter reconcile: status=%+v err=%v", status, err)
	}

	chain.present = false
	chain.rules = nil
	if status, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err == nil || status.Adapters[0].State != StateBlocked || status.Adapters[0].Reason != ReasonNoRegisteredAdapter {
		t.Fatalf("controller chain loss retained false green: status=%+v err=%v", status, err)
	}

	chain.present = true
	if status, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err != nil || status.Adapters[0].State != StateReady || status.Adapters[0].OwnedRules != 1 {
		t.Fatalf("returned mechanism did not self-heal: status=%+v err=%v", status, err)
	}
}

func TestIPMasqPodToClientReturnUsesDestinationCIDRAndCanonicalPrepend(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, nextHandle: 20}
	r := newTestReconciler(t, chain, "wg0")
	if _, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err != nil {
		t.Fatal(err)
	}
	want := "insert rule ip nat IP-MASQ-AGENT ip daddr 10.99.0.0/24 oifname wg0 return comment tunnex_k8s_ip_masq_bypass"
	if !strings.Contains(strings.Join(chain.calls, "\n"), want) {
		t.Fatalf("pod-to-client return exemption missing canonical prepend argv %q; calls=%v", want, chain.calls)
	}
	if strings.Contains(strings.Join(chain.calls, "\n"), " position ") {
		t.Fatalf("unproven position syntax used: %v", chain.calls)
	}
	owned := ownedRules(chain)
	if len(owned) != 1 || owned[0].direction != "daddr" {
		t.Fatalf("return rule direction=%+v, want destination match", owned)
	}
}

func TestIPMasqCIDRAndInterfaceReplacementPreservesForeignRules(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, nextHandle: 30, rules: []fakeChainRule{
		{handle: 4, cidr: "192.0.2.0/24", iface: "eth0", comment: "foreign-rule"},
		{handle: 5, direction: "saddr", cidr: "10.98.0.0/24", iface: "old0", comment: legacyRuleComment},
		{handle: 6, cidr: "10.98.0.0/24", iface: "wg0", comment: ownedRuleComment},
		{handle: 7, direction: "saddr", cidr: "10.99.0.0/24", iface: "wg0", comment: legacyRuleComment},
	}}
	r := newTestReconciler(t, chain, "wg0")
	if _, err := r.Reconcile(t.Context(), "10.99.0.2/24"); err != nil {
		t.Fatal(err)
	}
	owned := ownedRules(chain)
	if len(owned) != 1 || owned[0].direction != "daddr" || owned[0].cidr != "10.99.0.0/24" || owned[0].iface != "wg0" {
		t.Fatalf("replacement result=%+v", chain.rules)
	}
	if len(chain.rules) != 2 || chain.rules[0].comment != "foreign-rule" {
		t.Fatalf("foreign rule changed: %+v", chain.rules)
	}
}

func TestIPMasqWithdrawalSweepsOnlyOwnedRules(t *testing.T) {
	chain := &fakeIPMasqChain{present: true, nextHandle: 30, rules: []fakeChainRule{
		{handle: 4, cidr: "192.0.2.0/24", iface: "eth0", comment: "foreign-rule"},
		{handle: 5, cidr: "10.98.0.0/24", iface: "wg0", comment: ownedRuleComment},
		{handle: 6, cidr: "10.99.0.0/24", iface: "wg0", comment: ownedRuleComment},
	}}
	r := newTestReconciler(t, chain, "wg0")
	status, err := r.Withdraw(t.Context())
	if err != nil || status.Adapters[0].State != StateReady {
		t.Fatalf("withdraw: status=%+v err=%v", status, err)
	}
	if len(ownedRules(chain)) != 0 || len(chain.rules) != 1 || chain.rules[0].comment != "foreign-rule" {
		t.Fatalf("withdrawal touched wrong rules: %+v", chain.rules)
	}
}

func TestWireGuardRPFilterReadyIsReadOnly(t *testing.T) {
	chain := &fakeIPMasqChain{present: true}
	r := newTestReconciler(t, chain, "wg0")
	path := filepath.Join(r.procSys, "net/ipv4/conf/wg0/rp_filter")
	sentinel := time.Date(2000, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, sentinel, sentinel); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "0" {
		t.Fatalf("wg0 rp_filter=%q, want 0", value)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(sentinel) {
		t.Fatalf("read-only verification changed modtime from %s to %s", sentinel, info.ModTime())
	}
}

func TestWireGuardRPFilterMismatchBlocksWithoutMutation(t *testing.T) {
	chain := &fakeIPMasqChain{present: true}
	r := newTestReconciler(t, chain, "wg0")
	path := filepath.Join(r.procSys, "net/ipv4/conf/wg0/rp_filter")
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err == nil || status.Host.State != StateBlocked || status.Adapters[0].State != StateBlocked {
		t.Fatalf("strict rp_filter must block: status=%+v err=%v", status, err)
	}
	value, readErr := os.ReadFile(path)
	if readErr != nil || string(value) != "1" {
		t.Fatalf("blocked readback mutated value=%q err=%v", value, readErr)
	}
	if chain.insertCalls != 0 || chain.deleteCalls != 0 {
		t.Fatalf("blocked host readback mutated CNI: insert=%d delete=%d", chain.insertCalls, chain.deleteCalls)
	}
}

func TestWireGuardRPFilterMissingBlocksWithoutCreation(t *testing.T) {
	chain := &fakeIPMasqChain{present: true}
	r := newTestReconciler(t, chain, "wg0")
	path := filepath.Join(r.procSys, "net/ipv4/conf/wg0/rp_filter")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err == nil || status.Host.State != StateBlocked || status.Adapters[0].State != StateBlocked {
		t.Fatalf("missing rp_filter must block: status=%+v err=%v", status, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("missing rp_filter was created: %v", statErr)
	}
	if chain.insertCalls != 0 || chain.deleteCalls != 0 {
		t.Fatalf("missing host readback mutated CNI: insert=%d delete=%d", chain.insertCalls, chain.deleteCalls)
	}
}
