//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func awsTransitTestRule(cidr string) nftRuleView {
	ingress := nftIface("==", "wg0")
	ingress["match"].(map[string]any)["left"].(map[string]any)["meta"].(map[string]any)["key"] = "iifname"
	return nftRuleView{Family: "ip", Table: "nat", Chain: awsChain, Comment: AWSTransitOwnedRuleComment,
		Expr: []map[string]any{nftAddr("saddr", cidr), ingress, nftIface("==", "wg0"), {"return": nil}}}
}

func assertAWSTransitReceipts(t *testing.T, r *Reconciler, cidr string) {
	t.Helper()
	receipts, state, err := r.OwnedArtifacts(t.Context())
	if err != nil || state != StateReady || len(receipts) != 2 {
		t.Fatalf("AWS owned receipt census: %+v state=%s err=%v", receipts, state, err)
	}
	byMarker := make(map[string]OwnedRuleReceipt)
	for _, receipt := range receipts {
		if receipt.Handle == 0 || receipt.CIDR != cidr || receipt.Interface != "wg0" {
			t.Fatalf("inexact owned receipt: %+v", receipt)
		}
		if _, duplicate := byMarker[receipt.Marker]; duplicate {
			t.Fatalf("duplicate owned marker: %+v", receipts)
		}
		byMarker[receipt.Marker] = receipt
	}
	if destination, ok := byMarker[AWSOwnedRuleComment]; !ok || destination.Direction != "daddr" || destination.IngressInterface != "" {
		t.Fatalf("destination receipt broadened: %+v", destination)
	}
	if transit, ok := byMarker[AWSTransitOwnedRuleComment]; !ok || transit.Direction != "saddr" || transit.IngressInterface != "wg0" {
		t.Fatalf("transit receipt lost ingress/source binding: %+v", transit)
	}
}

func TestAWSTransitConvergesBothOwnedRules(t *testing.T) {
	f := newAWSTestKernel(t)
	before := f.listing()
	baseline, err := parseCNISnapshot(before)
	if err != nil {
		t.Fatal(err)
	}
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	status, err := r.Reconcile(t.Context(), "10.99.0.2/24")
	if err != nil || len(status.Adapters) != 2 || status.Host.State != StateReady || status.Adapters[0].State != StateNotApplicable || status.Adapters[1].State != StateReady || status.Adapters[1].OwnedRules != 2 {
		t.Fatalf("two-rule convergence: %+v err=%v", status, err)
	}
	assertAWSTransitReceipts(t, r, "10.99.0.0/24")
	after, err := parseCNISnapshot(f.listing())
	if err != nil {
		t.Fatal(err)
	}
	chain := nftKey("ip", "nat", awsChain)
	rules := after.rules[chain]
	if len(rules) != len(baseline.rules[chain])+2 || rules[0].Comment != AWSOwnedRuleComment || rules[1].Comment != AWSTransitOwnedRuleComment || !reflect.DeepEqual(rules[2:], baseline.rules[chain]) {
		t.Fatalf("owned order or foreign AWS rules changed: %+v", rules)
	}
	if len(f.mutations) != 2 {
		t.Fatalf("unexpected initial writes: %v", f.mutations)
	}
	if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil || len(f.mutations) != 2 {
		t.Fatalf("two-rule reconcile is not idempotent: %v writes=%v", err, f.mutations)
	}
	for range 2 {
		if _, err := r.Withdraw(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if f.listing() != before || len(f.mutations) != 4 {
		t.Fatalf("withdrawal changed foreign state or repeated writes: %v", f.mutations)
	}
}

func TestAWSTransitReplacesTunnelCIDR(t *testing.T) {
	f := newAWSTestKernel(t)
	before := f.listing()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	for _, cidr := range []string{"10.99.0.0/24", "10.98.0.7/24"} {
		if _, err := r.Reconcile(t.Context(), cidr); err != nil {
			t.Fatal(err)
		}
	}
	assertAWSTransitReceipts(t, r, "10.98.0.0/24")
	writes := len(f.mutations)
	if _, err := r.Reconcile(t.Context(), "10.98.0.0/24"); err != nil || len(f.mutations) != writes {
		t.Fatalf("replacement did not converge: %v writes=%v", err, f.mutations)
	}
	if _, err := r.Withdraw(t.Context()); err != nil || f.listing() != before {
		t.Fatalf("replacement/withdrawal changed foreign state: %v", err)
	}
}

func TestAWSTransitCleanupPartialAndDuplicateRules(t *testing.T) {
	for _, test := range []struct {
		name  string
		rules []nftRuleView
	}{
		{"destination only", []nftRuleView{nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment)}},
		{"transit only", []nftRuleView{awsTransitTestRule("10.99.0.0/24")}},
		{"duplicates and old CIDR", []nftRuleView{
			nftOwned(awsChain, "10.98.0.0/24", "wg0", AWSOwnedRuleComment), awsTransitTestRule("10.98.0.0/24"),
			nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), awsTransitTestRule("10.99.0.0/24"),
			awsTransitTestRule("10.99.0.0/24"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			before := f.listing()
			for _, rule := range test.rules {
				f.addRule(rule, true)
			}
			// Teardown must not depend on foreign AWS runtime qualification.
			f.save = strings.ReplaceAll(f.save, "--random-fully", "--random")
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
			for range 2 {
				if _, err := r.Withdraw(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if f.listing() != before || len(f.mutations) != len(test.rules) {
				t.Fatalf("partial/duplicate cleanup changed foreign state: %v", f.mutations)
			}
			for _, command := range f.mutations {
				if !strings.HasPrefix(command, "delete rule ip nat "+awsChain+" handle ") {
					t.Fatalf("cleanup escaped exact AWS handles: %q", command)
				}
			}
		})
	}
}

func TestAWSTransitRepairsPartialInsertionAndDuplicates(t *testing.T) {
	for _, test := range []struct {
		name  string
		rules []nftRuleView
	}{
		{"destination only", []nftRuleView{nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment)}},
		{"transit only", []nftRuleView{awsTransitTestRule("10.99.0.0/24")}},
		{"misordered and duplicate transit", []nftRuleView{awsTransitTestRule("10.98.0.0/24"), awsTransitTestRule("10.99.0.0/24"), awsTransitTestRule("10.99.0.0/24")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			before := f.listing()
			for _, rule := range test.rules {
				f.addRule(rule, false)
			}
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil {
				t.Fatal(err)
			}
			assertAWSTransitReceipts(t, r, "10.99.0.0/24")
			writes := len(f.mutations)
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err != nil || len(f.mutations) != writes {
				t.Fatalf("repaired rules did not converge: %v writes=%v", err, f.mutations)
			}
			if _, err := r.Withdraw(t.Context()); err != nil || f.listing() != before {
				t.Fatalf("repair/withdrawal changed foreign state: %v", err)
			}
		})
	}
}

func TestAWSTransitPartialWriteFailureCanBeCleaned(t *testing.T) {
	f := newAWSTestKernel(t)
	before := f.listing()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	inserts := 0
	r.runNFT = func(ctx context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "insert" {
			inserts++
			if inserts == 2 {
				return "", errors.New("injected second-rule insertion failure")
			}
		}
		return f.nft(ctx, args...)
	}
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if err == nil || status.Host.State != StateBlocked || len(f.mutations) != 1 {
		t.Fatalf("partial insertion became ready: %+v err=%v writes=%v", status, err, f.mutations)
	}
	// A new reconciler has no in-memory knowledge of which insertion reached
	// the kernel. Cleanup must recover solely from the exact owned readback.
	restarted := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	if _, err := restarted.Withdraw(t.Context()); err != nil || f.listing() != before {
		t.Fatalf("partial insertion could not be cleaned after restart: %v", err)
	}
}

func TestAWSTransitExpiryAfterFirstInsertStopsMutationAndAllowsFreshCleanup(t *testing.T) {
	f := newAWSTestKernel(t)
	before := f.listing()
	r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	var notAfter time.Time
	released := 0
	r.guard = func(context.Context) (AuthorityGrant, func(), error) {
		notAfter = time.Now().Add(200 * time.Millisecond)
		return AuthorityGrant{Scope: ScopeIPMasqAndAWSTransit, NotAfter: notAfter}, func() { released++ }, nil
	}
	inserts := 0
	r.runNFT = func(ctx context.Context, args ...string) (string, error) {
		out, err := f.nft(ctx, args...)
		if len(args) > 0 && args[0] == "insert" {
			inserts++
			if inserts == 1 {
				// Deliberately ignore cancellation and report successful insertion
				// after authority expires. The next mutation needs a live grant.
				time.Sleep(time.Until(notAfter) + time.Millisecond)
			}
		}
		return out, err
	}
	status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
	if !errors.Is(err, context.DeadlineExceeded) || status.Host.State != StateBlocked || released != 1 || inserts != 1 || len(f.mutations) != 1 {
		t.Fatalf("expired insertion continued or became ready: %+v err=%v releases=%d inserts=%d writes=%v", status, err, released, inserts, f.mutations)
	}
	for _, adapter := range status.Adapters {
		if adapter.State == StateReady {
			t.Fatalf("expired partial pair reported ready adapter: %+v", adapter)
		}
	}
	restarted := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
	if _, err := restarted.Withdraw(t.Context()); err != nil || f.listing() != before || len(f.mutations) != 2 {
		t.Fatalf("fresh authority failed exact partial-pair cleanup: %v writes=%v", err, f.mutations)
	}
}

func TestAWSLegacyScopeRefusesTransitBeforeWrite(t *testing.T) {
	for _, operation := range []string{"reconcile", "withdraw"} {
		t.Run(operation, func(t *testing.T) {
			f := newAWSTestKernel(t)
			// Include an obsolete destination so cleanup would write unless all
			// ownership is checked against schema-3 authority before mutation.
			f.addRule(nftOwned(awsChain, "10.98.0.0/24", "wg0", AWSOwnedRuleComment), true)
			f.addRule(awsTransitTestRule("10.99.0.0/24"), true)
			before := f.listing()
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWS)
			var err error
			if operation == "reconcile" {
				_, err = r.Reconcile(t.Context(), "10.99.0.0/24")
			} else {
				_, err = r.Withdraw(t.Context())
			}
			if err == nil || len(f.mutations) != 0 || f.listing() != before {
				t.Fatalf("schema-3 authority touched transit state: %v writes=%v", err, f.mutations)
			}
		})
	}
}

func TestAWSTransitMalformedOwnedRuleRefusesBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*nftRuleView){
		"destination instead of source": func(r *nftRuleView) { r.Expr[0] = nftAddr("daddr", "10.99.0.0/24") },
		"unmasked source":               func(r *nftRuleView) { r.Expr[0] = nftAddr("saddr", "10.99.0.2/24") },
		"IPv6 source":                   func(r *nftRuleView) { r.Expr[0] = nftAddr("saddr", "fd00::/64") },
		"missing source":                func(r *nftRuleView) { r.Expr = r.Expr[1:] },
		"missing ingress":               func(r *nftRuleView) { r.Expr = append(r.Expr[:1], r.Expr[2:]...) },
		"wrong ingress key":             func(r *nftRuleView) { r.Expr[1] = nftIface("==", "wg0") },
		"invalid ingress": func(r *nftRuleView) {
			r.Expr[1]["match"].(map[string]any)["right"] = "bad iface"
		},
		"wrong same interface": func(r *nftRuleView) {
			r.Expr[1]["match"].(map[string]any)["right"] = "old0"
			r.Expr[2] = nftIface("==", "old0")
		},
		"ingress egress mismatch": func(r *nftRuleView) { r.Expr[2] = nftIface("==", "eth0") },
		"invalid egress":          func(r *nftRuleView) { r.Expr[2] = nftIface("==", "bad iface") },
		"negative egress":         func(r *nftRuleView) { r.Expr[2] = nftIface("!=", "wg0") },
		"wrong verdict":           func(r *nftRuleView) { r.Expr[3] = map[string]any{"accept": nil} },
		"extra condition":         func(r *nftRuleView) { r.Expr = append(r.Expr, map[string]any{"counter": nil}) },
		"destination marker":      func(r *nftRuleView) { r.Comment = AWSOwnedRuleComment },
		"unknown marker":          func(r *nftRuleView) { r.Comment += "_unknown" },
		"IP-MASQ namespace":       func(r *nftRuleView) { r.Chain = ipMasqChain },
		"wrong chain":             func(r *nftRuleView) { r.Chain = "KUBE-POSTROUTING" },
		"wrong table":             func(r *nftRuleView) { r.Table = "filter" },
		"wrong family":            func(r *nftRuleView) { r.Family = "inet" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			f.addRule(nftOwned(awsChain, "10.98.0.0/24", "wg0", AWSOwnedRuleComment), true)
			rule := awsTransitTestRule("10.99.0.0/24")
			mutate(&rule)
			if _, err := parseExactOwnedNFTRule(rule); err == nil {
				t.Fatal("native parser accepted malformed transit ownership")
			}
			f.addRule(rule, true)
			before := f.listing()
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
			if _, err := r.Reconcile(t.Context(), "10.99.0.0/24"); err == nil {
				t.Fatal("malformed transit ownership reconciled")
			}
			if _, err := r.Withdraw(t.Context()); err == nil {
				t.Fatal("malformed transit ownership withdrew")
			}
			if _, state, err := r.OwnedArtifacts(t.Context()); err == nil || state != StateBlocked {
				t.Fatal("malformed transit ownership produced baseline receipts")
			}
			if len(f.mutations) != 0 || f.listing() != before {
				t.Fatalf("malformed transit rule allowed partial writes: %v", f.mutations)
			}
		})
	}
}

func TestAWSTransitNativeAndCompatReadbackMustAgree(t *testing.T) {
	rule := awsTransitTestRule("10.99.0.0/24")
	rule.Handle = 10001
	plain := "-A AWS-SNAT-CHAIN-0 -s 10.99.0.0/24 -i wg0 -o wg0 -j RETURN"
	marked := "-A AWS-SNAT-CHAIN-0 -s 10.99.0.0/24 -i wg0 -o wg0 -m comment --comment " + AWSTransitOwnedRuleComment + " -j RETURN"
	for _, line := range []string{plain, marked} {
		if err := validateOwnedAWSCompatRule(rule, line); err != nil {
			t.Fatalf("exact native transit formatter refused: %q: %v", line, err)
		}
	}
	for _, line := range []string{
		strings.Replace(plain, "-s 10.99.0.0/24", "-s 10.0.0.0/8", 1),
		strings.Replace(plain, "-s", "-d", 1),
		strings.Replace(plain, " -i wg0", "", 1),
		strings.Replace(plain, "-i wg0", "-i eth0", 1),
		strings.Replace(plain, "-o wg0", "-o eth0", 1),
		strings.Replace(plain, "RETURN", "ACCEPT", 1),
		strings.Replace(plain, awsChain, ipMasqChain, 1),
		strings.Replace(marked, AWSTransitOwnedRuleComment, AWSOwnedRuleComment, 1),
		strings.Replace(marked, AWSTransitOwnedRuleComment, AWSTransitOwnedRuleComment+"_unknown", 1),
	} {
		if err := validateOwnedAWSCompatRule(rule, line); err == nil {
			t.Fatalf("mismatched transit compat rule accepted: %q", line)
		}
	}
}

func TestAWSTransitAuthorityRequiredBeforeWrite(t *testing.T) {
	for name, guard := range map[string]AuthorityGuard{
		"nil": nil,
		"expired": func(context.Context) (AuthorityGrant, func(), error) {
			return AuthorityGrant{Scope: ScopeIPMasqAndAWSTransit, NotAfter: time.Now().Add(-time.Second)}, func() {}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			f.addRule(awsTransitTestRule("10.99.0.0/24"), true)
			before := f.listing()
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
			r.guard = guard
			if _, err := r.Reconcile(t.Context(), "10.98.0.0/24"); err == nil {
				t.Fatal("invalid transit authority reconciled")
			}
			if _, err := r.Withdraw(t.Context()); err == nil {
				t.Fatal("invalid transit authority withdrew")
			}
			if len(f.commands) != 0 || f.listing() != before {
				t.Fatalf("invalid transit authority reached kernel commands: %v", f.commands)
			}
		})
	}
}

func TestAWSTransitOwnedArtifactsCensusNeedsNoGuard(t *testing.T) {
	f := newAWSTestKernel(t)
	f.addRule(awsTransitTestRule("10.99.0.0/24"), true)
	f.addRule(nftOwned(awsChain, "10.99.0.0/24", "wg0", AWSOwnedRuleComment), true)
	before := f.listing()
	r := NewWithAWS("wg0", f.nft, f.iptables, nil)
	assertAWSTransitReceipts(t, r, "10.99.0.0/24")
	if len(f.mutations) != 0 || f.listing() != before {
		t.Fatal("guardless transit baseline census mutated rules")
	}
}

func TestAWSTransitScopePreservesIPMasqDestinationAuthority(t *testing.T) {
	for _, awsPresent := range []bool{false, true} {
		name := "IP-MASQ only"
		if awsPresent {
			name = "both mechanisms"
		}
		t.Run(name, func(t *testing.T) {
			f := newAWSTestKernel(t)
			f.addIPMasq()
			if !awsPresent {
				f.removeChain(awsChain)
				f.removeChain("KUBE-POSTROUTING")
			}
			before := f.listing()
			r := awsTestReconciler(t, f, ScopeIPMasqAndAWSTransit)
			status, err := r.Reconcile(t.Context(), "10.99.0.0/24")
			if err != nil || len(status.Adapters) != 2 || status.Adapters[0].State != StateReady || status.Adapters[0].OwnedRules != 1 {
				t.Fatalf("schema-4 IP-MASQ convergence: %+v err=%v", status, err)
			}
			if awsPresent && (status.Adapters[1].State != StateReady || status.Adapters[1].OwnedRules != 2) {
				t.Fatalf("schema-4 AWS convergence: %+v", status)
			}
			if !awsPresent && status.Adapters[1].State != StateNotApplicable {
				t.Fatalf("absent AWS was required: %+v", status)
			}
			receipts, _, err := r.OwnedArtifacts(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			foundIPMasq := false
			for _, receipt := range receipts {
				if receipt.Marker == ownedRuleComment {
					foundIPMasq = true
					if receipt.Direction != "daddr" || receipt.IngressInterface != "" {
						t.Fatalf("IP-MASQ authority expanded to transit: %+v", receipt)
					}
				}
			}
			if !foundIPMasq {
				t.Fatal("IP-MASQ destination receipt absent")
			}
			if _, err := r.Withdraw(t.Context()); err != nil || f.listing() != before {
				t.Fatalf("schema-4 cleanup changed foreign state: %v", err)
			}
		})
	}
}
