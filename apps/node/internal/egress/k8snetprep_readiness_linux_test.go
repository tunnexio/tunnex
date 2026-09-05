//go:build linux

package egress

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

type fakeK8sNetPrep struct {
	status         k8snetprep.ReconcileStatus
	err            error
	reconcileCalls int
	withdrawCalls  int
	tunnelCIDRs    []string
}

type blockingK8sNetPrep struct {
	status  k8snetprep.ReconcileStatus
	err     error
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *blockingK8sNetPrep) Reconcile(context.Context, string) (k8snetprep.ReconcileStatus, error) {
	f.once.Do(func() { close(f.started) })
	<-f.release
	return f.status, f.err
}

func (f *blockingK8sNetPrep) Withdraw(context.Context) (k8snetprep.ReconcileStatus, error) {
	return f.status, f.err
}

func (f *fakeK8sNetPrep) Reconcile(_ context.Context, tunnelCIDR string) (k8snetprep.ReconcileStatus, error) {
	f.reconcileCalls++
	f.tunnelCIDRs = append(f.tunnelCIDRs, tunnelCIDR)
	return f.status, f.err
}

func (f *fakeK8sNetPrep) Withdraw(context.Context) (k8snetprep.ReconcileStatus, error) {
	f.withdrawCalls++
	return f.status, f.err
}

func TestK8sNetPrepModeKeepsLegacyVMOutOfKubernetesAdapterPath(t *testing.T) {
	m := New("wg0")
	fake := &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateBlocked},
		Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateBlocked}},
	}, err: errors.New(k8snetprep.ReasonNoRegisteredAdapter)}
	m.k8sNetPrep = fake

	if err := m.ReconcileK8sNetPrep(t.Context()); err != nil {
		t.Fatalf("legacy VM/site mode entered Kubernetes adapter path: %v", err)
	}
	m.ResolveK8sVIPs(t.Context())
	if fake.reconcileCalls != 0 {
		t.Fatalf("legacy VM/site mode reconciled Kubernetes adapter %d times", fake.reconcileCalls)
	}

	m.SetKubernetesMode(true)
	m.runIPOutput = func(context.Context, ...string) (string, error) { return "", nil }
	m.ResolveK8sVIPs(t.Context())
	if fake.reconcileCalls != 1 {
		t.Fatalf("explicit Kubernetes mode adapter reconciles=%d, want 1", fake.reconcileCalls)
	}
}

func TestK8sNetPrepSubnetObservationFailurePreservesOwnedRuleAndRetractsReadiness(t *testing.T) {
	ready := k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
		Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateReady}},
	}
	m := New("wg0")
	m.SetKubernetesMode(true)
	fake := &fakeK8sNetPrep{status: ready}
	m.k8sNetPrep = fake
	m.runIPOutput = func(context.Context, ...string) (string, error) {
		return "7: wg0 inet 10.99.0.1/24 scope global wg0", nil
	}
	if err := m.ReconcileK8sNetPrep(t.Context()); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("initial exact subnet was not ready: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}

	m.runIPOutput = func(context.Context, ...string) (string, error) {
		return "", errors.New("temporary netlink failure")
	}
	err := m.ReconcileK8sNetPrep(t.Context())
	if err == nil || !strings.Contains(err.Error(), "temporary netlink failure") {
		t.Fatalf("subnet observation error=%v", err)
	}
	if m.K8sNetPrepReady() {
		t.Fatal("unknown subnet observation retained false-green readiness")
	}
	if fake.reconcileCalls != 1 || fake.withdrawCalls != 0 || strings.Join(fake.tunnelCIDRs, ",") != "10.99.0.1/24" {
		t.Fatalf("unknown observation mutated adapter: reconcile=%d withdraw=%d cidrs=%v", fake.reconcileCalls, fake.withdrawCalls, fake.tunnelCIDRs)
	}
}

func TestK8sVIPResolverSubnetObservationFailureDoesNotWithdrawNetPrep(t *testing.T) {
	ready := k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
		Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateReady}},
	}
	m := New("wg0")
	m.SetKubernetesMode(true)
	fake := &fakeK8sNetPrep{status: ready}
	m.k8sNetPrep = fake
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.1/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("test precondition: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
	m.runIPOutput = func(context.Context, ...string) (string, error) {
		return "", errors.New("temporary netlink failure")
	}
	m.ResolveK8sVIPs(t.Context())
	if m.K8sNetPrepReady() || fake.reconcileCalls != 1 || fake.withdrawCalls != 0 {
		t.Fatalf("resolver observation failure mutated adapter: ready=%v reconcile=%d withdraw=%d", m.K8sNetPrepReady(), fake.reconcileCalls, fake.withdrawCalls)
	}
}

func TestK8sNetPrepKnownSubnetAbsenceRemainsExplicitWithdrawal(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	fake := &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateNotApplicable},
		Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateNotApplicable}},
	}}
	m.k8sNetPrep = fake
	m.runIPOutput = func(context.Context, ...string) (string, error) { return "", nil }
	if err := m.ReconcileK8sNetPrep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if m.K8sNetPrepReady() || fake.reconcileCalls != 1 || len(fake.tunnelCIDRs) != 1 || fake.tunnelCIDRs[0] != "" {
		t.Fatalf("known absence was not explicit withdrawal: ready=%v calls=%d cidrs=%v", m.K8sNetPrepReady(), fake.reconcileCalls, fake.tunnelCIDRs)
	}
}

func TestParseWGSubnetRejectsMalformedSuccess(t *testing.T) {
	for name, output := range map[string]string{
		"malformed":             "7: wg0 inet not-a-prefix scope global wg0",
		"nonempty without inet": "unexpected output",
	} {
		t.Run(name, func(t *testing.T) {
			if subnet, err := parseWGSubnet(output); err == nil || subnet != "" {
				t.Fatalf("parseWGSubnet(%q) subnet=%q err=%v", output, subnet, err)
			}
		})
	}
	if subnet, err := parseWGSubnet("7: wg0 inet 10.99.0.1/24 scope global wg0"); err != nil || subnet != "10.99.0.1/24" {
		t.Fatalf("valid subnet=%q err=%v", subnet, err)
	}
	withDNSVIP := "7: wg0 inet 10.99.0.1/24 scope global wg0\n7: wg0 inet 100.64.0.2/32 scope global secondary wg0:tnxk8s"
	if subnet, err := parseWGSubnet(withDNSVIP); err != nil || subnet != "10.99.0.1/24" {
		t.Fatalf("primary subnet with DNS VIP=%q err=%v", subnet, err)
	}
}

func TestK8sNetPrepReadinessRequiresNonEmptyCIDRHostAndAdapterTruth(t *testing.T) {
	readyStatus := func() k8snetprep.ReconcileStatus {
		return k8snetprep.ReconcileStatus{
			Host: k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
			Adapters: []k8snetprep.ComponentStatus{{
				Name:  "ip_masq_agent",
				State: k8snetprep.StateReady,
			}},
		}
	}
	m := New("wg0")
	fake := &fakeK8sNetPrep{status: readyStatus()}
	m.k8sNetPrep = fake

	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("ready common state did not earn readiness: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}

	fake.status.Adapters[0].State = k8snetprep.StateBlocked
	fake.err = errors.New("permission denied")
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err == nil || m.K8sNetPrepReady() {
		t.Fatalf("blocked adapter retained false green: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}

	fake.status = readyStatus()
	fake.err = nil
	if err := m.reconcileK8sNetPrep(t.Context(), ""); err != nil || m.K8sNetPrepReady() {
		t.Fatalf("withdrawal must be not-ready: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
}

func TestK8sNetPrepReadinessRejectsNotApplicableAdapterForActiveTunnel(t *testing.T) {
	m := New("wg0")
	m.k8sNetPrep = &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host: k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
		Adapters: []k8snetprep.ComponentStatus{{
			Name:  "ip_masq_agent",
			State: k8snetprep.StateNotApplicable,
		}},
	}}
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if m.K8sNetPrepReady() {
		t.Fatal("active tunnel accepted not-applicable adapter as ready")
	}
}

func TestK8sNetPrepReadinessWithdrawsOnAdapterLossAndRecoversAfterSelfHeal(t *testing.T) {
	m := New("wg0")
	fake := &fakeK8sNetPrep{}
	m.k8sNetPrep = fake
	set := func(state k8snetprep.State, err error) {
		fake.status = k8snetprep.ReconcileStatus{
			Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
			Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: state}},
		}
		fake.err = err
	}

	set(k8snetprep.StateReady, nil)
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("initial ready state not accepted: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
	set(k8snetprep.StateBlocked, errors.New(k8snetprep.ReasonNoRegisteredAdapter))
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err == nil || m.K8sNetPrepReady() {
		t.Fatalf("adapter loss retained readiness: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
	set(k8snetprep.StateReady, nil)
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("self-heal did not restore readiness: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
}

func TestK8sNetPrepReadinessRejectsEmptyAdapterEvidence(t *testing.T) {
	m := New("wg0")
	m.k8sNetPrep = &fakeK8sNetPrep{status: k8snetprep.ReconcileStatus{
		Host: k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
	}}
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if m.K8sNetPrepReady() {
		t.Fatal("missing adapter evidence was accepted as ready")
	}
}

func TestK8sNetPrepSlowPassPreservesLastGoodUntilAtomicResult(t *testing.T) {
	readyStatus := k8snetprep.ReconcileStatus{
		Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
		Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateReady}},
	}
	m := New("wg0")
	m.k8sNetPrep = &fakeK8sNetPrep{status: readyStatus}
	if err := m.reconcileK8sNetPrep(t.Context(), "10.99.0.0/24"); err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("test precondition: last-good posture not ready: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}

	block := &blockingK8sNetPrep{
		status:  readyStatus,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	m.k8sNetPrep = block
	done := make(chan error, 1)
	go func() { done <- m.reconcileK8sNetPrep(context.Background(), "10.99.0.0/24") }()
	<-block.started
	if !m.K8sNetPrepReady() {
		t.Fatal("slow successful pass cleared last-good readiness while still in flight")
	}
	close(block.release)
	if err := <-done; err != nil || !m.K8sNetPrepReady() {
		t.Fatalf("slow successful pass did not publish ready atomically: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}

	blocked := &blockingK8sNetPrep{
		status: k8snetprep.ReconcileStatus{
			Host:     k8snetprep.ComponentStatus{Name: "wireguard_rp_filter", State: k8snetprep.StateReady},
			Adapters: []k8snetprep.ComponentStatus{{Name: "ip_masq_agent", State: k8snetprep.StateBlocked}},
		},
		err:     errors.New("adapter unavailable"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	m.k8sNetPrep = blocked
	done = make(chan error, 1)
	go func() { done <- m.reconcileK8sNetPrep(context.Background(), "10.99.0.0/24") }()
	<-blocked.started
	if !m.K8sNetPrepReady() {
		t.Fatal("in-flight observation retracted readiness before a blocked result existed")
	}
	close(blocked.release)
	if err := <-done; err == nil || m.K8sNetPrepReady() {
		t.Fatalf("completed blocked pass retained false green: ready=%v err=%v", m.K8sNetPrepReady(), err)
	}
}

func TestK8sNetPrepEarlyManagerErrorRetractsLastGood(t *testing.T) {
	m := New("invalid interface")
	m.SetKubernetesMode(true)
	m.k8sNetPrepReady.Store(true)
	if _, _, err := m.Reconcile(t.Context()); err == nil {
		t.Fatal("invalid interface unexpectedly reconciled")
	}
	if m.K8sNetPrepReady() {
		t.Fatal("actual Manager.Reconcile error retained last-good Kubernetes readiness")
	}
}

func TestKubernetesGatewayRolloutShutdownPreservesManagerOwnedNFTMarkers(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	prep := &fakeK8sNetPrep{}
	m.k8sNetPrep = prep
	m.nftRun = func(_ context.Context, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "tunnex_posture_owner") {
			return "table ip tunnex {\n chain tunnex_posture_owner { # handle 1\n  counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n }\n}\n", nil
		}
		return "", errors.New("DOCKER-USER absent")
	}
	var applied string
	m.apply = func(_ context.Context, ruleset string) error {
		applied = ruleset
		return nil
	}
	m.Teardown(t.Context())
	if prep.withdrawCalls != 1 {
		t.Fatalf("Kubernetes shutdown CNI withdrawals=%d, want 1", prep.withdrawCalls)
	}
	if !strings.Contains(applied, `comment "tunnex_host_posture_v1"`) || !strings.Contains(applied, "flush table ip tunnex") ||
		strings.Contains(applied, "delete table") || strings.Contains(applied, "chain forward") {
		t.Fatalf("rollout shutdown did not preserve marker-only manager ownership:\n%s", applied)
	}
}

func TestKubernetesGatewayShutdownRefusesAmbiguousNFTMarker(t *testing.T) {
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.k8sNetPrep = &fakeK8sNetPrep{}
	m.nftRun = func(_ context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "tunnex_posture_owner") {
			return `chain tunnex_posture_owner { counter comment "foreign" # handle 9 }`, nil
		}
		return "", errors.New("DOCKER-USER absent")
	}
	applied := false
	m.apply = func(context.Context, string) error { applied = true; return nil }
	m.Teardown(t.Context())
	if applied {
		t.Fatal("ambiguous manager ownership was mutated during gateway shutdown")
	}
}

func TestLegacyGatewayShutdownStillDeletesGatewayOwnedNFTTables(t *testing.T) {
	m := New("wg0")
	var applied string
	m.apply = func(_ context.Context, ruleset string) error { applied = ruleset; return nil }
	m.Teardown(t.Context())
	if applied != "delete table ip tunnex\ndelete table ip6 tunnex\n" {
		t.Fatalf("legacy cleanup changed: %q", applied)
	}
}
