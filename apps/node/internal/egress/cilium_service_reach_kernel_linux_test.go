//go:build linux

package egress

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// TestCiliumServiceReachKernel is the opt-in helper of K8N-6 (docs/K8N-6-cilium-service-reach.md). It
// loads the REAL Manager rendering for a gateway whose compiled policy is enforcing and EMPTY (no access
// rule) into the network namespace it runs in, through real `nft -f`, and leaves it there for probes run
// from outside the test. It is meant to run on a disposable kind node, in a privileged container that
// shares the node's network namespace, with a WireGuard interface `wg0` already up:
//
//	TUNNEX_TEST_F10_KERNEL=1 TUNNEX_TEST_F10_OUT=<dir> ./egress.test -test.run '^TestCiliumServiceReachKernel$' -test.v
//
// It never removes what it loaded; the probes need the table in force. With TUNNEX_TEST_F10_OUT it writes
// the rendered ruleset and the kernel's JSON listing, which is how
// walk-artifacts/k8n6-cilium-service-reach-20261124/k8n6-cilium-service-reach.{rendered.nft,nft-ruleset.json} were produced.
func TestCiliumServiceReachKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_F10_KERNEL") != "1" {
		t.Skip("opt in on a disposable node: it replaces the ip/ip6 tunnex tables of this network namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetKubernetesCNIAuthority(func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return k8snetprep.AuthorityGrant{Scope: k8snetprep.ScopeIPMasqAndAWS, NotAfter: time.Now().Add(k8snetprep.CNIOperationBudget)}, func() {}, nil
	}, nil, nil)
	// Enforcing, no access rule. Never nil: nil is the legacy mesh, which accepts everything from wg0.
	policy := &nodepolicy.Compiled{Version: 7, NodeID: "k8n6-gateway", Mode: "enforcing", Mesh: false}
	m.SetPolicy(policy)

	// Reconcile applies the table before the host/CNI check runs, so a refusal of that check (expected
	// here: no host-posture receipt is configured) leaves the table in force. It is recorded, not fatal.
	_, _, reconcileErr := m.Reconcile(ctx)
	t.Logf("F10_RECONCILE err=%v k8s_netprep_ready=%v", reconcileErr, m.K8sNetPrepReady())

	forward, err := nftRun(ctx, "-a", "list", "chain", "ip", "tunnex", "forward")
	if err != nil {
		t.Fatalf("the tunnex forward chain is not in the kernel: %v", err)
	}
	if !strings.Contains(forward, "policy drop") || !strings.Contains(forward, "tunnex_default_drop") {
		t.Fatalf("not the enforcing default-deny chain:\n%s", forward)
	}
	for _, line := range strings.Split(forward, "\n") {
		if strings.Contains(line, `iifname "wg0"`) && strings.Contains(line, "accept") {
			t.Fatalf("an accept for traffic from wg0 is in the chain of an empty policy: %s\n%s", line, forward)
		}
	}
	t.Logf("F10_FORWARD_CHAIN\n%s", forward)

	if dir := os.Getenv("TUNNEX_TEST_F10_OUT"); dir != "" {
		subnet, err := m.observeWGSubnet(ctx)
		if err != nil {
			t.Fatal(err)
		}
		listing, err := nftRun(ctx, "-j", "-a", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{
			"k8n6-cilium-service-reach.rendered.nft":     m.rulesetWith(subnet, policy),
			"k8n6-cilium-service-reach.nft-ruleset.json": listing,
		} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Log("F10_EMPTY_POLICY_TABLE_IN_FORCE")
}
