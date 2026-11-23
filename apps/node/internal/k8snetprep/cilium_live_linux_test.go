//go:build linux

package k8snetprep

import (
	"os"
	"testing"
)

// Today's rule check on the captured Cilium 1.20.5 node (see
// cilium_live_test.go for what the capture is). Cilium's feeder rule creates
// the `ip mangle POSTROUTING` base chain, which the hook check does not know,
// so the node is refused before any NAT rule is read.
func TestCiliumLiveNodeIsRefusedByTodaysHookCheck(t *testing.T) {
	listing, err := os.ReadFile(ciliumLiveA + "nft-ruleset.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := parseCNISnapshot(string(listing))
	if err != nil {
		t.Fatalf("parseCNISnapshot on the captured ruleset: %v", err)
	}
	err = snapshot.validateHookCoverage("wg0", "100.96.0.0/24")
	if err == nil || err.Error() != "unknown IPv4 postrouting hook coverage" {
		t.Fatalf("validateHookCoverage = %v, want the unknown-hook refusal", err)
	}
}
