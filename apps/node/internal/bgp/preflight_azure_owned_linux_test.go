//go:build linux

package bgp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Actual existing gateway namespace preflight: no peers, no forwarding authority.
// QualifyPreflight owns its temporary observer and enforces normal cleanup.
func TestAzureOwnedBGPPreflightStage(t *testing.T) {
	if os.Getenv("TUNNEX_AZURE_OWNED_BGP_PROBE") != "1" {
		t.Skip("explicit owned gateway diagnostic only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	q, err := QualifyPreflight(ctx, "/var/lib/tunnex-node/ipsec")
	if err != nil {
		stage := "unclassified"
		// Match only the known production prefix. Never print a wrapped error,
		// subprocess output, path, RIB, or an attacker-controlled suffix.
		prefix := ErrPackage.Error() + ": "
		if strings.HasPrefix(err.Error(), prefix) {
			detail := strings.TrimPrefix(err.Error(), prefix)
			for _, candidate := range []string{"input", "package", "package-identity", "identity", "routes-before", "private-directory", "observer-start", "observer-close", "routes-after-close", "private-directory-remove", "private-parent-open", "private-parent-sync", "missing-receipt", "receipt-current", "observer-alive", "children-identity", "children-listeners", "observer-rib", "observer-listeners-recheck", "routes-observed"} {
				if detail == candidate || strings.HasPrefix(detail, candidate+":") || strings.HasPrefix(detail, candidate+" ") {
					stage = candidate
					break
				}
			}
		}
		t.Fatalf("stage=%s result=fail", stage)
	}
	if q == nil || !q.Current() {
		t.Fatal("stage=receipt_current result=fail")
	}
	t.Log("stage=complete result=pass")
}
