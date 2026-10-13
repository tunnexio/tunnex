package bgp

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPreflightRefusalReasonIsFixedAndPreservesError(t *testing.T) {
	for _, reason := range []string{"input", "package", "package-identity", "identity", "routes-before", "private-directory", "observer-start", "observer-close", "routes-after-close", "private-directory-remove", "private-parent-open", "private-parent-sync", "missing-receipt", "receipt-current", "observer-alive", "children-identity", "children-listeners", "observer-rib", "observer-listeners-recheck", "routes-observed"} {
		original := fmt.Errorf("%w: %s secret daemon output", ErrPackage, reason)
		err := preflightRefused(reason, original)
		if !errors.Is(err, ErrPackage) || err.Error() != original.Error() || PreflightRefusalReason(err) != reason || strings.Contains(PreflightRefusalReason(err), "secret") {
			t.Fatalf("reason %s changed or disclosed", reason)
		}
	}
	for _, err := range []error{nil, errors.New("secret"), fmt.Errorf("%w: observer-start secret", ErrPackage), preflightRefused("secret", ErrPackage)} {
		if PreflightRefusalReason(err) != "unclassified" {
			t.Fatal("unknown error exported")
		}
	}
}
