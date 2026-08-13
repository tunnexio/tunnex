package operator

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoDBImport — S10.2 THE HARD RULE, made STRUCTURAL (grep-asserted, the subnetguard-census shape): the
// operator imports NO Tunnex DB / service-layer package. It is a controller-runtime CLIENT of the control-
// plane HTTP API; every invariant (Collect/OrgRanges, identity-binding, edition gate, audit cascade) is
// inherited ONLY through the CP handlers, and ONLY for as long as this holds. A DB import fails the build,
// not review.
func TestNoDBImport(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	// Forbidden: the Postgres driver, sqlc-generated code, the CP's migrations, and ANY CP internal
	// service/store package. The operator MAY import the CP's generated HTTP CLIENT (that is not a DB pkg).
	forbidden := []string{
		"github.com/jackc/pgx",
		"github.com/tunnexio/tunnex/apps/api/db",
		"github.com/tunnexio/tunnex/apps/api/internal",
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		for _, f := range forbidden {
			if strings.Contains(pkg, f) {
				t.Errorf("THE HARD RULE violated: the operator transitively imports %q — it is an API CLIENT, never a DB writer. Reach the control plane over HTTP.", pkg)
			}
		}
	}
}
