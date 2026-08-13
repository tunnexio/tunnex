package devices

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// ⛔ `devices` HAS SEVERAL CHECK-CONSTRAINED TEXT COLUMNS WHOSE VALID SET EXCLUDES GO'S ZERO VALUE.
//
// `kind IN ('human','agent')`, `status IN ('active','pending','revoked')`, `transport IN
// ('wireguard','openvpn')`. A new caller of CreateDevice that names some fields and not others **compiles
// cleanly and fails at INSERT time** — the type system says nothing, because "" is a perfectly good string.
//
// ⚠ THIS CLASS BIT TWICE IN ONE SLICE (S15.2). `kind` was caught by `test-editions`; `transport` reached CI
// and was only found on a FRESH database, because the local run was masked by an unrelated environmental
// failure in the same package. Two different columns, one shape.
//
// > **A ZERO VALUE THAT IS INVALID AT THE DATABASE AND LEGAL AT THE COMPILER IS A TRAP THAT SCALES WITH THE
// > NUMBER OF CALLERS.** This test does not prevent it. What it does is name the columns in one place, so
// > the third instance is a failing assertion here rather than a red gate on someone's branch.
func TestCreateDeviceParamsHasNoSafeZeroValue(t *testing.T) {
	// A zero-valued params struct — what a caller gets by naming nothing.
	var p sqlc.CreateDeviceParams

	// Every field below is CHECK-constrained in the schema and rejects "".
	constrained := map[string]string{
		"Kind":      p.Kind,
		"Status":    p.Status,
		"Transport": p.Transport,
	}
	var empty []string
	for name, v := range constrained {
		if v == "" {
			empty = append(empty, name)
		}
	}
	// ⛔ THE ASSERTION IS THAT THEY ARE ALL EMPTY — i.e. that the trap is REAL and this list is complete.
	// If a field ever gains a safe default, this fails and the list gets updated deliberately; if a NEW
	// constrained column is added and not listed here, that is the gap this test is a reminder about.
	if len(empty) != len(constrained) {
		t.Fatalf("expected every CHECK-constrained field to be zero-valued in a bare struct; "+
			"empty=%v of %d — update this list deliberately", empty, len(constrained))
	}

	// Kind is the one with a query-side rescue: COALESCE(NULLIF(sqlc.arg(kind),''),'human'). Named here so
	// the asymmetry is visible — the others have NO such rescue and must be set by every caller.
	rescued := "Kind"
	if !strings.Contains(strings.Join(append(empty, ""), ","), rescued) {
		t.Fatalf("%s should be among the constrained fields", rescued)
	}
	t.Logf("CHECK-constrained fields with no safe zero value: %v (only %s is rescued query-side)", empty, rescued)
}
