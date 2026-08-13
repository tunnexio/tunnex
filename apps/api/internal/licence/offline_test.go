package licence

import (
	"go/build"
	"strings"
	"testing"
	"time"
)

// ⛔ FULLY OFFLINE IS THE PRODUCT'S PROMISE, NOT A FEATURE — and a promise nothing measures cannot be
// broken, only discovered. This asserts it by construction rather than by intention.
//
// ⚠ SUBJECT CHOSEN BY CAPABILITY, NOT BY SHAPE (docs/laws.md): the subject is "packages this package can
// reach that could open a socket", derived from the real import graph — not "does any file contain the
// string http", which stops covering the moment someone reaches the network a different way.
func TestPackageMakesNoNetworkCalls(t *testing.T) {
	forbidden := []string{"net", "net/http", "net/url", "os/exec"}

	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("import dir: %v", err)
	}
	// Both halves: the package's own imports AND its tests', because a test that dials would still prove
	// the package can be built into something that dials.
	all := append([]string{}, pkg.Imports...)
	all = append(all, pkg.TestImports...)
	if len(all) == 0 {
		t.Fatal("no imports found at all — this census is reading nothing")
	}

	for _, imp := range all {
		for _, bad := range forbidden {
			if imp == bad || strings.HasPrefix(imp, bad+"/") {
				t.Errorf("⛔ %q IS IMPORTED HERE. Licence verification must work AIR-GAPPED: it is why a "+
					"sovereignty buyer chooses Tunnex, and a verifier that can reach the network has "+
					"broken the product rather than improved it.", imp)
			}
		}
	}
}

// ⛔ THE CLOCK REPORTS A BACKWARD JUMP AND NEVER REFUSES.
func TestClockDetectsBackwardJumpAndOnlyReports(t *testing.T) {
	var c Clock
	base := time.Unix(1_800_000_000, 0)

	if o := c.Observe(base); o.BackwardJump {
		t.Error("the first observation cannot be a jump — there is nothing to jump from")
	}
	if o := c.Observe(base.Add(time.Hour)); o.BackwardJump {
		t.Error("moving forward is not a jump")
	}

	// A small step back is NTP doing its job. Reporting it would train an operator to ignore the signal.
	if o := c.Observe(base.Add(time.Hour - time.Minute)); o.BackwardJump {
		t.Error("a step inside Tolerance must not be reported")
	}

	o := c.Observe(base.Add(-24 * time.Hour))
	if !o.BackwardJump {
		t.Fatal("⛔ a 25-hour backward jump was not reported — an expired key would read as live and " +
			"nothing would say so")
	}
	if o.By < 24*time.Hour {
		t.Errorf("By = %v, want >= 24h", o.By)
	}

	// ⚠ THE MARK ONLY ADVANCES. If a bad reading reset the baseline, the SECOND jump would look normal —
	// which is the one an attacker would rely on.
	if got, want := c.HighWater(), base.Add(time.Hour); !got.Equal(want) {
		t.Errorf("high water = %v, want %v (a jump must not lower it)", got, want)
	}
	if o := c.Observe(base.Add(-24 * time.Hour)); !o.BackwardJump {
		t.Error("a repeated jump must still be reported — the baseline did not move")
	}
}
