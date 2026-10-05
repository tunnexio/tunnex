package sandboxruntime

import (
	"errors"
	"testing"
)

// This test-only criterion accepts two independently evidenced non-execution
// outcomes. A completed child requires typed SIGKILL and an empty frozen scope;
// a retained child requires actual observed membership in a frozen scope. The
// native caller, rather than error text, extracts the kernel wait status.
func nativeLateChildOutcome(completed, sigkill, noMarker, frozen, populated, observedMembership, noOOM bool) (string, error) {
	if !noMarker || !frozen || !noOOM {
		return "", errors.New("late-child execution fence evidence incomplete")
	}
	if completed {
		if !sigkill || populated {
			return "", errors.New("late-child completion was not an empty-scope SIGKILL")
		}
		return "sigkill_before_marker", nil
	}
	if !populated || !observedMembership {
		return "", errors.New("late child lacks live frozen membership proof")
	}
	return "observed_frozen_child", nil
}

func TestNativeLateChildOutcomeCriteria(t *testing.T) {
	for _, test := range []struct {
		name                                                                       string
		completed, sigkill, noMarker, frozen, populated, observedMembership, noOOM bool
		want                                                                       string
	}{
		{"killed-before-marker", true, true, true, true, false, false, true, "sigkill_before_marker"},
		{"observed-frozen-child", false, false, true, true, true, true, true, "observed_frozen_child"},
		{"arbitrary-start-error", true, false, true, true, false, false, true, ""},
		{"normal-exit", true, false, true, true, false, true, true, ""},
		{"marker-written", true, true, false, true, false, false, true, ""},
		{"thawed-parent", true, true, true, false, false, false, true, ""},
		{"oom-kill", true, true, true, true, false, false, false, ""},
		{"retained-other-payload", true, true, true, true, true, false, true, ""},
		{"unobserved-live-child", false, false, true, true, true, false, true, ""},
		{"no-child-proof", false, false, true, true, false, false, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := nativeLateChildOutcome(test.completed, test.sigkill, test.noMarker, test.frozen, test.populated, test.observedMembership, test.noOOM)
			if got != test.want || (err == nil) != (test.want != "") {
				t.Fatalf("outcome=%q err=%v, want=%q", got, err, test.want)
			}
		})
	}
}
