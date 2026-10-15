package reconcile

import "testing"

func TestBackendRejectsInvalidWireGuardMTUCap(t *testing.T) {
	for _, cap := range []int{-1, 1, 1279, 1421, 1500} {
		if _, err := SelectBackendWithOptions("mem", "wg0", nil, BackendOptions{WireGuardMTUCap: cap}); err == nil {
			t.Fatalf("invalid cap %d accepted", cap)
		}
	}
	for _, cap := range []int{0, 1280, 1380, 1420} {
		if _, err := SelectBackendWithOptions("mem", "wg0", nil, BackendOptions{WireGuardMTUCap: cap}); err != nil {
			t.Fatalf("valid cap %d refused: %v", cap, err)
		}
	}
}
