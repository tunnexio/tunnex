//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// TestIsWfpNotFound pins the cleanup's idempotency boundary (S6.7 review): the three WFP
// "object not found" statuses are the already-gone case (success for cleanup), and ANY other
// error must surface (a still-referenced sublayer/provider = an incomplete removal that would
// silently strand the host or wedge the next arm).
func TestIsWfpNotFound(t *testing.T) {
	notFound := []uint32{cFWP_E_FILTER_NOT_FOUND, cFWP_E_SUBLAYER_NOT_FOUND, cFWP_E_PROVIDER_NOT_FOUND}
	for _, c := range notFound {
		if !isWfpNotFound(syscall.Errno(c)) {
			t.Errorf("isWfpNotFound(%#x) = false, want true (idempotent not-found)", c)
		}
		// Wrapped (as wrapErr/fmt.Errorf would) must still be recognized.
		if !isWfpNotFound(fmt.Errorf("delete: %w", syscall.Errno(c))) {
			t.Errorf("isWfpNotFound(wrapped %#x) = false, want true", c)
		}
	}
	// A DIFFERENT WFP status (e.g. FWP_E_IN_USE 0x8032000B — sublayer still referenced) must NOT
	// be swallowed, nor a generic error, nor nil.
	for _, err := range []error{syscall.Errno(0x8032000B), errors.New("boom"), nil} {
		if isWfpNotFound(err) {
			t.Errorf("isWfpNotFound(%v) = true, want false (must surface real failures)", err)
		}
	}
}
