package ipsec

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Identity is supplied to material construction before digest sealing or any
// journal write. The three BGP owners retain their relative order; both distinct
// static owners (one missing a standby) occupy every possible pair of positions.
// These are the existing continuity assertions, including the real 20s native
// window, all IO charges, both cycles, callbacks and unchanged original leases.
func TestPriorityActiveRenewalMixedOwnerOrders(t *testing.T) {
	for missingStandby := 0; missingStandby < 5; missingStandby++ {
		for healthyStatic := 0; healthyStatic < 5; healthyStatic++ {
			if missingStandby == healthyStatic {
				continue
			}
			t.Run(fmt.Sprintf("missing_static_%d_healthy_static_%d", missingStandby, healthyStatic), func(t *testing.T) {
				ids := make([]uuid.UUID, 5)
				bgpIndex := 0
				for position := 0; position < 5; position++ {
					owner := bgpIndex
					switch position {
					case missingStandby:
						owner = 3
					case healthyStatic:
						owner = 4
					default:
						bgpIndex++
					}
					ids[owner] = uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", position+1))
				}
				assertPriorityActiveRenewalCallerContinuity(t, true, ids...)
			})
		}
	}
}

// Record the real production caller boundary without changing that caller or
// charging extra simulated IO. This identifies optional samples before commit.
func priorityRenewalPulseBoundary() string {
	var pcs [16]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*RuntimeController).maintainIPsecRuntimeItems") {
			return fmt.Sprintf("runtime_maintenance.go:%d", frame.Line)
		}
		if !more {
			return "unknown"
		}
	}
}
