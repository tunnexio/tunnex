package ipsec

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestQuiescedTransportDiagnosticIsClosedAndObservable(t *testing.T) {
	connection := uuid.New()
	var events []RuntimeDiagnostic
	emit := func(event RuntimeDiagnostic) { events = append(events, event) }
	start := time.Now()
	emitRuntimeDiagnostic(emit, context.Background(), "bgp_apply", "quiesced_transport", connection, start, true)
	if len(events) != 1 || events[0].Operation != "bgp_apply" || events[0].Stage != "quiesced_transport" || events[0].ConnectionID != connection || !events[0].Refused {
		t.Fatal("quiesced transport refusal did not produce its existing closed diagnostic")
	}
	for _, operation := range []string{"apply", "maintenance", "cleanup", "unrecognized"} {
		emitRuntimeDiagnostic(emit, context.Background(), operation, "quiesced_transport", connection, start, true)
	}
	emitRuntimeDiagnostic(emit, context.Background(), "bgp_apply", "quiesced_transport:untrusted-detail", connection, start, true)
	if len(events) != 1 {
		t.Fatal("quiesced diagnostic accepted another operation or arbitrary stage detail")
	}
}
