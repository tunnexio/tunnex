package alerts

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestNoopPublisherValidatesClosedCatalogue(t *testing.T) {
	t.Parallel()
	publisher := NoopPublisher{}
	for _, key := range Keys() {
		if err := publisher.Publish(context.Background(), Event{
			OrgID: uuid.New(), Key: key, Severity: SeverityWarning,
			DedupKey: "agent:" + string(key), Subject: "agent-1",
		}); err != nil {
			t.Fatalf("publish %q: %v", key, err)
		}
	}
}

func TestEventValidationRejectsUnknownContractValues(t *testing.T) {
	t.Parallel()
	err := (Event{OrgID: uuid.New(), Key: "renamed.by.accident", Severity: SeverityWarning, DedupKey: "x", Subject: "x"}).Validate()
	if err == nil {
		t.Fatal("unknown event key was accepted")
	}
}
