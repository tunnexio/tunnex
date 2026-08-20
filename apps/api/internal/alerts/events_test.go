package alerts

import (
	"context"
	"encoding/json"
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

func TestEventJSONMatchesWebhookContract(t *testing.T) {
	t.Parallel()
	event := Event{OrgID: uuid.MustParse("01a01e40-c8f3-7f2d-a09d-54f4f456dd65"), Key: EventAgentOffline,
		Severity: SeverityCritical, DedupKey: "agent:one:offline", Subject: "Agent one is offline",
		Fields: map[string]string{"threshold_seconds": "60"}}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"org_id", "key", "severity", "dedup_key", "subject", "fields"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("payload %s missing %q", payload, key)
		}
	}
	if _, leaked := got["Subject"]; leaked {
		t.Fatalf("payload used Go field names: %s", payload)
	}
}

func TestEventValidationRejectsUnknownContractValues(t *testing.T) {
	t.Parallel()
	err := (Event{OrgID: uuid.New(), Key: "renamed.by.accident", Severity: SeverityWarning, DedupKey: "x", Subject: "x"}).Validate()
	if err == nil {
		t.Fatal("unknown event key was accepted")
	}
}
