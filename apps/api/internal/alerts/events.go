// Package alerts owns F11's typed event vocabulary. It is deliberately
// independent from audit-log action strings: those strings are historical,
// inline values rather than a safe subscription contract.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type EventKey string

const (
	EventAgentOffline            EventKey = "agent.offline"
	EventAgentDenialSpike        EventKey = "agent.denial_spike"
	EventAgentAccessExpiring     EventKey = "agent.access_expiring"
	EventAgentRotationFailed     EventKey = "agent.rotation_failed"
	EventAgentConfigurationDrift EventKey = "agent.configuration_drift"
)

// Keys is the closed F11 catalogue. Producers use these values rather than
// duplicating strings alongside audit actions.
func Keys() []EventKey {
	return []EventKey{
		EventAgentOffline,
		EventAgentDenialSpike,
		EventAgentAccessExpiring,
		EventAgentRotationFailed,
		EventAgentConfigurationDrift,
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Event struct {
	OrgID    uuid.UUID
	Key      EventKey
	Severity Severity
	// DedupKey is scoped by the publisher to one persistent condition. The
	// dispatcher will later enforce each destination's cooldown against it.
	DedupKey string
	// Subject and Fields are observability data, never a transport secret.
	Subject string
	Fields  map[string]string
}

func (e Event) Validate() error {
	if e.OrgID == uuid.Nil {
		return errors.New("alert event requires organization")
	}
	if !knownKey(e.Key) {
		return fmt.Errorf("unknown alert event key %q", e.Key)
	}
	if e.Severity != SeverityInfo && e.Severity != SeverityWarning && e.Severity != SeverityCritical {
		return fmt.Errorf("unknown alert severity %q", e.Severity)
	}
	if strings.TrimSpace(e.DedupKey) == "" {
		return errors.New("alert event requires dedup key")
	}
	if strings.TrimSpace(e.Subject) == "" {
		return errors.New("alert event requires subject")
	}
	return nil
}

func knownKey(key EventKey) bool {
	for _, known := range Keys() {
		if key == known {
			return true
		}
	}
	return false
}

// Publisher is the seam producers use. Slice 2 intentionally provides a
// no-op implementation only; the durable outbox publisher lands with the
// dispatcher after the SSRF-safe delivery client exists.
type Publisher interface {
	Publish(context.Context, Event) error
}

type NoopPublisher struct{}

func (NoopPublisher) Publish(_ context.Context, event Event) error {
	return event.Validate()
}
