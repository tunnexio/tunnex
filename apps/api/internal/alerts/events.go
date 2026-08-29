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
	EventAgentOffline                 EventKey = "agent.offline"
	EventAgentDenialSpike             EventKey = "agent.denial_spike"
	EventAgentAccessExpiring          EventKey = "agent.access_expiring"
	EventAgentRotationFailed          EventKey = "agent.rotation_failed"
	EventAgentConfigurationDrift      EventKey = "agent.configuration_drift"
	EventGatewayOffline               EventKey = "gateway.offline"
	EventGatewayPolicyDegraded        EventKey = "gateway.policy_degraded"
	EventSiteLinkDown                 EventKey = "site.link_down"
	EventDeviceOffline                EventKey = "device.offline"
	EventDevicePostureBlocked         EventKey = "device.posture_blocked"
	EventKubernetesConnectorDegraded  EventKey = "kubernetes.connector_degraded"
	EventKubernetesInventoryStale     EventKey = "kubernetes.inventory_stale"
	EventKubernetesServiceUnavailable EventKey = "kubernetes.service_unavailable"
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
		EventGatewayOffline,
		EventGatewayPolicyDegraded,
		EventSiteLinkDown,
		EventDeviceOffline,
		EventDevicePostureBlocked,
		EventKubernetesConnectorDegraded,
		EventKubernetesInventoryStale,
		EventKubernetesServiceUnavailable,
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type EventState string

const (
	EventStateFiring   EventState = "firing"
	EventStateResolved EventState = "resolved"
)

// ResourceRef identifies the product object whose condition is changing. It
// is deliberately provider-neutral and contains no transport credentials.
type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Event struct {
	OrgID    uuid.UUID `json:"org_id"`
	Key      EventKey  `json:"key"`
	Severity Severity  `json:"severity"`
	// DedupKey is scoped by the publisher to one persistent condition. The
	// dispatcher will later enforce each destination's cooldown against it.
	DedupKey string `json:"dedup_key"`
	// Subject and Fields are observability data, never a transport secret.
	Subject string            `json:"subject"`
	Fields  map[string]string `json:"fields"`
	// State and Resource are additive for the shared alert centre. Existing
	// agent producers omit them and are normalized to a firing condition.
	State    EventState   `json:"state,omitempty"`
	Resource *ResourceRef `json:"resource,omitempty"`
}

func (e Event) normalized() Event {
	if e.State == "" {
		e.State = EventStateFiring
	}
	return e
}

func (e Event) Validate() error {
	e = e.normalized()
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
	if e.State != EventStateFiring && e.State != EventStateResolved {
		return fmt.Errorf("unknown alert event state %q", e.State)
	}
	if e.Resource != nil {
		if strings.TrimSpace(e.Resource.Type) == "" || strings.TrimSpace(e.Resource.ID) == "" {
			return errors.New("alert event resource requires type and id")
		}
		if !knownResourceType(e.Resource.Type) {
			return fmt.Errorf("unknown alert resource type %q", e.Resource.Type)
		}
	}
	return nil
}

func knownResourceType(resourceType string) bool {
	switch resourceType {
	case "agent", "gateway", "site", "device", "kubernetes_cluster", "kubernetes_service":
		return true
	default:
		return false
	}
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
