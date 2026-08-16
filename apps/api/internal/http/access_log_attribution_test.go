package http

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
)

func TestAccessEventExposesOnlyVerifiedAgentAttribution(t *testing.T) {
	id := uuid.New()
	rev := int64(4)
	e := accesslog.Event{SrcDeviceID: &id, SrcKind: "agent", PolicyHash: "abcdef123456", PolicyVersion: 7, SrcConfigRevision: &rev, DecisionReason: accesslog.ReasonNoMatchingGrant}
	out := toAPIAccessEvent(e)
	if out.SrcAgentId == nil || uuid.UUID(*out.SrcAgentId) != id || out.PolicyHash == nil || *out.PolicyHash != "abcdef123456" || out.PolicyVersion == nil || *out.PolicyVersion != 7 || out.DecisionReason == nil {
		t.Fatalf("verified agent event lost attribution: %+v", out)
	}
	e.SrcKind = "human"
	if got := toAPIAccessEvent(e); got.SrcAgentId != nil {
		t.Fatalf("human device must never be exposed as src_agent_id: %+v", got)
	}
}
