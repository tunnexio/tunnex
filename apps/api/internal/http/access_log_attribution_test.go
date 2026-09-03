package http

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
)

func TestAccessEventExposesOnlyVerifiedAgentAttribution(t *testing.T) {
	id := uuid.New()
	userID := uuid.New()
	rev := int64(4)
	e := accesslog.Event{SrcDeviceID: &id, SrcUserID: &userID, SrcKind: "agent", PolicyHash: "abcdef123456", PolicyVersion: 7, SrcConfigRevision: &rev, DecisionReason: accesslog.ReasonNoMatchingGrant}
	out := toAPIAccessEvent(e)
	if out.SrcAgentId == nil || uuid.UUID(*out.SrcAgentId) != id || out.SrcDeviceId == nil || uuid.UUID(*out.SrcDeviceId) != id || out.SrcUserId == nil || uuid.UUID(*out.SrcUserId) != userID || out.SrcKind == nil || *out.SrcKind != "agent" || out.PolicyHash == nil || *out.PolicyHash != "abcdef123456" || out.PolicyVersion == nil || *out.PolicyVersion != 7 || out.DecisionReason == nil {
		t.Fatalf("verified agent event lost attribution: %+v", out)
	}
	e.SrcKind = "human"
	if got := toAPIAccessEvent(e); got.SrcAgentId != nil || got.SrcDeviceId == nil || got.SrcUserId == nil || got.SrcKind == nil || *got.SrcKind != "human" {
		t.Fatalf("human event must expose historical identity without src_agent_id: %+v", got)
	}
	e.SrcKind = ""
	if got := toAPIAccessEvent(e); got.SrcAgentId != nil || got.SrcDeviceId == nil || uuid.UUID(*got.SrcDeviceId) != id || got.SrcUserId == nil || uuid.UUID(*got.SrcUserId) != userID || got.SrcKind != nil {
		t.Fatalf("legacy event must preserve stored IDs without fabricating kind or agent attribution: %+v", got)
	}
	e = accesslog.Event{}
	if got := toAPIAccessEvent(e); got.SrcAgentId != nil || got.SrcDeviceId != nil || got.SrcUserId != nil || got.SrcKind != nil {
		t.Fatalf("unattributed event must not fabricate identity: %+v", got)
	}
}
