package k8s

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func promotionRequest(t *testing.T, transition Transition) ConnectorPoolPromotionRequest {
	t.Helper()
	org, site, pool, active, next := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	return ConnectorPoolPromotionRequest{
		OrgID: org, SiteID: site, PoolID: pool, ExpectedActiveID: active, ExpectedGeneration: 7,
		Decision: Decision{
			Transition: transition, FromID: active.String(), ToID: next.String(), Reason: "deterministic health decision",
			Pool: ConnectorPool{ActiveID: next.String(), Generation: 8},
		},
	}
}

func TestValidateConnectorPoolPromotionRequestAcceptsOnlyConsistentTransitions(t *testing.T) {
	for _, transition := range []Transition{Promoted, FailedBack} {
		req := promotionRequest(t, transition)
		from, to, reason, err := validateConnectorPoolPromotionRequest(req)
		if err != nil || from != req.ExpectedActiveID || to.String() != req.Decision.ToID || reason != req.Decision.Reason {
			t.Fatalf("%s: from=%s to=%s reason=%q err=%v", transition, from, to, reason, err)
		}
	}
}

func TestValidateConnectorPoolPromotionRequestRejectsNonTransitionAndForgedState(t *testing.T) {
	for name, mutate := range map[string]func(*ConnectorPoolPromotionRequest){
		"no change":          func(r *ConnectorPoolPromotionRequest) { r.Decision.Transition = NoChange },
		"wrong source":       func(r *ConnectorPoolPromotionRequest) { r.Decision.FromID = uuid.New().String() },
		"same source target": func(r *ConnectorPoolPromotionRequest) { r.Decision.ToID = r.Decision.FromID },
		"wrong generation":   func(r *ConnectorPoolPromotionRequest) { r.Decision.Pool.Generation-- },
		"empty reason":       func(r *ConnectorPoolPromotionRequest) { r.Decision.Reason = "" },
		"whitespace reason":  func(r *ConnectorPoolPromotionRequest) { r.Decision.Reason = " \t\n " },
		"oversized reason": func(r *ConnectorPoolPromotionRequest) {
			r.Decision.Reason = strings.Repeat("x", maxConnectorPoolAuditReason+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := promotionRequest(t, Promoted)
			mutate(&req)
			if _, _, _, err := validateConnectorPoolPromotionRequest(req); !errors.Is(err, ErrInvalidConnectorPoolDecision) {
				t.Fatalf("error = %v, want invalid decision", err)
			}
		})
	}
}
