package http

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestPolicyRuleFQDNProjectionDefaultsToGenerationUnavailable(t *testing.T) {
	ruleID, orgID, resourceID := uuid.New(), uuid.New(), uuid.New()
	out := toAPIRule(sqlc.PolicyRule{
		ID: ruleID, OrgID: orgID, SrcKind: "group", DstKind: "fqdn_resource", CreatedAt: time.Now(),
		DstFqdnResourceID: pgtype.UUID{Bytes: resourceID, Valid: true},
	}, false, false)
	if out.DstFqdnResourceId == nil || *out.DstFqdnResourceId != resourceID {
		t.Fatal("FQDN rule identity was not projected")
	}
	if out.FqdnDestinationStatus != api.GenerationUnavailable {
		t.Fatalf("FQDN rule status = %q, want %q; a bare mapping must not claim an active generation", out.FqdnDestinationStatus, api.GenerationUnavailable)
	}
	if normal := toAPIRule(sqlc.PolicyRule{ID: uuid.New(), OrgID: orgID, SrcKind: "group", DstKind: "resource", CreatedAt: time.Now()}, false, false); normal.FqdnDestinationStatus != api.NotApplicable {
		t.Fatalf("non-FQDN status = %q, want %q", normal.FqdnDestinationStatus, api.NotApplicable)
	}
}

func TestFQDNRuleStatusProjectionUsesAuthoritativeResourceState(t *testing.T) {
	for name, tc := range map[string]struct {
		entitled, optedIn, readable, exists bool
		want                                api.PolicyRuleFqdnDestinationStatus
	}{
		"feature absent":       {false, false, true, true, api.FeatureUnavailable},
		"read unavailable":     {true, false, false, true, api.ProjectionUnavailable},
		"opt-in disabled":      {true, false, true, true, api.OptInDisabled},
		"resource unavailable": {true, true, true, false, api.GenerationUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if got := fqdnDestinationStatusFor(tc.entitled, tc.optedIn, tc.readable, tc.exists, ""); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
	for state, want := range map[string]api.PolicyRuleFqdnDestinationStatus{
		"healthy":   api.ActiveGeneration,
		"draft":     api.GenerationPending,
		"resolving": api.GenerationPending,
		"stale":     api.GenerationWithdrawn,
		"nxdomain":  api.GenerationWithdrawn,
		"failed":    api.GenerationWithdrawn,
		"":          api.GenerationUnavailable,
	} {
		if got := fqdnDestinationStatus(state); got != want {
			t.Fatalf("state %q = %q, want %q", state, got, want)
		}
	}
}
