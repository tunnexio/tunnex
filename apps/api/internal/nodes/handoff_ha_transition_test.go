package nodes

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

func TestHandoffHAAuthoritySameRevisionKeepsOriginalExpiry(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	original := now.Add(2 * time.Minute)
	proposed := now.Add(7 * time.Minute)
	got, err := selectHandoffHAAuthorityIssueExpiry(now, proposed, []time.Time{original})
	if err != nil || !got.Equal(original) {
		t.Fatalf("same-revision expiry=%s want=%s err=%v", got, original, err)
	}
	if _, err := selectHandoffHAAuthorityIssueExpiry(now, proposed, []time.Time{now}); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("expired same-revision delivery was accepted: %v", err)
	}
	if _, err := selectHandoffHAAuthorityIssueExpiry(now, proposed, []time.Time{original, original}); !errors.Is(err, ErrHandoffHATransitionRefused) {
		t.Fatalf("ambiguous same-revision delivery was accepted: %v", err)
	}
}

func TestHandoffHAAuthorityRetryReasonIsExact(t *testing.T) {
	tests := []struct {
		name           string
		expired, stale bool
		want           string
		wantRetry      bool
	}{
		{name: "fresh", want: "", wantRetry: false},
		{name: "expired unacknowledged", expired: true, want: handoffHAAuthorityExpiredUnacknowledgedRetryReason, wantRetry: true},
		{name: "stale receipt", stale: true, want: handoffHAAuthorityStaleReceiptRetryReason, wantRetry: true},
		{name: "combined", expired: true, stale: true, want: handoffHAAuthorityCombinedRetryReason, wantRetry: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, retry := classifyHandoffHAAuthorityRetry(tt.expired, tt.stale)
			if got != tt.want || retry != tt.wantRetry {
				t.Fatalf("reason=%q retry=%t want=%q/%t", got, retry, tt.want, tt.wantRetry)
			}
		})
	}
}

func TestBootstrapBaseClassificationIsExactCompleteArmDomain(t *testing.T) {
	plan := handoffBootstrapPlan(t, time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC))
	got, err := bootstrapBaseClassification(plan)
	if err != nil {
		t.Fatal(err)
	}
	manifest := plan.CurrentOwnerEnvelope.Manifest
	if got.Scope.PoolID != plan.Scope.PoolID.String() || got.Disposition != KubernetesOwnershipPoolDispositionArmFence ||
		len(got.Fields.Routes) != len(manifest.Routes) || len(got.Fields.WGPeers) != len(manifest.WGPeers) ||
		len(got.Fields.VIPMappings) != len(manifest.Services) || len(got.Fields.DNSZones) != 1 {
		t.Fatalf("classification=%+v manifest=%+v", got, manifest)
	}
	if got.Fields.VIPMappings[0].ServiceID != manifest.Services[0].ServiceID || got.Fields.VIPMappings[0].VIP != manifest.Services[0].VIP ||
		got.Fields.DNSZones[0].ListenVIP != manifest.DNSVIP || got.Fields.DNSZones[0].Zone != manifest.DNSZone {
		t.Fatalf("classification lost service/DNS identity: %+v", got.Fields)
	}
}

func TestEnabledProductionCompositionRequiresBaseAuthorityDependencies(t *testing.T) {
	pool := &pgxpool.Pool{}
	store := &p2CompositionStore{}
	if got, err := NewHandoffSchedulerProductionComposition(true, pool, &leader.Elector{}, p2CompositionPolicy{}, k8s.NewService(pool), store, nil, nil); err == nil || got != nil {
		t.Fatalf("enabled composition accepted missing P3 dependencies: composition=%+v err=%v", got, err)
	}
}
