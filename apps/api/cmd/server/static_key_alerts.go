package main

import (
	"context"
	"strconv"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
)

// staticKeyExpiryAlerts turns a static key expiry reminder (AI-KEYS-1, 14 and
// 3 days) into a delivery-only alert event. It never carries the key itself.
func staticKeyExpiryAlerts(publisher alerts.Publisher) aigateway.StaticKeyExpiryNotifier {
	return func(ctx context.Context, e aigateway.StaticKeyExpiry) error {
		severity := alerts.SeverityWarning
		if e.DaysLeft <= 3 {
			severity = alerts.SeverityCritical
		}
		return publisher.Publish(ctx, alerts.Event{
			OrgID:    e.Org,
			Key:      alerts.EventAIWorkloadStaticKeyExpiring,
			Severity: severity,
			DedupKey: "ai_workload_static_key:" + e.Key.String() + ":" + strconv.Itoa(e.DaysLeft),
			Subject:  "Static API key \"" + e.Name + "\" of workload \"" + e.WorkloadName + "\" expires in " + strconv.Itoa(e.DaysLeft) + " days",
			Fields: map[string]string{
				"workload_id": e.Workload.String(),
				"workload":    e.WorkloadName,
				"key_id":      e.Key.String(),
				"key_name":    e.Name,
				"expires_at":  e.ExpiresAt.UTC().Format(time.RFC3339),
				"action":      "Rotate the key in AI Gateway, Workloads, API keys.",
			},
		})
	}
}
