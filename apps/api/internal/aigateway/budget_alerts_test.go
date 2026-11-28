package aigateway

import (
	"context"
	"errors"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
)

// AI-READY-1: 50/80/100% alerts of a daily limit, once per subject,
// threshold and UTC day; only the highest newly crossed one is sent.
func TestBudgetAlertsOncePerThresholdPerDay(t *testing.T) {
	ctx, f := newPriceFixture(t)
	publisher := &recordingPublisher{}
	f.policies.SetAlertPublisher(publisher)
	f.engine.unpriced = false
	budgetPage = budgetCursor{}
	f.exec(`UPDATE organizations SET ai_gateway_enabled=true WHERE id=$1`, f.org)

	pass := func() BudgetAlertResult {
		t.Helper()
		r, err := f.policies.EvaluateBudgetAlerts(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	severities := func() []alerts.Severity {
		publisher.mu.Lock()
		defer publisher.mu.Unlock()
		out := []alerts.Severity{}
		for _, e := range publisher.events {
			if e.Key == alerts.EventAIBudgetThreshold {
				out = append(out, e.Severity)
			}
		}
		return out
	}

	// Limit 5 USD. Under half: nothing.
	f.engine.usage = 2
	if r := pass(); r.Subjects != 1 || r.Published != 0 {
		t.Fatalf("under 50%%: %+v", r)
	}
	// 50%: one info alert; a second pass at the same spend sends nothing.
	f.engine.usage = 2.5
	pass()
	pass()
	if got := severities(); len(got) != 1 || got[0] != alerts.SeverityInfo {
		t.Fatalf("50%%: %v", got)
	}
	// A jump past 80% and 100% at once sends only the critical alert.
	f.engine.usage = 7
	pass()
	pass()
	got := severities()
	if len(got) != 2 || got[1] != alerts.SeverityCritical {
		t.Fatalf("jump to 100%%: %v", got)
	}
	publisher.mu.Lock()
	last := publisher.events[len(publisher.events)-1]
	publisher.mu.Unlock()
	if last.Fields["subject_kind"] != "user_group" || last.Fields["subject_name"] != "Engineering" || last.Fields["threshold_percent"] != "100" || last.Fields["limit_usd"] != "5.00" || last.Fields["spend_usd"] != "7.00" {
		t.Fatalf("alert fields: %+v", last.Fields)
	}
	var marks int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_alert_marks WHERE org_id=$1 AND mark_key LIKE 'budget:user_group:%'`, f.org).Scan(&marks); err != nil || marks != 3 {
		t.Fatalf("want three marks for today, got %d %v", marks, err)
	}

	// A failed usage read marks nothing and is retried next pass.
	f.exec(`DELETE FROM ai_gateway_alert_marks WHERE org_id=$1`, f.org)
	failed := errors.New("private usage failure")
	f.engine.usageFor = func([]string) (float64, error) { return 0, failed }
	if r := pass(); r.Skipped != 1 || r.Published != 0 {
		t.Fatalf("failed read: %+v", r)
	}
	f.engine.usageFor = nil
	if r := pass(); r.Published != 1 {
		t.Fatalf("retry after a failed read: %+v", r)
	}

	// A failed send keeps no mark, so the next pass sends it.
	f.exec(`DELETE FROM ai_gateway_alert_marks WHERE org_id=$1`, f.org)
	f.policies.SetAlertPublisher(failingPublisher{})
	if r := pass(); r.Published != 0 || r.Skipped != 1 {
		t.Fatalf("failed send: %+v", r)
	}
	f.policies.SetAlertPublisher(publisher)
	if r := pass(); r.Published != 1 {
		t.Fatalf("resend after a failed send: %+v", r)
	}

	// An organization with the gateway off is not evaluated.
	f.exec(`UPDATE organizations SET ai_gateway_enabled=false WHERE id=$1`, f.org)
	if r := pass(); r.Subjects != 0 {
		t.Fatalf("gateway off: %+v", r)
	}
}

type failingPublisher struct{}

func (failingPublisher) Publish(context.Context, alerts.Event) error {
	return errors.New("outbox down")
}
