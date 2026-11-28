package aigateway

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
)

// AI-READY-1 budget alerts: 50% (info), 80% (warning) and 100% (critical) of
// a daily cost limit, at most once per subject, threshold and UTC day. The
// leader evaluates a bounded page of limited subjects per pass from the same
// native ledger and attribution admission uses. A failed usage read skips the
// subject; nothing is marked, so the next pass retries.

const BudgetAlertInterval = 5 * time.Minute

var budgetThresholds = []struct {
	percent  int
	severity alerts.Severity
}{{100, alerts.SeverityCritical}, {80, alerts.SeverityWarning}, {50, alerts.SeverityInfo}}

type budgetSubject struct {
	org   uuid.UUID
	kind  string
	id    uuid.UUID
	name  string
	limit float64
	ids   []string
}

// BudgetAlertResult summarizes one pass for the leader's log.
type BudgetAlertResult struct {
	Subjects, Published, Skipped int
	MorePending                  bool
}

// budgetCursor rotates through subjects across passes when there are more
// than one page. It is process-local: a new leader starts from the beginning.
type budgetCursor struct {
	kind string
	id   uuid.UUID
}

var (
	budgetPageMu sync.Mutex
	budgetPage   budgetCursor
)

// EvaluateBudgetAlerts runs one bounded pass. It is safe on several replicas
// (marks are claimed atomically) but the caller runs it on the leader only.
func (s *Policies) EvaluateBudgetAlerts(ctx context.Context, maxSubjects int) (BudgetAlertResult, error) {
	var out BudgetAlertResult
	if s == nil || s.pool == nil || s.engine == nil || s.alerts == nil {
		return out, nil
	}
	if maxSubjects < 1 || maxSubjects > 1000 {
		maxSubjects = 500
	}
	now := time.Now().UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	subjects, more, err := s.limitedSubjects(ctx, maxSubjects)
	if err != nil {
		return out, err
	}
	out.MorePending = more
	for _, subject := range subjects {
		out.Subjects++
		if len(subject.ids) == 0 {
			continue // no attributed key yet: nothing spent
		}
		usage, err := s.engine.Usage(ctx, subject.ids, day, now)
		if err != nil || !validObservedUsage(usage) {
			out.Skipped++
			continue
		}
		published, err := s.alertBudget(ctx, subject, usage.TotalCost, day)
		if err != nil {
			out.Skipped++
			continue
		}
		if published {
			out.Published++
		}
	}
	// Marks older than two days can never suppress anything again.
	_, _ = s.pool.Exec(ctx, `DELETE FROM ai_gateway_alert_marks WHERE ctid IN (SELECT ctid FROM ai_gateway_alert_marks WHERE day < $1::date LIMIT 5000)`, day.AddDate(0, 0, -2).Format("2006-01-02"))
	return out, nil
}

// alertBudget claims every threshold the spend has crossed today and
// publishes only the highest newly claimed one, so a jump straight to 100%
// sends one critical alert rather than three.
func (s *Policies) alertBudget(ctx context.Context, subject budgetSubject, spend float64, day time.Time) (bool, error) {
	if subject.limit <= 0 || spend < subject.limit*0.5 {
		return false, nil
	}
	var publish *struct {
		percent  int
		severity alerts.Severity
	}
	var claimedKeys []string
	for i := range budgetThresholds {
		t := budgetThresholds[i]
		if spend < subject.limit*float64(t.percent)/100 {
			continue
		}
		key := "budget:" + subject.kind + ":" + subject.id.String() + ":" + strconv.Itoa(t.percent)
		claimed, err := s.claimAlertMark(ctx, subject.org, day, key)
		if err != nil {
			s.releaseAlertMarks(subject.org, day, claimedKeys)
			return false, err
		}
		if claimed {
			claimedKeys = append(claimedKeys, key)
			if publish == nil {
				publish = &budgetThresholds[i]
			}
		}
	}
	if publish == nil {
		return false, nil
	}
	label := subject.name
	if label == "" {
		label = subject.id.String()
	}
	kind := map[string]string{"user_group": "User group", "workload": "Workload", "agent_group": "Agent group"}[subject.kind]
	dayText := day.Format("2006-01-02")
	err := s.alerts.Publish(ctx, alerts.Event{
		OrgID: subject.org, Key: alerts.EventAIBudgetThreshold, Severity: publish.severity,
		DedupKey: fmt.Sprintf("ai_budget:%s:%s:%s:%d", subject.kind, subject.id, dayText, publish.percent),
		Subject:  fmt.Sprintf("%s %s reached %d%% of its daily cost limit", kind, label, publish.percent),
		Fields: map[string]string{
			"subject_kind": subject.kind, "subject_id": subject.id.String(), "subject_name": subject.name,
			"threshold_percent": strconv.Itoa(publish.percent),
			"limit_usd":         strconv.FormatFloat(subject.limit, 'f', 2, 64),
			"spend_usd":         strconv.FormatFloat(spend, 'f', 2, 64),
			"day":               dayText,
		},
	})
	if err != nil {
		// Not sent: release today's marks so the next pass tries again.
		s.releaseAlertMarks(subject.org, day, claimedKeys)
		return false, err
	}
	return true, nil
}

func (s *Policies) releaseAlertMarks(org uuid.UUID, day time.Time, keys []string) {
	if len(keys) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.pool.Exec(ctx, `DELETE FROM ai_gateway_alert_marks WHERE org_id=$1 AND day=$2::date AND mark_key=ANY($3::text[])`, org, day.UTC().Format("2006-01-02"), keys)
}

// limitedSubjects reads one page of subjects with a daily limit in
// organizations that have the AI gateway on, with their attributed engine
// key IDs (the same IDs admission reads usage for).
func (s *Policies) limitedSubjects(ctx context.Context, limit int) ([]budgetSubject, bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, false, aiUnavailable()
	}
	defer rollbackAI(tx)
	const subjects = `SELECT kind,id,org_id,name,daily_limit FROM (
 SELECT 'agent_group' AS kind,t.team_id AS id,t.org_id,g.name,t.daily_cost_limit AS daily_limit FROM ai_gateway_team_policies t JOIN agent_groups g ON g.org_id=t.org_id AND g.id=t.team_id WHERE t.daily_cost_limit IS NOT NULL
 UNION ALL SELECT 'user_group',l.group_id,l.org_id,g.name,l.daily_usd_threshold FROM ai_user_group_cost_limits l JOIN user_groups g ON g.org_id=l.org_id AND g.id=l.group_id WHERE l.daily_usd_threshold IS NOT NULL
 UNION ALL SELECT 'workload',w.id,w.org_id,w.name,w.daily_usd_threshold FROM ai_workloads w WHERE w.daily_usd_threshold IS NOT NULL
) s WHERE EXISTS (SELECT 1 FROM organizations o WHERE o.id=s.org_id AND o.ai_gateway_enabled)
 AND (kind,id) > ($1::text,$2::uuid) ORDER BY kind,id LIMIT $3`
	budgetPageMu.Lock()
	defer budgetPageMu.Unlock()
	page := budgetPage
	rows, err := tx.Query(ctx, subjects, page.kind, page.id, limit+1)
	if err != nil {
		return nil, false, aiUnavailable()
	}
	var out []budgetSubject
	for rows.Next() {
		var b budgetSubject
		if rows.Scan(&b.kind, &b.id, &b.org, &b.name, &b.limit) != nil {
			rows.Close()
			return nil, false, aiUnavailable()
		}
		out = append(out, b)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, false, aiUnavailable()
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
		last := out[len(out)-1]
		budgetPage = budgetCursor{kind: last.kind, id: last.id}
	} else {
		budgetPage = budgetCursor{}
	}
	for i := range out {
		b := &out[i]
		switch b.kind {
		case "user_group":
			b.ids, err = userGroupUsageIDs(ctx, tx, b.org, b.id)
		case "agent_group":
			team := b.id
			b.ids, err = bindingUsageIDs(ctx, tx, b.org, &team, nil)
		case "workload":
			var native string
			if err = tx.QueryRow(ctx, `SELECT native_key_id FROM ai_workloads WHERE org_id=$1 AND id=$2`, b.org, b.id).Scan(&native); err == nil && native != "" {
				b.ids = []string{native}
			}
		}
		if err != nil {
			b.ids = nil
		}
	}
	return out, more, nil
}
