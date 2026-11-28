package aigateway

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AI-READY-1 organization cost settings. A missing row is the default.
const (
	UnknownPriceBlock          = "block"
	UnknownPriceAllowAndAlert  = "allow_and_alert"
	DefaultRequestLogRetention = 30
)

type CostSettings struct {
	UnknownPricePolicy      string
	RequestLogRetentionDays int
	Revision                int64
	UpdatedAt               *time.Time
}

func (s *Policies) CostSettings(ctx context.Context, org uuid.UUID) (CostSettings, error) {
	if s == nil || s.pool == nil {
		return CostSettings{}, aiUnavailable()
	}
	out := CostSettings{UnknownPricePolicy: UnknownPriceBlock, RequestLogRetentionDays: DefaultRequestLogRetention}
	var updated time.Time
	err := s.pool.QueryRow(ctx, `SELECT unknown_price_policy,request_log_retention_days,revision,updated_at FROM ai_gateway_cost_settings WHERE org_id=$1`, org).Scan(&out.UnknownPricePolicy, &out.RequestLogRetentionDays, &out.Revision, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return CostSettings{}, aiUnavailable()
	}
	out.UpdatedAt = &updated
	return out, nil
}

// PutCostSettings changes both settings under an expected revision (0 when
// the organization has never saved them). Every change is audited.
func (s *Policies) PutCostSettings(ctx context.Context, org, actor uuid.UUID, policy string, retentionDays int, expected int64) (CostSettings, error) {
	if s == nil || s.pool == nil {
		return CostSettings{}, aiUnavailable()
	}
	if (policy != UnknownPriceBlock && policy != UnknownPriceAllowAndAlert) || retentionDays < 1 || retentionDays > 365 || expected < 0 || expected == math.MaxInt64 {
		return CostSettings{}, apierr.BadRequest("invalid_ai_cost_settings", "policy must be block or allow_and_alert and retention 1 to 365 days")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CostSettings{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	var out CostSettings
	var updated time.Time
	if expected == 0 {
		err = tx.QueryRow(ctx, `INSERT INTO ai_gateway_cost_settings(org_id,unknown_price_policy,request_log_retention_days,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING unknown_price_policy,request_log_retention_days,revision,updated_at`, org, policy, retentionDays, actor).Scan(&out.UnknownPricePolicy, &out.RequestLogRetentionDays, &out.Revision, &updated)
	} else {
		err = tx.QueryRow(ctx, `UPDATE ai_gateway_cost_settings SET unknown_price_policy=$2,request_log_retention_days=$3,updated_by=$4,revision=revision+1 WHERE org_id=$1 AND revision=$5 RETURNING unknown_price_policy,request_log_retention_days,revision,updated_at`, org, policy, retentionDays, actor, expected).Scan(&out.UnknownPricePolicy, &out.RequestLogRetentionDays, &out.Revision, &updated)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return CostSettings{}, apierr.New(409, "ai_cost_settings_revision_conflict", "AI cost settings changed; refresh and retry")
	}
	if err != nil {
		return CostSettings{}, aiUnavailable()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_gateway.cost_settings_changed','ai_policy',$6,jsonb_build_object('revision',$3::bigint,'unknown_price_policy',$4::text,'request_log_retention_days',$5::integer))`, org, actor, out.Revision, policy, retentionDays, org.String()); err != nil {
		return CostSettings{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return CostSettings{}, aiUnavailable()
	}
	out.UpdatedAt = &updated
	return out, nil
}

func unknownPriceAllowed(ctx context.Context, tx pgx.Tx, org uuid.UUID) (bool, error) {
	var policy string
	err := tx.QueryRow(ctx, `SELECT unknown_price_policy FROM ai_gateway_cost_settings WHERE org_id=$1`, org).Scan(&policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return policy == UnknownPriceAllowAndAlert, nil
}

// SetAlertPublisher wires budget and unknown-price alerts to the outbox.
func (s *Policies) SetAlertPublisher(p alerts.Publisher) {
	if s != nil {
		s.alerts = p
	}
}

// costSubject names who a daily limit belongs to, for unknown-price alerts.
type costSubject struct {
	Kind string // user_group, workload, workload_key or agent_group
	ID   uuid.UUID
}

// claimAlertMark records an alert for today (UTC). Only the call that
// created the mark returns true, so each alert is published once a day.
func (s *Policies) claimAlertMark(ctx context.Context, org uuid.UUID, day time.Time, key string) (bool, error) {
	var claimed bool
	err := s.pool.QueryRow(ctx, `INSERT INTO ai_gateway_alert_marks(org_id,day,mark_key) VALUES($1,$2::date,$3) ON CONFLICT DO NOTHING RETURNING true`, org, day.UTC().Format("2006-01-02"), key).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return claimed, err
}

// subjectName is the display name of a limited subject, or "" when gone.
func (s *Policies) subjectName(ctx context.Context, org uuid.UUID, subject costSubject) string {
	var q string
	switch subject.Kind {
	case "user_group":
		q = `SELECT name FROM user_groups WHERE org_id=$1 AND id=$2`
	case "workload":
		q = `SELECT name FROM ai_workloads WHERE org_id=$1 AND id=$2`
	case "agent_group":
		q = `SELECT name FROM agent_groups WHERE org_id=$1 AND id=$2`
	case "workload_key":
		q = `SELECT name FROM ai_workload_static_keys WHERE org_id=$1 AND id=$2`
	default:
		return ""
	}
	var name string
	if s.pool.QueryRow(ctx, q, org, subject.ID).Scan(&name) != nil {
		return ""
	}
	return name
}

// notifyUnknownPrice raises ai.price_unknown for the first allowed call per
// subject, model and UTC day. It never delays or fails the inference request:
// it runs detached, bounded to four at a time, and is dropped when busy.
func (s *Policies) notifyUnknownPrice(org uuid.UUID, subject costSubject, model string) {
	if s == nil || s.alerts == nil || s.pool == nil || subject.ID == uuid.Nil {
		return
	}
	select {
	case s.alertSlots() <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-s.alertSlots() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		now := time.Now().UTC()
		key := "price_unknown:" + subject.Kind + ":" + subject.ID.String() + ":" + model
		claimed, err := s.claimAlertMark(ctx, org, now, key)
		if err != nil || !claimed {
			return
		}
		name := s.subjectName(ctx, org, subject)
		subjectLabel := name
		if subjectLabel == "" {
			subjectLabel = subject.ID.String()
		}
		err = s.alerts.Publish(ctx, alerts.Event{
			OrgID: org, Key: alerts.EventAIPriceUnknown, Severity: alerts.SeverityWarning,
			DedupKey: "ai_price_unknown:" + subject.Kind + ":" + subject.ID.String() + ":" + model + ":" + now.Format("2006-01-02"),
			Subject:  "Model without a price used under a daily limit: " + model,
			Fields: map[string]string{
				"subject_kind": subject.Kind, "subject_id": subject.ID.String(), "subject_name": name,
				"model": model, "day": now.Format("2006-01-02"),
			},
		})
		if err != nil {
			s.releaseAlertMarks(org, now, []string{key}) // the next allowed call tries again
		}
	}()
}

// unknownPriceAlertSlots bounds detached alert senders process-wide.
var unknownPriceAlertSlots = make(chan struct{}, 4)

func (s *Policies) alertSlots() chan struct{} { return unknownPriceAlertSlots }
