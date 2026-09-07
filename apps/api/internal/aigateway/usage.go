package aigateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const maxAIUsageBindings = 64

// bindingUsageIDs selects retained attribution, deliberately without joining the
// current assignment or group membership. Moving an agent must not relabel its
// historical requests. Native IDs are never accepted from a public caller.
func bindingUsageIDs(ctx context.Context, tx pgx.Tx, org uuid.UUID, team, device *uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT native_key_id FROM ai_gateway_key_bindings
 WHERE org_id=$1 AND ($2::uuid IS NULL OR team_id=$2) AND ($3::uuid IS NULL OR device_id=$3)
 ORDER BY native_key_id LIMIT 65`, org, team, device)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, aiUnavailable()
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || len(ids) > maxAIUsageBindings || (len(ids) > 0 && !validEngineList(ids, false)) {
		return nil, aiUnavailable()
	}
	return ids, nil
}

func usageWindow(from, to, now time.Time) (time.Time, time.Time, error) {
	if to.IsZero() {
		to = now
	}
	if from.IsZero() {
		utc := now.UTC()
		from = time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	}
	from, to = from.UTC(), to.UTC()
	if !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return time.Time{}, time.Time{}, apierr.BadRequest("invalid_usage_range", "usage range must be positive and at most 31 days")
	}
	return from, to, nil
}
func validObservedUsage(u Usage) bool {
	return u.TotalRequests >= 0 && u.TotalTokens >= 0 && u.PromptTokens >= 0 && u.CompletionTokens >= 0 && validEngineCost(u.TotalCost) && u.UncostedRequests >= 0 && u.UncostedRequests <= u.TotalRequests
}

// Usage reads the engine's sole native ledger. IDs are tenant-scoped in CP and
// retain historical team attribution. An empty binding set is explicit zero,
// never the engine's unfiltered/all-tenant default. Times default to today UTC.
func (p *Policies) Usage(ctx context.Context, org uuid.UUID, teamID, deviceID *uuid.UUID, from, to time.Time) (Usage, error) {
	if org == uuid.Nil || (teamID != nil && *teamID == uuid.Nil) || (deviceID != nil && *deviceID == uuid.Nil) {
		return Usage{}, apierr.BadRequest("invalid_usage_scope", "invalid AI usage scope")
	}
	from, to, err := usageWindow(from, to, time.Now())
	if err != nil {
		return Usage{}, err
	}
	if p == nil || p.pool == nil {
		return Usage{}, aiUnavailable()
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Usage{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	// Archives/soft deletions do not erase attribution. Existence is scoped to
	// this organization; current active membership is an inference condition.
	if teamID != nil {
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_groups WHERE org_id=$1 AND id=$2)`, org, *teamID).Scan(&exists) != nil {
			return Usage{}, aiUnavailable()
		}
		if !exists {
			return Usage{}, apierr.NotFound("not_found", "AI team not found")
		}
	}
	if deviceID != nil {
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE org_id=$1 AND id=$2 AND kind='agent')`, org, *deviceID).Scan(&exists) != nil {
			return Usage{}, aiUnavailable()
		}
		if !exists {
			return Usage{}, apierr.NotFound("not_found", "AI agent not found")
		}
	}
	ids, err := bindingUsageIDs(ctx, tx, org, teamID, deviceID)
	if err != nil {
		return Usage{}, err
	}
	if tx.Commit(ctx) != nil {
		return Usage{}, aiUnavailable()
	}
	if len(ids) == 0 {
		return Usage{}, nil
	}
	if p.engine == nil {
		return Usage{}, aiUnavailable()
	}
	result, err := p.engine.Usage(ctx, ids, from, to)
	if err != nil || !validObservedUsage(result) {
		return Usage{}, aiUnavailable()
	}
	return result, nil
}

// enforceCost is observational admission, not a reservation or another ledger.
// Concurrent requests may all pass before native async accounting catches up.
// The resolver owns tx and its canonical device lock; this helper never borrows
// another connection, commits that transaction, or changes an accounting row.
func (p *Policies) enforceCost(ctx context.Context, tx pgx.Tx, org, team uuid.UUID, model string, limit *float64) error {
	if limit == nil {
		return nil
	}
	if *limit <= 0 || *limit > 100000 || math.IsNaN(*limit) || math.IsInf(*limit, 0) {
		return apierr.BadRequest("invalid_cost_limit", "daily soft threshold must be positive and at most 100000")
	}
	if p == nil || p.engine == nil || tx == nil || org == uuid.Nil || team == uuid.Nil {
		return aiUnavailable()
	}
	if !strings.HasPrefix(model, "openrouter/") {
		return apierr.Forbidden("ai_price_unavailable", "exact model pricing is required for this policy")
	}
	nativeModel := strings.TrimPrefix(model, "openrouter/")
	if !engineModel.MatchString(nativeModel) {
		return apierr.Forbidden("ai_price_unavailable", "exact model pricing is required for this policy")
	}
	price, err := p.engine.Price(ctx, "openrouter", nativeModel)
	if err != nil {
		return aiUnavailable()
	}
	if !price.Known || price.InputCostPerToken == nil || price.OutputCostPerToken == nil || !validEngineCost(*price.InputCostPerToken) || !validEngineCost(*price.OutputCostPerToken) {
		return apierr.Forbidden("ai_price_unavailable", "exact model pricing is required for this policy")
	}
	ids, err := bindingUsageIDs(ctx, tx, org, &team, nil)
	if err != nil {
		return err
	}
	// An applied assignment must already retain a verified binding. Missing
	// attribution under monetary admission is unavailable, not free usage.
	if len(ids) == 0 {
		return aiUnavailable()
	}
	now := time.Now().UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	observed, err := p.engine.Usage(ctx, ids, day, now)
	if err != nil || !validObservedUsage(observed) || observed.UncostedRequests > 0 {
		return aiUnavailable()
	}
	if observed.TotalCost >= *limit {
		return apierr.Forbidden("ai_daily_threshold_reached", "AI daily soft usage threshold reached")
	}
	return nil
}
