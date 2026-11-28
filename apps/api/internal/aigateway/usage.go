package aigateway

import (
	"context"
	"math"
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
	ids, err := bindingUsageIDsBase(ctx, tx, org, team, device)
	if err != nil || team != nil || device != nil {
		return ids, err
	}
	return appendStaticKeyUsageIDs(ctx, tx, org, ids, time.Time{}, time.Time{})
}

// appendStaticKeyUsageIDs adds the engine ids of static keys active at any
// time in [from,to) (AI-KEYS-1). A zero window means every key ever created,
// for callers that do not pass a window. Only org-wide usage includes them.
func appendStaticKeyUsageIDs(ctx context.Context, tx pgx.Tx, org uuid.UUID, ids []string, from, to time.Time) ([]string, error) {
	var rows pgx.Rows
	var err error
	if from.IsZero() || to.IsZero() {
		rows, err = tx.Query(ctx, `SELECT native_key_id FROM ai_workload_static_keys WHERE org_id=$1 AND native_key_id<>'' ORDER BY native_key_id LIMIT 4097`, org)
	} else {
		rows, err = tx.Query(ctx, `SELECT native_key_id FROM ai_workload_static_keys WHERE org_id=$1 AND native_key_id<>'' AND created_at<$3::timestamptz+interval '1 hour' AND least(revoked_at,expires_at)>$2::timestamptz-interval '1 hour' ORDER BY native_key_id LIMIT 4097`, org, from, to)
	}
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	added := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, aiUnavailable()
		}
		added++
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if rows.Err() != nil || added > 4096 || len(ids) > 0 && !validEngineIDs(ids) {
		return nil, aiUnavailable()
	}
	return ids, nil
}

func bindingUsageIDsBase(ctx context.Context, tx pgx.Tx, org uuid.UUID, team, device *uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT native_key_id FROM ai_gateway_key_bindings
 WHERE org_id=$1 AND ($2::uuid IS NULL OR team_id=$2) AND ($3::uuid IS NULL OR device_id=$3)
 UNION SELECT native_key_id FROM ai_user_model_grants WHERE org_id=$1 AND $2::uuid IS NULL AND $3::uuid IS NULL AND native_key_id<>''
 UNION SELECT native_key_id FROM ai_workloads WHERE org_id=$1 AND $2::uuid IS NULL AND $3::uuid IS NULL AND native_key_id<>''
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
	ids, err := bindingUsageIDsBase(ctx, tx, org, teamID, deviceID)
	if err != nil {
		return Usage{}, err
	}
	if teamID == nil && deviceID == nil {
		if ids, err = appendStaticKeyUsageIDs(ctx, tx, org, ids, from, to); err != nil {
			return Usage{}, err
		}
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
	result, err := engineUsageBatched(ctx, p.engine, ids, from, to)
	if err != nil || !validObservedUsage(result) {
		return Usage{}, aiUnavailable()
	}
	return result, nil
}

// engineUsageBatched asks the engine in batches of at most 64 ids and sums the
// results. Up to 64 ids it is exactly one engine call, as before AI-KEYS-1.
// Any failed or invalid batch fails the whole query.
func engineUsageBatched(ctx context.Context, engine PolicyEngine, ids []string, from, to time.Time) (Usage, error) {
	if len(ids) <= maxAIUsageBindings {
		return engine.Usage(ctx, ids, from, to)
	}
	var total Usage
	for start := 0; start < len(ids); start += maxAIUsageBindings {
		end := min(start+maxAIUsageBindings, len(ids))
		part, err := engine.Usage(ctx, ids[start:end], from, to)
		if err != nil || !validObservedUsage(part) {
			return Usage{}, aiUnavailable()
		}
		if !addCount(&total.TotalRequests, part.TotalRequests) || !addCount(&total.TotalTokens, part.TotalTokens) || !addCount(&total.PromptTokens, part.PromptTokens) ||
			!addCount(&total.CompletionTokens, part.CompletionTokens) || !addCount(&total.UncostedRequests, part.UncostedRequests) || !addCost(&total.TotalCost, part.TotalCost) {
			return Usage{}, aiUnavailable()
		}
	}
	return total, nil
}

// enforceCost is observational admission, not a reservation or another ledger.
// Concurrent requests may all pass before native async accounting catches up.
// The resolver owns tx and its canonical device lock; this helper never borrows
// another connection, commits that transaction, or changes an accounting row.
func (p *Policies) enforceCost(ctx context.Context, tx pgx.Tx, org, team uuid.UUID, model string, limit *float64) error {
	return p.enforceCostMode(ctx, tx, org, team, model, ModeChat, limit)
}
func (p *Policies) enforceCostMode(ctx context.Context, tx pgx.Tx, org, team uuid.UUID, model string, mode ModelMode, limit *float64) error {
	return p.enforceCostFor(ctx, tx, org, costSubject{Kind: "agent_group", ID: team}, model, mode, limit, func() ([]string, error) {
		if team == uuid.Nil {
			return nil, aiUnavailable()
		}
		return bindingUsageIDs(ctx, tx, org, &team, nil)
	})
}

// enforceCostBindings keeps its signature for callers without a named subject;
// an unknown-price alert then cannot name one and is not raised.
func (p *Policies) enforceCostBindings(ctx context.Context, tx pgx.Tx, org uuid.UUID, model string, mode ModelMode, limit *float64, bindings func() ([]string, error)) error {
	return p.enforceCostFor(ctx, tx, org, costSubject{}, model, mode, limit, bindings)
}

// enforceCostFor applies a daily limit. The price is an engine-confirmed
// operator price, else the bundled exact price. Without one, the
// organization's unknown-price policy decides: Block (default) refuses with
// ai_price_unavailable and fails closed on uncosted observed usage; Allow and
// alert admits, compares only the costed spend with the limit, and raises
// ai.price_unknown once per subject, model and UTC day.
func (p *Policies) enforceCostFor(ctx context.Context, tx pgx.Tx, org uuid.UUID, subject costSubject, model string, mode ModelMode, limit *float64, bindings func() ([]string, error)) error {
	if limit == nil {
		return nil
	}
	if *limit <= 0 || *limit > 100000 || math.IsNaN(*limit) || math.IsInf(*limit, 0) {
		return apierr.BadRequest("invalid_cost_limit", "daily soft threshold must be positive and at most 100000")
	}
	if p == nil || p.engine == nil || tx == nil || org == uuid.Nil {
		return aiUnavailable()
	}
	provider, nativeModel, valid := splitProviderModel(model)
	if !valid {
		return apierr.Forbidden("ai_price_unavailable", "exact model pricing is required for this policy")
	}
	allowUnknown, err := unknownPriceAllowed(ctx, tx, org)
	if err != nil {
		return aiUnavailable()
	}
	priced := false
	if mode == ModeChat || mode == ModeCompletion || mode == ModeEmbedding {
		price, err := p.admissionPrice(ctx, tx, org, provider, nativeModel)
		if err != nil {
			return aiUnavailable()
		}
		inputReady := price.InputCostPerToken != nil && validEngineCost(*price.InputCostPerToken)
		outputReady := price.OutputCostPerToken != nil && validEngineCost(*price.OutputCostPerToken)
		priced = inputReady && (mode == ModeEmbedding || (price.Known && outputReady))
	}
	if !priced && !allowUnknown {
		if mode != ModeChat && mode != ModeCompletion && mode != ModeEmbedding {
			return apierr.Forbidden("ai_price_unavailable", "mode-specific pricing is required for this policy")
		}
		return apierr.Forbidden("ai_price_unavailable", "exact model pricing is required for this policy")
	}
	ids, err := bindings()
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
	observed, err := engineUsageBatched(ctx, p.engine, ids, day, now)
	if err != nil || !validObservedUsage(observed) || (observed.UncostedRequests > 0 && !allowUnknown) {
		return aiUnavailable()
	}
	if observed.TotalCost >= *limit {
		return apierr.Forbidden("ai_daily_threshold_reached", "AI daily soft usage threshold reached")
	}
	if !priced {
		p.notifyUnknownPrice(org, subject, model)
	}
	return nil
}

// validEngineIDs is validEngineList without the 64-id bound, for lists that
// are sent to the engine in batches (AI-KEYS-1).
func validEngineIDs(values []string) bool {
	if len(values) == 0 || len(values) > 8192 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !engineIdentifier.MatchString(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
