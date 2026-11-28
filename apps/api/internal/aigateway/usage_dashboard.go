package aigateway

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type dashboardEngine interface {
	Dashboard(context.Context, []string, time.Time, time.Time) (EngineDashboard, error)
}
type usageBinding struct {
	human               bool
	workload            bool
	staticKey           *api.AIUsageWorkloadKey
	native              string
	team, agent         uuid.UUID
	teamName, agentName string
}

// UsageDashboard joins native accounting to retained request-time attribution.
// No native key IDs or names cross the customer API boundary.
func (p *Policies) UsageDashboard(ctx context.Context, org uuid.UUID, team, device *uuid.UUID, from, to time.Time) (Usage, api.AIUsageDashboard, error) {
	empty := emptyDashboard()
	if org == uuid.Nil || (team != nil && *team == uuid.Nil) || (device != nil && *device == uuid.Nil) {
		return Usage{}, empty, apierr.BadRequest("invalid_usage_scope", "invalid AI usage scope")
	}
	from, to, err := usageWindow(from, to, time.Now())
	if err != nil {
		return Usage{}, empty, err
	}
	if p == nil || p.pool == nil {
		return Usage{}, empty, aiUnavailable()
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Usage{}, empty, aiUnavailable()
	}
	defer rollbackAI(tx)
	if team != nil {
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_groups WHERE org_id=$1 AND id=$2)`, org, *team).Scan(&exists) != nil {
			return Usage{}, empty, aiUnavailable()
		}
		if !exists {
			return Usage{}, empty, apierr.NotFound("not_found", "AI team not found")
		}
	}
	if device != nil {
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE org_id=$1 AND id=$2 AND kind='agent')`, org, *device).Scan(&exists) != nil {
			return Usage{}, empty, aiUnavailable()
		}
		if !exists {
			return Usage{}, empty, apierr.NotFound("not_found", "AI agent not found")
		}
	}
	rows, err := tx.Query(ctx, `SELECT b.native_key_id,b.team_id,b.device_id,g.name,d.name,false,false
 FROM ai_gateway_key_bindings b
 JOIN agent_groups g ON g.org_id=b.org_id AND g.id=b.team_id
 JOIN devices d ON d.org_id=b.org_id AND d.id=b.device_id AND d.kind='agent'
 WHERE b.org_id=$1 AND ($2::uuid IS NULL OR b.team_id=$2) AND ($3::uuid IS NULL OR b.device_id=$3)
 UNION ALL SELECT native_key_id,group_ref,group_ref,group_name,group_name,true,false FROM ai_user_model_grants
 WHERE org_id=$1 AND $2::uuid IS NULL AND $3::uuid IS NULL AND native_key_id<>''
 UNION ALL SELECT native_key_id,id,id,name,name,false,true FROM ai_workloads WHERE org_id=$1 AND $2::uuid IS NULL AND $3::uuid IS NULL AND native_key_id<>''
 ORDER BY 1 LIMIT 65`, org, team, device)
	if err != nil {
		return Usage{}, empty, aiUnavailable()
	}
	bindings := []usageBinding{}
	ids := []string{}
	for rows.Next() {
		var b usageBinding
		if rows.Scan(&b.native, &b.team, &b.agent, &b.teamName, &b.agentName, &b.human, &b.workload) != nil {
			rows.Close()
			return Usage{}, empty, aiUnavailable()
		}
		bindings = append(bindings, b)
		ids = append(ids, b.native)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) > maxAIUsageBindings || (len(ids) > 0 && !validEngineList(ids, false)) {
		return Usage{}, empty, aiUnavailable()
	}
	if team == nil && device == nil {
		// AI-KEYS-1: static keys active at any time in the window roll up into
		// their workload row and get their own attribution row.
		if bindings, ids, err = appendStaticKeyBindings(ctx, tx, org, bindings, ids, from, to); err != nil {
			return Usage{}, empty, err
		}
	}
	if tx.Commit(ctx) != nil {
		return Usage{}, empty, aiUnavailable()
	}
	if len(ids) == 0 {
		return Usage{}, empty, nil
	}
	engine, ok := p.engine.(dashboardEngine)
	if !ok {
		return Usage{}, empty, aiUnavailable()
	}
	native, err := dashboardBatched(ctx, engine, ids, from, to)
	if err != nil || !validObservedUsage(native.Usage) {
		return Usage{}, empty, aiUnavailable()
	}
	groups := map[uuid.UUID]api.AIUsageAttribution{}
	workloads := map[uuid.UUID]api.AIUsageAttribution{}
	teams := map[uuid.UUID]api.AIUsageAttribution{}
	agents := map[uuid.UUID]api.AIUsageAttribution{}
	known := map[string]bool{}
	for _, b := range bindings {
		known[b.native] = true
	}
	for id := range native.Keys {
		if !known[id] {
			return Usage{}, empty, aiUnavailable()
		}
	}
	keyRows := []api.AIUsageWorkloadKey{}
	for _, b := range bindings {
		v := native.Keys[b.native]
		if b.staticKey != nil {
			r := *b.staticKey
			if !addCount(&r.Requests, v.Requests) || !addCount(&r.Tokens, v.Tokens) || !addCount(&r.UncostedRequests, v.UncostedRequests) || !addCost(&r.Cost, v.Cost) {
				return Usage{}, empty, aiUnavailable()
			}
			keyRows = append(keyRows, r)
		}
		targets := []struct {
			m    map[uuid.UUID]api.AIUsageAttribution
			id   uuid.UUID
			name string
		}{{teams, b.team, b.teamName}, {agents, b.agent, b.agentName}}
		if b.human {
			targets = targets[:1]
			targets[0].m = groups
		}
		if b.workload {
			targets = targets[:1]
			targets[0].m = workloads
		}
		for _, target := range targets {
			r := target.m[target.id]
			r.Id = target.id
			r.Name = target.name
			if !addCount(&r.Requests, v.Requests) || !addCount(&r.Tokens, v.Tokens) || !addCount(&r.UncostedRequests, v.UncostedRequests) || !addCost(&r.Cost, v.Cost) {
				return Usage{}, empty, aiUnavailable()
			}
			target.m[target.id] = r
		}
	}
	for _, v := range teams {
		native.Dashboard.Teams = append(native.Dashboard.Teams, v)
	}
	for _, v := range agents {
		native.Dashboard.Agents = append(native.Dashboard.Agents, v)
	}
	groupRows := []api.AIUsageAttribution{}
	for _, v := range groups {
		groupRows = append(groupRows, v)
	}
	sortAttribution(groupRows)
	native.Dashboard.UserGroups = &groupRows
	workloadRows := []api.AIUsageAttribution{}
	for _, v := range workloads {
		workloadRows = append(workloadRows, v)
	}
	sortAttribution(workloadRows)
	native.Dashboard.Workloads = &workloadRows
	if team == nil && device == nil {
		sort.Slice(keyRows, func(i, j int) bool {
			if keyRows[i].Cost != keyRows[j].Cost {
				return keyRows[i].Cost > keyRows[j].Cost
			}
			return keyRows[i].Id.String() < keyRows[j].Id.String()
		})
		native.Dashboard.WorkloadKeys = &keyRows
	}
	sortAttribution(native.Dashboard.Teams)
	sortAttribution(native.Dashboard.Agents)
	return native.Usage, native.Dashboard, nil
}
func sortAttribution(rows []api.AIUsageAttribution) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Cost != rows[j].Cost {
			return rows[i].Cost > rows[j].Cost
		}
		return rows[i].Id.String() < rows[j].Id.String()
	})
}

func appendStaticKeyBindings(ctx context.Context, tx pgx.Tx, org uuid.UUID, bindings []usageBinding, ids []string, from, to time.Time) ([]usageBinding, []string, error) {
	rows, err := tx.Query(ctx, `SELECT k.native_key_id,k.id,k.name,k.scope,w.id,w.name FROM ai_workload_static_keys k
 JOIN ai_workloads w ON w.org_id=k.org_id AND w.id=k.workload_id
 WHERE k.org_id=$1 AND k.native_key_id<>'' AND k.created_at<$3::timestamptz+interval '1 hour' AND least(k.revoked_at,k.expires_at)>$2::timestamptz-interval '1 hour'
 ORDER BY 1 LIMIT 4097`, org, from, to)
	if err != nil {
		return nil, nil, aiUnavailable()
	}
	defer rows.Close()
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	count := 0
	for rows.Next() {
		var b usageBinding
		var key api.AIUsageWorkloadKey
		var scope string
		if rows.Scan(&b.native, &key.Id, &key.Name, &scope, &b.team, &b.teamName) != nil {
			return nil, nil, aiUnavailable()
		}
		count++
		if seen[b.native] {
			return nil, nil, aiUnavailable()
		}
		seen[b.native] = true
		key.WorkloadId, key.Scope = b.team, api.AIWorkloadStaticKeyScope(scope)
		b.agent, b.agentName, b.workload, b.staticKey = b.team, b.teamName, true, &key
		bindings = append(bindings, b)
		ids = append(ids, b.native)
	}
	if rows.Err() != nil || count > 4096 || (len(ids) > 0 && !validEngineIDs(ids)) {
		return nil, nil, aiUnavailable()
	}
	return bindings, ids, nil
}

// dashboardBatched asks the engine in batches of at most 64 ids and merges
// the results. Up to 64 ids it is exactly one engine call.
func dashboardBatched(ctx context.Context, engine dashboardEngine, ids []string, from, to time.Time) (EngineDashboard, error) {
	if len(ids) <= maxAIUsageBindings {
		return engine.Dashboard(ctx, ids, from, to)
	}
	out := EngineDashboard{Dashboard: emptyDashboard(), Keys: map[string]api.AIUsageAttribution{}}
	days := map[string]*api.AIUsageDay{}
	models := map[string]float64{}
	for start := 0; start < len(ids); start += maxAIUsageBindings {
		end := min(start+maxAIUsageBindings, len(ids))
		part, err := engine.Dashboard(ctx, ids[start:end], from, to)
		if err != nil || !validObservedUsage(part.Usage) {
			return EngineDashboard{}, aiUnavailable()
		}
		u := &out.Usage
		d := &out.Dashboard
		if !addCount(&u.TotalRequests, part.Usage.TotalRequests) || !addCount(&u.TotalTokens, part.Usage.TotalTokens) || !addCount(&u.PromptTokens, part.Usage.PromptTokens) ||
			!addCount(&u.CompletionTokens, part.Usage.CompletionTokens) || !addCount(&u.UncostedRequests, part.Usage.UncostedRequests) || !addCost(&u.TotalCost, part.Usage.TotalCost) ||
			!addCount(&d.SuccessfulRequests, part.Dashboard.SuccessfulRequests) || !addCount(&d.FailedRequests, part.Dashboard.FailedRequests) || !addCount(&d.CancelledRequests, part.Dashboard.CancelledRequests) {
			return EngineDashboard{}, aiUnavailable()
		}
		for id, v := range part.Keys {
			if _, dup := out.Keys[id]; dup {
				return EngineDashboard{}, aiUnavailable()
			}
			out.Keys[id] = v
		}
		for _, day := range part.Dashboard.Daily {
			acc, ok := days[day.Date]
			if !ok {
				acc = &api.AIUsageDay{Date: day.Date}
				days[day.Date] = acc
			}
			if !addCount(&acc.Requests, day.Requests) || !addCount(&acc.Tokens, day.Tokens) || !addCount(&acc.UncostedRequests, day.UncostedRequests) || !addCost(&acc.Cost, day.Cost) {
				return EngineDashboard{}, aiUnavailable()
			}
		}
		for _, m := range part.Dashboard.Models {
			total := models[m.Name]
			if !addCost(&total, m.Cost) {
				return EngineDashboard{}, aiUnavailable()
			}
			models[m.Name] = total
		}
	}
	for _, day := range days {
		out.Dashboard.Daily = append(out.Dashboard.Daily, *day)
	}
	sort.Slice(out.Dashboard.Daily, func(i, j int) bool { return out.Dashboard.Daily[i].Date < out.Dashboard.Daily[j].Date })
	for name, cost := range models {
		out.Dashboard.Models = append(out.Dashboard.Models, api.AIUsageModel{Name: name, Cost: cost})
	}
	sort.Slice(out.Dashboard.Models, func(i, j int) bool {
		a, b := out.Dashboard.Models[i], out.Dashboard.Models[j]
		if a.Cost != b.Cost {
			return a.Cost > b.Cost
		}
		return a.Name < b.Name
	})
	return out, nil
}
