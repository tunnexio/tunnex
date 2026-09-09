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
	native, err := engine.Dashboard(ctx, ids, from, to)
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
	for _, b := range bindings {
		v := native.Keys[b.native]
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
