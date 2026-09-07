package aigateway

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"strings"
	"testing"
	"time"
)

type dashboardFixture struct {
	PolicyEngine
	fn func([]string) (EngineDashboard, error)
}

func (f dashboardFixture) Dashboard(_ context.Context, ids []string, _, _ time.Time) (EngineDashboard, error) {
	return f.fn(ids)
}
func TestAIUsageDashboardHistoricalAttribution(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newAICredentialFixture(t, ctx, pool)
	other := newAICredentialFixture(t, ctx, pool)
	empty := newAICredentialFixture(t, ctx, pool)
	old, current, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		org, device, team uuid.UUID
		key, name         string
	}{{f.org, f.device, old, "native-old", "Old team"}, {f.org, f.device, current, "native-current", "Current team"}, {other.org, other.device, foreign, "native-foreign", "Foreign team"}} {
		f.exec(`INSERT INTO agent_groups(id,org_id,name) VALUES($1,$2,$3)`, row.team, row.org, row.name)
		f.exec(`INSERT INTO ai_gateway_team_policies(org_id,team_id,models,key_ids,revision) VALUES($1,$2,'{openrouter/model}','{provider-key}',1)`, row.org, row.team)
		f.exec(`INSERT INTO ai_gateway_key_bindings(org_id,device_id,team_id,native_key_id,sealed_key,binding_revision) VALUES($1,$2,$3,$4,'fixture',1)`, row.org, row.device, row.team, row.key)
	}
	f.exec(`UPDATE agent_groups SET archived_at=now() WHERE id=$1`, old)
	calls := 0
	service := &Policies{pool: pool, engine: dashboardFixture{fn: func(ids []string) (EngineDashboard, error) {
		calls++
		out := EngineDashboard{Dashboard: emptyDashboard(), Keys: map[string]api.AIUsageAttribution{}}
		for _, id := range ids {
			if id == "native-foreign" {
				t.Fatal("foreign key reached native query")
			}
			out.Keys[id] = api.AIUsageAttribution{Requests: 1, Tokens: 7, Cost: 0.01}
			out.Usage.TotalRequests++
		}
		return out, nil
	}}}
	_, d, err := service.UsageDashboard(ctx, f.org, nil, nil, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Teams) != 2 || len(d.Agents) != 1 || d.Agents[0].Id != f.device || d.Agents[0].Requests != 2 {
		t.Fatalf("historical attribution lost: %+v", d)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "native-") {
		t.Fatal("native ID leaked")
	}
	_, d, err = service.UsageDashboard(ctx, f.org, &old, &f.device, time.Time{}, time.Time{})
	if err != nil || len(d.Teams) != 1 || d.Teams[0].Name != "Old team" || d.Teams[0].Id != old {
		t.Fatalf("archived team history lost: %v", err)
	}
	before := calls
	for _, scope := range []struct{ team, agent *uuid.UUID }{{&foreign, nil}, {nil, &other.device}} {
		if _, _, err := service.UsageDashboard(ctx, f.org, scope.team, scope.agent, time.Time{}, time.Time{}); usageStatus(err) != 404 {
			t.Fatal("foreign selector accepted")
		}
	}
	u, d, err := service.UsageDashboard(ctx, empty.org, nil, nil, time.Time{}, time.Time{})
	if err != nil || u.TotalRequests != 0 || len(d.Teams) != 0 || calls != before {
		t.Fatal("empty/foreign scope reached engine")
	}
}
