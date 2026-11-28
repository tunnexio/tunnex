package aigateway

import (
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func requireAIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var e *apierr.Error
	if !errors.As(err, &e) || e.Status != status || e.Code != code {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

func floatPtr(v float64) *float64 { return &v }

// A user group's daily cost limit is shared by all members across all of the
// group's grants, and a member of several groups is admitted through any group
// still under its limit (AI-CATALOG-1 decision "Daily cost limit for a user group").
func TestUserGroupDailyCostLimitAdmission(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	const model, second = "openrouter/engineering", "openrouter/second"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "Engineering provider", Models: []string{model, second}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	groupA, groupB := uuid.New(), uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering'),($3,$2,'Research')`, groupA, f.org, groupB)
	onlyA, both := uuid.New(), uuid.New()
	for _, user := range []uuid.UUID{onlyA, both} {
		f.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Engineer',now())`, user, user.String()+"@test.local")
		f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
		f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, groupA, user)
	}
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, groupB, both)
	grant := func(group uuid.UUID, m string) UserModelGrant {
		t.Helper()
		g, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, m, true, 0)
		if err != nil || g.Status != "applied" {
			t.Fatalf("grant: %+v %v", g, err)
		}
		return g
	}
	gA, gB, gA2 := grant(groupA, model), grant(groupB, model), grant(groupA, second)
	keyOf := func(g UserModelGrant) string {
		t.Helper()
		value, err := openBoundKey(f.policies.sealer, userGrantKeyPurpose, f.org, g.ID, g.native, g.bindingRevision, g.sealed)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	spend := map[string]float64{}
	var usageErr error
	engine.usageFor = func(ids []string) (float64, error) {
		if usageErr != nil {
			return 0, usageErr
		}
		total := 0.0
		for _, id := range ids {
			total += spend[id]
		}
		return total, nil
	}
	admittedVia := func(user uuid.UUID, want UserModelGrant) {
		t.Helper()
		g, err := f.policies.ResolveUserModel(ctx, f.org, user, model)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if g.VirtualKey != keyOf(want) {
			t.Fatalf("admitted through the wrong group's grant")
		}
	}
	setLimit := func(group uuid.UUID, limit *float64) UserGroup {
		t.Helper()
		var current int64
		groups, err := f.policies.ListUserGroups(ctx, f.org)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range groups {
			if g.ID == group {
				current = g.LimitRevision
			}
		}
		g, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, limit, current)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}

	// No limit: spend does not matter.
	spend[gA.native] = 1000
	admittedVia(onlyA, gA)

	// Under the limit is admitted; at and over it is refused with the threshold error.
	setLimit(groupA, floatPtr(5))
	spend[gA.native] = 4.99
	admittedVia(onlyA, gA)
	spend[gA.native] = 5
	_, err = f.policies.ResolveUserModel(ctx, f.org, onlyA, model)
	requireDailyThreshold(t, err)
	spend[gA.native] = 7
	_, err = f.policies.ResolveUserModel(ctx, f.org, onlyA, model)
	requireDailyThreshold(t, err)

	// A member of a second group with the same model is admitted through it.
	admittedVia(both, gB)

	// The second group under its own limit admits; over it, the threshold error wins over a denial.
	setLimit(groupB, floatPtr(2))
	spend[gB.native] = 1
	admittedVia(both, gB)
	spend[gB.native] = 2
	_, err = f.policies.ResolveUserModel(ctx, f.org, both, model)
	requireDailyThreshold(t, err)

	// The limit is shared across all of the group's grants, revoked ones included.
	spend[gA.native], spend[gB.native] = 0, 0
	admittedVia(onlyA, gA)
	revoked, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, groupA, p.ID, second, false, gA2.Revision)
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("revoke: %+v %v", revoked, err)
	}
	spend[gA2.native] = 5
	_, err = f.policies.ResolveUserModel(ctx, f.org, onlyA, model)
	requireDailyThreshold(t, err)
	spend[gA2.native] = 0

	// Groups without a limit are tried first, so they do not use up a limited group's budget.
	setLimit(groupB, nil)
	admittedVia(both, gB)
	setLimit(groupB, floatPtr(50))
	setLimit(groupA, nil)
	admittedVia(both, gA)
	setLimit(groupA, floatPtr(5))

	// "My models" keeps listing a model while its group is over the limit.
	spend[gA.native] = 9
	models, err := f.policies.UserModels(ctx, f.org, onlyA)
	if err != nil || !slices.ContainsFunc(models, func(m UserModel) bool { return m.Model == model }) {
		t.Fatalf("over-limit model hidden from my models: %+v %v", models, err)
	}
	spend[gA.native] = 0

	// Unknown pricing blocks a limited group only.
	engine.unpriced = true
	_, err = f.policies.ResolveUserModel(ctx, f.org, onlyA, model)
	requireAIError(t, err, 403, "ai_price_unavailable")
	setLimit(groupB, nil)
	admittedVia(both, gB)

	// A usage read that fails for one group moves on to the next candidate.
	engine.unpriced = false
	usageErr = errors.New("private usage failure")
	_, err = f.policies.ResolveUserModel(ctx, f.org, onlyA, model)
	requireAIError(t, err, 503, "ai_gateway_unavailable")
	admittedVia(both, gB)
	usageErr = nil

	// Precedence when every candidate is blocked: the threshold error wins over a failed usage read.
	setLimit(groupB, floatPtr(50))
	spend[gA.native] = 5
	engine.usageFor = func(ids []string) (float64, error) {
		total := 0.0
		for _, id := range ids {
			if id == gB.native {
				return 0, errors.New("private usage failure")
			}
			total += spend[id]
		}
		return total, nil
	}
	_, err = f.policies.ResolveUserModel(ctx, f.org, both, model)
	requireDailyThreshold(t, err)

	// Deleting the group removes its limit.
	f.exec(`DELETE FROM user_groups WHERE org_id=$1 AND id=$2`, f.org, groupB)
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ai_user_group_cost_limits WHERE org_id=$1 AND group_id=$2`, f.org, groupB).Scan(&n); err != nil || n != 0 {
		t.Fatalf("deleted group kept its limit: %d %v", n, err)
	}
}

func TestPutUserGroupCostLimit(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	other := newPolicyFixture(t, ctx, pool)
	group, foreign := uuid.New(), uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, f.org)
	other.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Elsewhere')`, foreign, other.org)

	for _, bad := range []float64{0, -1, 100000.01, math.NaN(), math.Inf(1)} {
		_, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(bad), 0)
		requireAIError(t, err, 400, "invalid_ai_policy")
	}
	_, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), -1)
	requireAIError(t, err, 400, "invalid_ai_policy")
	_, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, foreign, floatPtr(5), 0)
	requireAIError(t, err, 404, "ai_policy_not_found")
	_, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, uuid.New(), floatPtr(5), 0)
	requireAIError(t, err, 404, "ai_policy_not_found")
	_, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), 1)
	requireAIError(t, err, 409, "ai_policy_revision_conflict")

	g, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(100000), 0)
	if err != nil || g.LimitRevision != 1 || g.DailyUsdThreshold == nil || *g.DailyUsdThreshold != 100000 || g.Name != "Engineering" || g.ID != group {
		t.Fatalf("set: %+v %v", g, err)
	}
	_, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(3), 0)
	requireAIError(t, err, 409, "ai_policy_revision_conflict")
	g, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), 1)
	if err != nil || g.LimitRevision != 2 || *g.DailyUsdThreshold != 5 {
		t.Fatalf("update: %+v %v", g, err)
	}
	g, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, nil, 2)
	if err != nil || g.LimitRevision != 3 || g.DailyUsdThreshold != nil {
		t.Fatalf("remove: %+v %v", g, err)
	}
	// Removing keeps the revision moving forward, so an editor that saw no limit is stale.
	_, err = f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), 0)
	requireAIError(t, err, 409, "ai_policy_revision_conflict")

	groups, err := f.policies.ListUserGroups(ctx, f.org)
	if err != nil || len(groups) != 1 || groups[0].LimitRevision != 3 || groups[0].DailyUsdThreshold != nil {
		t.Fatalf("list: %+v %v", groups, err)
	}
	if _, err := f.policies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(7.5), 3); err != nil {
		t.Fatal(err)
	}
	groups, err = f.policies.ListUserGroups(ctx, f.org)
	if err != nil || groups[0].LimitRevision != 4 || groups[0].DailyUsdThreshold == nil || *groups[0].DailyUsdThreshold != 7.5 {
		t.Fatalf("list after set: %+v %v", groups, err)
	}
	otherGroups, err := other.policies.ListUserGroups(ctx, other.org)
	if err != nil || len(otherGroups) != 1 || otherGroups[0].LimitRevision != 0 || otherGroups[0].DailyUsdThreshold != nil {
		t.Fatalf("limit leaked to another organization: %+v %v", otherGroups, err)
	}

	rows, err := pool.Query(ctx, `SELECT actor_user_id,target_type,(metadata->>'revision')::bigint,metadata->'daily_usd_threshold' FROM audit_logs WHERE org_id=$1 AND action='ai_user_group.cost_limit_changed' AND target_id=$2 ORDER BY (metadata->>'revision')::bigint`, f.org, group.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := []string{"100000", "5", "null", "7.5"}
	i := 0
	for rows.Next() {
		var actor uuid.UUID
		var targetType, value string
		var revision int64
		if err := rows.Scan(&actor, &targetType, &revision, &value); err != nil {
			t.Fatal(err)
		}
		if i >= len(want) || actor != f.owner || targetType != "ai_policy" || revision != int64(i+1) || value != want[i] {
			t.Fatalf("audit %d: %v %s %d %s", i, actor, targetType, revision, value)
		}
		i++
	}
	if rows.Err() != nil || i != len(want) {
		t.Fatalf("audit entries: %d %v", i, rows.Err())
	}

	var nilPolicies *Policies
	_, err = nilPolicies.PutUserGroupCostLimit(ctx, f.org, f.owner, group, floatPtr(5), 0)
	requireAIError(t, err, 503, "ai_gateway_unavailable")
}
