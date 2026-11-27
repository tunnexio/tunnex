package http

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	policyservice "github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TestAgentOwnerAccessPostgres proves the Access tab contract on a real database: the summary lists what
// reaches the agent, the preview creates nothing, create makes only the chosen rules and never a second
// rule for a covered destination, and neither another organization nor an agent without an owner gets
// candidates.
func TestAgentOwnerAccessPostgres(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for the AI-UX-1 access integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, otherOrg, owner, admin, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	userGroup, agentGroup, direct, viaGroup, groupReach, site := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	count := func(stmt string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, stmt, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i, id := range []uuid.UUID{org, otherOrg} {
		exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'AIUX1 access',$2,$3)`, id, "aiux1-acc-"+id.String()[:8], []string{"10.98.0.0/24", "10.97.0.0/24"}[i])
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{org, otherOrg})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{owner, admin})
	})
	for _, user := range []uuid.UUID{owner, admin} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, user, user.String()+"@aiux1.example")
	}
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, owner)
	exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'admin')`, org, admin)
	exec(`INSERT INTO nodes (id,org_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,'aiux1-gw','active',$3,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820',now())`, node, org, "aiux1-cert-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'aiux1-agent','linux',$5,'10.98.0.7','active','agent')`, device, org, owner, node, "aiux1-key-"+device.String())
	exec(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'Engineering')`, userGroup, org)
	exec(`INSERT INTO group_members (org_id,group_id,user_id) VALUES ($1,$2,$3)`, org, userGroup, owner)
	exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'Builders')`, agentGroup, org)
	exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, org, agentGroup, device, admin)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'direct','10.98.1.0/24','tcp',443,443)`, direct, org)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'via-group','10.98.2.0/24','any')`, viaGroup, org)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'group-reach','10.98.3.0/24','any')`, groupReach, org)
	exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'office')`, site, org)
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES ($1,'user',$2,'resource',$3)`, org, owner, direct)
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_group_id,dst_kind,dst_resource_id) VALUES ($1,'group',$2,'resource',$3)`, org, userGroup, viaGroup)
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_user_id,dst_kind,dst_site_id) VALUES ($1,'user',$2,'site',$3)`, org, owner, site)
	// The owner also reaches group-reach, which the agent already reaches through its agent group.
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES ($1,'user',$2,'resource',$3)`, org, owner, groupReach)
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_agent_group_id,dst_kind,dst_resource_id) VALUES ($1,'agent_group',$2,'resource',$3)`, org, agentGroup, groupReach)
	// An expired owner rule and a refusal for the summary.
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'expired','10.98.4.0/24','any')`, uuid.New(), org)
	exec(`INSERT INTO policy_rules (org_id,src_kind,src_user_id,dst_kind,dst_resource_id,expires_at) SELECT $1,'user',$2,'resource',id,now()-interval '1 minute' FROM resources WHERE org_id=$1 AND name='expired'`, org, owner)
	exec(`INSERT INTO access_events (org_id,seq,occurred_at,decision,src_device_id,src_user_id,src_ip,dst_ip,protocol,dst_port,src_kind) VALUES ($1,1,now(),'deny',$2,$3,'10.98.0.7','10.98.9.9','tcp',5432,'agent')`, org, device, owner)
	exec(`INSERT INTO access_events (org_id,seq,occurred_at,decision,src_device_id,src_user_id,src_ip,dst_ip,protocol,dst_port,src_kind,deny_count) VALUES ($1,2,now(),'deny_aggregate',$2,$3,'10.98.0.7','10.98.9.9','tcp',5432,'agent',9)`, org, device, owner)

	q := sqlc.New(pool)
	s := apiServer{system: q, policy: policyservice.NewService(pool), devices: devices.NewService(pool, nil, nil)}
	as := func(user uuid.UUID, in uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{in: role}})
	}
	adminCtx := as(admin, org, rbac.RoleAdmin)
	rules := func() int { return count(`SELECT count(*) FROM policy_rules WHERE org_id=$1`, org) }
	audits := func() int { return count(`SELECT count(*) FROM audit_logs WHERE org_id=$1`, org) }
	preview := func() api.AgentOwnerAccessPreview {
		t.Helper()
		res, err := s.PreviewAgentOwnerAccess(adminCtx, api.PreviewAgentOwnerAccessRequestObject{OrgId: org, DeviceId: device})
		if err != nil {
			t.Fatal(err)
		}
		return res.(api.PreviewAgentOwnerAccess200JSONResponse).Body
	}
	create := func(c context.Context, in uuid.UUID, keys ...string) (api.CreateAgentRulesFromOwnerAccessResponseObject, error) {
		return s.CreateAgentRulesFromOwnerAccess(c, api.CreateAgentRulesFromOwnerAccessRequestObject{OrgId: in, DeviceId: device, Body: &api.CreateAgentRulesFromOwnerAccessRequest{Keys: keys}})
	}
	summary := func() api.AgentAccessSummary {
		t.Helper()
		res, err := s.GetAgentAccessSummary(adminCtx, api.GetAgentAccessSummaryRequestObject{OrgId: org, DeviceId: device})
		if err != nil {
			t.Fatal(err)
		}
		return res.(api.GetAgentAccessSummary200JSONResponse).Body
	}

	// Summary before anything is created: only the agent group rule; refusals need the access log.
	before := summary()
	if len(before.Rules) != 1 || before.Rules[0].Via != api.AgentAccessRuleViaAgentGroup || before.Rules[0].GroupName == nil || *before.Rules[0].GroupName != "Builders" || before.Rules[0].Destination.Name != "group-reach" {
		t.Fatalf("summary rules: %+v", before.Rules)
	}
	if before.Refusals.Available || before.Refusals.RequiredPlan == nil || *before.Refusals.RequiredPlan == "" || len(before.Refusals.Items) != 0 {
		t.Fatalf("without the access log refusals must be unavailable and name the plan: %+v", before.Refusals)
	}
	s.accessLog = NewAccessLogPort(pool, accesslog.NewHealth())
	withLog := summary().Refusals
	if !withLog.Available || withLog.RequiredPlan != nil || len(withLog.Items) != 1 || withLog.Items[0].Dst != "10.98.9.9" || withLog.Items[0].Count != 10 || withLog.Items[0].Port == nil || *withLog.Items[0].Port != 5432 {
		t.Fatalf("refusals: %+v", withLog)
	}

	// Preview creates nothing.
	ruleCount, auditCount := rules(), audits()
	first := preview()
	if rules() != ruleCount || audits() != auditCount {
		t.Fatal("preview must create nothing")
	}
	if first.OwnerEmail == nil || *first.OwnerEmail != owner.String()+"@aiux1.example" || len(first.Candidates) != 4 {
		t.Fatalf("preview: %+v", first)
	}
	keyOf := map[string]api.AgentOwnerAccessCandidate{}
	for _, c := range first.Candidates {
		keyOf[c.Destination.Name] = c
	}
	if c := keyOf["via-group"]; c.Via != api.AgentOwnerAccessViaGroup || c.ViaGroupName == nil || *c.ViaGroupName != "Engineering" || !c.Copyable || c.AlreadyCovered {
		t.Fatalf("group candidate: %+v", c)
	}
	if c := keyOf["group-reach"]; !c.AlreadyCovered {
		t.Fatalf("a destination the agent group already reaches must be marked covered: %+v", c)
	}

	// Refusals of the whole request: unknown key, covered key, another organization.
	for name, keys := range map[string][]string{
		"unknown key":       {keyOf["direct"].Key, "not-a-key"},
		"covered key":       {keyOf["direct"].Key, keyOf["group-reach"].Key},
		"other agent's key": {ownerAccessKey(org, uuid.New(), keyOf["direct"].SourceRuleId, "resource", direct, nil)},
	} {
		if _, err := create(adminCtx, org, keys...); !hasCode(err, 409, "owner_access_preview_stale") {
			t.Fatalf("%s: want 409 owner_access_preview_stale, got %v", name, err)
		}
	}
	if _, err := create(adminCtx, otherOrg, keyOf["direct"].Key); !hasCode(err, 403, "forbidden") && !hasCode(err, 404, "org_not_found") {
		t.Fatalf("an administrator of another organization must be refused: %v", err)
	}
	if _, err := create(as(admin, otherOrg, rbac.RoleAdmin), otherOrg, keyOf["direct"].Key); !hasCode(err, 404, "agent_not_found") {
		t.Fatalf("an agent of another organization must not be found: %v", err)
	}
	if _, err := s.PreviewAgentOwnerAccess(as(admin, otherOrg, rbac.RoleAdmin), api.PreviewAgentOwnerAccessRequestObject{OrgId: otherOrg, DeviceId: device}); !hasCode(err, 404, "agent_not_found") {
		t.Fatalf("cross-organization preview: %v", err)
	}
	if _, err := s.GetAgentAccessSummary(as(admin, otherOrg, rbac.RoleAdmin), api.GetAgentAccessSummaryRequestObject{OrgId: otherOrg, DeviceId: device}); !hasCode(err, 404, "agent_not_found") {
		t.Fatalf("cross-organization summary: %v", err)
	}
	if rules() != ruleCount || audits() != auditCount {
		t.Fatal("a refused request must create nothing")
	}

	// Create makes only the chosen rules.
	res, err := create(adminCtx, org, keyOf["direct"].Key, keyOf["office"].Key)
	if err != nil {
		t.Fatal(err)
	}
	created := res.(api.CreateAgentRulesFromOwnerAccess201JSONResponse).Body.RuleIds
	if len(created) != 2 || rules() != ruleCount+2 {
		t.Fatalf("want exactly two new rules, got ids %v and %d rules", created, rules()-ruleCount)
	}
	if n := count(`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND id=ANY($2) AND src_kind='agent' AND src_device_id=$3 AND expires_at IS NULL AND (dst_resource_id=$4 OR dst_site_id=$5)`, org, created, device, direct, site); n != 2 {
		t.Fatalf("created rules must name this agent and the chosen destinations, matched %d", n)
	}
	var meta []byte
	var actor uuid.UUID
	var targetType, targetID string
	if err := pool.QueryRow(ctx, `SELECT metadata,actor_user_id,target_type,target_id FROM audit_logs WHERE org_id=$1 AND action='agent.access_rules_created_from_owner'`, org).Scan(&meta, &actor, &targetType, &targetID); err != nil {
		t.Fatal(err)
	}
	var recorded struct {
		RuleIDs []uuid.UUID `json:"rule_ids"`
	}
	if err := json.Unmarshal(meta, &recorded); err != nil || len(recorded.RuleIDs) != 2 || recorded.RuleIDs[0] != created[0] || recorded.RuleIDs[1] != created[1] || actor != admin || targetType != "device" || targetID != device.String() {
		t.Fatalf("audit row must name the created rules, the actor and the agent: %s %v %s %s (%v)", meta, actor, targetType, targetID, err)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='policy.rule_created' AND target_id=ANY($2)`, org, []string{created[0].String(), created[1].String()}); n != 2 {
		t.Fatalf("each rule keeps its own policy.rule_created entry, got %d", n)
	}

	// The same request again creates no second rule for a covered destination.
	ruleCount, auditCount = rules(), audits()
	if _, err := create(adminCtx, org, keyOf["direct"].Key, keyOf["office"].Key); !hasCode(err, 409, "owner_access_preview_stale") {
		t.Fatalf("repeat: want 409 owner_access_preview_stale, got %v", err)
	}
	if rules() != ruleCount || audits() != auditCount {
		t.Fatal("a repeated request must create nothing")
	}
	for _, c := range preview().Candidates {
		if (c.Destination.Name == "direct" || c.Destination.Name == "office") != c.AlreadyCovered && c.Destination.Name != "group-reach" {
			t.Fatalf("coverage after create: %+v", c)
		}
	}
	if got := summary().Rules; len(got) != 3 {
		t.Fatalf("summary must list the group rule and the two new rules: %+v", got)
	}

	// An agent whose owner is no longer a member has nobody to copy from.
	exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, org, owner)
	if _, err := s.PreviewAgentOwnerAccess(adminCtx, api.PreviewAgentOwnerAccessRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 409, "agent_owner_unattributable") {
		t.Fatalf("no owner preview: %v", err)
	}
	if _, err := create(adminCtx, org, keyOf["via-group"].Key); !hasCode(err, 409, "agent_owner_unattributable") {
		t.Fatalf("no owner create: %v", err)
	}
	if rules() != ruleCount {
		t.Fatal("no owner must create nothing")
	}
}
