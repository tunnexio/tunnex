//go:build enterprise

package http

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentTemplateRouteAuthorizationOptInAndRefetch(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F09 route proof")
	}
	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_f09_route_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	fresh := *base
	fresh.Path = "/" + databaseName
	if err := db.MigrateTo(fresh.String(), 98); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, fresh.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	org, owner, member := uuid.New(), uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug) VALUES ($1,'F09 route',$2)`, org, "f09-route-"+org.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	for _, row := range []struct {
		id   uuid.UUID
		role string
	}{{owner, rbac.RoleOwner}, {member, rbac.RoleMember}} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, row.id, row.id.String()+"@f09.test")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)`, org, row.id, row.role)
	}
	with := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	s := apiServer{system: sqlc.New(pool), agentTemplates: NewAgentTemplatePort(pool, nil), policy: policy.NewService(pool)}
	if _, err := s.ListAgentGroups(with(owner, rbac.RoleOwner), api.ListAgentGroupsRequestObject{OrgId: org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("default-off read: %v", err)
	}
	if _, err := s.SetOrganizationAgentPolicyTemplatesEnabled(with(member, rbac.RoleMember), api.SetOrganizationAgentPolicyTemplatesEnabledRequestObject{OrgId: org, Body: &api.AgentPolicyTemplateSetting{Enabled: true}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member opt-in: %v", err)
	}
	if _, err := s.SetOrganizationAgentPolicyTemplatesEnabled(with(owner, rbac.RoleOwner), api.SetOrganizationAgentPolicyTemplatesEnabledRequestObject{OrgId: org, Body: &api.AgentPolicyTemplateSetting{Enabled: true}}); err != nil {
		t.Fatalf("owner opt-in: %v", err)
	}
	created, err := s.CreateAgentGroup(with(owner, rbac.RoleOwner), api.CreateAgentGroupRequestObject{OrgId: org, Body: &api.CreateAgentGroupRequest{Name: "workers"}})
	if err != nil {
		t.Fatal(err)
	}
	createdBody, ok := created.(api.CreateAgentGroup201JSONResponse)
	if !ok || createdBody.Body.Name != "workers" {
		t.Fatalf("create response: %#v", created)
	}
	listed, err := s.ListAgentGroups(with(owner, rbac.RoleOwner), api.ListAgentGroupsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	listedBody, ok := listed.(api.ListAgentGroups200JSONResponse)
	if !ok || len(listedBody.Body) != 1 || listedBody.Body[0].Id != createdBody.Body.Id {
		t.Fatalf("server refetch: %#v", listed)
	}
	updated, err := s.UpdateAgentGroup(with(owner, rbac.RoleOwner), api.UpdateAgentGroupRequestObject{OrgId: org, GroupId: createdBody.Body.Id, Body: &api.UpdateAgentGroupJSONRequestBody{Name: "workers-renamed"}})
	if err != nil {
		t.Fatal(err)
	}
	updatedBody, ok := updated.(api.UpdateAgentGroup200JSONResponse)
	if !ok || updatedBody.Body.Name != "workers-renamed" {
		t.Fatalf("update group response: %#v", updated)
	}
	createdTemplate, err := s.CreateAgentPolicyTemplate(with(owner, rbac.RoleOwner), api.CreateAgentPolicyTemplateRequestObject{OrgId: org, Body: &api.CreateAgentPolicyTemplateRequest{Name: "database"}})
	if err != nil {
		t.Fatal(err)
	}
	templateBody, ok := createdTemplate.(api.CreateAgentPolicyTemplate201JSONResponse)
	if !ok {
		t.Fatalf("create template response: %#v", createdTemplate)
	}
	updatedTemplate, err := s.UpdateAgentPolicyTemplate(with(owner, rbac.RoleOwner), api.UpdateAgentPolicyTemplateRequestObject{OrgId: org, TemplateId: templateBody.Body.Id, Body: &api.UpdateAgentPolicyTemplateJSONRequestBody{Name: "database-renamed"}})
	if err != nil {
		t.Fatal(err)
	}
	updatedTemplateBody, ok := updatedTemplate.(api.UpdateAgentPolicyTemplate200JSONResponse)
	if !ok || updatedTemplateBody.Body.Name != "database-renamed" {
		t.Fatalf("update template response: %#v", updatedTemplate)
	}
	assignmentsResponse, err := s.ListAgentPolicyTemplateAssignments(with(owner, rbac.RoleOwner), api.ListAgentPolicyTemplateAssignmentsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	assignmentsBody, ok := assignmentsResponse.(api.ListAgentPolicyTemplateAssignments200JSONResponse)
	if !ok || len(assignmentsBody.Body) != 0 {
		t.Fatalf("empty assignment refetch: %#v", assignmentsResponse)
	}
	resource, version, item, assignment, rule := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol) VALUES ($1,$2,'managed-db','10.77.0.0/24','tcp')`, resource, org)
	exec(`INSERT INTO agent_policy_template_versions (id,org_id,template_id,version,created_by_user_id) VALUES ($1,$2,$3,1,$4)`, version, org, templateBody.Body.Id, owner)
	exec(`INSERT INTO agent_policy_template_version_items (id,org_id,template_version_id,ordinal,dst_kind,dst_resource_id) VALUES ($1,$2,$3,1,'resource',$4)`, item, org, version, resource)
	impactResponse, err := s.GetAgentPolicyTemplateDestinationImpact(with(owner, rbac.RoleOwner), api.GetAgentPolicyTemplateDestinationImpactRequestObject{OrgId: org, Params: api.GetAgentPolicyTemplateDestinationImpactParams{DestinationKind: "resource", DestinationId: resource}})
	if err != nil {
		t.Fatal(err)
	}
	impactBody, ok := impactResponse.(api.GetAgentPolicyTemplateDestinationImpact200JSONResponse)
	if !ok || impactBody.Body.VersionCount != 1 {
		t.Fatalf("destination impact: %#v", impactResponse)
	}
	exec(`INSERT INTO agent_policy_template_assignments (id,org_id,agent_group_id,template_id,template_version_id,preview_digest,idempotency_key,applied_by_user_id) VALUES ($1,$2,$3,$4,$5,$6,'route-managed',$7)`, assignment, org, createdBody.Body.Id, templateBody.Body.Id, version, strings.Repeat("a", 64), owner)
	exec(`INSERT INTO policy_rules (id,org_id,src_kind,src_agent_group_id,dst_kind,dst_resource_id) VALUES ($1,$2,'agent_group',$3,'resource',$4)`, rule, org, createdBody.Body.Id, resource)
	exec(`INSERT INTO agent_policy_template_rule_bindings (org_id,assignment_id,template_version_item_id,policy_rule_id) VALUES ($1,$2,$3,$4)`, org, assignment, item, rule)
	ownerRules, err := s.ListPolicyRules(with(owner, rbac.RoleOwner), api.ListPolicyRulesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	ownerRulesBody, ok := ownerRules.(api.ListPolicyRules200JSONResponse)
	if !ok || len(ownerRulesBody.Body) != 1 || !ownerRulesBody.Body[0].ManagedByAgentTemplate || ownerRulesBody.Body[0].SrcAgentGroupId == nil || *ownerRulesBody.Body[0].SrcAgentGroupId != createdBody.Body.Id {
		t.Fatalf("owner managed-rule surface: %#v", ownerRules)
	}
	memberRules, err := s.ListPolicyRules(with(member, rbac.RoleOperator), api.ListPolicyRulesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	memberRulesBody, ok := memberRules.(api.ListPolicyRules200JSONResponse)
	if !ok || len(memberRulesBody.Body) != 0 {
		t.Fatalf("ordinary policy operator must receive zero F09 rule facts: %#v", memberRules)
	}
	exec(`DELETE FROM agent_policy_template_rule_bindings WHERE assignment_id=$1`, assignment)
	exec(`DELETE FROM policy_rules WHERE id=$1`, rule)
	exec(`DELETE FROM agent_policy_template_assignments WHERE id=$1`, assignment)
	if _, err := s.ListAgentGroupMembers(with(member, rbac.RoleMember), api.ListAgentGroupMembersRequestObject{OrgId: org, GroupId: createdBody.Body.Id}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member existing group: %v", err)
	}
	if _, err := s.ListAgentGroupMembers(with(member, rbac.RoleMember), api.ListAgentGroupMembersRequestObject{OrgId: org, GroupId: uuid.New()}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member missing group no-oracle: %v", err)
	}
	if _, err := s.RemoveAgentGroupMember(with(member, rbac.RoleMember), api.RemoveAgentGroupMemberRequestObject{OrgId: org, GroupId: createdBody.Body.Id, DeviceId: uuid.New()}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member remove no-oracle: %v", err)
	}
	if _, err := s.RemoveAgentPolicyTemplateAssignment(with(member, rbac.RoleMember), api.RemoveAgentPolicyTemplateAssignmentRequestObject{OrgId: org, AssignmentId: uuid.New()}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member assignment removal no-oracle: %v", err)
	}
	if _, err := s.GetAgentPolicyTemplateDestinationImpact(with(member, rbac.RoleMember), api.GetAgentPolicyTemplateDestinationImpactRequestObject{OrgId: org, Params: api.GetAgentPolicyTemplateDestinationImpactParams{DestinationKind: "resource", DestinationId: resource}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member destination impact no-oracle: %v", err)
	}
	if _, err := s.ArchiveAgentPolicyTemplate(with(owner, rbac.RoleOwner), api.ArchiveAgentPolicyTemplateRequestObject{OrgId: org, TemplateId: templateBody.Body.Id}); err != nil {
		t.Fatalf("archive empty template: %v", err)
	}
	if _, err := s.ArchiveAgentGroup(with(owner, rbac.RoleOwner), api.ArchiveAgentGroupRequestObject{OrgId: org, GroupId: createdBody.Body.Id}); err != nil {
		t.Fatalf("archive empty group: %v", err)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action IN ('org.agent_policy_templates_enabled','agent_group.created') AND actor_user_id=$2`, org, owner).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("atomic owner audit count=%d err=%v", auditCount, err)
	}
}
