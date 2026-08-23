package http

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

func TestAgentProfileHandlersAuthorizationAndAtomicity(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for handler integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var migrated bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('agent_profiles') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("migration 0088 is not applied")
	}

	org, owner, manager, nextOwner, outsider, node, device, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,max_devices_per_user) VALUES ($1,'F01',$2,10)`, org, "f01-"+org.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })
	for _, u := range []uuid.UUID{owner, manager, nextOwner, outsider} {
		if _, err = pool.Exec(ctx, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F01','active')`, u, u.String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820')`, node, org, "serial-"+node.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,transport,kind) VALUES ($1,$2,$3,$4,'agent','agent','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','10.99.0.10','active','wireguard','agent')`, device, org, owner, node); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_profiles (device_id) VALUES ($1)`, device); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'Agent managers')`, group, org); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO group_members (org_id,group_id,user_id) VALUES ($1,$2,$3)`, org, group, manager); err != nil {
		t.Fatal(err)
	}

	s := apiServer{devices: devices.NewService(pool, nil, nil), nodes: nodes.NewService(pool, nil, nil), members: tenancy.NewMembershipService(pool, nil), policy: NewPolicyPort(pool, nil)}
	memberCtx := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	listReq := api.ListAgentsRequestObject{OrgId: org}
	ownerList, err := s.ListAgents(memberCtx(owner, rbac.RoleMember), listReq)
	if err != nil {
		t.Fatalf("owner agent list: %v", err)
	}
	ownerListBody, ok := ownerList.(api.ListAgents200JSONResponse)
	if !ok || len(ownerListBody.Body.Items) != 1 || ownerListBody.Body.Items[0].OwnerEmail == nil || *ownerListBody.Body.Items[0].OwnerEmail != owner.String()+"@example.test" {
		t.Fatalf("owner list omitted own owner email: %#v", ownerList)
	}
	outsiderList, err := s.ListAgents(memberCtx(outsider, rbac.RoleMember), listReq)
	if err != nil {
		t.Fatalf("member agent list: %v", err)
	}
	outsiderBody, ok := outsiderList.(api.ListAgents200JSONResponse)
	if !ok || len(outsiderBody.Body.Items) != 1 || outsiderBody.Body.Items[0].OwnerEmail != nil {
		t.Fatalf("plain member list leaked owner email: %#v", outsiderList)
	}
	adminList, err := s.ListAgents(memberCtx(owner, rbac.RoleOwner), listReq)
	if err != nil {
		t.Fatalf("admin/owner agent list: %v", err)
	}
	adminBody, ok := adminList.(api.ListAgents200JSONResponse)
	if !ok || len(adminBody.Body.Items) != 1 || adminBody.Body.Items[0].OwnerEmail == nil {
		t.Fatalf("management list omitted owner email: %#v", adminList)
	}
	if _, err := s.GetAgentProfile(memberCtx(outsider, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unrelated member profile read: %v", err)
	}
	missingAgent := uuid.New()
	_, existingRevokeErr := s.RevokeDevice(memberCtx(outsider, rbac.RoleMember), api.RevokeDeviceRequestObject{OrgId: org, DeviceId: device})
	_, missingRevokeErr := s.RevokeDevice(memberCtx(outsider, rbac.RoleMember), api.RevokeDeviceRequestObject{OrgId: org, DeviceId: missingAgent})
	if !hasCode(existingRevokeErr, 403, "forbidden") || !hasCode(missingRevokeErr, 403, "forbidden") || existingRevokeErr.Error() != missingRevokeErr.Error() {
		t.Fatalf("agent revoke existence oracle: existing=%v missing=%v", existingRevokeErr, missingRevokeErr)
	}
	_, existingRemoveErr := s.RemoveDevice(memberCtx(outsider, rbac.RoleMember), api.RemoveDeviceRequestObject{OrgId: org, DeviceId: device})
	_, missingRemoveErr := s.RemoveDevice(memberCtx(outsider, rbac.RoleMember), api.RemoveDeviceRequestObject{OrgId: org, DeviceId: missingAgent})
	if !hasCode(existingRemoveErr, 403, "forbidden") || !hasCode(missingRemoveErr, 403, "forbidden") || existingRemoveErr.Error() != missingRemoveErr.Error() {
		t.Fatalf("agent remove existence oracle: existing=%v missing=%v", existingRemoveErr, missingRemoveErr)
	}
	if _, err := s.GetAgentProfile(memberCtx(manager, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unassigned manager profile read: %v", err)
	}

	env, runtime := "staging", "python"
	labels := map[string]string{"team": "sec"}
	ownerBody := &api.UpdateAgentProfileRequest{Environment: &env, Runtime: &runtime, Labels: &labels}
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: ownerBody}); err != nil {
		t.Fatalf("owner metadata update: %v", err)
	}
	refetched, err := s.GetAgentProfile(memberCtx(owner, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device})
	if err != nil {
		t.Fatalf("owner metadata refetch: %v", err)
	}
	profile, ok := refetched.(api.GetAgentProfile200JSONResponse)
	if !ok || profile.Body.Environment != env || profile.Body.Runtime != runtime || profile.Body.Labels["team"] != "sec" {
		t.Fatalf("metadata was not persisted in server refetch: %#v", refetched)
	}
	ownerPermissions := profile.Body.Permissions
	if !ownerPermissions.ViewPrivileged || !ownerPermissions.Manage || !ownerPermissions.Revoke || ownerPermissions.Assign || ownerPermissions.GrantAccess || ownerPermissions.RotateCredentials {
		t.Fatalf("accountable member-owner effective permissions: %#v", ownerPermissions)
	}
	status := api.UpdateAgentProfileRequestStatus("suspended")
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &status}}); err != nil {
		t.Fatalf("scoped owner suspend: %v", err)
	}
	active := api.UpdateAgentProfileRequestStatus("active")
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &active}}); err != nil {
		t.Fatalf("scoped owner resume: %v", err)
	}

	adminCtx := memberCtx(owner, rbac.RoleOwner)
	// The candidate membership and user rows are locked in the assignment
	// transaction. A concurrent deactivation must serialize after that check,
	// never commit between validation and the owner write.
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlc.New(pool).WithTx(lockTx).GetCurrentAgentOwnerCandidate(ctx, sqlc.GetCurrentAgentOwnerCandidateParams{OrgID: org, UserID: nextOwner}); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatal(err)
	}
	deactivated := make(chan error, 1)
	go func() {
		_, updateErr := pool.Exec(context.Background(), `UPDATE users SET status='deactivated' WHERE id=$1`, nextOwner)
		deactivated <- updateErr
	}()
	select {
	case updateErr := <-deactivated:
		_ = lockTx.Rollback(ctx)
		t.Fatalf("candidate row lock did not serialize deactivation: %v", updateErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case updateErr := <-deactivated:
		if updateErr != nil {
			t.Fatal(updateErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deactivation remained blocked after candidate transaction ended")
	}
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{OwnerId: &nextOwner}}); !hasCode(err, 400, "invalid_agent_owner") {
		t.Fatalf("deactivated owner candidate accepted: %v", err)
	}
	var preservedOwner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT user_id FROM devices WHERE id=$1`, device).Scan(&preservedOwner); err != nil || preservedOwner != owner {
		t.Fatalf("rejected owner update changed canonical owner=%s err=%v", preservedOwner, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, nextOwner); err != nil {
		t.Fatal(err)
	}
	assignment, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{
		OwnerId: &nextOwner, ManagingGroupUpdate: &api.AgentManagingGroupUpdate{GroupId: &group},
	}})
	if err != nil {
		t.Fatalf("atomic owner/team assignment: %v", err)
	}
	assigned, ok := assignment.(api.UpdateAgentProfile200JSONResponse)
	if !ok || assigned.Body.OwnerId != nextOwner || assigned.Body.ManagingGroupId == nil || *assigned.Body.ManagingGroupId != group || assigned.Body.ManagingGroupName == nil || *assigned.Body.ManagingGroupName != "Agent managers" {
		t.Fatalf("assignment response was not server truth: %#v", assignment)
	}
	// Audit is part of the same transaction. Force only this device's
	// assignment audit to fail and prove neither ownership nor delegation is
	// partially changed.
	fn := "f06_fail_assignment_audit_" + strings.ReplaceAll(device.String(), "-", "")
	trigger := fn + "_trigger"
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='agent.assignment_updated' AND NEW.target_id='%s' THEN RAISE EXCEPTION 'f06 forced audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION %s()`, fn, device, trigger, fn)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON audit_logs; DROP FUNCTION IF EXISTS %s()`, trigger, fn))
	})
	clearForFailure := api.AgentManagingGroupUpdate{GroupId: nil}
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{OwnerId: &owner, ManagingGroupUpdate: &clearForFailure}}); err == nil {
		t.Fatal("forced assignment audit failure unexpectedly committed")
	}
	var rollbackOwner uuid.UUID
	var rollbackGroup uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT d.user_id,ap.managing_group_id FROM devices d JOIN agent_profiles ap ON ap.device_id=d.id WHERE d.id=$1`, device).Scan(&rollbackOwner, &rollbackGroup); err != nil || rollbackOwner != nextOwner || rollbackGroup != group {
		t.Fatalf("audit failure partially committed owner/group=%s/%s err=%v", rollbackOwner, rollbackGroup, err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON audit_logs; DROP FUNCTION %s()`, trigger, fn)); err != nil {
		t.Fatal(err)
	}
	groupsResponse, err := s.ListGroups(adminCtx, api.ListGroupsRequestObject{OrgId: org})
	if err != nil {
		t.Fatalf("list groups with delegation impact: %v", err)
	}
	groupsBody, ok := groupsResponse.(api.ListGroups200JSONResponse)
	if !ok || len(groupsBody.Body) != 1 || groupsBody.Body[0].ManagedAgentCount == nil || *groupsBody.Body[0].ManagedAgentCount != 1 {
		t.Fatalf("server-owned managing-agent count: %#v", groupsResponse)
	}
	membersResponse, err := s.ListMembers(adminCtx, api.ListMembersRequestObject{OrgId: org})
	if err != nil {
		t.Fatalf("list members with delegation impact: %v", err)
	}
	membersBody := membersResponse.(api.ListMembers200JSONResponse).Body
	var managerDelegations *int
	for _, member := range membersBody {
		if member.UserId == manager {
			managerDelegations = member.ManagedAgentDelegations
		}
	}
	if managerDelegations == nil || *managerDelegations != 1 {
		t.Fatalf("server-owned member delegation impact: %#v", membersBody)
	}
	if _, err := s.GetAgentProfile(memberCtx(owner, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("previous owner retained scoped access: %v", err)
	}
	managerCtx := memberCtx(manager, rbac.RoleMember)
	managerProfile, err := s.GetAgentProfile(managerCtx, api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device})
	if err != nil {
		t.Fatalf("managing group view: %v", err)
	}
	managerBody := managerProfile.(api.GetAgentProfile200JSONResponse).Body
	if !managerBody.Permissions.ViewPrivileged || !managerBody.Permissions.Manage || managerBody.Permissions.Assign || managerBody.Permissions.Revoke || managerBody.Permissions.GrantAccess || managerBody.Permissions.RotateCredentials {
		t.Fatalf("managing group effective permissions: %#v", managerBody.Permissions)
	}
	managerEnv := "managed"
	if _, err := s.UpdateAgentProfile(managerCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Environment: &managerEnv}}); err != nil {
		t.Fatalf("managing group metadata update: %v", err)
	}
	if _, err := s.UpdateAgentProfile(managerCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{OwnerId: &owner}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("scoped manager changed governance: %v", err)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='agent.assignment_updated' AND target_id=$2`, org, device.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("assignment audit count=%d err=%v", auditCount, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, org, group, manager); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAgentProfile(managerCtx, api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("removed group member retained authority: %v", err)
	}
	clear := &api.AgentManagingGroupUpdate{GroupId: nil}
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{ManagingGroupUpdate: clear}}); err != nil {
		t.Fatalf("clear managing group: %v", err)
	}
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{ManagingGroupUpdate: &api.AgentManagingGroupUpdate{GroupId: &group}}}); err != nil {
		t.Fatalf("restore managing group before delete: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM user_groups WHERE id=$1 AND org_id=$2`, group, org); err != nil {
		t.Fatal(err)
	}
	postDelete, err := s.GetAgentProfile(memberCtx(nextOwner, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device})
	if err != nil {
		t.Fatalf("owner refetch after group delete: %v", err)
	}
	postDeleteBody := postDelete.(api.GetAgentProfile200JSONResponse).Body
	if postDeleteBody.OwnerId != nextOwner || postDeleteBody.ManagingGroupId != nil || postDeleteBody.ManagingGroupName != nil {
		t.Fatalf("group delete did not clear only delegated management: %#v", postDeleteBody)
	}

	for _, terminal := range []string{"pending", "revoked"} {
		if _, err := pool.Exec(ctx, `UPDATE devices SET status=$2 WHERE id=$1`, device, terminal); err != nil {
			t.Fatal(err)
		}
		badEnv := "must-not-commit"
		if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Environment: &badEnv, Status: &status}}); !hasCode(err, 409, "invalid_agent_transition") {
			t.Fatalf("%s lifecycle bypass: %v", terminal, err)
		}
		var got string
		if err := pool.QueryRow(ctx, `SELECT environment FROM agent_profiles WHERE device_id=$1`, device).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != managerEnv {
			t.Fatalf("%s failure partially committed metadata: got %q want %q", terminal, got, managerEnv)
		}
	}
}
