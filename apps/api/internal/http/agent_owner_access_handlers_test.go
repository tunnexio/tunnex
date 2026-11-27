package http

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func ownerAccessText(v string) *string { return &v }

func ownerAccessRow(srcKind, dstKind string, dst uuid.UUID, name string) sqlc.ListAccessRulesForSubjectsRow {
	row := sqlc.ListAccessRulesForSubjectsRow{RuleID: uuid.New(), SrcKind: srcKind, DstKind: dstKind}
	ref := pgtype.UUID{Bytes: dst, Valid: true}
	switch dstKind {
	case "resource":
		row.DstResourceID, row.ResourceName = ref, &name
		row.ResourceCidr, row.ResourceProtocol = ownerAccessText("10.1.2.0/24"), ownerAccessText("tcp")
		low, high := int32(443), int32(444)
		row.ResourcePortLow, row.ResourcePortHigh = &low, &high
	case "group":
		row.DstGroupID, row.DstGroupName = ref, &name
	case "site":
		row.DstSiteID, row.SiteName = ref, &name
	case "k8s_service":
		row.DstK8sServiceID, row.K8sServiceName, row.K8sServiceNamespace = ref, &name, ownerAccessText("prod")
	case "k8s_cluster_scope":
		row.DstK8sClusterID, row.K8sClusterName = ref, &name
	case "fqdn_resource":
		row.DstFqdnResourceID, row.FqdnName, row.FqdnHost = ref, &name, ownerAccessText("db.example.com")
	case "k8s_api":
		row.K8sApiClusterID, row.K8sApiClusterName = ref, &name
	}
	return row
}

func TestOwnerAccessCandidatesCopyableKindsAndCoverage(t *testing.T) {
	org, device := uuid.New(), uuid.New()
	resource, covered, fqdn, cluster, api443, service := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	group := ownerAccessRow("group", "resource", covered, "covered")
	group.SrcGroupName = ownerAccessText("Engineering")
	disabled := ownerAccessRow("user", "site", uuid.New(), "disabled")
	disabled.Disabled = true
	gone := ownerAccessRow("user", "k8s_service", uuid.New(), "gone")
	gone.K8sServiceName = nil
	ownerRows := []sqlc.ListAccessRulesForSubjectsRow{
		ownerAccessRow("user", "resource", resource, "db"), group,
		ownerAccessRow("user", "fqdn_resource", fqdn, "fqdn"),
		ownerAccessRow("user", "k8s_cluster_scope", cluster, "cluster"),
		ownerAccessRow("user", "k8s_api", api443, "cluster api"),
		ownerAccessRow("user", "k8s_service", service, "web"),
		disabled, gone,
		ownerAccessRow("site", "resource", uuid.New(), "not the owner's"),
	}
	agentRows := []sqlc.ListAccessRulesForSubjectsRow{ownerAccessRow("agent_group", "resource", covered, "covered")}
	got := ownerAccessCandidates(org, device, ownerRows, agentRows)
	if len(got) != 6 {
		t.Fatalf("want 6 candidates (disabled, removed and non-owner rules dropped), got %d: %+v", len(got), got)
	}
	byKind := map[string]ownerAccessCandidate{}
	keys := map[string]bool{}
	for _, c := range got {
		byKind[c.api.Destination.Kind+":"+c.api.Destination.Name] = c
		if len(c.api.Key) == 0 || len(c.api.Key) > 128 || keys[c.api.Key] {
			t.Fatalf("key must be unique and within the contract length: %q", c.api.Key)
		}
		keys[c.api.Key] = true
	}
	db := byKind["resource:db"]
	if !db.api.Copyable || db.api.AlreadyCovered || db.api.Via != api.AgentOwnerAccessViaUser || db.api.ViaGroupName != nil ||
		db.input.SrcKind != "agent" || db.input.SrcAgentDeviceID == nil || *db.input.SrcAgentDeviceID != device ||
		db.input.DstResourceID == nil || *db.input.DstResourceID != resource || db.input.ExpiresAt != nil {
		t.Fatalf("resource candidate: %+v", db)
	}
	if d := db.api.Destination; d.Address == nil || *d.Address != "10.1.2.0/24" || d.PortLow == nil || *d.PortLow != 443 || d.PortHigh == nil || *d.PortHigh != 444 || d.Protocol == nil || *d.Protocol != "tcp" {
		t.Fatalf("resource destination: %+v", d)
	}
	if c := byKind["resource:covered"]; !c.api.AlreadyCovered || c.api.Via != api.AgentOwnerAccessViaGroup || c.api.ViaGroupName == nil || *c.api.ViaGroupName != "Engineering" {
		t.Fatalf("covered group candidate: %+v", c.api)
	}
	if c := byKind["k8s_service:prod/web"]; !c.api.Copyable || c.input.DstK8sServiceID == nil || *c.input.DstK8sServiceID != service {
		t.Fatalf("k8s service candidate: %+v", c)
	}
	for _, name := range []string{"fqdn_resource:fqdn", "k8s_cluster_scope:cluster", "k8s_api:cluster api"} {
		if c, ok := byKind[name]; !ok || c.api.Copyable {
			t.Fatalf("%s must be listed as not copyable: %+v", name, c.api)
		}
	}
}

func TestOwnerAccessCandidatesOnePerDestinationAndExpiryKept(t *testing.T) {
	org, device, dst, temporary := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	viaGroup := ownerAccessRow("group", "site", dst, "office")
	direct := ownerAccessRow("user", "site", dst, "office")
	temp := ownerAccessRow("user", "resource", temporary, "temp")
	temp.ExpiresAt = pgtype.Timestamptz{Time: expires, Valid: true}
	got := ownerAccessCandidates(org, device, []sqlc.ListAccessRulesForSubjectsRow{viaGroup, direct, temp}, nil)
	if len(got) != 2 {
		t.Fatalf("one candidate per destination: %+v", got)
	}
	if got[0].api.SourceRuleId != direct.RuleID || got[0].api.Via != api.AgentOwnerAccessViaUser {
		t.Fatalf("the rule naming the owner must win over the group rule: %+v", got[0].api)
	}
	if got[1].input.ExpiresAt == nil || !got[1].input.ExpiresAt.Equal(expires) {
		t.Fatalf("a temporary rule must be copied with its expiry: %+v", got[1].input)
	}
	// The key is bound to the agent, the source rule and the expiry.
	base := ownerAccessKey(org, device, direct.RuleID, "site", dst, nil)
	if got[0].api.Key != base {
		t.Fatal("key must be reproducible from a fresh preview")
	}
	for _, other := range []string{
		ownerAccessKey(org, uuid.New(), direct.RuleID, "site", dst, nil),
		ownerAccessKey(uuid.New(), device, direct.RuleID, "site", dst, nil),
		ownerAccessKey(org, device, viaGroup.RuleID, "site", dst, nil),
		ownerAccessKey(org, device, direct.RuleID, "site", dst, &expires),
	} {
		if other == base {
			t.Fatal("key must change with the agent, organization, source rule and expiry")
		}
	}
}

func TestAgentAccessRulesListsDirectAndGroupRules(t *testing.T) {
	groupID := uuid.New()
	viaGroup := ownerAccessRow("agent_group", "site", uuid.New(), "office")
	viaGroup.SrcAgentGroupID, viaGroup.SrcAgentGroupName = pgtype.UUID{Bytes: groupID, Valid: true}, ownerAccessText("Builders")
	viaGroup.Disabled = true
	direct := ownerAccessRow("agent", "resource", uuid.New(), "db")
	expires := time.Now().Add(time.Hour)
	direct.ExpiresAt = pgtype.Timestamptz{Time: expires, Valid: true}
	gone := ownerAccessRow("agent", "k8s_service", uuid.New(), "gone")
	gone.K8sServiceName = nil
	got := agentAccessRules([]sqlc.ListAccessRulesForSubjectsRow{direct, viaGroup, gone, ownerAccessRow("user", "site", uuid.New(), "owner's")})
	if len(got) != 3 {
		t.Fatalf("only agent and agent group rules are listed: %+v", got)
	}
	if got[0].Via != api.AgentAccessRuleViaAgent || got[0].GroupId != nil || !got[0].Enabled || got[0].ExpiresAt == nil || !got[0].ExpiresAt.Equal(expires) || got[0].Destination.Name != "db" {
		t.Fatalf("direct rule: %+v", got[0])
	}
	if got[1].Via != api.AgentAccessRuleViaAgentGroup || got[1].GroupId == nil || *got[1].GroupId != groupID || got[1].GroupName == nil || *got[1].GroupName != "Builders" || got[1].Enabled {
		t.Fatalf("group rule: %+v", got[1])
	}
	if got[2].Destination.Name != "No longer available" {
		t.Fatalf("a removed destination must say so: %+v", got[2].Destination)
	}
}

func TestAgentAccessRefusalsGroupedNewestFirst(t *testing.T) {
	now := time.Now()
	events := []accesslog.Event{
		{Decision: accesslog.DecisionDeny, DstIP: "10.0.0.5", DstPort: 22, Protocol: "tcp", OccurredAt: now.Add(-3 * time.Hour)},
		{Decision: accesslog.DecisionDenyAggregate, DstIP: "10.0.0.5", DstPort: 22, Protocol: "tcp", DenyCount: 40, OccurredAt: now.Add(-time.Hour)},
		{Decision: accesslog.DecisionDeny, DstIP: "10.0.0.9", Protocol: "any", OccurredAt: now.Add(-time.Minute)},
		{Decision: accesslog.DecisionDeny, DstIP: "10.0.0.7", DstPort: 80, Protocol: "tcp", OccurredAt: now.Add(-8 * 24 * time.Hour)},
		{Decision: accesslog.DecisionTerminated, DstIP: "10.0.0.8", DstPort: 80, Protocol: "tcp", OccurredAt: now},
		{Decision: accesslog.DecisionGap, OccurredAt: now},
	}
	got := agentAccessRefusals(events, now)
	if len(got) != 2 {
		t.Fatalf("want two destinations (old, ended and gap rows dropped): %+v", got)
	}
	if got[0].Dst != "10.0.0.9" || got[0].Port != nil || got[0].Count != 1 {
		t.Fatalf("newest first, no port for a portless refusal: %+v", got[0])
	}
	if got[1].Dst != "10.0.0.5" || got[1].Port == nil || *got[1].Port != 22 || got[1].Count != 41 || !got[1].LastSeen.Equal(now.Add(-time.Hour)) {
		t.Fatalf("grouped refusal: %+v", got[1])
	}
}

func TestOwnerAccessAuthorization(t *testing.T) {
	org, device := uuid.New(), uuid.New()
	s := apiServer{}
	for _, role := range []string{rbac.RoleMember, "viewer"} {
		ctx := principalWithRole(org, role)
		if _, err := s.PreviewAgentOwnerAccess(ctx, api.PreviewAgentOwnerAccessRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
			t.Fatalf("%s preview: %v", role, err)
		}
		if _, err := s.CreateAgentRulesFromOwnerAccess(ctx, api.CreateAgentRulesFromOwnerAccessRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
			t.Fatalf("%s create: %v", role, err)
		}
	}
	if _, err := s.PreviewAgentOwnerAccess(context.Background(), api.PreviewAgentOwnerAccessRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("anonymous preview: %v", err)
	}
	owner := principalWithRole(org, rbac.RoleOwner)
	for _, keys := range [][]string{nil, {}, {"a", "a"}, {""}} {
		if _, err := s.CreateAgentRulesFromOwnerAccess(owner, api.CreateAgentRulesFromOwnerAccessRequestObject{OrgId: org, DeviceId: device,
			Body: &api.CreateAgentRulesFromOwnerAccessRequest{Keys: keys}}); !hasCode(err, 400, "invalid_request") {
			t.Fatalf("keys %v: %v", keys, err)
		}
	}
}
