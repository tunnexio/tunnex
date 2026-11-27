package http

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// AI-UX-1: a plan that cannot use runtime synchronization is told so at the switch, before anything is
// saved. No database is reachable from this server value, so a 403 here also proves nothing was written.
func TestAgentRuntimeEnableIsRefusedOnAPlanWithoutIt(t *testing.T) {
	org := uuid.New()
	owner := principalWithRole(org, rbac.RoleOwner)
	on := api.SetOrganizationAgentRuntimeEnabledRequestObject{OrgId: org, Body: &api.AgentRuntimeSetting{Enabled: true}}

	for name, s := range map[string]apiServer{
		"no licence":        {},
		"community licence": {licence: licence.NewTestManager("community", time.Now().Add(time.Hour))},
	} {
		if _, err := s.SetOrganizationAgentRuntimeEnabled(owner, on); !hasCode(err, 403, "feature_required") {
			t.Fatalf("%s: want 403 feature_required, got %v", name, err)
		}
	}
	// Permission is still decided first.
	if _, err := (apiServer{}).SetOrganizationAgentRuntimeEnabled(principalWithRole(org, rbac.RoleMember), on); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member: want forbidden, got %v", err)
	}
	for _, tier := range []string{"trial", "starter", "growth", "scale"} {
		s := apiServer{licence: licence.NewTestManager(tier, time.Now().Add(time.Hour))}
		if err := s.requireAgentRuntimePlan(); err != nil {
			t.Fatalf("%s must be able to turn runtime synchronization on: %v", tier, err)
		}
	}
}

func TestAgentFeatureItemsNameThePlanWhenUnavailable(t *testing.T) {
	find := func(items []api.AgentFeature, key api.AgentFeatureKey) api.AgentFeature {
		t.Helper()
		for _, item := range items {
			if item.Key == key {
				return item
			}
		}
		t.Fatalf("feature %s missing from %+v", key, items)
		return api.AgentFeature{}
	}
	plan := func(f api.AgentFeature) string {
		if f.RequiredPlan == nil {
			return ""
		}
		return *f.RequiredPlan
	}

	community := agentFeatureItems(licence.TierCommunity, agentFeatureSwitches{runtimeSync: true, mcp: true})
	wantOrder := []api.AgentFeatureKey{api.AgentFeatureRuntimeSync, api.AgentFeatureAgentGroups, api.AgentFeatureMCP, api.AgentFeatureAgentJIT}
	if len(community) != len(wantOrder) {
		t.Fatalf("items = %+v", community)
	}
	for i, key := range wantOrder {
		if community[i].Key != key {
			t.Fatalf("item %d = %s, want %s", i, community[i].Key, key)
		}
	}
	if f := find(community, api.AgentFeatureRuntimeSync); f.Available || plan(f) != "starter" || !f.Enabled {
		t.Fatalf("community runtime sync = %+v (plan %q)", f, plan(f))
	}
	if f := find(community, api.AgentFeatureAgentJIT); f.Available || plan(f) != "scale" || f.Enabled {
		t.Fatalf("community agent JIT = %+v (plan %q)", f, plan(f))
	}
	// Agent groups and MCP are in every plan.
	if f := find(community, api.AgentFeatureAgentGroups); !f.Available || f.RequiredPlan != nil || f.Enabled {
		t.Fatalf("community agent groups = %+v", f)
	}
	if f := find(community, api.AgentFeatureMCP); !f.Available || f.RequiredPlan != nil || !f.Enabled {
		t.Fatalf("community MCP = %+v", f)
	}

	starter := agentFeatureItems(licence.TierStarter, agentFeatureSwitches{})
	if f := find(starter, api.AgentFeatureRuntimeSync); !f.Available || f.RequiredPlan != nil || f.Enabled {
		t.Fatalf("starter runtime sync = %+v", f)
	}
	if f := find(starter, api.AgentFeatureAgentJIT); f.Available || plan(f) != "scale" {
		t.Fatalf("starter agent JIT = %+v (plan %q)", f, plan(f))
	}

	scale := agentFeatureItems(licence.TierScale, agentFeatureSwitches{agentJIT: true, agentGroups: true})
	for _, f := range scale {
		if !f.Available || f.RequiredPlan != nil {
			t.Fatalf("scale %s = %+v", f.Key, f)
		}
	}
	if !find(scale, api.AgentFeatureAgentJIT).Enabled || !find(scale, api.AgentFeatureAgentGroups).Enabled {
		t.Fatalf("scale switches = %+v", scale)
	}

	// The answer always matches what the switch itself will do.
	for _, tier := range []licence.Tier{licence.TierCommunity, licence.TierTrial, licence.TierStarter, licence.TierGrowth, licence.TierScale} {
		s := apiServer{licence: licence.NewTestManager(string(tier), time.Now().Add(time.Hour))}
		listed := find(agentFeatureItems(tier, agentFeatureSwitches{}), api.AgentFeatureRuntimeSync).Available
		if accepted := s.requireAgentRuntimePlan() == nil; listed != accepted {
			t.Fatalf("%s: listed available=%v but the switch accepts=%v", tier, listed, accepted)
		}
	}
}

func TestAgentFeaturesAndMCPSettingPermissions(t *testing.T) {
	org := uuid.New()
	s := apiServer{}
	if _, err := s.ListAgentFeatures(principalWithRole(uuid.New(), rbac.RoleOwner), api.ListAgentFeaturesRequestObject{OrgId: org}); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other organization features: %v", err)
	}
	if _, err := s.GetOrganizationMCPSetting(principalWithRole(uuid.New(), rbac.RoleOwner), api.GetOrganizationMCPSettingRequestObject{OrgId: org}); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other organization MCP setting: %v", err)
	}
	put := api.SetOrganizationMCPEnabledRequestObject{OrgId: org, Body: &api.MCPSetting{Enabled: true}}
	for _, role := range []string{rbac.RoleMember, rbac.RoleOperator} {
		if _, err := s.SetOrganizationMCPEnabled(principalWithRole(org, role), put); !hasCode(err, 403, "forbidden") {
			t.Fatalf("%s MCP switch: want forbidden, got %v", role, err)
		}
	}
	if _, err := s.GetAgentBootstrapTokenStatus(principalWithRole(org, rbac.RoleMember), api.GetAgentBootstrapTokenStatusRequestObject{OrgId: org, TokenId: uuid.New()}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member token status: want forbidden, got %v", err)
	}
}

func TestBootstrapTokenStatusStates(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	ts := func(at time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: at, Valid: true} }
	id, device := uuid.New(), uuid.New()
	base := sqlc.GetAgentBootstrapTokenStatusRow{ID: id, AgentName: "build-agent", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(59 * time.Minute)}

	pending := toAPIBootstrapTokenStatus(base, now)
	if pending.State != api.AgentBootstrapTokenPending || pending.Id != id || pending.AgentName != "build-agent" || pending.EnrolledAt != nil || pending.DeviceId != nil || pending.Tunnel != nil {
		t.Fatalf("pending = %+v", pending)
	}

	revoked := base
	revoked.RevokedAt = ts(now.Add(-time.Second))
	if got := toAPIBootstrapTokenStatus(revoked, now); got.State != api.AgentBootstrapTokenRevoked || got.Tunnel != nil {
		t.Fatalf("revoked = %+v", got)
	}

	expired := base
	expired.ExpiresAt = now
	if got := toAPIBootstrapTokenStatus(expired, now); got.State != api.AgentBootstrapTokenExpired || got.Tunnel != nil {
		t.Fatalf("expired = %+v", got)
	}
	// A revoked token stays revoked after its expiry passes.
	expired.RevokedAt = ts(now.Add(-time.Hour))
	if got := toAPIBootstrapTokenStatus(expired, now); got.State != api.AgentBootstrapTokenRevoked {
		t.Fatalf("revoked then expired = %+v", got)
	}

	// Enrolled, gateway reporting, no handshake yet: known to be not connected.
	enrolled := base
	enrolled.ConsumedAt = ts(now.Add(-30 * time.Second))
	enrolled.ConsumedDeviceID = pgtype.UUID{Bytes: device, Valid: true}
	enrolled.DeviceID = pgtype.UUID{Bytes: device, Valid: true}
	enrolled.GatewayLastSeenAt = ts(time.Now())
	got := toAPIBootstrapTokenStatus(enrolled, now)
	if got.State != api.AgentBootstrapTokenEnrolled || got.EnrolledAt == nil || !got.EnrolledAt.Equal(now.Add(-30*time.Second)) || got.DeviceId == nil || *got.DeviceId != device {
		t.Fatalf("enrolled = %+v", got)
	}
	if got.Tunnel == nil || got.Tunnel.Connected || !got.Tunnel.GatewayReporting || got.Tunnel.LastHandshakeAt != nil {
		t.Fatalf("enrolled tunnel = %+v", got.Tunnel)
	}
	// An enrolled token stays enrolled after its expiry passes.
	late := enrolled
	late.ExpiresAt = now.Add(-time.Minute)
	if got := toAPIBootstrapTokenStatus(late, now); got.State != api.AgentBootstrapTokenEnrolled {
		t.Fatalf("enrolled then expired = %+v", got)
	}

	// Tunnel connected: the same handshake window and reporter clock as the agents list.
	connected := enrolled
	handshake := time.Now().Add(-10 * time.Second)
	connected.LastHandshakeAt = ts(handshake)
	connected.StatusReportedAt = ts(time.Now())
	got = toAPIBootstrapTokenStatus(connected, now)
	if got.Tunnel == nil || !got.Tunnel.Connected || !got.Tunnel.GatewayReporting || got.Tunnel.LastHandshakeAt == nil || !got.Tunnel.LastHandshakeAt.Equal(handshake) {
		t.Fatalf("connected tunnel = %+v", got.Tunnel)
	}
	if want := deviceOnline(&handshake); got.Tunnel.Connected != want {
		t.Fatalf("connected = %v, agents list says %v", got.Tunnel.Connected, want)
	}

	// A silent gateway is unknown, not offline: gateway_reporting=false.
	silent := enrolled
	silent.StatusReportedAt = ts(time.Now().Add(-24 * time.Hour))
	silent.GatewayLastSeenAt = ts(time.Now())
	got = toAPIBootstrapTokenStatus(silent, now)
	if got.Tunnel == nil || got.Tunnel.Connected || got.Tunnel.GatewayReporting {
		t.Fatalf("silent gateway tunnel = %+v", got.Tunnel)
	}

	// The agent was removed after it enrolled: still enrolled, with no agent or tunnel to point at.
	removed := enrolled
	removed.ConsumedDeviceID, removed.DeviceID = pgtype.UUID{}, pgtype.UUID{}
	got = toAPIBootstrapTokenStatus(removed, now)
	if got.State != api.AgentBootstrapTokenEnrolled || got.DeviceId != nil || got.Tunnel != nil {
		t.Fatalf("removed agent = %+v", got)
	}

	encoded, err := json.Marshal(toAPIBootstrapTokenStatus(connected, now))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "hash") || strings.Contains(string(encoded), "tnx_agent_") {
		t.Fatalf("status carries token material: %s", encoded)
	}
}
