package http

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpoauth"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
)

func TestRuntimeReportAndLeaseAfterGatewayEnforcement(t *testing.T) {
	f := mcpfixture.New(t)
	q := sqlc.New(f.Pool)
	runtime := agentruntime.New(f.Pool, func(context.Context, uuid.UUID) (agentruntime.OptInState, error) {
		return agentruntime.OptInEnabled, nil
	})
	sealer, err := crypto.NewSealer(make([]byte, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	policy := mcptoolpolicy.New(f.Pool)
	server := apiServer{agentRuntime: runtime, system: q, mcpToolPolicy: policy, mcpOAuth: mcpoauth.New(q, sealer, nil, "https://control.example")}
	identity := agentruntime.Identity{OrgID: f.Org, DeviceID: f.Agent}
	ctx := agentruntime.WithIdentity(f.Ctx, identity)
	if _, _, err := runtime.Poll(f.Ctx, identity, 0, 1, "v-test"); err != nil {
		t.Fatal(err)
	}
	report := func(tool string, discovery map[string]interface{}) {
		t.Helper()
		inventory := map[string]interface{}{"servers": []interface{}{map[string]interface{}{"endpoint": mcpfixture.Endpoint, "server_name": "billing", "status": "healthy", "tools": []interface{}{map[string]interface{}{"name": tool, "input_schema_hash": "agent-said-so"}}}}}
		body := api.AgentRuntimeReport{AppliedRevision: 1, AttemptedRevision: 1, ClientVersion: "v-test", McpInventory: &inventory}
		if discovery != nil {
			body.McpOauthDiscovery = &discovery
		}
		if _, err := server.ReportAgentRuntime(ctx, api.ReportAgentRuntimeRequestObject{Body: &body}); err != nil {
			t.Fatalf("report: %v", err)
		}
	}
	stored := func() (string, string) {
		t.Helper()
		var snapshot, source string
		if err := f.Pool.QueryRow(f.Ctx, `SELECT snapshot::text, source FROM agent_mcp_inventory WHERE device_id=$1`, f.Agent).Scan(&snapshot, &source); err != nil {
			t.Fatal(err)
		}
		return snapshot, source
	}

	// Before any gateway observation the agent-reported list is stored, as it always was.
	report("agent_tool", nil)
	if snapshot, source := stored(); source != "agent" || !strings.Contains(snapshot, "agent_tool") {
		t.Fatalf("legacy report: %s %s", source, snapshot)
	}

	// Once the gateway has observed the server, what the agent host reports no longer replaces it.
	if err := policy.RecordGatewayInventory(f.Ctx, f.Org, f.Node, f.Agent, mcptoolpolicy.GatewayObservation{Endpoint: mcpfixture.Endpoint, Status: "healthy", ServerName: "billing", Tools: []mcptoolpolicy.ObservedTool{{Name: "gateway_tool", InputSchema: json.RawMessage(`{"type":"object"}`)}}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var observedBefore time.Time
	if err := f.Pool.QueryRow(f.Ctx, `SELECT observed_at FROM agent_mcp_inventory WHERE device_id=$1`, f.Agent).Scan(&observedBefore); err != nil {
		t.Fatal(err)
	}
	report("fabricated_tool", map[string]interface{}{"servers": []interface{}{map[string]interface{}{"endpoint": mcpfixture.Endpoint, "status": "discovered"}}})
	snapshot, source := stored()
	if source != "gateway" || strings.Contains(snapshot, "fabricated_tool") || strings.Contains(snapshot, "agent-said-so") || !strings.Contains(snapshot, "gateway_tool") {
		t.Fatalf("agent report overwrote gateway inventory: %s %s", source, snapshot)
	}
	if !strings.Contains(snapshot, `"oauth_discovery"`) || !strings.Contains(snapshot, "discovered") {
		t.Fatalf("OAuth discovery metadata was not kept: %s", snapshot)
	}
	var observedAfter time.Time
	if err := f.Pool.QueryRow(f.Ctx, `SELECT observed_at FROM agent_mcp_inventory WHERE device_id=$1`, f.Agent).Scan(&observedAfter); err != nil || !observedAfter.Equal(observedBefore) {
		t.Fatalf("an agent report refreshed the gateway observation time: %v -> %v, %v", observedBefore, observedAfter, err)
	}
	// The statement itself refuses too, whatever the handler read first.
	if _, err := q.UpsertAgentMCPInventory(f.Ctx, sqlc.UpsertAgentMCPInventoryParams{DeviceID: f.Agent, OrgID: f.Org, Snapshot: []byte(`{"servers":[]}`), ObservedAt: time.Now()}); err == nil {
		t.Fatal("the agent upsert replaced a gateway row")
	}

	// Lease: a connected credential is handed to the runtime only inside grace and only while the runtime
	// has not declared the gateway path.
	const oauthEndpoint = "https://mcp.example/mcp" // OAuth connections exist only for HTTPS endpoints
	sealed, err := sealer.Seal([]byte("upstream-token"))
	if err != nil {
		t.Fatal(err)
	}
	f.Exec(`INSERT INTO agent_mcp_oauth_connections (org_id,device_id,endpoint,protected_resource,issuer,client_id,access_token_sealed,token_expires_at,state,connected_at) VALUES ($1,$2,$3,$3,'https://issuer.example/','client',$4,now()+interval '1 hour','connected',now())`, f.Org, f.Agent, oauthEndpoint, sealed)
	lease := func() error {
		_, err := server.GetRuntimeMCPOAuthLease(ctx, api.GetRuntimeMCPOAuthLeaseRequestObject{Params: api.GetRuntimeMCPOAuthLeaseParams{Endpoint: oauthEndpoint}})
		return err
	}
	if err := lease(); !hasCode(err, 502, "mcp_oauth_lease_unavailable") {
		t.Fatalf("lease without grace err = %v", err)
	}
	f.Exec(`INSERT INTO organization_mcp_direct_path_grace (org_id, grace_until) VALUES ($1, now()+interval '30 days')`, f.Org)
	if err := lease(); err != nil {
		t.Fatalf("lease inside grace: %v", err)
	}
	if _, _, err := runtime.PollWith(f.Ctx, identity, 0, 1, "v-test", agentruntime.PollOptions{MCPGateway: true}); err != nil {
		t.Fatal(err)
	}
	if err := lease(); !hasCode(err, 502, "mcp_oauth_lease_unavailable") {
		t.Fatalf("lease for a gateway-capable runtime err = %v", err)
	}
	f.Exec(`UPDATE agent_runtime_state SET mcp_gateway_capable_at=NULL WHERE device_id=$1`, f.Agent)
	f.Exec(`UPDATE organization_mcp_direct_path_grace SET grace_until=now()-interval '1 minute' WHERE org_id=$1`, f.Org)
	if err := lease(); !hasCode(err, 502, "mcp_oauth_lease_unavailable") {
		t.Fatalf("lease after grace err = %v", err)
	}
}
