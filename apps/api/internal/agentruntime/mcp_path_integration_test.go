package agentruntime

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/mcpfixture"
)

func TestReadyMCPGatewayAddress(t *testing.T) {
	for name, tt := range map[string]struct {
		caps string
		want string
	}{
		"ready on the gateway address": {`{"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.1"}`, "10.123.0.1"},
		"not ready":                    {`{"mcp_gateway_ready":false,"mcp_gateway_address":"10.123.0.1"}`, ""},
		"older gateway":                {`{"ai_vpn_http_ready":true,"ai_vpn_http_address":"10.123.0.1"}`, ""},
		"another pool address":         {`{"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.9"}`, ""},
		"public address":               {`{"mcp_gateway_ready":true,"mcp_gateway_address":"8.8.8.8"}`, ""},
		"not an address":               {`{"mcp_gateway_ready":true,"mcp_gateway_address":"http://10.123.0.1"}`, ""},
		"garbage":                      {`[`, ""},
	} {
		if got := readyMCPGatewayAddress([]byte(tt.caps), "10.123.0.0/24"); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}

func TestFingerprintCoversMCPGatewayURL(t *testing.T) {
	upstream, gateway, other := "http://10.0.0.5/mcp", "http://10.123.0.1:8084/mcp", "http://10.123.0.2:8084/mcp"
	routes := []string{"10.123.0.0/24"}
	none := fingerprintRuntimeConfig(routes, nil, nil)
	legacy := fingerprintRuntimeConfig(routes, &upstream, nil)
	viaGateway := fingerprintRuntimeConfig(routes, nil, &gateway)
	if none == legacy || none == viaGateway || legacy == viaGateway || viaGateway == fingerprintRuntimeConfig(routes, nil, &other) {
		t.Fatal("the fingerprint does not separate the MCP paths")
	}
}

func TestPollMCPGatewayPath(t *testing.T) {
	f := mcpfixture.New(t)
	svc := New(f.Pool, func(context.Context, uuid.UUID) (OptInState, error) { return OptInEnabled, nil })
	var hooked []uuid.UUID
	svc.SetMCPGatewayCapableHook(func(_ context.Context, _, deviceID uuid.UUID) { hooked = append(hooked, deviceID) })
	id := Identity{OrgID: f.Org, DeviceID: f.Agent}
	poll := func(declare bool) Config {
		t.Helper()
		cfg, unchanged, err := svc.PollWith(f.Ctx, id, 0, 1, "v-test", PollOptions{MCPGateway: declare})
		if err != nil || unchanged {
			t.Fatalf("poll: unchanged=%v err=%v", unchanged, err)
		}
		return cfg
	}
	gatewayReports := func(caps string) {
		f.Exec(`UPDATE nodes SET capabilities=$2::jsonb, policy_reported_at=now() WHERE id=$1`, f.Node, caps)
	}
	const ready = `{"mcp_gateway_ready":true,"mcp_gateway_address":"10.123.0.1"}`
	const wantURL = "http://10.123.0.1:8084/mcp"

	// A new organization has no grace: an old runtime on an old gateway gets no MCP at all.
	cfg := poll(false)
	if cfg.MCPUpstream != nil || cfg.MCPGatewayURL != nil {
		t.Fatalf("no grace, old gateway: %+v", cfg)
	}
	if svc.MCPDirectLeaseAllowed(f.Ctx, f.Org, f.Agent) {
		t.Fatal("direct lease allowed without grace")
	}
	if path, err := svc.DescribeMCPPath(f.Ctx, f.Org, f.Agent); err != nil || !path.Assigned || path.Enforcement != MCPEnforcementUnavailable || path.GraceUntil != nil {
		t.Fatalf("described path = %+v, %v", path, err)
	}

	// Inside the grace period the old runtime keeps the path it had, gateway capable or not.
	f.Exec(`INSERT INTO organization_mcp_direct_path_grace (org_id, grace_until) VALUES ($1, now()+interval '30 days')`, f.Org)
	cfg = poll(false)
	if cfg.MCPUpstream == nil || *cfg.MCPUpstream != mcpfixture.Endpoint || cfg.MCPGatewayURL != nil {
		t.Fatalf("grace, old runtime: %+v", cfg)
	}
	legacyRevision := cfg.Revision
	if !svc.MCPDirectLeaseAllowed(f.Ctx, f.Org, f.Agent) {
		t.Fatal("direct lease refused inside grace")
	}
	gatewayReports(ready)
	if cfg = poll(false); cfg.MCPUpstream == nil || cfg.MCPGatewayURL != nil || cfg.Revision != legacyRevision {
		t.Fatalf("grace, old runtime, capable gateway: %+v", cfg)
	}
	if len(hooked) != 0 {
		t.Fatal("hook ran for a runtime that declared nothing")
	}

	// A runtime that declares the gateway path on a gateway that does not report it stays on the old
	// path during grace. The declaration is stored, and the hook runs exactly once.
	gatewayReports(`{}`)
	if cfg = poll(true); cfg.MCPUpstream == nil || cfg.MCPGatewayURL != nil {
		t.Fatalf("capable runtime, old gateway, grace: %+v", cfg)
	}
	if len(hooked) != 1 || hooked[0] != f.Agent {
		t.Fatalf("hook calls = %v", hooked)
	}
	if f.Count(`SELECT count(*) FROM agent_runtime_state WHERE device_id=$1 AND mcp_gateway_capable_at IS NOT NULL`, f.Agent) != 1 {
		t.Fatal("declaration was not stored")
	}
	if svc.MCPDirectLeaseAllowed(f.Ctx, f.Org, f.Agent) {
		t.Fatal("direct lease allowed for a runtime that declared the gateway path")
	}

	// Capable runtime + capable gateway: the URL, no upstream, and a new revision.
	gatewayReports(ready)
	cfg = poll(true)
	if cfg.MCPGatewayURL == nil || *cfg.MCPGatewayURL != wantURL || cfg.MCPUpstream != nil || cfg.Revision <= legacyRevision {
		t.Fatalf("gateway path: %+v", cfg)
	}
	if len(hooked) != 1 {
		t.Fatalf("hook ran again: %v", hooked)
	}
	if path, _ := svc.DescribeMCPPath(f.Ctx, f.Org, f.Agent); path.Enforcement != MCPEnforcementGateway || path.GraceUntil == nil {
		t.Fatalf("described path = %+v", path)
	}
	// Leaving the declaration out afterwards does not bring the direct path back.
	if cfg = poll(false); cfg.MCPUpstream != nil || cfg.MCPGatewayURL == nil {
		t.Fatalf("declaration dropped: %+v", cfg)
	}

	// A stale capability report is not a capability.
	f.Exec(`UPDATE nodes SET policy_reported_at=now()-interval '5 minutes' WHERE id=$1`, f.Node)
	if cfg = poll(true); cfg.MCPGatewayURL != nil || cfg.MCPUpstream == nil {
		t.Fatalf("stale gateway report inside grace: %+v", cfg)
	}

	// After grace, a gateway without the capability means no MCP: no upstream, no URL, no lease.
	svc.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	if cfg = poll(true); cfg.MCPGatewayURL != nil || cfg.MCPUpstream != nil {
		t.Fatalf("after grace, old gateway: %+v", cfg)
	}
	if path, _ := svc.DescribeMCPPath(f.Ctx, f.Org, f.Agent); path.Enforcement != MCPEnforcementUnavailable {
		t.Fatalf("described path after grace = %+v", path)
	}
	f.Exec(`UPDATE agent_runtime_state SET mcp_gateway_capable_at=NULL WHERE device_id=$1`, f.Agent)
	if svc.MCPDirectLeaseAllowed(f.Ctx, f.Org, f.Agent) {
		t.Fatal("direct lease allowed after grace")
	}
}
