package agentruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// Where MCP tool policy is enforced for one agent right now (AI-SEC-2).
const (
	// MCPEnforcementGateway: the gateway's MCP listener decides every call; the runtime only forwards.
	MCPEnforcementGateway = "gateway"
	// MCPEnforcementAgentHost: the older local-proxy path, allowed only until the organization's grace date.
	MCPEnforcementAgentHost = "agent_host"
	// MCPEnforcementUnavailable: grace is over (or there never was any) and the gateway or the runtime
	// cannot use the gateway path, so MCP is withheld: no upstream and no token lease.
	MCPEnforcementUnavailable = "unavailable"
)

// MCPPath is how an agent reaches its MCP server.
type MCPPath struct {
	// Assigned is false when the agent inherits no MCP profile; every other field is then empty.
	Assigned    bool
	Enforcement string
	Endpoint    string
	// Upstream is set only on the agent-host path, GatewayURL only on the gateway path.
	Upstream   *string
	GatewayURL *string
	// GraceUntil is the organization's direct-path grace date, nil when it has none.
	GraceUntil *time.Time
	// Servers are all the agent's MCP servers, first one first. Endpoint above is the first one's. The
	// agent-host path only ever carries the first; the gateway path carries all of them.
	Servers []MCPServer
}

// gatewayServers is what the runtime is told on the gateway path: every server by name.
func (p MCPPath) gatewayServers() []MCPServer {
	if p.GatewayURL == nil {
		return nil
	}
	return p.Servers
}

// fingerprintServers is the part of the server list a config revision depends on. One server adds
// nothing, so an agent that has a single MCP server keeps the revision it had before several were possible.
func (p MCPPath) fingerprintServers() []MCPServer {
	if p.GatewayURL == nil || len(p.Servers) < 2 {
		return nil
	}
	return p.Servers
}

// mcpPath decides the path from four facts: the assigned profile, whether the agent's gateway freshly
// reports its MCP listener, whether the runtime forwards to it, and the organization's grace date.
//
//	gateway reports + runtime forwards -> gateway
//	otherwise, inside the grace period  -> agent host (the path that existed before)
//	otherwise                           -> unavailable
func (s *Service) mcpPath(ctx context.Context, orgID, deviceID, nodeID uuid.UUID, poolCIDR string, runtimeCapable bool) (MCPPath, error) {
	servers, err := s.mcpServersForDevice(ctx, orgID, deviceID)
	if err != nil {
		return MCPPath{}, err
	}
	if len(servers) == 0 {
		return MCPPath{}, nil
	}
	endpoint := &servers[0].Endpoint
	out := MCPPath{Assigned: true, Endpoint: *endpoint, Enforcement: MCPEnforcementUnavailable, Servers: servers}
	grace, err := s.q.GetOrganizationMCPDirectPathGrace(ctx, orgID)
	switch {
	case err == nil:
		out.GraceUntil = &grace
	case !errors.Is(err, pgx.ErrNoRows):
		return MCPPath{}, err
	}
	address := ""
	caps, err := s.q.GetFreshNodeCapabilities(ctx, sqlc.GetFreshNodeCapabilitiesParams{OrgID: orgID, NodeID: nodeID})
	switch {
	case err == nil:
		address = readyMCPGatewayAddress(caps, poolCIDR)
	case !errors.Is(err, pgx.ErrNoRows):
		return MCPPath{}, err
	}
	switch {
	case runtimeCapable && address != "":
		url := "http://" + address + ":" + strconv.Itoa(mcpwire.ListenerPort) + "/mcp"
		out.Enforcement, out.GatewayURL = MCPEnforcementGateway, &url
	case out.GraceUntil != nil && out.GraceUntil.After(s.now()):
		out.Enforcement, out.Upstream = MCPEnforcementAgentHost, endpoint
	}
	return out, nil
}

// readyMCPGatewayAddress accepts only a typed ready report for the organization's own gateway address,
// exactly as the VPN AI listener's report is read. The caller has already checked freshness with the
// database clock.
func readyMCPGatewayAddress(raw []byte, poolCIDR string) string {
	var caps struct {
		Ready   bool   `json:"mcp_gateway_ready"`
		Address string `json:"mcp_gateway_address"`
	}
	if json.Unmarshal(raw, &caps) != nil || !caps.Ready {
		return ""
	}
	ip, err := netip.ParseAddr(caps.Address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != caps.Address {
		return ""
	}
	gateway, err := ipalloc.GatewayCIDR(poolCIDR)
	if err != nil {
		return ""
	}
	prefix, err := netip.ParsePrefix(gateway)
	if err != nil || prefix.Addr() != ip {
		return ""
	}
	return ip.String()
}

// DescribeMCPPath reports the path for the agent as it stands, for the administrator's view. It reads the
// stored runtime declaration; it never records one.
func (s *Service) DescribeMCPPath(ctx context.Context, orgID, deviceID uuid.UUID) (MCPPath, error) {
	if s == nil || s.q == nil {
		return MCPPath{}, ErrRuntimeStateMissing
	}
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if err != nil || dev.Kind != "agent" || dev.DeletedAt.Valid {
		return MCPPath{}, ErrRuntimeStateMissing
	}
	org, err := s.q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return MCPPath{}, ErrRuntimeStateMissing
	}
	capable, err := s.mcpGatewayCapable(ctx, orgID, deviceID)
	if err != nil {
		return MCPPath{}, err
	}
	return s.mcpPath(ctx, orgID, deviceID, dev.NodeID, org.PoolCidr, capable)
}

func (s *Service) mcpGatewayCapable(ctx context.Context, orgID, deviceID uuid.UUID) (bool, error) {
	state, err := s.q.GetAgentRuntimeState(ctx, sqlc.GetAgentRuntimeStateParams{DeviceID: deviceID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return state.McpGatewayCapableAt.Valid, nil
}

// MCPDirectLeaseAllowed reports whether the runtime may still be handed the MCP server's credential
// itself. It may not once it has declared the gateway path, or once the organization's grace period is
// over (or never existed): from then on the credential is leased only to the gateway, per forwarded call.
// Any failure to read the facts refuses.
func (s *Service) MCPDirectLeaseAllowed(ctx context.Context, orgID, deviceID uuid.UUID) bool {
	if s == nil || s.q == nil {
		return false
	}
	capable, err := s.mcpGatewayCapable(ctx, orgID, deviceID)
	if err != nil || capable {
		return false
	}
	grace, err := s.q.GetOrganizationMCPDirectPathGrace(ctx, orgID)
	return err == nil && grace.After(s.now())
}
