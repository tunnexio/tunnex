package http

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mcpdecision"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// SetMCPDecision exposes gateway-enforced MCP only on the certificate-authenticated node channel
// (AI-SEC-2). nil leaves the four routes answering 503; public HTTP handlers never read the peer-evidence
// headers these routes consume.
func (a *AgentChannel) SetMCPDecision(svc *mcpdecision.Service) { a.mcp = svc }

// mcpDecideBodyLimit bounds a decide request: one MCP request body plus its JSON envelope.
const mcpDecideBodyLimit = mcpwire.MaxRequestBytes + 64<<10

// mcpInventoryBodyLimit bounds one agent's reported tool list.
const mcpInventoryBodyLimit = 4 << 20

// mcpDecide answers whether one MCP request from one tunnel peer may be forwarded. The organization and
// the gateway come from the client certificate. The agent comes only from the tunnel evidence the gateway
// observed: exactly one address header and exactly one key header. A missing, repeated or malformed header
// is refused before anything is looked up.
func (a *AgentChannel) mcpDecide(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.mcp == nil {
		http.Error(w, "MCP gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	ips, keys := r.Header.Values(mcpwire.HeaderVPNIP), r.Header.Values(mcpwire.HeaderVPNKey)
	if len(ips) != 1 || len(keys) != 1 || ips[0] == "" || keys[0] == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req mcpwire.DecideRequest
	if !decodeMCPBody(w, r, mcpDecideBodyLimit, &req) {
		return
	}
	response := a.mcp.Decide(r.Context(), mcpdecision.Evidence{OrgID: node.OrgID, NodeID: node.ID, VPNIP: ips[0], VPNKey: keys[0]}, req)
	writeMCPJSON(w, response)
}

// mcpResult closes an allowed call with the outcome the gateway saw upstream.
func (a *AgentChannel) mcpResult(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.mcp == nil {
		http.Error(w, "MCP gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	var req mcpwire.ResultRequest
	if !decodeMCPBody(w, r, 16<<10, &req) {
		return
	}
	a.writeMCPOutcome(w, r, a.mcp.Result(r.Context(), node.OrgID, node.ID, req))
}

// mcpTargets lists the agents homed on the calling gateway whose MCP server it discovers.
func (a *AgentChannel) mcpTargets(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.mcp == nil {
		http.Error(w, "MCP gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	targets, err := a.mcp.Targets(r.Context(), node.OrgID, node.ID)
	if err != nil {
		apierr.Write(w, r, err)
		return
	}
	writeMCPJSON(w, mcpwire.TargetsResponse{Targets: targets})
}

// mcpInventory stores the raw tool definitions the gateway observed for one of its agents.
func (a *AgentChannel) mcpInventory(w http.ResponseWriter, r *http.Request) {
	node, r, ok := a.authenticateAgent(w, r)
	if !ok {
		return
	}
	if a.mcp == nil {
		http.Error(w, "MCP gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	var report mcpwire.InventoryReport
	if !decodeMCPBody(w, r, mcpInventoryBodyLimit, &report) {
		return
	}
	a.writeMCPOutcome(w, r, a.mcp.Inventory(r.Context(), node.OrgID, node.ID, report))
}

func (a *AgentChannel) writeMCPOutcome(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, mcpdecision.ErrInvalid):
		http.Error(w, "invalid body", http.StatusBadRequest)
	case errors.Is(err, mcpdecision.ErrNotFound):
		// One answer for an unknown subject and for one that belongs to another gateway.
		http.Error(w, "not found", http.StatusNotFound)
	default:
		apierr.Write(w, r, err)
	}
}

func decodeMCPBody(w http.ResponseWriter, r *http.Request, limit int64, into interface{}) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit || json.Unmarshal(body, into) != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return false
	}
	return true
}

// writeMCPJSON answers with a body that may carry a credential for the gateway: never cacheable.
func writeMCPJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}
