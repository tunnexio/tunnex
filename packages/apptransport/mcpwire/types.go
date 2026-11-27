// Package mcpwire is the wire contract between a gateway's MCP listener and the control plane (AI-SEC-2).
//
// The gateway identifies the calling agent from tunnel evidence it observed itself (the source address and
// WireGuard key of the peer) and asks the control plane for a decision over its node mTLS channel. The
// control plane owns the decision: assigned profile, tool allow-list, definition pin, argument checks, rate
// limit and step-up. The gateway forwards to the MCP server only on an allow, using only the upstream and
// the credential the decision names.
//
// Types only. The control plane (apps/api) and the gateway (apps/node) are separate modules that both import
// this stdlib-only package, so there is exactly one description of the wire.
package mcpwire

import (
	"encoding/json"
	"errors"
)

// Paths on the node mTLS channel. They are hand-routed beside the other agent-channel routes and are not part
// of the public OpenAPI contract.
const (
	PathDecide    = "/agent/mcp/decide"
	PathResult    = "/agent/mcp/result"
	PathTargets   = "/agent/mcp/targets"
	PathInventory = "/agent/mcp/inventory"
)

// Evidence headers set by the gateway from what it observed on the tunnel. The control plane requires exactly
// one of each and takes the organization and node from the mTLS certificate. Anything of the same name sent
// by the caller is discarded by the gateway before it sets its own.
const (
	HeaderVPNIP  = "X-Tunnex-VPN-IP"
	HeaderVPNKey = "X-Tunnex-VPN-Key"
)

// Gateway capabilities reported to the control plane.
const (
	CapabilityGatewayReady   = "mcp_gateway_ready"
	CapabilityGatewayAddress = "mcp_gateway_address"
)

// ListenerPort is the TCP port of the gateway MCP listener on its tunnel address.
const ListenerPort = 8084

// MaxRequestBytes bounds one MCP request body read by the gateway.
const MaxRequestBytes = 1 << 20

// Decisions.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// JSON-RPC error codes and messages. They are the ones the agent-host proxy has always returned.
const (
	CodeDenied              = -32100
	CodeArgumentsDenied     = -32101
	CodeRateLimited         = -32102
	CodeStepUpRequired      = -32103
	CodeUpstreamUnavailable = -32020

	MessageDenied              = "MCP tool is denied by policy"
	MessageArgumentsDenied     = "MCP tool arguments are denied by policy"
	MessageRateLimited         = "MCP tool rate limit exceeded"
	MessageStepUpRequired      = "MCP tool requires step-up approval"
	MessageUpstreamUnavailable = "MCP upstream is unavailable"
)

// Messages maps each policy error code to its message.
var Messages = map[int]string{
	CodeDenied:              MessageDenied,
	CodeArgumentsDenied:     MessageArgumentsDenied,
	CodeRateLimited:         MessageRateLimited,
	CodeStepUpRequired:      MessageStepUpRequired,
	CodeUpstreamUnavailable: MessageUpstreamUnavailable,
}

// Deny reasons recorded in activity and audit. Not sent to the agent.
const (
	ReasonNoProfile         = "no_profile"
	ReasonNoInventory       = "no_inventory"
	ReasonPolicy            = "policy"
	ReasonMethod            = "method"
	ReasonDefinitionChanged = "definition_changed"
	ReasonArguments         = "arguments"
	ReasonSchema            = "schema"
	ReasonRateLimit         = "rate_limit"
	ReasonStepUpRequired    = "step_up_required"
	ReasonStepUpDenied      = "step_up_denied"
	ReasonUnavailable       = "unavailable"
)

// Result statuses reported back for an allowed call.
const (
	ResultOK                  = "ok"
	ResultError               = "error"
	ResultUpstreamUnavailable = "upstream_unavailable"
)

// DecideRequest is what the gateway sends for one MCP JSON-RPC request. Arguments are the call's arguments
// exactly as the agent sent them; the control plane canonicalizes them itself.
type DecideRequest struct {
	Method          string          `json:"method"`
	ToolName        string          `json:"tool_name,omitempty"`
	Arguments       json.RawMessage `json:"arguments,omitempty"`
	ProtocolVersion string          `json:"protocol_version,omitempty"`
}

// ErrorData is the optional JSON-RPC error data.
type ErrorData struct {
	// RequestID is the step-up approval request the agent's retry will be matched against.
	RequestID string `json:"request_id,omitempty"`
}

// Error is the refusal the gateway returns to the agent verbatim as a JSON-RPC error with HTTPStatus.
type Error struct {
	HTTPStatus int        `json:"http_status"`
	Code       int        `json:"code"`
	Message    string     `json:"message"`
	Data       *ErrorData `json:"data,omitempty"`
}

// DecideResponse is the control plane's answer.
//
// On an allow, Upstream is the only URL the gateway may forward to and Authorization, when present, is the
// credential for that single call; the gateway never returns it to the agent. CallableTools is set for
// tools/list so the gateway can filter the server's answer to what the agent may call. CallID identifies the
// activity row the gateway closes with a ResultRequest.
type DecideResponse struct {
	Decision      string   `json:"decision"`
	Upstream      string   `json:"upstream,omitempty"`
	Authorization string   `json:"authorization,omitempty"`
	CallableTools []string `json:"callable_tools,omitempty"`
	CallID        string   `json:"call_id,omitempty"`
	Error         *Error   `json:"error,omitempty"`
}

// ErrInvalidDecision means the control plane's answer is not one the gateway may act on. The gateway treats
// it as a denial and forwards nothing.
var ErrInvalidDecision = errors.New("mcpwire: invalid decision")

// Valid reports whether the response is internally consistent: an allow names an upstream and carries no
// error; a deny carries an error and neither an upstream nor a credential.
func (r DecideResponse) Valid() error {
	switch r.Decision {
	case DecisionAllow:
		if r.Upstream == "" || r.Error != nil {
			return ErrInvalidDecision
		}
	case DecisionDeny:
		if r.Error == nil || r.Upstream != "" || r.Authorization != "" {
			return ErrInvalidDecision
		}
	default:
		return ErrInvalidDecision
	}
	return nil
}

// ResultRequest closes an allowed call.
type ResultRequest struct {
	CallID             string `json:"call_id"`
	Status             string `json:"status"`
	UpstreamHTTPStatus int    `json:"upstream_http_status,omitempty"`
}

// Target is one agent whose MCP server the gateway discovers. Authorization, when present, is the credential
// for discovery against Endpoint and is never logged or returned to the agent.
type Target struct {
	DeviceID      string `json:"device_id"`
	VPNIP         string `json:"vpn_ip"`
	Endpoint      string `json:"endpoint"`
	Authorization string `json:"authorization,omitempty"`
}

// TargetsResponse lists the agents homed on the calling gateway that have an MCP profile.
type TargetsResponse struct {
	Targets []Target `json:"targets"`
}

// ObservedTool is a tool definition exactly as the MCP server returned it. The control plane computes every
// hash from these raw fields and ignores any hash a caller supplies.
type ObservedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// InventoryReport is what the gateway observed for one agent's MCP server.
type InventoryReport struct {
	DeviceID        string         `json:"device_id"`
	Endpoint        string         `json:"endpoint"`
	Status          string         `json:"status"` // healthy | unavailable | unauthorized | invalid
	ServerName      string         `json:"server_name,omitempty"`
	ProtocolVersion string         `json:"protocol_version,omitempty"`
	LatencyMillis   int64          `json:"latency_millis,omitempty"`
	Tools           []ObservedTool `json:"tools"`
}
