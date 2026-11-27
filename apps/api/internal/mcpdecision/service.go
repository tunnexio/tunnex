package mcpdecision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolpolicy"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

// SystemActor attributes audit rows a gateway-forwarded request causes.
const SystemActor = "mcp-gateway"

// AuditCallDenied is written for every refused request of a resolved agent, with the reason.
const AuditCallDenied = "agent.mcp_tool_call.denied"

// MessageAuthorizationUnavailable is the -32020 message the agent-host proxy has always used when the
// stored credential for the MCP server cannot be produced.
const MessageAuthorizationUnavailable = "MCP authorization is unavailable"

var (
	// ErrInvalid means a gateway sent something that is not a well-formed report.
	ErrInvalid = errors.New("invalid MCP gateway request")
	// ErrNotFound means the call or agent a gateway named is not one it was given.
	ErrNotFound = errors.New("MCP gateway subject not found")
)

// Leaser hands out the credential for an agent's MCP server. It is called only after every other check has
// passed, so the token leaves the control plane for exactly one forwarded request and never reaches the
// agent host.
type Leaser interface {
	Lease(ctx context.Context, orgID, deviceID uuid.UUID, endpoint string) (string, time.Time, error)
}

// Evidence is who is asking: the gateway, from its mTLS certificate, and the tunnel peer it observed.
// Nothing in it comes from the agent.
type Evidence struct {
	OrgID  uuid.UUID
	NodeID uuid.UUID
	VPNIP  string
	VPNKey string
}

type Service struct {
	pool      *pgxpool.Pool
	q         *sqlc.Queries
	policy    *mcptoolpolicy.Service
	approvals *mcptoolapproval.Service
	oauth     Leaser
	limiter   RateLimiter
	logger    *slog.Logger
	now       func() time.Time
}

// New builds the decision service. oauth may be nil (no MCP server credential is ever attached). A nil
// limiter denies every rate-limited tool: a limit that cannot be counted is not treated as unlimited.
func New(pool *pgxpool.Pool, policy *mcptoolpolicy.Service, approvals *mcptoolapproval.Service, oauth Leaser, limiter RateLimiter, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{pool: pool, q: sqlc.New(pool), policy: policy, approvals: approvals, oauth: oauth, limiter: limiter, logger: logger, now: time.Now}
}

// call is everything known about one request while it is being decided.
type call struct {
	ev            Evidence
	deviceID      uuid.UUID
	method        string
	toolName      string
	endpoint      string
	serverName    string
	digest        *string
	policyVersion *int64
}

// Decide answers one MCP JSON-RPC request. It never returns an allow it is unsure of: any failure to read
// state is a denial. The checks run in a fixed order and the first refusal wins:
//
//	device, assigned profile, method, fresh gateway inventory, allow-list rule, definition pin,
//	observed schema, argument constraints, rate limit, credential, step-up.
func (s *Service) Decide(ctx context.Context, ev Evidence, req mcpwire.DecideRequest) mcpwire.DecideResponse {
	c := call{ev: ev, method: req.Method, toolName: req.ToolName}
	deviceID, ok := s.resolveDevice(ctx, ev)
	if !ok {
		// No agent is behind this evidence (a human device, a stale key, a forged address). There is no
		// agent to attribute a row to, and the caller learns nothing beyond the refusal.
		return denial(http.StatusForbidden, mcpwire.CodeDenied, mcpwire.MessageDenied, "")
	}
	c.deviceID = deviceID
	if c.method == "" || len(c.method) > 128 || len(c.toolName) > 512 {
		c.method, c.toolName = boundedMethod(c.method), ""
		return s.deny(ctx, c, mcpwire.ReasonMethod, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	endpoint, err := s.assignedEndpoint(ctx, ev.OrgID, deviceID)
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if endpoint == "" {
		return s.deny(ctx, c, mcpwire.ReasonNoProfile, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	c.endpoint = endpoint

	switch c.method {
	case "initialize", "notifications/initialized", "ping":
		// Session and transport methods cannot invoke a tool.
		c.toolName = ""
		return s.passthrough(ctx, c, nil)
	case "tools/list":
		c.toolName = ""
		callable, err := s.callableTools(ctx, c)
		if err != nil {
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		}
		return s.passthrough(ctx, c, callable)
	case "tools/call":
		return s.decideToolCall(ctx, c, req.Arguments)
	default:
		c.toolName = ""
		return s.deny(ctx, c, mcpwire.ReasonMethod, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
}

func (s *Service) decideToolCall(ctx context.Context, c call, arguments json.RawMessage) mcpwire.DecideResponse {
	if c.toolName == "" {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	digest, canonical, err := mcptoolapproval.CanonicalDigest(c.method, c.toolName, arguments)
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonArguments, http.StatusForbidden, mcpwire.CodeArgumentsDenied, "")
	}
	c.digest = &digest

	server, ok, err := s.freshServer(ctx, c)
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if !ok {
		return s.deny(ctx, c, mcpwire.ReasonNoInventory, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	c.serverName = server.ServerName

	policy, err := s.policy.Get(ctx, c.ev.OrgID, c.deviceID)
	if errors.Is(err, mcptoolpolicy.ErrNotFound) {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	version := policy.Version
	c.policyVersion = &version
	rule, ok := findRule(policy.Rules, c.endpoint, c.toolName)
	if !ok {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	tool, ok := server.Tool(c.toolName)
	if !ok {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	// The pin: the rule allows exactly the definition an administrator saw. An unpinned rule (one the
	// first gateway inventory could not match) is treated as changed, never as allowed.
	if rule.ToolDefinitionHash == "" || rule.ToolDefinitionHash != tool.ToolDefinitionHash || rule.ServerName != server.ServerName {
		return s.deny(ctx, c, mcpwire.ReasonDefinitionChanged, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if err := CheckArguments(tool.InputSchema, canonical); err != nil {
		return s.deny(ctx, c, mcpwire.ReasonSchema, http.StatusForbidden, mcpwire.CodeArgumentsDenied, "")
	}
	if err := CheckConstraints(rule.ArgumentConstraints, canonical); err != nil {
		return s.deny(ctx, c, mcpwire.ReasonArguments, http.StatusForbidden, mcpwire.CodeArgumentsDenied, "")
	}
	if rule.RateLimitPerMinute != nil {
		if s.limiter == nil {
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		}
		within, err := s.limiter.Allow(ctx, rateKey(c.deviceID, c.endpoint, c.toolName), *rule.RateLimitPerMinute, RateWindow)
		if err != nil {
			s.logger.Warn("mcp_rate_limit_unavailable", slog.String("device_id", c.deviceID.String()), slog.String("error", err.Error()))
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		}
		if !within {
			return s.deny(ctx, c, mcpwire.ReasonRateLimit, http.StatusTooManyRequests, mcpwire.CodeRateLimited, "")
		}
	}
	// The credential is produced before an approval is spent, so a lease that fails does not burn one.
	authorization := s.authorization(ctx, c)
	var approvalID pgtype.UUID
	if rule.StepUpRequired {
		if s.approvals == nil {
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		}
		request, outcome, err := s.approvals.Decide(ctx, c.ev.OrgID, c.deviceID, mcptoolapproval.Identity{
			PolicyVersion: policy.Version, Endpoint: c.endpoint, ServerName: server.ServerName, ToolName: c.toolName,
			InputSchemaHash: tool.InputSchemaHash, RequestDigest: digest, ToolDefinitionHash: tool.ToolDefinitionHash, Arguments: canonical,
		})
		switch {
		case err != nil:
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		case outcome == mcptoolapproval.OutcomeDenied:
			return s.deny(ctx, c, mcpwire.ReasonStepUpDenied, http.StatusForbidden, mcpwire.CodeDenied, "")
		case outcome != mcptoolapproval.OutcomeAllowed:
			return s.deny(ctx, c, mcpwire.ReasonStepUpRequired, http.StatusForbidden, mcpwire.CodeStepUpRequired, request.ID.String())
		}
		approvalID = pgtype.UUID{Bytes: request.ID, Valid: true}
	}
	row, err := s.q.InsertAgentMCPToolActivity(ctx, sqlc.InsertAgentMCPToolActivityParams{
		OrgID: c.ev.OrgID, DeviceID: c.deviceID, NodeID: pgtype.UUID{Bytes: c.ev.NodeID, Valid: true}, Endpoint: c.endpoint, ServerName: c.serverName,
		Method: c.method, ToolName: c.toolName, ArgumentsDigest: c.digest, Decision: mcpwire.DecisionAllow, Reason: "",
		PolicyVersion: c.policyVersion, ApprovalRequestID: approvalID, ResultStatus: "pending",
	})
	if err != nil {
		// An allowed call that cannot be recorded is not forwarded.
		s.logger.Error("mcp_activity_write_failed", slog.String("device_id", c.deviceID.String()), slog.String("error", err.Error()))
		return denial(http.StatusForbidden, mcpwire.CodeDenied, mcpwire.MessageDenied, "")
	}
	return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: c.endpoint, Authorization: authorization, CallID: row.ID.String()}
}

// passthrough allows a session method. It writes no activity row: activity is what an agent did with a
// tool, and these methods cannot call one.
func (s *Service) passthrough(ctx context.Context, c call, callable []string) mcpwire.DecideResponse {
	return mcpwire.DecideResponse{Decision: mcpwire.DecisionAllow, Upstream: c.endpoint, Authorization: s.authorization(ctx, c), CallableTools: callable}
}

// authorization leases the stored credential for the agent's MCP server, if it has one. With no connected
// credential the request is forwarded without one, as the agent-host proxy did; a caller-supplied
// credential is never forwarded by the gateway.
func (s *Service) authorization(ctx context.Context, c call) string {
	if s.oauth == nil {
		return ""
	}
	token, _, err := s.oauth.Lease(ctx, c.ev.OrgID, c.deviceID, c.endpoint)
	if err != nil || token == "" {
		return ""
	}
	return "Bearer " + token
}

func (s *Service) resolveDevice(ctx context.Context, ev Evidence) (uuid.UUID, bool) {
	ip, err := netip.ParseAddr(ev.VPNIP)
	raw, keyErr := base64.StdEncoding.DecodeString(ev.VPNKey)
	if s == nil || s.q == nil || ev.OrgID == uuid.Nil || ev.NodeID == uuid.Nil || err != nil || !ip.Is4() || ip.IsUnspecified() || ip.String() != ev.VPNIP || keyErr != nil || len(raw) != 32 {
		return uuid.Nil, false
	}
	address := ip.String()
	row, err := s.q.ResolveAgentDeviceByTunnelEvidence(ctx, sqlc.ResolveAgentDeviceByTunnelEvidenceParams{OrgID: ev.OrgID, NodeID: ev.NodeID, PublicKey: ev.VPNKey, AssignedIp: &address})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("mcp_device_resolution_failed", slog.String("node_id", ev.NodeID.String()), slog.String("error", err.Error()))
		}
		return uuid.Nil, false
	}
	return row.ID, true
}

// assignedEndpoint returns the one MCP endpoint the agent inherits, or "" when it has none or more than
// one (a state the assignment trigger prevents; never pick).
func (s *Service) assignedEndpoint(ctx context.Context, orgID, deviceID uuid.UUID) (string, error) {
	profiles, err := s.q.ListAgentMCPProfilesForDevice(ctx, sqlc.ListAgentMCPProfilesForDeviceParams{OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return "", err
	}
	if len(profiles) != 1 {
		return "", nil
	}
	endpoint := strings.TrimSpace(profiles[0].Endpoint)
	if !validEndpoint(endpoint) {
		return "", nil
	}
	return endpoint, nil
}

func validEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// freshServer returns the gateway's own, recent, healthy observation of the agent's endpoint. A list the
// agent host reported, an old one, or a failed discovery is no inventory.
func (s *Service) freshServer(ctx context.Context, c call) (mcptoolpolicy.InventoryServer, bool, error) {
	inventory, err := s.policy.LoadInventory(ctx, c.ev.OrgID, c.deviceID)
	if errors.Is(err, mcptoolpolicy.ErrNotFound) {
		return mcptoolpolicy.InventoryServer{}, false, nil
	}
	if err != nil {
		return mcptoolpolicy.InventoryServer{}, false, err
	}
	now := s.now().UTC()
	if inventory.Source != mcptoolpolicy.SourceGateway || now.Sub(inventory.ObservedAt) > mcptoolpolicy.InventoryFreshness || inventory.ObservedAt.After(now.Add(time.Minute)) {
		return mcptoolpolicy.InventoryServer{}, false, nil
	}
	server, ok := inventory.Server(c.endpoint)
	if !ok || server.Status != mcptoolpolicy.StatusHealthy {
		return mcptoolpolicy.InventoryServer{}, false, nil
	}
	return server, true, nil
}

// callableTools is what the gateway filters a tools/list answer to: the tools a call would not be refused
// for on policy or definition grounds right now. With no usable inventory or policy it is empty, and the
// gateway shows the agent no tools.
func (s *Service) callableTools(ctx context.Context, c call) ([]string, error) {
	server, ok, err := s.freshServer(ctx, c)
	if err != nil || !ok {
		return nil, err
	}
	policy, err := s.policy.Get(ctx, c.ev.OrgID, c.deviceID)
	if errors.Is(err, mcptoolpolicy.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rule := range policy.Rules {
		if rule.Endpoint != c.endpoint || rule.ToolDefinitionHash == "" || rule.ServerName != server.ServerName {
			continue
		}
		if tool, ok := server.Tool(rule.ToolName); ok && tool.ToolDefinitionHash == rule.ToolDefinitionHash {
			out = append(out, rule.ToolName)
		}
	}
	sort.Strings(out)
	return out, nil
}

func findRule(rules []mcptoolpolicy.Rule, endpoint, tool string) (mcptoolpolicy.Rule, bool) {
	for _, rule := range rules {
		if rule.Endpoint == endpoint && rule.ToolName == tool {
			return rule, true
		}
	}
	return mcptoolpolicy.Rule{}, false
}

// deny records a refusal and returns it. The activity row and the audit row are written together. A
// repeat of a call that is still waiting for approval is not audited again: the request it waits on was
// audited when it was opened.
func (s *Service) deny(ctx context.Context, c call, reason string, status, code int, requestID string) mcpwire.DecideResponse {
	message := mcpwire.Messages[code]
	if err := s.recordDenial(ctx, c, reason, reason != mcpwire.ReasonStepUpRequired); err != nil {
		s.logger.Error("mcp_denial_write_failed", slog.String("device_id", c.deviceID.String()), slog.String("reason", reason), slog.String("error", err.Error()))
	}
	return denial(status, code, message, requestID)
}

func (s *Service) recordDenial(ctx context.Context, c call, reason string, audited bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := s.q.WithTx(tx).InsertAgentMCPToolActivity(ctx, sqlc.InsertAgentMCPToolActivityParams{
		OrgID: c.ev.OrgID, DeviceID: c.deviceID, NodeID: pgtype.UUID{Bytes: c.ev.NodeID, Valid: true}, Endpoint: c.endpoint, ServerName: c.serverName,
		Method: c.method, ToolName: c.toolName, ArgumentsDigest: c.digest, Decision: mcpwire.DecisionDeny, Reason: reason,
		PolicyVersion: c.policyVersion, ResultStatus: "not_forwarded",
	}); err != nil {
		return err
	}
	if audited {
		metadata := map[string]any{"reason": reason, "method": c.method, "tool_name": c.toolName, "endpoint": c.endpoint, "server_name": c.serverName, "node_id": c.ev.NodeID.String()}
		if c.digest != nil {
			metadata["arguments_digest"] = *c.digest
		}
		if c.policyVersion != nil {
			metadata["policy_version"] = *c.policyVersion
		}
		raw, _ := json.Marshal(metadata)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata) VALUES ($1,$2,$3,'agent',$4,$5)`, c.ev.OrgID, SystemActor, AuditCallDenied, c.deviceID.String(), raw); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func denial(status, code int, message, requestID string) mcpwire.DecideResponse {
	out := mcpwire.DecideResponse{Decision: mcpwire.DecisionDeny, Error: &mcpwire.Error{HTTPStatus: status, Code: code, Message: message}}
	if requestID != "" {
		out.Error.Data = &mcpwire.ErrorData{RequestID: requestID}
	}
	return out
}

func boundedMethod(method string) string {
	if method == "" {
		return "(none)"
	}
	if len(method) > 128 {
		return strings.ToValidUTF8(method[:128], "")
	}
	return method
}

// Result closes an allowed call with what the gateway saw upstream. Only the gateway that was given the
// call can close it, and only once.
func (s *Service) Result(ctx context.Context, orgID, nodeID uuid.UUID, req mcpwire.ResultRequest) error {
	callID, err := uuid.Parse(req.CallID)
	if err != nil || orgID == uuid.Nil || nodeID == uuid.Nil {
		return ErrInvalid
	}
	switch req.Status {
	case mcpwire.ResultOK, mcpwire.ResultError, mcpwire.ResultUpstreamUnavailable:
	default:
		return ErrInvalid
	}
	var upstream *int32
	if req.UpstreamHTTPStatus != 0 {
		if req.UpstreamHTTPStatus < 100 || req.UpstreamHTTPStatus > 599 {
			return ErrInvalid
		}
		value := int32(req.UpstreamHTTPStatus)
		upstream = &value
	}
	rows, err := s.q.CompleteAgentMCPToolActivity(ctx, sqlc.CompleteAgentMCPToolActivityParams{ResultStatus: req.Status, UpstreamHttpStatus: upstream, ID: callID, OrgID: orgID, NodeID: pgtype.UUID{Bytes: nodeID, Valid: true}})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

// Targets lists the agents homed on the gateway that have exactly one valid MCP endpoint, each with the
// credential (if any) the gateway needs to discover that agent's tools.
func (s *Service) Targets(ctx context.Context, orgID, nodeID uuid.UUID) ([]mcpwire.Target, error) {
	if orgID == uuid.Nil || nodeID == uuid.Nil {
		return nil, ErrInvalid
	}
	rows, err := s.q.ListAgentMCPTargetsForNode(ctx, sqlc.ListAgentMCPTargetsForNodeParams{OrgID: orgID, NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	profiles := map[uuid.UUID]int{}
	for _, row := range rows {
		profiles[row.DeviceID]++
	}
	out := make([]mcpwire.Target, 0, len(rows))
	for _, row := range rows {
		endpoint := strings.TrimSpace(row.Endpoint)
		if profiles[row.DeviceID] != 1 || row.AssignedIp == nil || !validEndpoint(endpoint) {
			continue
		}
		target := mcpwire.Target{DeviceID: row.DeviceID.String(), VPNIP: *row.AssignedIp, Endpoint: endpoint}
		target.Authorization = s.authorization(ctx, call{ev: Evidence{OrgID: orgID, NodeID: nodeID}, deviceID: row.DeviceID, endpoint: endpoint})
		out = append(out, target)
	}
	return out, nil
}

// Inventory stores what the gateway discovered for one of its agents. Hashes are computed here from the
// raw definitions; the report carries none.
func (s *Service) Inventory(ctx context.Context, orgID, nodeID uuid.UUID, report mcpwire.InventoryReport) error {
	deviceID, err := uuid.Parse(report.DeviceID)
	if err != nil || orgID == uuid.Nil || nodeID == uuid.Nil || !validEndpoint(report.Endpoint) {
		return ErrInvalid
	}
	observation := mcptoolpolicy.GatewayObservation{Endpoint: report.Endpoint, Status: report.Status, ServerName: report.ServerName, ProtocolVersion: report.ProtocolVersion, LatencyMillis: report.LatencyMillis, Tools: make([]mcptoolpolicy.ObservedTool, 0, len(report.Tools))}
	for _, tool := range report.Tools {
		observation.Tools = append(observation.Tools, mcptoolpolicy.ObservedTool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema})
	}
	err = s.policy.RecordGatewayInventory(ctx, orgID, nodeID, deviceID, observation, s.now())
	switch {
	case errors.Is(err, mcptoolpolicy.ErrNotFound), errors.Is(err, mcptoolpolicy.ErrEndpointNotAssigned):
		return ErrNotFound
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return ErrInvalid
	}
	return err
}
