package mcpdecision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
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
	// waitHold and waitTick bound a held call; zero means the defaults (45 seconds, re-read every second).
	waitHold, waitTick time.Duration
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
	// server is the assigned MCP server the request is for. policySource and policyGroup say which
	// policy decided (the agent's own or its group's); they are set together with policyVersion.
	server       mcptoolpolicy.AssignedServer
	policySource *string
	policyGroup  pgtype.UUID
}

// Decide answers one MCP JSON-RPC request. It never returns an allow it is unsure of: any failure to read
// state is a denial. The checks run in a fixed order and the first refusal wins:
//
//	device, assigned server, method, fresh gateway inventory, allow-list rule, definition pin,
//	observed schema, argument constraints, rate limit, credential, step-up.
//
// An agent can have several MCP servers. The request names one by its server name; no name means the
// first one (the earliest assignment), which is what a client that predates server names reaches.
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
	// MCP off for the organization: nothing is forwarded. The refusal is the ordinary policy denial.
	if !s.mcpOn(ctx, ev.OrgID) {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if req.Server != "" && !mcpwire.ValidServerName(req.Server) {
		return s.deny(ctx, c, mcpwire.ReasonNoProfile, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	server, found, err := s.assignedServer(ctx, ev.OrgID, deviceID, req.Server)
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if !found {
		return s.deny(ctx, c, mcpwire.ReasonNoProfile, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	c.server, c.endpoint = server, server.Endpoint

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

	// One policy decides for this server: the agent's own where it overrides the endpoint, otherwise the
	// group's. No policy at all denies.
	policy, err := s.policy.Effective(ctx, c.ev.OrgID, c.deviceID, c.server)
	if err != nil {
		return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	if !policy.Found {
		return s.deny(ctx, c, mcpwire.ReasonPolicy, http.StatusForbidden, mcpwire.CodeDenied, "")
	}
	version, source := policy.Version, policy.Source
	c.policyVersion, c.policySource = &version, &source
	if policy.GroupID != uuid.Nil {
		c.policyGroup = pgtype.UUID{Bytes: policy.GroupID, Valid: true}
	}
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
			PolicySource: policy.Source, PolicyGroupID: policy.GroupID,
			PolicyVersion: policy.Version, Endpoint: c.endpoint, ServerName: server.ServerName, ToolName: c.toolName,
			InputSchemaHash: tool.InputSchemaHash, RequestDigest: digest, ToolDefinitionHash: tool.ToolDefinitionHash, Arguments: canonical,
		})
		switch {
		case err != nil:
			return s.deny(ctx, c, mcpwire.ReasonUnavailable, http.StatusForbidden, mcpwire.CodeDenied, "")
		case outcome == mcptoolapproval.OutcomeDenied:
			return s.deny(ctx, c, mcpwire.ReasonStepUpDenied, http.StatusForbidden, mcpwire.CodeDenied, "")
		case outcome != mcptoolapproval.OutcomeAllowed:
			response := s.deny(ctx, c, mcpwire.ReasonStepUpRequired, http.StatusForbidden, mcpwire.CodeStepUpRequired, request.ID.String())
			// Only a runtime that said it keeps the call open is told to wait; any other gets the
			// refusal at once, as before.
			if s.holdCapable(ctx, c) {
				response.HoldSeconds = mcpwire.MaxHoldSeconds
			}
			return response
		}
		approvalID = pgtype.UUID{Bytes: request.ID, Valid: true}
	}
	row, err := s.q.InsertAgentMCPToolActivity(ctx, sqlc.InsertAgentMCPToolActivityParams{
		OrgID: c.ev.OrgID, DeviceID: c.deviceID, NodeID: pgtype.UUID{Bytes: c.ev.NodeID, Valid: true}, Endpoint: c.endpoint, ServerName: c.serverName,
		Method: c.method, ToolName: c.toolName, ArgumentsDigest: c.digest, Decision: mcpwire.DecisionAllow, Reason: "",
		PolicyVersion: c.policyVersion, ApprovalRequestID: approvalID, ResultStatus: "pending",
		PolicySource: c.policySource, PolicyGroupID: c.policyGroup,
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

// assignedServer returns the MCP server a request is for: the one it names, or the first when it names
// none. A server whose endpoint is not a usable address is not offered.
func (s *Service) assignedServer(ctx context.Context, orgID, deviceID uuid.UUID, name string) (mcptoolpolicy.AssignedServer, bool, error) {
	servers, err := mcptoolpolicy.AssignedServers(ctx, s.q, orgID, deviceID)
	if err != nil {
		return mcptoolpolicy.AssignedServer{}, false, err
	}
	usable := servers[:0]
	for _, server := range servers {
		if validEndpoint(server.Endpoint) {
			usable = append(usable, server)
		}
	}
	server, ok := mcptoolpolicy.FindServer(usable, name)
	return server, ok, nil
}

// mcpOn reports whether MCP is turned on for the organization. No setting, or any failure to read it, is off.
func (s *Service) mcpOn(ctx context.Context, orgID uuid.UUID) bool {
	setting, err := s.q.GetOrganizationMCPSetting(ctx, orgID)
	return err == nil && setting.Enabled
}

// holdCapable reports whether the agent's runtime declared that it keeps an MCP call open while an
// approval is pending. Any doubt is "no".
func (s *Service) holdCapable(ctx context.Context, c call) bool {
	row, err := s.q.GetAgentRuntimeDeclarations(ctx, sqlc.GetAgentRuntimeDeclarationsParams{DeviceID: c.deviceID, OrgID: c.ev.OrgID})
	return err == nil && row.McpHoldCapableAt.Valid
}

func validEndpoint(endpoint string) bool { return mcptoolpolicy.ValidEndpoint(endpoint) }

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
	// The row's time is the newest report for any of the agent's servers. With several servers each one
	// must itself have been seen recently.
	if seen, err := time.Parse(time.RFC3339Nano, server.ObservedAt); err == nil && (now.Sub(seen) > mcptoolpolicy.InventoryFreshness || seen.After(now.Add(time.Minute))) {
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
	policy, err := s.policy.Effective(ctx, c.ev.OrgID, c.deviceID, c.server)
	if err != nil || !policy.Found {
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
		PolicySource: c.policySource, PolicyGroupID: c.policyGroup,
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
		if c.policySource != nil {
			metadata["policy_source"] = *c.policySource
		}
		if c.policyGroup.Valid {
			metadata["policy_group_id"] = uuid.UUID(c.policyGroup.Bytes).String()
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

// Targets lists what the gateway discovers: every MCP server of every agent homed on it, each with the
// credential (if any) needed to read that server's tools, and the addresses an administrator asked it to
// read while connecting a server. A preview target names no agent and carries no credential.
func (s *Service) Targets(ctx context.Context, orgID, nodeID uuid.UUID) ([]mcpwire.Target, error) {
	if orgID == uuid.Nil || nodeID == uuid.Nil {
		return nil, ErrInvalid
	}
	if !s.mcpOn(ctx, orgID) {
		return []mcpwire.Target{}, nil
	}
	rows, err := s.q.ListAgentMCPTargetsForNode(ctx, sqlc.ListAgentMCPTargetsForNodeParams{OrgID: orgID, NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	type key struct {
		device   uuid.UUID
		endpoint string
	}
	seen := make(map[key]bool, len(rows))
	out := make([]mcpwire.Target, 0, len(rows))
	for _, row := range rows {
		endpoint := strings.TrimSpace(row.Endpoint)
		k := key{row.DeviceID, endpoint}
		if seen[k] || row.AssignedIp == nil || !validEndpoint(endpoint) {
			continue
		}
		seen[k] = true
		target := mcpwire.Target{DeviceID: row.DeviceID.String(), VPNIP: *row.AssignedIp, Endpoint: endpoint}
		target.Authorization = s.authorization(ctx, call{ev: Evidence{OrgID: orgID, NodeID: nodeID}, deviceID: row.DeviceID, endpoint: endpoint})
		out = append(out, target)
	}
	previews, err := s.q.ListWaitingAgentMCPConnectionPreviewsForNode(ctx, sqlc.ListWaitingAgentMCPConnectionPreviewsForNodeParams{OrgID: orgID, NodeID: pgtype.UUID{Bytes: nodeID, Valid: true}})
	if err != nil {
		return nil, err
	}
	for _, preview := range previews {
		if validEndpoint(preview.Endpoint) {
			out = append(out, mcpwire.Target{PreviewID: preview.ID.String(), Endpoint: preview.Endpoint})
		}
	}
	return out, nil
}

// Inventory stores what the gateway discovered for one MCP server of one of its agents, or for a
// connection preview. Hashes are computed here from the raw definitions; the report carries none.
func (s *Service) Inventory(ctx context.Context, orgID, nodeID uuid.UUID, report mcpwire.InventoryReport) error {
	if orgID == uuid.Nil || nodeID == uuid.Nil || !validEndpoint(report.Endpoint) {
		return ErrInvalid
	}
	observation := mcptoolpolicy.GatewayObservation{Endpoint: report.Endpoint, Status: report.Status, ServerName: report.ServerName, ProtocolVersion: report.ProtocolVersion, LatencyMillis: report.LatencyMillis, Tools: make([]mcptoolpolicy.ObservedTool, 0, len(report.Tools))}
	for _, tool := range report.Tools {
		observation.Tools = append(observation.Tools, mcptoolpolicy.ObservedTool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema})
	}
	if !s.mcpOn(ctx, orgID) {
		return ErrNotFound
	}
	var err error
	if report.PreviewID != "" {
		previewID, parseErr := uuid.Parse(report.PreviewID)
		if parseErr != nil || report.DeviceID != "" {
			return ErrInvalid
		}
		err = s.policy.CompletePreview(ctx, orgID, nodeID, previewID, observation, s.now())
	} else {
		deviceID, parseErr := uuid.Parse(report.DeviceID)
		if parseErr != nil {
			return ErrInvalid
		}
		err = s.policy.RecordGatewayInventory(ctx, orgID, nodeID, deviceID, observation, s.now())
	}
	switch {
	case errors.Is(err, mcptoolpolicy.ErrNotFound), errors.Is(err, mcptoolpolicy.ErrEndpointNotAssigned):
		return ErrNotFound
	case errors.Is(err, mcptoolpolicy.ErrInvalid):
		return ErrInvalid
	}
	return err
}
