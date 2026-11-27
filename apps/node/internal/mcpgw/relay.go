// Package mcpgw is the gateway's MCP listener (AI-SEC-2).
//
// An agent reaches its MCP server only through this listener, on the gateway's tunnel address. The
// gateway identifies the caller from what it observed itself (the tunnel source address and the WireGuard
// key that owns it), asks the control plane for a decision over the node mTLS channel, and forwards to
// the MCP server only on an allow, only to the upstream that decision names, with only the credential
// that decision carries. The agent host never holds that credential and cannot go around the policy: the
// compiled policy denies its direct path to the server.
package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/aivpn"
	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

const (
	// Path is the one path the listener serves.
	Path = "/mcp"
	// UpstreamTimeout bounds connecting to the MCP server and receiving its response headers, in total.
	UpstreamTimeout = 5 * time.Second
	// decideTimeout bounds one decision on the node channel.
	decideTimeout = 10 * time.Second
	// maxCallDuration bounds one forwarded call, including a streamed answer.
	maxCallDuration = 5 * time.Minute
	maxConcurrent   = 64

	messageDecisionUnavailable = "MCP policy decision is unavailable"
)

// Control is the control-plane side of the mcpwire contract, on the node mTLS channel.
type Control interface {
	MCPDecide(ctx context.Context, vpnIP, vpnKey string, request mcpwire.DecideRequest) (mcpwire.DecideResponse, error)
	MCPResult(ctx context.Context, vpnIP, vpnKey string, result mcpwire.ResultRequest) error
	MCPTargets(ctx context.Context) ([]mcpwire.Target, error)
	MCPInventory(ctx context.Context, report mcpwire.InventoryReport) error
}

// NewUpstreamTransport is the transport to MCP servers. It uses no proxy from the environment, shares no
// connection between calls (each carries its own caller's credential) and is never asked to follow a
// redirect: the relay calls RoundTrip directly.
func NewUpstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: UpstreamTimeout}).DialContext,
		TLSHandshakeTimeout:    UpstreamTimeout,
		ResponseHeaderTimeout:  UpstreamTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
}

// Handler must ONLY be served by a listener bound to the WireGuard interface. The caller is whoever owns
// the connection's source address in the kernel WireGuard peer table; nothing the caller sends
// (Authorization, cookies, forwarded-for or identity headers) is used or forwarded.
func Handler(host string, control Control, upstream http.RoundTripper, peers aivpn.KernelPeers, logger *slog.Logger) http.Handler {
	return &relay{host: host, control: control, upstream: upstream, peers: peers, logger: logger,
		headerTimeout: UpstreamTimeout, slots: make(chan struct{}, maxConcurrent)}
}

type relay struct {
	host          string
	control       Control
	upstream      http.RoundTripper
	peers         aivpn.KernelPeers
	logger        *slog.Logger
	headerTimeout time.Duration
	slots         chan struct{}
}

func (h *relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestHost := r.Host
	if name, _, err := net.SplitHostPort(requestHost); err == nil {
		requestHost = name
	}
	if !strings.EqualFold(requestHost, h.host) {
		writeError(w, http.StatusMisdirectedRequest, codeInvalidRequest, "MCP gateway does not serve this host", nil)
		return
	}
	if r.URL.Path != Path || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeError(w, http.StatusNotFound, codeInvalidRequest, "MCP gateway serves "+Path+" only", nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, codeInvalidRequest, "MCP gateway accepts POST only", nil)
		return
	}
	// A browser on the agent host can reach the tunnel address too. A cross-site page cannot send a JSON
	// content type without a preflight this listener never answers, and always sends an Origin.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Origin")) != 0 {
		writeError(w, http.StatusForbidden, codeInvalidRequest, "MCP gateway accepts JSON requests only", nil)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeError(w, http.StatusTooManyRequests, codeTransport, "MCP gateway is busy", nil)
		return
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeInvalidRequest, "MCP caller is not a VPN device", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), maxCallDuration)
	defer cancel()
	readback, err := h.peers(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeTransport, "VPN identity is unavailable", nil)
		return
	}
	key, err := aivpn.PeerKey(readback, source)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeInvalidRequest, "MCP caller is not a VPN device", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpwire.MaxRequestBytes))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(w, status, codeInvalidRequest, "MCP request body is invalid", nil)
		return
	}
	req, invalid := parseRequest(body)
	if invalid != nil {
		writeError(w, invalid.status, invalid.code, invalid.message, nil)
		return
	}
	protocol, invalid := checkMirrors(req, r.Header)
	if invalid != nil {
		writeError(w, invalid.status, invalid.code, invalid.message, nil)
		return
	}

	decideCtx, decideCancel := context.WithTimeout(ctx, decideTimeout)
	decision, err := h.control.MCPDecide(decideCtx, source, key, mcpwire.DecideRequest{
		Method: req.Method, ToolName: req.ToolName, Arguments: req.Arguments, ProtocolVersion: protocol,
	})
	decideCancel()
	// No decision, or one that is not internally consistent, is a denial: nothing is forwarded.
	if err != nil || decision.Valid() != nil {
		h.logger.Warn("mcp_gateway_decision_unavailable", "source", source)
		writeError(w, http.StatusServiceUnavailable, codeTransport, messageDecisionUnavailable, nil)
		return
	}
	if decision.Decision != mcpwire.DecisionAllow {
		status := decision.Error.HTTPStatus
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		writeError(w, status, decision.Error.Code, decision.Error.Message, decision.Error.Data)
		return
	}
	h.forward(ctx, w, r, forwarded{source: source, key: key, method: req.Method, body: body, decision: decision})
}

type forwarded struct {
	source, key string
	method      string
	body        []byte
	decision    mcpwire.DecideResponse
}

// forward sends the request to the decision's upstream and relays the answer. The upstream URL and the
// credential come from the decision and from nowhere else.
func (h *relay) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, f forwarded) {
	unavailable := func(status string, upstreamStatus int) {
		h.report(f, status, upstreamStatus)
		writeError(w, http.StatusBadGateway, mcpwire.CodeUpstreamUnavailable, mcpwire.MessageUpstreamUnavailable, nil)
	}
	target, err := url.Parse(f.decision.Upstream)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Fragment != "" {
		unavailable(mcpwire.ResultUpstreamUnavailable, 0)
		return
	}
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(f.body))
	if err != nil {
		unavailable(mcpwire.ResultUpstreamUnavailable, 0)
		return
	}
	// The outbound headers are built from nothing: only the MCP transport headers are copied, so no
	// identity, forwarding or credential header of the caller can reach the server.
	out.Header = http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}, "User-Agent": {"tunnex-mcp-gateway"}}
	for _, name := range []string{"Mcp-Session-Id", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
		if values := r.Header.Values(name); len(values) == 1 && values[0] != "" && len(values[0]) <= 1024 {
			out.Header.Set(name, values[0])
		}
	}
	if accept := r.Header.Values("Accept"); len(accept) == 1 && accept[0] != "" && len(accept[0]) <= 256 {
		out.Header.Set("Accept", accept[0])
	}
	if credential := f.decision.Authorization; credential != "" {
		out.Header.Set("Authorization", bearer(credential))
	}

	// Connecting and receiving the response headers share one five-second budget. The body that follows
	// (possibly a stream) is bounded by the call's own deadline instead.
	headerCtx, abort := context.WithCancel(ctx)
	defer abort()
	timer := time.AfterFunc(h.headerTimeout, abort)
	response, err := h.upstream.RoundTrip(out.WithContext(headerCtx))
	inTime := timer.Stop()
	if err != nil || !inTime {
		if response != nil {
			_ = response.Body.Close()
		}
		h.logger.Warn("mcp_gateway_upstream_unavailable", "source", f.source)
		unavailable(mcpwire.ResultUpstreamUnavailable, 0)
		return
	}
	defer response.Body.Close()
	// A redirect is never followed: the credential and the call go to the decision's upstream only.
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		unavailable(mcpwire.ResultError, response.StatusCode)
		return
	}
	status := mcpwire.ResultOK
	if response.StatusCode < 200 || response.StatusCode > 299 {
		status = mcpwire.ResultError
	}
	passHeaders := func() {
		for _, name := range []string{"Mcp-Session-Id", "Mcp-Protocol-Version"} {
			if value := response.Header.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		w.Header().Set("Cache-Control", "no-store")
	}
	if f.method == "tools/list" {
		if status != mcpwire.ResultOK {
			// A failed list is reported with the server's status and none of its body.
			h.report(f, status, response.StatusCode)
			passHeaders()
			writeError(w, response.StatusCode, mcpwire.CodeUpstreamUnavailable, mcpwire.MessageUpstreamUnavailable, nil)
			return
		}
		filtered, contentType, err := filterToolsList(response.Header.Get("Content-Type"), response.Body, f.decision.CallableTools)
		if err != nil {
			unavailable(mcpwire.ResultError, response.StatusCode)
			return
		}
		h.report(f, status, response.StatusCode)
		passHeaders()
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(filtered)
		return
	}
	passHeaders()
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(response.StatusCode)
	flusher := http.NewResponseController(w)
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				break
			}
			_ = flusher.Flush()
		}
		if readErr != nil {
			break
		}
	}
	h.report(f, status, response.StatusCode)
}

// report closes the call's activity row. It runs detached from the caller's connection (the caller may
// already be gone) and never delays the answer.
func (h *relay) report(f forwarded, status string, upstreamStatus int) {
	if f.decision.CallID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), decideTimeout)
		defer cancel()
		result := mcpwire.ResultRequest{CallID: f.decision.CallID, Status: status, UpstreamHTTPStatus: upstreamStatus}
		if err := h.control.MCPResult(ctx, f.source, f.key, result); err != nil {
			h.logger.Warn("mcp_gateway_result_report_failed", "source", f.source)
		}
	}()
}

// writeError answers in the shape the agent-host proxy has always used.
func writeError(w http.ResponseWriter, status, code int, message string, data *mcpwire.ErrorData) {
	type rpcError struct {
		Code    int                `json:"code"`
		Message string             `json:"message"`
		Data    *mcpwire.ErrorData `json:"data,omitempty"`
	}
	body, _ := json.Marshal(struct {
		JSONRPC string           `json:"jsonrpc"`
		Error   rpcError         `json:"error"`
		ID      *json.RawMessage `json:"id"`
	}{JSONRPC: "2.0", Error: rpcError{Code: code, Message: message, Data: data}})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
