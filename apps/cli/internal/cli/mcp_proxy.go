package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MCPProxyPolicy is a secret-free, fail-closed runtime projection. The proxy
// maps one configured upstream endpoint to the exact allowed tool names.
type MCPProxyPolicy struct {
	Version int64
	Rules   []MCPProxyRule
}

type MCPProxyRule struct {
	Endpoint           string
	ServerName         string
	ToolName           string
	InputSchemaHash    string
	Arguments          *MCPArgumentConstraints
	RateLimitPerMinute int
	StepUpRequired     bool
}

// MCPArgumentConstraints is the intentionally small, policy-authored subset
// of JSON Schema accepted by F16. The provider's input schema remains only an
// F14 inventory pin; this restricts tenant-approved values within that shape.
type MCPArgumentConstraints struct {
	Required   []string
	Properties map[string]MCPArgumentConstraint
}

type MCPArgumentConstraint struct {
	Type      string
	Enum      []json.RawMessage
	MaxLength *int
	Minimum   *float64
	Maximum   *float64
}

type MCPPolicySource func(context.Context) (MCPProxyPolicy, error)
type MCPUpstreamSource func(context.Context) (string, error)
type MCPAuthorizationSource func(context.Context) (string, error)
type MCPStepUpSource func(context.Context, MCPProxyPolicy, MCPProxyRule, MCPToolRequest) (bool, error)

// MCPToolProxy is an explicit HTTP MCP proxy. Its caller chooses a loopback
// listener; this handler never makes a direct client connection protected.
func MCPToolProxy(upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) (http.Handler, error) {
	return MCPToolProxyDynamic(func(context.Context) (string, error) { return upstream, nil }, policy, authorization, stepUp...)
}

// MCPToolProxyDynamic resolves the upstream per request from the authenticated
// runtime desired state. An absent profile leaves the loopback proxy fail-closed.
func MCPToolProxyDynamic(upstream MCPUpstreamSource, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) (http.Handler, error) {
	if upstream == nil || policy == nil {
		return nil, errors.New("MCP proxy requires upstream and policy sources")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	limiter := newMCPRateLimiter(time.Now)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMCPProxyError(w, http.StatusMethodNotAllowed, -32600, "MCP proxy accepts POST only")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPRequestBody+1))
		if err != nil || len(body) > maxMCPRequestBody {
			writeMCPProxyError(w, http.StatusBadRequest, -32600, "MCP request is invalid")
			return
		}
		expected := MCPProtocol20251125
		if r.Header.Get("MCP-Protocol-Version") == MCPProtocol20260728 {
			expected = MCPProtocol20260728
		}
		request, validation := ValidateMCPToolRequest(expected, r.Header, body)
		if validation != nil {
			writeMCPProxyError(w, http.StatusBadRequest, -32020, "MCP request headers do not match its body")
			return
		}
		upstreamURL, upstreamErr := upstream(r.Context())
		target, parseErr := url.Parse(upstreamURL)
		if upstreamErr != nil || parseErr != nil || target.Scheme == "" || target.Host == "" || target.User != nil {
			writeMCPProxyError(w, http.StatusForbidden, -32100, "MCP tool is denied by policy")
			return
		}
		if request.ToolName == "" {
			switch request.Method {
			case "initialize", "notifications/initialized", "tools/list", "ping":
				// Fixed transport/control methods establish and inspect an MCP
				// session; they cannot invoke a tool. Every other unnamed method
				// remains default-denied.
			default:
				writeMCPProxyError(w, http.StatusForbidden, -32100, "MCP tool is denied by policy")
				return
			}
		} else {
			current, err := policy(r.Context())
			rule, allowed := mcpProxyRule(current, target.String(), request.ToolName)
			if err != nil || current.Version == 0 || !allowed {
				writeMCPProxyError(w, http.StatusForbidden, -32100, "MCP tool is denied by policy")
				return
			}
			if err := rule.Arguments.Validate(request.Arguments); err != nil {
				writeMCPProxyError(w, http.StatusForbidden, -32101, "MCP tool arguments are denied by policy")
				return
			}
			if !limiter.allow(current.Version, rule, time.Now()) {
				writeMCPProxyError(w, http.StatusTooManyRequests, -32102, "MCP tool rate limit exceeded")
				return
			}
			if rule.StepUpRequired && (len(stepUp) == 0 || stepUp[0] == nil) {
				writeMCPProxyError(w, http.StatusForbidden, -32103, "MCP tool requires step-up approval")
				return
			}
			if rule.StepUpRequired {
				allowed, approvalErr := stepUp[0](r.Context(), current, rule, request)
				if approvalErr != nil || !allowed {
					writeMCPProxyError(w, http.StatusForbidden, -32103, "MCP tool requires step-up approval")
					return
				}
			}
		}
		outbound := r.Clone(r.Context())
		outbound.URL = target
		outbound.Host = target.Host
		outbound.RequestURI = ""
		outbound.Body = io.NopCloser(bytes.NewReader(body))
		outbound.ContentLength = int64(len(body))
		outbound.Header = r.Header.Clone()
		outbound.Header.Del("Authorization")
		outbound.Header.Del("Proxy-Authorization")
		if authorization != nil {
			bearer, authErr := authorization(r.Context())
			if authErr != nil {
				writeMCPProxyError(w, http.StatusBadGateway, -32020, "MCP authorization is unavailable")
				return
			}
			if bearer != "" {
				outbound.Header.Set("Authorization", "Bearer "+bearer)
			}
		}
		response, err := transport.RoundTrip(outbound)
		if err != nil {
			writeMCPProxyError(w, http.StatusBadGateway, -32020, "MCP upstream is unavailable")
			return
		}
		defer response.Body.Close()
		copyMCPProxyHeaders(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}), nil
}

func MCPApprovalDigest(request MCPToolRequest) string {
	h := sha256.New()
	_, _ = h.Write([]byte(request.Method))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(request.ToolName))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(request.Arguments)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func allowsMCPProxyTool(policy MCPProxyPolicy, endpoint, tool string) bool {
	_, ok := mcpProxyRule(policy, endpoint, tool)
	return ok
}

func mcpProxyRule(policy MCPProxyPolicy, endpoint, tool string) (MCPProxyRule, bool) {
	for _, rule := range policy.Rules {
		if strings.TrimSpace(rule.Endpoint) == endpoint && rule.ToolName == tool {
			return rule, true
		}
	}
	return MCPProxyRule{}, false
}

// Validate accepts only a JSON object. A missing arguments field means an
// empty object, which lets a required-list reject it without special cases.
func (c *MCPArgumentConstraints) Validate(arguments json.RawMessage) error {
	if c == nil {
		return nil
	}
	value := map[string]json.RawMessage{}
	if len(arguments) > 0 && string(arguments) != "null" {
		if err := json.Unmarshal(arguments, &value); err != nil {
			return errors.New("arguments must be an object")
		}
	}
	for _, required := range c.Required {
		if _, ok := value[required]; !ok {
			return errors.New("required argument is missing")
		}
	}
	for name, raw := range value {
		constraint, ok := c.Properties[name]
		if !ok {
			return errors.New("argument is not allowed")
		}
		if err := constraint.validate(raw); err != nil {
			return err
		}
	}
	return nil
}

func (c MCPArgumentConstraint) validate(raw json.RawMessage) error {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("argument is invalid")
	}
	switch c.Type {
	case "string":
		s, ok := value.(string)
		if !ok || (c.MaxLength != nil && len([]rune(s)) > *c.MaxLength) {
			return errors.New("string argument is denied")
		}
	case "number":
		n, ok := value.(float64)
		if !ok || (c.Minimum != nil && n < *c.Minimum) || (c.Maximum != nil && n > *c.Maximum) {
			return errors.New("number argument is denied")
		}
	case "integer":
		n, ok := value.(float64)
		if !ok || n != float64(int64(n)) || (c.Minimum != nil && n < *c.Minimum) || (c.Maximum != nil && n > *c.Maximum) {
			return errors.New("integer argument is denied")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return errors.New("boolean argument is denied")
		}
	default:
		return errors.New("argument constraint type is invalid")
	}
	if len(c.Enum) > 0 {
		canonical, _ := json.Marshal(value)
		matched := false
		for _, allowed := range c.Enum {
			if string(canonical) == string(allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("argument enum is denied")
		}
	}
	return nil
}

type mcpRateWindow struct {
	started time.Time
	used    int
}

type mcpRateLimiter struct {
	now     func() time.Time
	mu      sync.Mutex
	windows map[string]mcpRateWindow
}

func newMCPRateLimiter(now func() time.Time) *mcpRateLimiter {
	return &mcpRateLimiter{now: now, windows: map[string]mcpRateWindow{}}
}
func (l *mcpRateLimiter) allow(version int64, rule MCPProxyRule, at time.Time) bool {
	if rule.RateLimitPerMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := strconv.FormatInt(version, 10) + "\x00" + rule.Endpoint + "\x00" + rule.ToolName
	w := l.windows[key]
	if w.started.IsZero() || at.Sub(w.started) >= time.Minute {
		w = mcpRateWindow{started: at}
	}
	if w.used >= rule.RateLimitPerMinute {
		return false
	}
	w.used++
	l.windows[key] = w
	return true
}

func writeMCPProxyError(w http.ResponseWriter, status, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":` + strconv.Itoa(code) + `,"message":"` + message + `"},"id":null}`))
}

func copyMCPProxyHeaders(dst, src http.Header) {
	for key, values := range src {
		if strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// mcpLoopbackGuard keeps the loopback listener from being driven by a browser.
// A page open on the agent host can send a cross-site POST to 127.0.0.1, and a
// DNS-rebinding page can read the reply, so the tool gate is reachable only by
// a request that names this listener, carries no Origin and is plain JSON (a
// content type a page cannot send without a preflight this proxy never
// answers).
func mcpLoopbackGuard(listen string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(listen)
	allowed := map[string]bool{listen: true, net.JoinHostPort("localhost", port): true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if !allowed[r.Host] || len(r.Header.Values("Origin")) != 0 || err != nil || mediaType != "application/json" {
			writeMCPProxyError(w, http.StatusForbidden, -32600, "MCP proxy accepts local JSON requests only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// MCPGatewaySource returns the gateway MCP listener URL from the runtime's current desired state, or ""
// when the control plane named none (an older gateway, or the organization's grace period).
type MCPGatewaySource func(context.Context) string

const (
	// mcpGatewayDialTimeout bounds reaching the gateway listener (AI-SEC-2: five seconds).
	mcpGatewayDialTimeout = 5 * time.Second
	// mcpGatewayHeaderTimeout bounds a gateway that accepted the connection and then says nothing. It is
	// longer than the dial bound on purpose: before it answers, the gateway asks the control plane for a
	// decision and gives the MCP server its own five seconds, and that answer must not be cut short here.
	mcpGatewayHeaderTimeout = 10 * time.Second
)

// mcpGatewayForwarder is the loopback proxy once the gateway enforces MCP policy (AI-SEC-2). It decides
// nothing: no tool policy, no token lease, no discovery. The gateway identifies the agent from the tunnel
// and the control plane decides; this only carries the request there and the answer back.
type mcpGatewayForwarder struct {
	gateway       MCPGatewaySource
	dialTimeout   time.Duration
	headerTimeout time.Duration
	dial          func(context.Context, string, string) (net.Conn, error)
	once          sync.Once
	transport     *http.Transport
}

func newMCPGatewayForwarder(gateway MCPGatewaySource) *mcpGatewayForwarder {
	return &mcpGatewayForwarder{gateway: gateway, dialTimeout: mcpGatewayDialTimeout, headerTimeout: mcpGatewayHeaderTimeout}
}

func (f *mcpGatewayForwarder) roundTripper() *http.Transport {
	f.once.Do(func() {
		dial := f.dial
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		timeout := f.dialTimeout
		f.transport = &http.Transport{
			// The gateway is a tunnel address: never route it through an environment proxy.
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				return dial(ctx, network, address)
			},
			ResponseHeaderTimeout: f.headerTimeout,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
		}
	})
	return f.transport
}

// mcpGatewayRequestHeader reports whether a caller header travels to the gateway. Only what the MCP
// transport itself needs: the caller's Authorization, cookies and anything that could pass for identity
// stay on this host.
func mcpGatewayRequestHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Content-Type", "Accept", "Mcp-Session-Id", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name":
		return true
	}
	return false
}

func (f *mcpGatewayForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMCPProxyError(w, http.StatusMethodNotAllowed, -32600, "MCP proxy accepts POST only")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPRequestBody+1))
	if err != nil || len(body) > maxMCPRequestBody {
		writeMCPProxyError(w, http.StatusBadRequest, -32600, "MCP request is invalid")
		return
	}
	target, err := url.Parse(f.gateway(r.Context()))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil {
		writeMCPProxyError(w, http.StatusBadGateway, -32020, "MCP upstream is unavailable")
		return
	}
	outbound, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		writeMCPProxyError(w, http.StatusBadGateway, -32020, "MCP upstream is unavailable")
		return
	}
	for name, values := range r.Header {
		if mcpGatewayRequestHeader(name) {
			outbound.Header[name] = append([]string(nil), values...)
		}
	}
	response, err := f.roundTripper().RoundTrip(outbound)
	if err != nil {
		writeMCPProxyError(w, http.StatusBadGateway, -32020, "MCP upstream is unavailable")
		return
	}
	defer response.Body.Close()
	// The loopback listener serves MCP, never a web page. Whatever the gateway's address answers with, the
	// local client receives JSON or an event stream (fixed values, not the upstream's), with sniffing off.
	streamed := false
	if mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type")); parseErr == nil && mediaType == "text/event-stream" {
		streamed = true
	}
	for key, values := range response.Header {
		if strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Transfer-Encoding") ||
			strings.EqualFold(key, "Content-Type") || strings.EqualFold(key, "X-Content-Type-Options") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if streamed {
		w.Header().Set("Content-Type", "text/event-stream")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(response.StatusCode)
	// Flush as it arrives so a streamed (text/event-stream) answer is not held back.
	controller := http.NewResponseController(w)
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			_ = controller.Flush()
		}
		if readErr != nil {
			return
		}
	}
}

// managedMCPProxyHandler is the loopback proxy the managed runtime serves. The AI-SEC-1 guard is applied
// first in every mode. With a gateway URL the request is forwarded to the gateway and nothing local runs;
// without one the legacy local proxy (policy, lease, direct upstream) handles it exactly as before.
func managedMCPProxyHandler(listen string, gateway MCPGatewaySource, upstream MCPUpstreamSource, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) (http.Handler, error) {
	legacy, err := MCPToolProxyDynamic(upstream, policy, authorization, stepUp...)
	if err != nil {
		return nil, err
	}
	if gateway == nil {
		return mcpLoopbackGuard(listen, legacy), nil
	}
	forwarder := newMCPGatewayForwarder(gateway)
	return mcpLoopbackGuard(listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gateway(r.Context()) != "" {
			forwarder.ServeHTTP(w, r)
			return
		}
		legacy.ServeHTTP(w, r)
	})), nil
}

// StartMCPToolProxy serves only a loopback listener. It is intentionally
// separate from RunManagedAgent so an operator must configure a client to use it.
func StartMCPToolProxy(ctx context.Context, listen, upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) error {
	return StartMCPToolProxyDynamic(ctx, listen, func(context.Context) (string, error) { return upstream, nil }, policy, authorization, stepUp...)
}

func StartMCPToolProxyDynamic(ctx context.Context, listen string, upstream MCPUpstreamSource, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) error {
	return StartManagedMCPToolProxy(ctx, listen, nil, upstream, policy, authorization, stepUp...)
}

// StartManagedMCPToolProxy serves the loopback proxy of the managed runtime: a forwarder to the gateway
// MCP listener whenever gateway returns a URL, the legacy local proxy otherwise. A nil gateway source is
// the legacy proxy alone.
func StartManagedMCPToolProxy(ctx context.Context, listen string, gateway MCPGatewaySource, upstream MCPUpstreamSource, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("MCP proxy listener must be loopback")
	}
	handler, err := managedMCPProxyHandler(listen, gateway, upstream, policy, authorization, stepUp...)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
