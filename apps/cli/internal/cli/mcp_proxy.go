package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
type MCPAuthorizationSource func(context.Context) (string, error)
type MCPStepUpSource func(context.Context, MCPProxyPolicy, MCPProxyRule, MCPToolRequest) (bool, error)

// MCPToolProxy is an explicit HTTP MCP proxy. Its caller chooses a loopback
// listener; this handler never makes a direct client connection protected.
func MCPToolProxy(upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) (http.Handler, error) {
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme == "" || target.Host == "" || policy == nil {
		return nil, errors.New("MCP proxy requires an absolute upstream and policy source")
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

// StartMCPToolProxy serves only a loopback listener. It is intentionally
// separate from RunManagedAgent so an operator must configure a client to use it.
func StartMCPToolProxy(ctx context.Context, listen, upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource, stepUp ...MCPStepUpSource) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("MCP proxy listener must be loopback")
	}
	handler, err := MCPToolProxy(upstream, policy, authorization, stepUp...)
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
