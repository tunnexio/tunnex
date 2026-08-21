package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MCPProxyPolicy is a secret-free, fail-closed runtime projection. The proxy
// maps one configured upstream endpoint to the exact allowed tool names.
type MCPProxyPolicy struct {
	Version int64
	Rules   []MCPProxyRule
}

type MCPProxyRule struct {
	Endpoint string
	ToolName string
}

type MCPPolicySource func(context.Context) (MCPProxyPolicy, error)
type MCPAuthorizationSource func(context.Context) (string, error)

// MCPToolProxy is an explicit HTTP MCP proxy. Its caller chooses a loopback
// listener; this handler never makes a direct client connection protected.
func MCPToolProxy(upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource) (http.Handler, error) {
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme == "" || target.Host == "" || policy == nil {
		return nil, errors.New("MCP proxy requires an absolute upstream and policy source")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
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
		if err != nil || current.Version == 0 || !allowsMCPProxyTool(current, target.String(), request.ToolName) {
			writeMCPProxyError(w, http.StatusForbidden, -32100, "MCP tool is denied by policy")
			return
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

func allowsMCPProxyTool(policy MCPProxyPolicy, endpoint, tool string) bool {
	for _, rule := range policy.Rules {
		if strings.TrimSpace(rule.Endpoint) == endpoint && rule.ToolName == tool {
			return true
		}
	}
	return false
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
func StartMCPToolProxy(ctx context.Context, listen, upstream string, policy MCPPolicySource, authorization MCPAuthorizationSource) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("MCP proxy listener must be loopback")
	}
	handler, err := MCPToolProxy(upstream, policy, authorization)
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
