package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/mcpwire"
)

const (
	// DiscoveryInterval is how often the gateway observes the MCP servers of the agents homed on it.
	DiscoveryInterval = 30 * time.Second

	discoveryPassTimeout    = 25 * time.Second
	discoveryRequestTimeout = 10 * time.Second
	discoveryConcurrency    = 4
	maxDiscoveryTargets     = 1024
	maxDiscoveryBytes       = 1 << 20
	maxDiscoveryPages       = 20
	maxDiscoveredTools      = 2000

	statusHealthy      = "healthy"
	statusUnavailable  = "unavailable"
	statusUnauthorized = "unauthorized"
	statusInvalid      = "invalid"
)

// discoveryVersions are offered newest first; a server that refuses one is asked with the next.
var discoveryVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

var supportedVersions = map[string]struct{}{"2024-11-05": {}, "2025-03-26": {}, "2025-06-18": {}, "2025-11-25": {}}

var errUnauthorized = errors.New("MCP server refused the credential")

// discoverer observes MCP servers FROM THE GATEWAY and reports their raw tool definitions (AI-SEC-2).
// The allow-list an administrator approves is built from this, not from a list the agent host reports,
// and the control plane computes every hash itself: nothing here hashes anything.
type discoverer struct {
	control  Control
	upstream http.RoundTripper
	logger   *slog.Logger
}

// pass runs one discovery round: fetch the targets, observe each server once, report per agent.
//
// Agents that share an endpoint and have no credential of their own share one observation. A target
// that carries a credential is always observed on its own, with only that credential. An agent with
// several servers is listed once per server and gets one report per endpoint.
//
// A preview target (AI-UX-1) is an address an administrator is about to connect: it names a preview and
// no agent, is observed the same way, and is reported under its preview id. The control plane lists it
// only until that report arrives, so a preview is read once.
func (d *discoverer) pass(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, discoveryPassTimeout)
	defer cancel()
	targets, err := d.control.MCPTargets(ctx)
	if err != nil {
		d.logger.Warn("mcp_gateway_targets_unavailable")
		return
	}
	if len(targets) > maxDiscoveryTargets {
		targets = targets[:maxDiscoveryTargets]
	}
	// recipient is who one observation is reported for: an agent, or a preview when it names no agent.
	type recipient struct{ device, preview string }
	type group struct {
		endpoint, authorization string
		recipients              []recipient
	}
	var groups []*group
	shared := map[string]*group{}
	type listing struct {
		recipient
		endpoint, authorization string
	}
	listed := map[listing]struct{}{}
	for _, target := range targets {
		to := recipient{device: target.DeviceID}
		if to.device == "" {
			to.preview = target.PreviewID
		}
		if to == (recipient{}) || target.Endpoint == "" {
			continue
		}
		// The same server listed twice for one agent (it reaches it through two groups) is one report.
		entry := listing{recipient: to, endpoint: target.Endpoint, authorization: target.Authorization}
		if _, again := listed[entry]; again {
			continue
		}
		listed[entry] = struct{}{}
		if target.Authorization != "" {
			groups = append(groups, &group{endpoint: target.Endpoint, authorization: target.Authorization, recipients: []recipient{to}})
			continue
		}
		g, ok := shared[target.Endpoint]
		if !ok {
			g = &group{endpoint: target.Endpoint}
			shared[target.Endpoint] = g
			groups = append(groups, g)
		}
		g.recipients = append(g.recipients, to)
	}
	slots := make(chan struct{}, discoveryConcurrency)
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			observed := d.observe(ctx, g.endpoint, g.authorization)
			for _, to := range g.recipients {
				report := observed
				report.DeviceID, report.PreviewID = to.device, to.preview
				if err := d.control.MCPInventory(ctx, report); err != nil {
					d.logger.Warn("mcp_gateway_inventory_report_failed")
				}
			}
		}()
	}
	wg.Wait()
}

// observe runs initialize, notifications/initialized and tools/list against one server and returns what
// it saw. It never calls a tool. The report names no agent or preview yet.
func (d *discoverer) observe(ctx context.Context, endpoint, authorization string) mcpwire.InventoryReport {
	report := mcpwire.InventoryReport{Endpoint: endpoint, Status: statusUnavailable, Tools: []mcpwire.ObservedTool{}}
	target, err := url.Parse(endpoint)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.Fragment != "" {
		report.Status = statusInvalid
		return report
	}
	session := &discoverySession{d: d, endpoint: target.String(), authorization: authorization}
	defer session.close(ctx)
	for _, version := range discoveryVersions {
		session.id, session.protocol = "", ""
		start := time.Now()
		reply, err := session.call(ctx, 1, "initialize", map[string]any{
			"protocolVersion": version, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "tunnex-gateway", "version": "1"},
		})
		if errors.Is(err, errUnauthorized) {
			report.Status = statusUnauthorized
			return report
		}
		if err != nil {
			continue
		}
		var result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		}
		if len(reply["result"]) == 0 || json.Unmarshal(reply["result"], &result) != nil {
			continue
		}
		if _, ok := supportedVersions[result.ProtocolVersion]; !ok {
			report.Status = statusInvalid
			return report
		}
		report.ProtocolVersion, report.ServerName = result.ProtocolVersion, boundedText(result.ServerInfo.Name, 128)
		report.LatencyMillis = time.Since(start).Milliseconds()
		session.protocol = result.ProtocolVersion
		_ = session.notify(ctx, "notifications/initialized")
		tools, status := session.listTools(ctx)
		report.Status = status
		if status == statusHealthy {
			report.Tools = tools
		}
		return report
	}
	return report
}

type discoverySession struct {
	d             *discoverer
	endpoint      string
	authorization string
	id            string // server-issued Mcp-Session-Id
	protocol      string // negotiated version, sent on every request after initialize
}

// listTools pages through tools/list. A server that answers with a JSON-RPC error has no tools to offer
// (it is healthy and empty); one that cannot be reached or read mid-list is unavailable, never a shorter
// list presented as the whole.
func (s *discoverySession) listTools(ctx context.Context) ([]mcpwire.ObservedTool, string) {
	tools := []mcpwire.ObservedTool{}
	cursor := ""
	for page := 0; page < maxDiscoveryPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		reply, err := s.call(ctx, 2+page, "tools/list", params)
		if errors.Is(err, errUnauthorized) {
			return nil, statusUnauthorized
		}
		if err != nil {
			return nil, statusUnavailable
		}
		if len(reply["result"]) == 0 {
			return tools, statusHealthy
		}
		var result struct {
			Tools      []map[string]json.RawMessage `json:"tools"`
			NextCursor string                       `json:"nextCursor"`
		}
		if json.Unmarshal(reply["result"], &result) != nil {
			return nil, statusInvalid
		}
		for _, definition := range result.Tools {
			tool := mcpwire.ObservedTool{InputSchema: definition["inputSchema"]}
			if !isJSONString(definition["name"]) || json.Unmarshal(definition["name"], &tool.Name) != nil || strings.TrimSpace(tool.Name) == "" {
				return nil, statusInvalid
			}
			if raw, present := definition["description"]; present && json.Unmarshal(raw, &tool.Description) != nil {
				return nil, statusInvalid
			}
			if len(tools) == maxDiscoveredTools {
				return nil, statusInvalid
			}
			tools = append(tools, tool)
		}
		if result.NextCursor == "" || result.NextCursor == cursor {
			return tools, statusHealthy
		}
		cursor = result.NextCursor
	}
	return nil, statusInvalid
}

func (s *discoverySession) call(ctx context.Context, id int, method string, params any) (map[string]json.RawMessage, error) {
	response, err := s.send(ctx, http.MethodPost, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryBytes+1))
	if err != nil || len(data) > maxDiscoveryBytes {
		return nil, errors.New("MCP response is unreadable")
	}
	if mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type")); mediaType == "text/event-stream" {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), maxDiscoveryBytes+1)
		for scanner.Scan() {
			payload, isData := strings.CutPrefix(scanner.Text(), "data:")
			if !isData {
				continue
			}
			if reply, ok := rpcResponse([]byte(strings.TrimSpace(payload))); ok {
				return reply, nil
			}
		}
		return nil, errors.New("MCP event stream holds no response")
	}
	reply, ok := rpcResponse(bytes.TrimSpace(data))
	if !ok {
		return nil, errors.New("MCP response is not a JSON-RPC response")
	}
	return reply, nil
}

func (s *discoverySession) notify(ctx context.Context, method string) error {
	response, err := s.send(ctx, http.MethodPost, map[string]any{"jsonrpc": "2.0", "method": method, "params": map[string]any{}})
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return response.Body.Close()
}

// close ends the server-side session the observation opened, so a pass every thirty seconds does not
// leave sessions behind on a stateful server. Best effort.
func (s *discoverySession) close(ctx context.Context) {
	if s.id == "" {
		return
	}
	if response, err := s.send(ctx, http.MethodDelete, nil); err == nil {
		_ = response.Body.Close()
	}
}

// send performs one request and returns a 2xx response (a DELETE returns any). It never follows a
// redirect, so the credential goes to the configured endpoint only.
func (s *discoverySession) send(ctx context.Context, method string, message any) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryRequestTimeout)
	var body io.Reader
	if message != nil {
		encoded, err := json.Marshal(message)
		if err != nil {
			cancel()
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.endpoint, body)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header = http.Header{"Accept": {"application/json, text/event-stream"}, "User-Agent": {"tunnex-mcp-gateway"}}
	if message != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.id != "" {
		req.Header.Set("Mcp-Session-Id", s.id)
	}
	if s.protocol != "" {
		req.Header.Set("Mcp-Protocol-Version", s.protocol)
	}
	if s.authorization != "" {
		req.Header.Set("Authorization", bearer(s.authorization))
	}
	response, err := s.d.upstream.RoundTrip(req)
	if err != nil {
		cancel()
		return nil, errors.New("MCP server is unreachable")
	}
	response.Body = cancelOnClose{response.Body, cancel}
	if method == http.MethodDelete {
		return response, nil
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		_ = response.Body.Close()
		return nil, errUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_ = response.Body.Close()
		return nil, errors.New("MCP server answered with an error status")
	}
	if next := strings.TrimSpace(response.Header.Get("Mcp-Session-Id")); next != "" && len(next) <= 1024 {
		s.id = next
	}
	return response, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// rpcResponse decodes one JSON-RPC message and reports whether it is a response (a result or an error),
// as opposed to a notification or a request the server put on the stream.
func rpcResponse(data []byte) (map[string]json.RawMessage, bool) {
	var message map[string]json.RawMessage
	if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &message) != nil {
		return nil, false
	}
	_, hasResult := message["result"]
	_, hasError := message["error"]
	return message, hasResult || hasError
}

// bearer turns the control plane's credential into an Authorization value; it may already be one.
func bearer(credential string) string {
	if len(credential) >= 7 && strings.EqualFold(credential[:7], "bearer ") {
		return credential
	}
	return "Bearer " + credential
}

func boundedText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return ""
	}
	return value
}
