package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ObserveMCPInventory performs read-only MCP discovery for explicitly configured
// HTTP endpoints. Failures are represented per server; one unavailable server
// cannot suppress inventory from another.
func ObserveMCPInventory(ctx context.Context, endpoints []string) map[string]interface{} {
	servers := make([]interface{}, 0, len(endpoints))
	for _, raw := range endpoints {
		servers = append(servers, observeMCPEndpoint(ctx, strings.TrimSpace(raw)))
	}
	return map[string]interface{}{"servers": servers}
}

// ObserveMCPOAuthDiscovery obtains only protected-resource metadata. It sends
// no authorization header and does not follow an authorization-server redirect.
// The resulting facts are for an administrator to begin consent; no credential
// crosses this runtime-to-control-plane report.
func ObserveMCPOAuthDiscovery(ctx context.Context, endpoints []string) map[string]interface{} {
	servers := make([]interface{}, 0, len(endpoints))
	for _, endpoint := range endpoints {
		servers = append(servers, observeMCPOAuthEndpoint(ctx, strings.TrimSpace(endpoint)))
	}
	return map[string]interface{}{"servers": servers}
}

func observeMCPOAuthEndpoint(ctx context.Context, endpoint string) map[string]interface{} {
	fact := map[string]interface{}{"endpoint": endpoint, "status": "not_protected"}
	u, err := canonicalMCPEndpoint(endpoint)
	if err != nil {
		fact["status"] = "invalid_endpoint"
		return fact
	}
	metadataURL := protectedResourceMetadataHint(ctx, u)
	if metadataURL == "" {
		metadataURL = protectedResourceMetadataFallback(u)
	}
	metadata, err := fetchProtectedResourceMetadata(ctx, metadataURL)
	if err != nil {
		fact["status"] = "unavailable"
		return fact
	}
	resource, _ := metadata["resource"].(string)
	if resource == "" || resource != canonicalURL(u) {
		fact["status"] = "invalid_metadata"
		return fact
	}
	issuers := stringList(metadata["authorization_servers"], 8)
	if len(issuers) == 0 {
		fact["status"] = "invalid_metadata"
		return fact
	}
	fact["status"] = "protected"
	fact["protected_resource"] = resource
	fact["authorization_servers"] = issuers
	if scopes := stringList(metadata["scopes_supported"], 64); len(scopes) > 0 {
		fact["scopes_supported"] = scopes
	}
	return fact
}

func protectedResourceMetadataHint(ctx context.Context, endpoint *url.URL) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	return protectedResourceMetadataFromChallenge(resp.Header.Values("WWW-Authenticate"))
}

var resourceMetadataParameter = regexp.MustCompile(`(?i)resource_metadata="([^"]+)"`)

func protectedResourceMetadataFromChallenge(challenges []string) string {
	for _, challenge := range challenges {
		match := resourceMetadataParameter.FindStringSubmatch(challenge)
		if len(match) == 2 {
			if u, err := url.Parse(match[1]); err == nil && u.IsAbs() && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
				return u.String()
			}
		}
	}
	return ""
}

func protectedResourceMetadataFallback(endpoint *url.URL) string {
	copy := *endpoint
	copy.RawQuery, copy.Fragment = "", ""
	copy.Path = "/.well-known/oauth-protected-resource" + strings.TrimSuffix(copy.Path, "/")
	return copy.String()
}

func fetchProtectedResourceMetadata(ctx context.Context, raw string) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid protected-resource metadata URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("protected-resource metadata HTTP %d", resp.StatusCode)
	}
	var metadata map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func canonicalMCPEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("MCP endpoint must be an absolute URL without credentials, query, or fragment")
	}
	return u, nil
}

func canonicalURL(u *url.URL) string {
	copy := *u
	copy.RawQuery, copy.Fragment = "", ""
	copy.Path = strings.TrimSuffix(copy.Path, "/")
	if copy.Path == "" {
		copy.Path = "/"
	}
	return copy.String()
}

func stringList(raw interface{}, limit int) []string {
	values, _ := raw.([]interface{})
	out := make([]string, 0, len(values))
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || len(value) == 0 || len(value) > 2048 || len(out) == limit {
			continue
		}
		u, err := url.Parse(value)
		if strings.Contains(value, "://") && (err != nil || !u.IsAbs() || u.User != nil || u.RawQuery != "" || u.Fragment != "") {
			continue
		}
		out = append(out, value)
	}
	return out
}

func observeMCPEndpoint(ctx context.Context, endpoint string) map[string]interface{} {
	base := map[string]interface{}{"endpoint": endpoint, "status": "failed"}
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		start := time.Now()
		init, sessionID, err := mcpSessionRequest(ctx, endpoint, 1, "initialize", map[string]interface{}{"protocolVersion": version, "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "tunnex-agent-runtime", "version": "f12"}}, "")
		if err != nil {
			continue
		}
		result, ok := init["result"].(map[string]interface{})
		if !ok {
			continue
		}
		negotiated, _ := result["protocolVersion"].(string)
		if _, ok := supportedMCPVersions[negotiated]; !ok {
			base["status"] = "unsupported_version"
			return base
		}
		base["status"], base["protocol_version"], base["latency_millis"] = "healthy", negotiated, time.Since(start).Milliseconds()
		if info, ok := result["serverInfo"].(map[string]interface{}); ok {
			base["server_name"], _ = info["name"].(string)
		}
		base["capabilities"] = result["capabilities"]
		_, sessionID, _ = mcpSessionRequest(ctx, endpoint, 2, "notifications/initialized", map[string]interface{}{}, sessionID)
		for _, spec := range []struct{ key, method string }{{"tools", "tools/list"}, {"resources", "resources/list"}, {"prompts", "prompts/list"}} {
			if reply, nextSessionID, err := mcpSessionRequest(ctx, endpoint, 3, spec.method, map[string]interface{}{}, sessionID); err == nil {
				sessionID = nextSessionID
				if r, ok := reply["result"].(map[string]interface{}); ok {
					base[spec.key] = r[spec.key]
				}
			}
		}
		normalized, err := normalizeObservedSnapshot(base)
		if err != nil {
			base["status"] = "invalid_inventory"
			return base
		}
		encoded, _ := json.Marshal(normalized)
		var out map[string]interface{}
		_ = json.Unmarshal(encoded, &out)
		out["status"] = "healthy"
		return out
	}
	return base
}

func mcpRequest(ctx context.Context, endpoint string, id int, method string, params interface{}) (map[string]interface{}, error) {
	reply, _, err := mcpSessionRequest(ctx, endpoint, id, method, params, "")
	return reply, err
}

// mcpSessionRequest preserves the server-issued streamable-HTTP session across
// inventory discovery requests. It never invokes an MCP tool.
func mcpSessionRequest(ctx context.Context, endpoint string, id int, method string, params interface{}, sessionID string) (map[string]interface{}, string, error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, sessionID, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, sessionID, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, sessionID, fmt.Errorf("MCP HTTP %d", resp.StatusCode)
	}
	if next := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); next != "" {
		sessionID = next
	}
	var data []byte
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 256<<10))
		scanner.Buffer(make([]byte, 1024), 256<<10)
		for scanner.Scan() {
			if line := scanner.Text(); strings.HasPrefix(line, "data: ") {
				data = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, sessionID, err
		}
		if len(data) == 0 {
			return nil, sessionID, errors.New("MCP SSE response contains no data event")
		}
	} else {
		var err error
		data, err = io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		if err != nil {
			return nil, sessionID, err
		}
	}
	var reply map[string]interface{}
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, sessionID, err
	}
	return reply, sessionID, nil
}

func normalizeObservedSnapshot(raw map[string]interface{}) (MCPInventorySnapshot, error) {
	s := MCPInventorySnapshot{Endpoint: fmt.Sprint(raw["endpoint"]), ServerName: fmt.Sprint(raw["server_name"]), ProtocolVersion: fmt.Sprint(raw["protocol_version"]), Transport: "streamable_http", ObservedAt: time.Now().UTC()}
	if n, ok := raw["latency_millis"].(int64); ok {
		s.LatencyMillis = int(n)
	}
	if caps, ok := raw["capabilities"].(map[string]interface{}); ok {
		if tools, ok := caps["tools"].(map[string]interface{}); ok {
			s.Capabilities.ToolsListChanged, _ = tools["listChanged"].(bool)
		}
		if resources, ok := caps["resources"].(map[string]interface{}); ok {
			s.Capabilities.ResourcesListChanged, _ = resources["listChanged"].(bool)
			s.Capabilities.ResourcesSubscribe, _ = resources["subscribe"].(bool)
		}
		if prompts, ok := caps["prompts"].(map[string]interface{}); ok {
			s.Capabilities.PromptsListChanged, _ = prompts["listChanged"].(bool)
		}
	}
	decode := func(v interface{}, into interface{}) { b, _ := json.Marshal(v); _ = json.Unmarshal(b, into) }
	decode(raw["tools"], &s.Tools)
	// MCP wire names use camel case, while the persisted snapshot deliberately
	// uses snake case. Keep the boundary explicit so valid current-protocol
	// `inputSchema`/`outputSchema` and `mimeType` fields are not discarded.
	for i, tool := range inventoryObjects(raw, "tools") {
		if i >= len(s.Tools) {
			break
		}
		if schema, ok := tool["inputSchema"]; ok {
			b, _ := json.Marshal(schema)
			s.Tools[i].InputSchema = b
		}
		if schema, ok := tool["outputSchema"]; ok {
			b, _ := json.Marshal(schema)
			s.Tools[i].OutputSchema = b
		}
	}
	decode(raw["resources"], &s.Resources)
	for i, resource := range inventoryObjects(raw, "resources") {
		if i < len(s.Resources) {
			s.Resources[i].MIMEType, _ = resource["mimeType"].(string)
		}
	}
	decode(raw["prompts"], &s.Prompts)
	return NormalizeMCPInventory(s)
}

func inventoryObjects(raw map[string]interface{}, key string) []map[string]interface{} {
	values, _ := raw[key].([]interface{})
	objects := make([]map[string]interface{}, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]interface{}); ok {
			objects = append(objects, object)
		}
	}
	return objects
}

// MCPInventorySnapshot is the secret-free result of one MCP discovery pass.
// It deliberately has no request headers, session id, resource contents,
// prompt messages, or tool results.
type MCPInventorySnapshot struct {
	Endpoint        string                 `json:"endpoint"`
	ServerName      string                 `json:"server_name"`
	ProtocolVersion string                 `json:"protocol_version"`
	Transport       string                 `json:"transport"`
	LatencyMillis   int                    `json:"latency_millis"`
	ObservedAt      time.Time              `json:"observed_at"`
	Capabilities    MCPServerCapabilities  `json:"capabilities"`
	Tools           []MCPToolInventory     `json:"tools"`
	Resources       []MCPResourceInventory `json:"resources"`
	Prompts         []MCPPromptInventory   `json:"prompts"`
}

type MCPServerCapabilities struct {
	ToolsListChanged     bool `json:"tools_list_changed"`
	ResourcesListChanged bool `json:"resources_list_changed"`
	ResourcesSubscribe   bool `json:"resources_subscribe"`
	PromptsListChanged   bool `json:"prompts_list_changed"`
}

type MCPToolInventory struct {
	Name             string          `json:"name"`
	Title            string          `json:"title,omitempty"`
	Description      string          `json:"description,omitempty"`
	InputSchema      json.RawMessage `json:"input_schema"`
	OutputSchema     json.RawMessage `json:"output_schema,omitempty"`
	InputSchemaHash  string          `json:"input_schema_hash"`
	OutputSchemaHash string          `json:"output_schema_hash,omitempty"`
}

type MCPResourceInventory struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type,omitempty"`
}

type MCPPromptInventory struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

var supportedMCPVersions = map[string]struct{}{
	"2024-11-05": {}, "2025-03-26": {}, "2025-06-18": {}, "2025-11-25": {},
}

func NormalizeMCPInventory(snapshot MCPInventorySnapshot) (MCPInventorySnapshot, error) {
	if _, ok := supportedMCPVersions[snapshot.ProtocolVersion]; !ok {
		return MCPInventorySnapshot{}, errors.New("unsupported MCP protocol version")
	}
	u, err := url.Parse(snapshot.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return MCPInventorySnapshot{}, errors.New("MCP endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if snapshot.Transport != "streamable_http" && snapshot.Transport != "legacy_sse" {
		return MCPInventorySnapshot{}, errors.New("unsupported MCP transport")
	}
	if snapshot.LatencyMillis < 0 || snapshot.LatencyMillis > 120000 || snapshot.ObservedAt.IsZero() {
		return MCPInventorySnapshot{}, errors.New("invalid MCP observation facts")
	}
	if snapshot.ServerName = boundedMCPText(snapshot.ServerName, 128); snapshot.ServerName == "" {
		return MCPInventorySnapshot{}, errors.New("MCP server name is required")
	}
	for i := range snapshot.Tools {
		t := &snapshot.Tools[i]
		if t.Name = boundedMCPText(t.Name, 128); t.Name == "" || !json.Valid(t.InputSchema) || len(t.InputSchema) > 64<<10 || len(t.OutputSchema) > 64<<10 || (len(t.OutputSchema) > 0 && !json.Valid(t.OutputSchema)) {
			return MCPInventorySnapshot{}, fmt.Errorf("invalid MCP tool at index %d", i)
		}
		t.Title, t.Description = boundedMCPText(t.Title, 256), boundedMCPText(t.Description, 2048)
		t.InputSchemaHash = mcpSchemaHash(t.InputSchema)
		if len(t.OutputSchema) > 0 {
			t.OutputSchemaHash = mcpSchemaHash(t.OutputSchema)
		}
	}
	for i := range snapshot.Resources {
		r := &snapshot.Resources[i]
		if r.URI = boundedMCPText(r.URI, 2048); r.URI == "" || strings.ContainsAny(r.URI, "\r\n") {
			return MCPInventorySnapshot{}, fmt.Errorf("invalid MCP resource at index %d", i)
		}
		r.Name, r.Title, r.Description, r.MIMEType = boundedMCPText(r.Name, 256), boundedMCPText(r.Title, 256), boundedMCPText(r.Description, 2048), boundedMCPText(r.MIMEType, 256)
	}
	for i := range snapshot.Prompts {
		p := &snapshot.Prompts[i]
		if p.Name = boundedMCPText(p.Name, 128); p.Name == "" {
			return MCPInventorySnapshot{}, fmt.Errorf("invalid MCP prompt at index %d", i)
		}
		p.Title, p.Description = boundedMCPText(p.Title, 256), boundedMCPText(p.Description, 2048)
	}
	sort.Slice(snapshot.Tools, func(i, j int) bool { return snapshot.Tools[i].Name < snapshot.Tools[j].Name })
	sort.Slice(snapshot.Resources, func(i, j int) bool { return snapshot.Resources[i].URI < snapshot.Resources[j].URI })
	sort.Slice(snapshot.Prompts, func(i, j int) bool { return snapshot.Prompts[i].Name < snapshot.Prompts[j].Name })
	return snapshot, nil
}

func boundedMCPText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return ""
	}
	return value
}
func mcpSchemaHash(schema []byte) string {
	sum := sha256.Sum256(schema)
	return hex.EncodeToString(sum[:])
}
