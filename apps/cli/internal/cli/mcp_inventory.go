package cli

import (
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

func observeMCPEndpoint(ctx context.Context, endpoint string) map[string]interface{} {
	base := map[string]interface{}{"endpoint": endpoint, "status": "failed"}
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		start := time.Now()
		init, err := mcpRequest(ctx, endpoint, 1, "initialize", map[string]interface{}{"protocolVersion": version, "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "tunnex-agent-runtime", "version": "f12"}})
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
		_, _ = mcpRequest(ctx, endpoint, 2, "notifications/initialized", map[string]interface{}{})
		for _, spec := range []struct{ key, method string }{{"tools", "tools/list"}, {"resources", "resources/list"}, {"prompts", "prompts/list"}} {
			if reply, err := mcpRequest(ctx, endpoint, 3, spec.method, map[string]interface{}{}); err == nil {
				if r, ok := reply["result"].(map[string]interface{}); ok {
					base[spec.key] = r[spec.key]
				}
			}
		}
		return base
	}
	return base
}

func mcpRequest(ctx context.Context, endpoint string, id int, method string, params interface{}) (map[string]interface{}, error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("MCP HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("data: "))
	var reply map[string]interface{}
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, err
	}
	return reply, nil
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
