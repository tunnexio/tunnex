package mcptoolpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// Tool definition states relative to the rule that pins the tool.
const (
	DefinitionCurrent = "current"
	DefinitionChanged = "changed"
)

// Inventory sources.
const (
	SourceAgent   = "agent"
	SourceGateway = "gateway"
)

// StatusHealthy is the only server status a tool list is usable under.
const StatusHealthy = "healthy"

const (
	maxObservedTools       = 2048
	maxObservedSchemaBytes = 64 << 10
	maxObservedDescription = 64 << 10
	maxStoredDescription   = 2048
	maxSnapshotBytes       = 512 << 10
)

// ErrInvalidDefinition means a reported tool definition cannot be hashed or stored.
var ErrInvalidDefinition = errors.New("invalid MCP tool definition")

// canonicalJSON re-encodes a JSON value with sorted object keys. It is the same normal form the agent host
// produced for input schemas before discovery moved to the gateway, so an input schema hash computed here
// equals the one an existing rule already carries.
func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, ErrInvalidDefinition
	}
	return json.Marshal(value)
}

// InputSchemaHash is the SHA-256 of a tool's canonical input schema.
func InputSchemaHash(schema json.RawMessage) (string, error) {
	canonical, err := canonicalJSON(schema)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// DefinitionHash is the SHA-256 of the canonical {name, description, input_schema} of a tool. It is always
// computed by the control plane from the raw definition; a hash supplied by a reporter is never used.
func DefinitionHash(name, description string, inputSchema json.RawMessage) (string, error) {
	var schema interface{}
	if err := json.Unmarshal(inputSchema, &schema); err != nil {
		return "", ErrInvalidDefinition
	}
	canonical, err := json.Marshal(map[string]interface{}{"name": name, "description": description, "input_schema": schema})
	if err != nil {
		return "", ErrInvalidDefinition
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// ObservedTool is a tool definition exactly as an MCP server returned it to the gateway.
type ObservedTool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// GatewayObservation is what a gateway saw for one agent's MCP server.
type GatewayObservation struct {
	Endpoint        string
	Status          string
	ServerName      string
	ProtocolVersion string
	LatencyMillis   int64
	Tools           []ObservedTool
}

// InventoryTool is one tool of the stored inventory.
type InventoryTool struct {
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	InputSchema        json.RawMessage `json:"input_schema,omitempty"`
	InputSchemaHash    string          `json:"input_schema_hash"`
	ToolDefinitionHash string          `json:"tool_definition_hash,omitempty"`
	DefinitionState    string          `json:"definition_state,omitempty"`
	FirstSeenAt        string          `json:"first_seen_at,omitempty"`
	LastSeenAt         string          `json:"last_seen_at,omitempty"`
	Changed            bool            `json:"changed"`
}

// InventoryServer is one MCP server of the stored inventory.
type InventoryServer struct {
	Endpoint        string          `json:"endpoint"`
	ServerName      string          `json:"server_name"`
	Status          string          `json:"status"`
	ProtocolVersion string          `json:"protocol_version,omitempty"`
	Transport       string          `json:"transport,omitempty"`
	LatencyMillis   int64           `json:"latency_millis"`
	ObservedAt      string          `json:"observed_at,omitempty"`
	Tools           []InventoryTool `json:"tools"`
}

// Inventory is the typed view of a stored inventory row that policy decisions read.
type Inventory struct {
	Source     string
	ObservedAt time.Time
	Servers    []InventoryServer
}

// Server returns the inventory of one endpoint.
func (i Inventory) Server(endpoint string) (InventoryServer, bool) {
	for _, server := range i.Servers {
		if server.Endpoint == endpoint {
			return server, true
		}
	}
	return InventoryServer{}, false
}

// Tool returns one tool of the server by name.
func (s InventoryServer) Tool(name string) (InventoryTool, bool) {
	for _, tool := range s.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return InventoryTool{}, false
}

func parseInventory(snapshot []byte, source string, observed time.Time) Inventory {
	var value struct {
		Servers []InventoryServer `json:"servers"`
	}
	_ = json.Unmarshal(snapshot, &value)
	return Inventory{Source: source, ObservedAt: observed, Servers: value.Servers}
}

// observedServer turns a gateway observation into the stored server entry. An observation that is not
// healthy, or whose definitions cannot be hashed, keeps the tools last seen (so an administrator still sees
// them) under a status no decision will accept.
func observedServer(in GatewayObservation, previous InventoryServer, hadPrevious bool, now time.Time) InventoryServer {
	seen := now.UTC().Format(time.RFC3339Nano)
	out := InventoryServer{Endpoint: in.Endpoint, ServerName: strings.TrimSpace(in.ServerName), Status: in.Status, ProtocolVersion: boundedText(in.ProtocolVersion, 64), Transport: "streamable_http", ObservedAt: seen, Tools: []InventoryTool{}}
	if in.LatencyMillis > 0 && in.LatencyMillis <= 120000 {
		out.LatencyMillis = in.LatencyMillis
	}
	switch in.Status {
	case StatusHealthy, "unavailable", "unauthorized", "invalid":
	default:
		out.Status = "invalid"
	}
	tools, ok := observedTools(in.Tools, previous, seen)
	if out.Status == StatusHealthy && (!ok || out.ServerName == "" || len(out.ServerName) > 128) {
		out.Status = "invalid"
	}
	if out.Status != StatusHealthy {
		if hadPrevious {
			out.Tools = previous.Tools
			if out.ServerName == "" || len(out.ServerName) > 128 {
				out.ServerName = previous.ServerName
			}
		}
		if len(out.ServerName) > 128 {
			out.ServerName = ""
		}
		return out
	}
	out.Tools = tools
	return out
}

func observedTools(in []ObservedTool, previous InventoryServer, seen string) ([]InventoryTool, bool) {
	if len(in) > maxObservedTools {
		return nil, false
	}
	out := make([]InventoryTool, 0, len(in))
	names := make(map[string]bool, len(in))
	for _, tool := range in {
		name := strings.TrimSpace(tool.Name)
		if name == "" || name != tool.Name || len(name) > 128 || names[name] || !utf8.ValidString(tool.Description) || len(tool.Description) > maxObservedDescription || len(tool.InputSchema) == 0 || len(tool.InputSchema) > maxObservedSchemaBytes {
			return nil, false
		}
		names[name] = true
		schema, err := canonicalJSON(tool.InputSchema)
		if err != nil {
			return nil, false
		}
		var object map[string]interface{}
		if json.Unmarshal(schema, &object) != nil || object == nil {
			return nil, false
		}
		schemaHash, err := InputSchemaHash(tool.InputSchema)
		if err != nil {
			return nil, false
		}
		definitionHash, err := DefinitionHash(tool.Name, tool.Description, tool.InputSchema)
		if err != nil {
			return nil, false
		}
		item := InventoryTool{Name: name, Description: storedDescription(tool.Description), InputSchema: schema, InputSchemaHash: schemaHash, ToolDefinitionHash: definitionHash, FirstSeenAt: seen, LastSeenAt: seen, Changed: true}
		if prior, ok := previous.Tool(name); ok {
			if prior.FirstSeenAt != "" {
				item.FirstSeenAt = prior.FirstSeenAt
			}
			item.Changed = prior.ToolDefinitionHash != definitionHash
		}
		out = append(out, item)
	}
	sortTools(out)
	return out, true
}

func sortTools(tools []InventoryTool) {
	for i := 1; i < len(tools); i++ {
		for j := i; j > 0 && tools[j].Name < tools[j-1].Name; j-- {
			tools[j], tools[j-1] = tools[j-1], tools[j]
		}
	}
}

// storedDescription bounds what is kept for display. The definition hash always covers the full text.
func storedDescription(value string) string {
	if len(value) <= maxStoredDescription {
		return value
	}
	cut := maxStoredDescription
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

func boundedText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return ""
	}
	return value
}

func validDefinitionHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
