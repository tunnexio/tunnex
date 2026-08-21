package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	MCPProtocol20251125 = "2025-11-25"
	MCPProtocol20260728 = "2026-07-28"
	maxMCPRequestBody   = 1 << 20
	// -32100 is deliberately outside MCP's reserved -32000..-32099 range.
	mcpToolDeniedCode = -32100
)

// MCPToolRequest is the bounded authoritative subset needed for a per-tool
// decision. Body is retained only until the request is forwarded; callers must
// not persist it or include it in an audit/log record.
type MCPToolRequest struct {
	Method   string
	ToolName string
	ID       json.RawMessage
	Body     []byte
}

// MCPRequestError is safe to render as a local JSON-RPC error. It intentionally
// contains no request body, header value, upstream detail, or credential.
type MCPRequestError struct {
	HTTPStatus int
	Code       int
	Message    string
}

func (e *MCPRequestError) Error() string { return e.Message }

// ValidateMCPToolRequest validates the one HTTP MCP revision selected by the
// configured/observed upstream. The JSON-RPC body is authoritative. Modern
// mirrored headers are required and compared only as an integrity check.
func ValidateMCPToolRequest(expectedVersion string, header http.Header, body []byte) (MCPToolRequest, *MCPRequestError) {
	if expectedVersion != MCPProtocol20251125 && expectedVersion != MCPProtocol20260728 {
		return MCPToolRequest{}, invalidMCPRequest("unsupported MCP protocol version")
	}
	if len(body) == 0 || len(body) > maxMCPRequestBody {
		return MCPToolRequest{}, invalidMCPRequest("MCP request body is invalid")
	}
	var raw struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.JSONRPC != "2.0" || strings.TrimSpace(raw.Method) == "" || !isJSONObject(body) {
		return MCPToolRequest{}, invalidMCPRequest("MCP request body is invalid")
	}
	out := MCPToolRequest{Method: raw.Method, ID: raw.ID, Body: append([]byte(nil), body...)}
	var params struct {
		Name string                 `json:"name"`
		URI  string                 `json:"uri"`
		Meta map[string]interface{} `json:"_meta"`
	}
	if len(raw.Params) > 0 && json.Unmarshal(raw.Params, &params) != nil {
		return MCPToolRequest{}, invalidMCPRequest("MCP request parameters are invalid")
	}
	if raw.Method == "tools/call" {
		if strings.TrimSpace(params.Name) == "" {
			return MCPToolRequest{}, invalidMCPRequest("tools/call has no tool name")
		}
		out.ToolName = params.Name
	}
	if expectedVersion == MCPProtocol20260728 {
		if v, _ := params.Meta["io.modelcontextprotocol/protocolVersion"].(string); v != expectedVersion {
			return MCPToolRequest{}, headerMismatch("MCP protocol version does not match request body")
		}
	}
	name := ""
	switch raw.Method {
	case "tools/call", "prompts/get":
		name = params.Name
	case "resources/read":
		name = params.URI
	}
	if expectedVersion != MCPProtocol20260728 {
		// Legacy Streamable HTTP does not require the mirrored headers. If a
		// caller sends one, keep it an integrity check rather than a claim.
		if method := header.Get("Mcp-Method"); method != "" && method != out.Method {
			return MCPToolRequest{}, headerMismatch("MCP method header does not match request body")
		}
		if name != "" && header.Get("Mcp-Name") != "" {
			headerName, err := decodeMCPHeaderValue(header.Get("Mcp-Name"))
			if err != nil || headerName != name {
				return MCPToolRequest{}, headerMismatch("MCP name header does not match request body")
			}
		}
		return out, nil
	}
	if header.Get("MCP-Protocol-Version") != expectedVersion {
		return MCPToolRequest{}, headerMismatch("MCP protocol version header does not match request body")
	}
	if header.Get("Mcp-Method") != out.Method {
		return MCPToolRequest{}, headerMismatch("MCP method header does not match request body")
	}
	if name != "" {
		headerName, err := decodeMCPHeaderValue(header.Get("Mcp-Name"))
		if err != nil || headerName != name {
			return MCPToolRequest{}, headerMismatch("MCP name header does not match request body")
		}
	}
	return out, nil
}

func isJSONObject(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func invalidMCPRequest(message string) *MCPRequestError {
	return &MCPRequestError{HTTPStatus: http.StatusBadRequest, Code: -32600, Message: message}
}

func headerMismatch(message string) *MCPRequestError {
	return &MCPRequestError{HTTPStatus: http.StatusBadRequest, Code: -32020, Message: message}
}

func decodeMCPHeaderValue(value string) (string, error) {
	if value == "" {
		return "", errors.New("missing MCP header")
	}
	if strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?="))
		if err != nil || !utf8.Valid(decoded) {
			return "", errors.New("invalid encoded MCP header")
		}
		return string(decoded), nil
	}
	if !utf8.ValidString(value) {
		return "", errors.New("invalid MCP header")
	}
	return value, nil
}

// MCPToolGate proves the request-side enforcement seam. The final proxy will
// attach an endpoint-bound credential and a concrete upstream transport; this
// gate already ensures a rejected tool call never reaches that transport.
func MCPToolGate(expectedVersion string, allowed func(tool string) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPRequestBody))
		if err != nil {
			writeMCPError(w, MCPToolRequest{}, invalidMCPRequest("MCP request body is invalid"))
			return
		}
		request, validation := ValidateMCPToolRequest(expectedVersion, r.Header, body)
		if validation != nil {
			writeMCPError(w, request, validation)
			return
		}
		if request.ToolName != "" && (allowed == nil || !allowed(request.ToolName)) {
			writeMCPError(w, request, &MCPRequestError{HTTPStatus: http.StatusForbidden, Code: mcpToolDeniedCode, Message: "MCP tool access denied"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(request.Body))
		r.ContentLength = int64(len(request.Body))
		next.ServeHTTP(w, r)
	})
}

func writeMCPError(w http.ResponseWriter, request MCPToolRequest, failure *MCPRequestError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(failure.HTTPStatus)
	id := interface{}(nil)
	if len(request.ID) > 0 {
		id = json.RawMessage(request.ID)
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": failure.Code, "message": failure.Message}})
}
