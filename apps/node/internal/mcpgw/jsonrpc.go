package mcpgw

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
	protocol20260728 = "2026-07-28"
	metaProtocolKey  = "io.modelcontextprotocol/protocolVersion"
	maxJSONDepth     = 128

	codeInvalidRequest = -32600
	// codeTransport is the code the agent-host proxy has always used for a request whose mirrored headers
	// disagree with its body, and for an unavailable upstream (mcpwire.CodeUpstreamUnavailable).
	codeTransport = -32020
)

// request is the part of one MCP JSON-RPC request the gateway acts on. The body is forwarded byte for
// byte; nothing here is persisted or logged.
type request struct {
	Method    string
	ToolName  string
	Arguments json.RawMessage
	// name is what a modern client mirrors in the Mcp-Name header: the tool or prompt name, or the
	// resource URI.
	name string
	// metaProtocol is params._meta's protocol version, which the 2026-07-28 revision mirrors in a header.
	metaProtocol string
	// initializeProtocol is the version an initialize request asks for.
	initializeProtocol string
}

// requestError is safe to return to the caller: it holds no request content.
type requestError struct {
	status  int
	code    int
	message string
}

func invalidRequest(message string) *requestError {
	return &requestError{status: http.StatusBadRequest, code: codeInvalidRequest, message: message}
}

// parseRequest reads one JSON-RPC request the way the control plane and ANY MCP server must agree on.
//
// The control plane decides on the method, tool name and arguments this function extracts, and the MCP
// server then parses the same bytes with its own JSON library. A body two parsers can read differently is
// a way around the policy, so it is refused rather than interpreted:
//
//   - one JSON object only: an array (a JSON-RPC batch) and trailing data are refused;
//   - valid UTF-8 only;
//   - no object anywhere in the body may repeat a key (a first-wins and a last-wins parser disagree);
//   - in the envelope (the request object, params and the arguments object) no two keys may differ only
//     by letter case, and a key that spells jsonrpc, id, method, params, name, uri, arguments or _meta
//     must be spelled exactly so (a case-insensitive parser would read `Method` or `Arguments`).
func parseRequest(body []byte) (request, *requestError) {
	bad := invalidRequest("MCP request body is invalid")
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 || trimmed[0] != '{' || !utf8.Valid(trimmed) || !json.Valid(trimmed) {
		return request{}, bad
	}
	if rejectDuplicateKeys(trimmed) != nil {
		return request{}, bad
	}
	envelope, ok := exactObject(trimmed, "jsonrpc", "id", "method", "params")
	if !ok {
		return request{}, bad
	}
	var version, method string
	if json.Unmarshal(envelope["jsonrpc"], &version) != nil || version != "2.0" {
		return request{}, bad
	}
	if !isJSONString(envelope["method"]) || json.Unmarshal(envelope["method"], &method) != nil ||
		strings.TrimSpace(method) == "" || len(method) > 256 {
		return request{}, bad
	}
	if id := bytes.TrimSpace(envelope["id"]); len(id) > 0 && (id[0] == '{' || id[0] == '[' || id[0] == 't' || id[0] == 'f') {
		return request{}, bad
	}
	out := request{Method: method}
	params := map[string]json.RawMessage{}
	if raw := bytes.TrimSpace(envelope["params"]); len(raw) > 0 {
		if raw[0] != '{' {
			return request{}, invalidRequest("MCP request parameters are invalid")
		}
		if params, ok = exactObject(raw, "name", "uri", "arguments", "_meta", "protocolVersion"); !ok {
			return request{}, invalidRequest("MCP request parameters are invalid")
		}
	}
	str := func(key string) (string, bool) {
		raw, present := params[key]
		if !present {
			return "", true
		}
		var value string
		if !isJSONString(raw) || json.Unmarshal(raw, &value) != nil {
			return "", false
		}
		return value, true
	}
	name, nameOK := str("name")
	uri, uriOK := str("uri")
	switch method {
	case "tools/call":
		if !nameOK || strings.TrimSpace(name) == "" {
			return request{}, invalidRequest("tools/call has no tool name")
		}
		out.ToolName, out.name = name, name
		if raw, present := params["arguments"]; present {
			arguments := bytes.TrimSpace(raw)
			if len(arguments) == 0 || arguments[0] != '{' {
				return request{}, invalidRequest("MCP request parameters are invalid")
			}
			if _, ok := exactObject(arguments); !ok {
				return request{}, invalidRequest("MCP request parameters are invalid")
			}
			out.Arguments = append(json.RawMessage(nil), arguments...)
		}
	case "prompts/get":
		if !nameOK {
			return request{}, invalidRequest("MCP request parameters are invalid")
		}
		out.name = name
	case "resources/read":
		if !uriOK {
			return request{}, invalidRequest("MCP request parameters are invalid")
		}
		out.name = uri
	case "initialize":
		if version, ok := str("protocolVersion"); ok {
			out.initializeProtocol = version
		}
	}
	if raw := bytes.TrimSpace(params["_meta"]); len(raw) > 0 && raw[0] == '{' {
		var meta map[string]json.RawMessage
		if json.Unmarshal(raw, &meta) == nil && isJSONString(meta[metaProtocolKey]) {
			_ = json.Unmarshal(meta[metaProtocolKey], &out.metaProtocol)
		}
	}
	return out, nil
}

// checkMirrors compares the headers a client mirrors from the body. The body is authoritative; a header
// is only ever an integrity check, never a claim. The 2026-07-28 revision requires them, older revisions
// do not send them. It returns the protocol version to tell the control plane.
func checkMirrors(req request, header http.Header) (string, *requestError) {
	mismatch := func(message string) *requestError {
		return &requestError{status: http.StatusBadRequest, code: codeTransport, message: message}
	}
	version := ""
	if values := header.Values("Mcp-Protocol-Version"); len(values) > 1 {
		return "", mismatch("MCP protocol version header does not match request body")
	} else if len(values) == 1 {
		if version = values[0]; !isProtocolVersion(version) {
			return "", mismatch("MCP protocol version header does not match request body")
		}
	}
	if version != protocol20260728 {
		if method := header.Get("Mcp-Method"); method != "" && method != req.Method {
			return "", mismatch("MCP method header does not match request body")
		}
		if req.name != "" && header.Get("Mcp-Name") != "" {
			if name, err := decodeHeaderValue(header.Get("Mcp-Name")); err != nil || name != req.name {
				return "", mismatch("MCP name header does not match request body")
			}
		}
		if version == "" && isProtocolVersion(req.initializeProtocol) {
			version = req.initializeProtocol
		}
		return version, nil
	}
	if req.metaProtocol != version {
		return "", mismatch("MCP protocol version does not match request body")
	}
	if header.Get("Mcp-Method") != req.Method {
		return "", mismatch("MCP method header does not match request body")
	}
	if req.name != "" {
		if name, err := decodeHeaderValue(header.Get("Mcp-Name")); err != nil || name != req.name {
			return "", mismatch("MCP name header does not match request body")
		}
	}
	return version, nil
}

// isProtocolVersion accepts the YYYY-MM-DD form of an MCP revision.
func isProtocolVersion(value string) bool {
	if len(value) != 10 || value[4] != '-' || value[7] != '-' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if i != 4 && i != 7 && (value[i] < '0' || value[i] > '9') {
			return false
		}
	}
	return true
}

func decodeHeaderValue(value string) (string, error) {
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

func isJSONString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '"'
}

// exactObject decodes one JSON object by its exact key spelling. It refuses an object in which two keys
// differ only by letter case, or in which a key spells one of the reserved names in another case.
func exactObject(raw []byte, reserved ...string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, false
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		for _, name := range reserved {
			if key != name && strings.EqualFold(key, name) {
				return nil, false
			}
		}
		for _, seen := range keys {
			if strings.EqualFold(seen, key) {
				return nil, false
			}
		}
		keys = append(keys, key)
	}
	return object, true
}

// rejectDuplicateKeys walks one JSON document and fails if any object repeats a key (after escape
// decoding) or the nesting is deeper than the gateway is willing to follow.
func rejectDuplicateKeys(data []byte) error {
	type frame struct {
		keys    map[string]struct{} // nil for an array
		wantKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].wantKey = true
		}
	}
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return errors.New("JSON nesting is too deep")
				}
				f := frame{}
				if value == '{' {
					f.keys, f.wantKey = map[string]struct{}{}, true
				}
				stack = append(stack, f)
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].wantKey {
				if _, repeated := stack[n-1].keys[value]; repeated {
					return errors.New("JSON object repeats a key")
				}
				stack[n-1].keys[value] = struct{}{}
				stack[n-1].wantKey = false
				continue
			}
			valueDone()
		default:
			valueDone()
		}
	}
	if len(stack) != 0 {
		return errors.New("JSON document is incomplete")
	}
	return nil
}
