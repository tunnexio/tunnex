package mcpgw

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
)

// maxListBytes bounds a tools/list answer the gateway holds in memory to filter.
const maxListBytes = 4 << 20

var errListUnreadable = errors.New("tools/list response cannot be filtered")

// filterToolsList reduces a tools/list answer to the tools the decision says the agent may call
// (AI-SEC-2: an agent sees only callable tools). The answer is plain JSON or, on a streamable-HTTP
// server, an event stream whose JSON-RPC response is one `data:` line; other events on the stream
// (notifications) are not passed on. It returns the body and content type to send.
//
// It fails closed: an answer that is too large, is not one JSON object, repeats a key, or whose tool
// list is not a list is an error, and the caller sends nothing from it.
func filterToolsList(contentType string, body io.Reader, callable []string) ([]byte, string, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxListBytes+1))
	if err != nil || len(data) > maxListBytes {
		return nil, "", errListUnreadable
	}
	allowed := make(map[string]struct{}, len(callable))
	for _, name := range callable {
		allowed[name] = struct{}{}
	}
	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType == "text/event-stream" {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), maxListBytes+1)
		for scanner.Scan() {
			payload, isData := strings.CutPrefix(scanner.Text(), "data:")
			if !isData {
				continue
			}
			filtered, isResponse, err := filterListMessage([]byte(strings.TrimSpace(payload)), allowed)
			if err != nil {
				return nil, "", err
			}
			if !isResponse {
				continue
			}
			return append(append([]byte("event: message\ndata: "), filtered...), "\n\n"...), "text/event-stream", nil
		}
		return nil, "", errListUnreadable
	}
	filtered, isResponse, err := filterListMessage(bytes.TrimSpace(data), allowed)
	if err != nil || !isResponse {
		return nil, "", errListUnreadable
	}
	return filtered, "application/json", nil
}

// filterListMessage filters one JSON-RPC message. isResponse is false for a message that is neither a
// result nor an error (a notification or a server request on the stream).
func filterListMessage(data []byte, allowed map[string]struct{}) (out []byte, isResponse bool, err error) {
	if len(data) == 0 || data[0] != '{' || !json.Valid(data) || rejectDuplicateKeys(data) != nil {
		return nil, false, errListUnreadable
	}
	message, ok := exactObject(data, "result", "error")
	if !ok {
		return nil, false, errListUnreadable
	}
	rawResult, hasResult := message["result"]
	if !hasResult {
		_, hasError := message["error"]
		return data, hasError, nil
	}
	result, ok := exactObject(rawResult, "tools")
	if !ok {
		return nil, false, errListUnreadable
	}
	rawTools, hasTools := result["tools"]
	if !hasTools {
		return data, true, nil
	}
	var tools []json.RawMessage
	if json.Unmarshal(rawTools, &tools) != nil {
		return nil, false, errListUnreadable
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		definition, ok := exactObject(tool, "name")
		if !ok {
			continue
		}
		var name string
		if !isJSONString(definition["name"]) || json.Unmarshal(definition["name"], &name) != nil {
			continue
		}
		if _, callable := allowed[name]; callable {
			kept = append(kept, tool)
		}
	}
	if result["tools"], err = json.Marshal(kept); err != nil {
		return nil, false, errListUnreadable
	}
	if message["result"], err = json.Marshal(result); err != nil {
		return nil, false, errListUnreadable
	}
	if out, err = json.Marshal(message); err != nil {
		return nil, false, errListUnreadable
	}
	return out, true, nil
}
