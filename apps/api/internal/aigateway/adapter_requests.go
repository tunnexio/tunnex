package aigateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Request validation runs before authorization, so malformed or unqualified
// payloads never reach cost admission or the engine. Every object is decoded
// with duplicate keys refused, every field is allowlisted per route and role,
// and every value has a type and size bound. See docs/AI-COMPAT-1-decisions.md.

var errInvalidRequest = errors.New("invalid inference payload")

var (
	toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	integerPattern  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	tokenIDPattern  = regexp.MustCompile(`^(0|[1-9][0-9]{0,7})$`)
	dataImageURL    = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp);base64,`)
)

const (
	maxToolCount        = 128
	maxToolDescription  = 4096
	maxSchemaBytes      = 64 << 10
	maxAllToolsBytes    = 1 << 20
	maxToolArguments    = 256 << 10
	maxIdentifierBytes  = 256
	maxContentParts     = 256
	maxImageBytes       = 20 << 20
	maxEmbeddingInputs  = 2048
	maxEmbeddingTokens  = 8192
	maxStopSequences    = 16
	maxStopBytes        = 256
	maxMetadataEntries  = 16
	maxMetadataKey      = 64
	maxMetadataValue    = 512
	maxLogitBiasEntries = 300
)

// strictObject decodes one JSON object, refusing duplicate keys, nulls (unless
// nullable names the key) and trailing data.
func strictObject(raw []byte, nullable ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, dup := out[key]; dup {
			return nil, false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, false
		}
		if isJSONNull(v) && !contains(nullable, key) {
			return nil, false
		}
		out[key] = v
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func isJSONNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// onlyKeys reports whether every key of m is allowed.
func onlyKeys(m map[string]json.RawMessage, allowed ...string) bool {
	for k := range m {
		if !contains(allowed, k) {
			return false
		}
	}
	return true
}

func jsonString(raw json.RawMessage, min, max int) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) < min || len(s) > max {
		return "", false
	}
	return s, true
}

func jsonBool(raw json.RawMessage) bool {
	var b bool
	raw = bytes.TrimSpace(raw)
	return (len(raw) > 0 && (raw[0] == 't' || raw[0] == 'f')) && json.Unmarshal(raw, &b) == nil
}

func jsonNumber(raw json.RawMessage, min, max float64) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !(raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
		return false
	}
	var f float64
	return json.Unmarshal(raw, &f) == nil && f >= min && f <= max
}

func jsonInt(raw json.RawMessage, min, max int64) (int64, bool) {
	s := string(bytes.TrimSpace(raw))
	if !integerPattern.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

func jsonArray(raw json.RawMessage, min, max int) ([]json.RawMessage, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) < min || len(items) > max {
		return nil, false
	}
	return items, true
}

func jsonEnum(raw json.RawMessage, values ...string) bool {
	s, ok := jsonString(raw, 1, 64)
	return ok && contains(values, s)
}

// boundedObject is any JSON object (for example a JSON schema) of at most max
// bytes. Its content is the provider's to interpret.
func boundedObject(raw json.RawMessage, max int) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && len(raw) <= max && raw[0] == '{' && json.Valid(raw)
}

// stringOrList accepts one string or an array of 1..maxCount strings.
func stringOrList(raw json.RawMessage, maxCount, maxLen int) bool {
	if _, ok := jsonString(raw, 1, maxLen); ok {
		return true
	}
	items, ok := jsonArray(raw, 1, maxCount)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := jsonString(item, 1, maxLen); !ok {
			return false
		}
	}
	return true
}

func validMetadata(raw json.RawMessage) bool {
	m, ok := strictObject(raw)
	if !ok || len(m) > maxMetadataEntries {
		return false
	}
	for k, v := range m {
		if k == "" || len(k) > maxMetadataKey {
			return false
		}
		if _, ok := jsonString(v, 0, maxMetadataValue); !ok {
			return false
		}
	}
	return true
}

func validLogitBias(raw json.RawMessage) bool {
	m, ok := strictObject(raw)
	if !ok || len(m) > maxLogitBiasEntries {
		return false
	}
	for k, v := range m {
		if !tokenIDPattern.MatchString(k) || !jsonNumber(v, -100, 100) {
			return false
		}
	}
	return true
}

func validDataImage(url string) bool {
	loc := dataImageURL.FindStringIndex(url)
	if loc == nil {
		return false
	}
	return validBase64(url[loc[1]:], maxImageBytes)
}

func validBase64(data string, maxDecoded int) bool {
	if data == "" || base64.StdEncoding.DecodedLen(len(data)) > maxDecoded+3 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(data)
	return err == nil
}

// catalogOutputLimit is the bundled catalog's maximum output for an exact
// provider/model id, or 0 when unknown or ambiguous.
func catalogOutputLimit(model string) int {
	if loadModelCatalog() != nil {
		return 0
	}
	best := 0
	for _, row := range bakedCatalogIndex[model] {
		n := 0
		for _, key := range []string{"max_output_tokens", "max_tokens"} {
			if v, ok := jsonInt(row.Metadata[key], 1, 10_000_000); ok {
				n = int(v)
				break
			}
		}
		if n == 0 {
			return 0
		}
		if best == 0 || n < best {
			best = n
		}
	}
	return best
}

// defaultOutputTokens is used when a request names no output limit.
func (a *Adapter) defaultOutputTokens(model string) int {
	if n := catalogOutputLimit(model); n > 0 {
		return min(n, a.limits.MaxOutputTokens)
	}
	return a.limits.DefaultOutputTokens
}

func (a *Adapter) normalizeJSON(path string, mode ModelMode, body []byte) ([]byte, string, bool, error) {
	switch path {
	case "/v1/chat/completions":
		return a.normalizeChat(body)
	case "/anthropic/v1/messages":
		return a.normalizeMessages(body)
	case "/v1/responses":
		return a.normalizeResponses(body)
	}
	out, model, err := a.normalizedModeJSON(body, mode)
	if err != nil {
		return nil, "", false, err
	}
	stream := false
	if mode == ModeCompletion {
		var p struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(out, &p)
		stream = p.Stream
	}
	return out, model, stream, nil
}

func validModel(raw json.RawMessage) (string, bool) {
	model, ok := jsonString(raw, 1, 256)
	return model, ok && strings.TrimSpace(model) == model
}

func (a *Adapter) outputLimit(raw json.RawMessage) bool {
	_, ok := jsonInt(raw, 1, int64(a.limits.MaxOutputTokens))
	return ok
}

// ---- OpenAI chat completions ----

func (a *Adapter) normalizeChat(body []byte) ([]byte, string, bool, error) {
	p, ok := strictObject(body)
	if !ok || !onlyKeys(p, "model", "messages", "stream", "stream_options", "max_tokens", "max_completion_tokens", "temperature", "top_p",
		"frequency_penalty", "presence_penalty", "stop", "seed", "n", "user", "safety_identifier", "prompt_cache_key", "logprobs", "top_logprobs",
		"logit_bias", "reasoning_effort", "verbosity", "metadata", "service_tier", "store", "parallel_tool_calls", "tools", "tool_choice", "response_format") {
		return nil, "", false, errInvalidRequest
	}
	model, ok := validModel(p["model"])
	if !ok || p["messages"] == nil {
		return nil, "", false, errInvalidRequest
	}
	if p["max_tokens"] != nil && p["max_completion_tokens"] != nil {
		return nil, "", false, errInvalidRequest
	}
	tools, ok := validChatTools(p["tools"])
	if !ok {
		return nil, "", false, errInvalidRequest
	}
	for key, raw := range p {
		valid := true
		switch key {
		case "model", "tools":
		case "messages":
			valid = a.validChatMessages(raw)
		case "stream", "logprobs", "parallel_tool_calls":
			valid = jsonBool(raw)
		case "stream_options":
			m, ok := strictObject(raw)
			valid = ok && onlyKeys(m, "include_usage") && (m["include_usage"] == nil || jsonBool(m["include_usage"]))
		case "max_tokens", "max_completion_tokens":
			valid = a.outputLimit(raw)
		case "temperature":
			valid = jsonNumber(raw, 0, 2)
		case "top_p":
			valid = jsonNumber(raw, 0, 1)
		case "frequency_penalty", "presence_penalty":
			valid = jsonNumber(raw, -2, 2)
		case "stop":
			valid = stringOrList(raw, 4, maxStopBytes)
		case "seed":
			_, valid = jsonInt(raw, -1<<53, 1<<53)
		case "n":
			_, valid = jsonInt(raw, 1, 1)
		case "user", "safety_identifier", "prompt_cache_key":
			_, valid = jsonString(raw, 1, maxIdentifierBytes)
		case "top_logprobs":
			_, valid = jsonInt(raw, 0, 20)
		case "logit_bias":
			valid = validLogitBias(raw)
		case "reasoning_effort":
			valid = jsonEnum(raw, "minimal", "low", "medium", "high")
		case "verbosity":
			valid = jsonEnum(raw, "low", "medium", "high")
		case "metadata":
			valid = validMetadata(raw)
		case "service_tier":
			valid = jsonEnum(raw, "auto", "default")
		case "store":
			valid = string(bytes.TrimSpace(raw)) == "false"
		case "tool_choice":
			valid = validChatToolChoice(raw, tools)
		case "response_format":
			valid = validChatResponseFormat(raw)
		default:
			valid = false
		}
		if !valid {
			return nil, "", false, errInvalidRequest
		}
	}
	if p["tool_choice"] != nil && len(tools) == 0 {
		return nil, "", false, errInvalidRequest
	}
	if limit, ok := p["max_completion_tokens"]; ok {
		p["max_tokens"] = limit
		delete(p, "max_completion_tokens")
	}
	if _, ok := p["max_tokens"]; !ok {
		p["max_tokens"] = json.RawMessage(strconv.Itoa(a.defaultOutputTokens(model)))
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, "", false, errInvalidRequest
	}
	return out, model, string(bytes.TrimSpace(p["stream"])) == "true", nil
}

// validChatTools returns the declared function names.
func validChatTools(raw json.RawMessage) (map[string]bool, bool) {
	names := map[string]bool{}
	if raw == nil {
		return names, true
	}
	items, ok := jsonArray(raw, 1, maxToolCount)
	if !ok || len(bytes.TrimSpace(raw)) > maxAllToolsBytes {
		return nil, false
	}
	for _, item := range items {
		t, ok := strictObject(item)
		if !ok || !onlyKeys(t, "type", "function") || !jsonEnum(t["type"], "function") || t["function"] == nil {
			return nil, false
		}
		f, ok := strictObject(t["function"])
		if !ok || !onlyKeys(f, "name", "description", "parameters", "strict") {
			return nil, false
		}
		name, ok := jsonString(f["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) || names[name] {
			return nil, false
		}
		if f["description"] != nil {
			if _, ok := jsonString(f["description"], 0, maxToolDescription); !ok {
				return nil, false
			}
		}
		if f["parameters"] != nil && !boundedObject(f["parameters"], maxSchemaBytes) {
			return nil, false
		}
		if f["strict"] != nil && !jsonBool(f["strict"]) {
			return nil, false
		}
		names[name] = true
	}
	return names, true
}

func validChatToolChoice(raw json.RawMessage, tools map[string]bool) bool {
	if jsonEnum(raw, "none", "auto", "required") {
		return true
	}
	c, ok := strictObject(raw)
	if !ok || !onlyKeys(c, "type", "function") || !jsonEnum(c["type"], "function") || c["function"] == nil {
		return false
	}
	f, ok := strictObject(c["function"])
	if !ok || !onlyKeys(f, "name") {
		return false
	}
	name, ok := jsonString(f["name"], 1, 64)
	return ok && tools[name]
}

func validChatResponseFormat(raw json.RawMessage) bool {
	f, ok := strictObject(raw)
	if !ok {
		return false
	}
	switch {
	case jsonEnum(f["type"], "text", "json_object"):
		return onlyKeys(f, "type")
	case jsonEnum(f["type"], "json_schema"):
		if !onlyKeys(f, "type", "json_schema") || f["json_schema"] == nil {
			return false
		}
		s, ok := strictObject(f["json_schema"])
		if !ok || !onlyKeys(s, "name", "description", "schema", "strict") {
			return false
		}
		name, ok := jsonString(s["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) {
			return false
		}
		if s["description"] != nil {
			if _, ok := jsonString(s["description"], 0, maxToolDescription); !ok {
				return false
			}
		}
		if s["schema"] != nil && !boundedObject(s["schema"], maxSchemaBytes) {
			return false
		}
		return s["strict"] == nil || jsonBool(s["strict"])
	}
	return false
}

func (a *Adapter) validChatMessages(raw json.RawMessage) bool {
	items, ok := jsonArray(raw, 1, a.limits.MaxMessages)
	if !ok {
		return false
	}
	for _, item := range items {
		if !validChatMessage(item) {
			return false
		}
	}
	return true
}

func validChatMessage(raw json.RawMessage) bool {
	m, ok := strictObject(raw, "content")
	if !ok {
		return false
	}
	role, ok := jsonString(m["role"], 1, 16)
	if !ok {
		return false
	}
	if m["name"] != nil {
		name, ok := jsonString(m["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) || role == "tool" {
			return false
		}
	}
	content, hasContent := m["content"]
	switch role {
	case "system", "developer":
		return onlyKeys(m, "role", "content", "name") && hasContent && validChatContent(content, "text")
	case "user":
		return onlyKeys(m, "role", "content", "name") && hasContent && validChatContent(content, "text", "image_url", "input_audio")
	case "tool":
		if !onlyKeys(m, "role", "content", "tool_call_id") || !hasContent || !validChatContent(content, "text") {
			return false
		}
		_, ok := jsonString(m["tool_call_id"], 1, maxIdentifierBytes)
		return ok
	case "assistant":
		if !onlyKeys(m, "role", "content", "name", "tool_calls", "refusal") {
			return false
		}
		if m["refusal"] != nil {
			if _, ok := jsonString(m["refusal"], 0, 1<<20); !ok {
				return false
			}
		}
		if m["tool_calls"] != nil && !validChatToolCalls(m["tool_calls"]) {
			return false
		}
		if !hasContent || isJSONNull(content) {
			// Content may be null or absent only alongside tool calls.
			return m["tool_calls"] != nil
		}
		return validChatContent(content, "text", "refusal")
	}
	return false
}

func validChatToolCalls(raw json.RawMessage) bool {
	items, ok := jsonArray(raw, 1, maxToolCount)
	if !ok {
		return false
	}
	for _, item := range items {
		c, ok := strictObject(item)
		if !ok || !onlyKeys(c, "id", "type", "function") || !jsonEnum(c["type"], "function") || c["function"] == nil {
			return false
		}
		if _, ok := jsonString(c["id"], 1, maxIdentifierBytes); !ok {
			return false
		}
		f, ok := strictObject(c["function"])
		if !ok || !onlyKeys(f, "name", "arguments") {
			return false
		}
		name, ok := jsonString(f["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) {
			return false
		}
		if _, ok := jsonString(f["arguments"], 0, maxToolArguments); !ok {
			return false
		}
	}
	return true
}

// validChatContent accepts a string or an array of the allowed part types.
func validChatContent(raw json.RawMessage, parts ...string) bool {
	if _, ok := jsonString(raw, 0, 1<<30); ok {
		return true
	}
	items, ok := jsonArray(raw, 1, maxContentParts)
	if !ok {
		return false
	}
	for _, item := range items {
		p, ok := strictObject(item)
		if !ok {
			return false
		}
		kind, ok := jsonString(p["type"], 1, 32)
		if !ok || !contains(parts, kind) {
			return false
		}
		switch kind {
		case "text":
			_, ok = jsonString(p["text"], 0, 1<<30)
			ok = ok && onlyKeys(p, "type", "text")
		case "refusal":
			_, ok = jsonString(p["refusal"], 0, 1<<20)
			ok = ok && onlyKeys(p, "type", "refusal")
		case "image_url":
			ok = onlyKeys(p, "type", "image_url") && p["image_url"] != nil
			if ok {
				img, valid := strictObject(p["image_url"])
				url, urlOK := jsonString(img["url"], 1, 1<<30)
				ok = valid && onlyKeys(img, "url", "detail") && urlOK && validDataImage(url) && (img["detail"] == nil || jsonEnum(img["detail"], "auto", "low", "high"))
			}
		case "input_audio":
			ok = onlyKeys(p, "type", "input_audio") && p["input_audio"] != nil
			if ok {
				audio, valid := strictObject(p["input_audio"])
				data, dataOK := jsonString(audio["data"], 1, 1<<30)
				ok = valid && onlyKeys(audio, "data", "format") && dataOK && validBase64(data, maxImageBytes) && jsonEnum(audio["format"], "wav", "mp3")
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// ---- Messages API (/anthropic/v1/messages) ----

func (a *Adapter) normalizeMessages(body []byte) ([]byte, string, bool, error) {
	p, ok := strictObject(body)
	if !ok || !onlyKeys(p, "model", "messages", "max_tokens", "system", "stream", "temperature", "top_p", "top_k", "stop_sequences", "metadata", "tools", "tool_choice", "thinking") {
		return nil, "", false, errInvalidRequest
	}
	model, ok := validModel(p["model"])
	if !ok || p["messages"] == nil {
		return nil, "", false, errInvalidRequest
	}
	rewrite := false
	if p["max_tokens"] == nil {
		// The Messages API requires max_tokens; supply the same default the
		// chat route uses rather than refusing.
		p["max_tokens"] = json.RawMessage(strconv.Itoa(a.defaultOutputTokens(model)))
		rewrite = true
	}
	maxTokens, ok := jsonInt(p["max_tokens"], 1, int64(a.limits.MaxOutputTokens))
	if !ok {
		return nil, "", false, errInvalidRequest
	}
	tools, ok := validMessagesTools(p["tools"])
	if !ok {
		return nil, "", false, errInvalidRequest
	}
	for key, raw := range p {
		valid := true
		switch key {
		case "model", "max_tokens", "tools":
		case "messages":
			items, ok := jsonArray(raw, 1, a.limits.MaxMessages)
			valid = ok
			for _, item := range items {
				valid = valid && validMessagesMessage(item)
			}
		case "system":
			if _, ok := jsonString(raw, 0, 1<<30); !ok {
				valid = validMessagesBlocks(raw, "user", "text")
			}
		case "stream":
			valid = jsonBool(raw)
		case "temperature", "top_p":
			valid = jsonNumber(raw, 0, 1)
		case "top_k":
			_, valid = jsonInt(raw, 1, 1000)
		case "stop_sequences":
			items, ok := jsonArray(raw, 0, maxStopSequences)
			valid = ok
			for _, item := range items {
				_, ok := jsonString(item, 1, maxStopBytes)
				valid = valid && ok
			}
		case "metadata":
			m, ok := strictObject(raw)
			valid = ok && onlyKeys(m, "user_id")
			if valid && m["user_id"] != nil {
				_, valid = jsonString(m["user_id"], 1, maxIdentifierBytes)
			}
		case "tool_choice":
			valid = validMessagesToolChoice(raw, tools)
		case "thinking":
			valid = validThinking(raw, maxTokens)
		default:
			valid = false
		}
		if !valid {
			return nil, "", false, errInvalidRequest
		}
	}
	if p["tool_choice"] != nil && len(tools) == 0 {
		return nil, "", false, errInvalidRequest
	}
	stream := string(bytes.TrimSpace(p["stream"])) == "true"
	if !rewrite {
		// The original bytes are forwarded: only validation, no rewriting.
		return body, model, stream, nil
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, "", false, errInvalidRequest
	}
	return out, model, stream, nil
}

func validCacheControl(raw json.RawMessage) bool {
	c, ok := strictObject(raw)
	return ok && onlyKeys(c, "type", "ttl") && jsonEnum(c["type"], "ephemeral") && (c["ttl"] == nil || jsonEnum(c["ttl"], "5m", "1h"))
}

func validMessagesTools(raw json.RawMessage) (map[string]bool, bool) {
	names := map[string]bool{}
	if raw == nil {
		return names, true
	}
	items, ok := jsonArray(raw, 1, maxToolCount)
	if !ok || len(bytes.TrimSpace(raw)) > maxAllToolsBytes {
		return nil, false
	}
	for _, item := range items {
		t, ok := strictObject(item)
		if !ok || !onlyKeys(t, "type", "name", "description", "input_schema", "cache_control") {
			return nil, false
		}
		// Only caller-executed custom tools; provider server tools are refused.
		if t["type"] != nil && !jsonEnum(t["type"], "custom") {
			return nil, false
		}
		name, ok := jsonString(t["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) || names[name] || !boundedObject(t["input_schema"], maxSchemaBytes) {
			return nil, false
		}
		if t["description"] != nil {
			if _, ok := jsonString(t["description"], 0, maxToolDescription); !ok {
				return nil, false
			}
		}
		if t["cache_control"] != nil && !validCacheControl(t["cache_control"]) {
			return nil, false
		}
		names[name] = true
	}
	return names, true
}

func validMessagesToolChoice(raw json.RawMessage, tools map[string]bool) bool {
	c, ok := strictObject(raw)
	if !ok || (c["disable_parallel_tool_use"] != nil && !jsonBool(c["disable_parallel_tool_use"])) {
		return false
	}
	switch {
	case jsonEnum(c["type"], "auto", "any"):
		return onlyKeys(c, "type", "disable_parallel_tool_use")
	case jsonEnum(c["type"], "none"):
		return onlyKeys(c, "type")
	case jsonEnum(c["type"], "tool"):
		name, ok := jsonString(c["name"], 1, 64)
		return ok && tools[name] && onlyKeys(c, "type", "name", "disable_parallel_tool_use")
	}
	return false
}

func validThinking(raw json.RawMessage, maxTokens int64) bool {
	t, ok := strictObject(raw)
	if !ok {
		return false
	}
	switch {
	case jsonEnum(t["type"], "disabled"):
		return onlyKeys(t, "type")
	case jsonEnum(t["type"], "enabled"):
		budget, ok := jsonInt(t["budget_tokens"], 1024, maxTokens-1)
		return ok && budget < maxTokens && onlyKeys(t, "type", "budget_tokens")
	}
	return false
}

func validMessagesMessage(raw json.RawMessage) bool {
	m, ok := strictObject(raw)
	if !ok || !onlyKeys(m, "role", "content") || m["content"] == nil {
		return false
	}
	role, ok := jsonString(m["role"], 1, 16)
	if !ok || (role != "user" && role != "assistant") {
		return false
	}
	if _, ok := jsonString(m["content"], 0, 1<<30); ok {
		return true
	}
	if role == "user" {
		return validMessagesBlocks(m["content"], role, "text", "image", "tool_result")
	}
	return validMessagesBlocks(m["content"], role, "text", "tool_use", "thinking", "redacted_thinking")
}

func validMessagesBlocks(raw json.RawMessage, role string, kinds ...string) bool {
	items, ok := jsonArray(raw, 1, maxContentParts)
	if !ok {
		return false
	}
	for _, item := range items {
		b, ok := strictObject(item)
		if !ok {
			return false
		}
		kind, ok := jsonString(b["type"], 1, 32)
		if !ok || !contains(kinds, kind) {
			return false
		}
		if b["cache_control"] != nil && !validCacheControl(b["cache_control"]) {
			return false
		}
		switch kind {
		case "text":
			_, ok = jsonString(b["text"], 0, 1<<30)
			ok = ok && onlyKeys(b, "type", "text", "cache_control")
		case "image":
			ok = onlyKeys(b, "type", "source", "cache_control") && validImageSource(b["source"])
		case "tool_use":
			_, idOK := jsonString(b["id"], 1, maxIdentifierBytes)
			name, nameOK := jsonString(b["name"], 1, 64)
			ok = onlyKeys(b, "type", "id", "name", "input", "cache_control") && idOK && nameOK && toolNamePattern.MatchString(name) && boundedObject(b["input"], maxToolArguments)
		case "tool_result":
			_, idOK := jsonString(b["tool_use_id"], 1, maxIdentifierBytes)
			ok = onlyKeys(b, "type", "tool_use_id", "content", "is_error", "cache_control") && idOK && (b["is_error"] == nil || jsonBool(b["is_error"]))
			if ok && b["content"] != nil {
				if _, isString := jsonString(b["content"], 0, 1<<30); !isString {
					ok = validMessagesBlocks(b["content"], role, "text", "image")
				}
			}
		case "thinking":
			_, textOK := jsonString(b["thinking"], 0, 1<<30)
			_, sigOK := jsonString(b["signature"], 0, 1<<20)
			ok = onlyKeys(b, "type", "thinking", "signature") && textOK && sigOK
		case "redacted_thinking":
			_, ok = jsonString(b["data"], 1, 1<<24)
			ok = ok && onlyKeys(b, "type", "data")
		}
		if !ok {
			return false
		}
	}
	return true
}

func validImageSource(raw json.RawMessage) bool {
	s, ok := strictObject(raw)
	if !ok || !onlyKeys(s, "type", "media_type", "data") || !jsonEnum(s["type"], "base64") || !jsonEnum(s["media_type"], "image/png", "image/jpeg", "image/gif", "image/webp") {
		return false
	}
	data, ok := jsonString(s["data"], 1, 1<<30)
	return ok && validBase64(data, maxImageBytes)
}

// ---- OpenAI Responses API ----

func (a *Adapter) normalizeResponses(body []byte) ([]byte, string, bool, error) {
	p, ok := strictObject(body)
	if !ok || !onlyKeys(p, "model", "input", "instructions", "max_output_tokens", "temperature", "top_p", "stream", "tools", "tool_choice",
		"parallel_tool_calls", "text", "reasoning", "include", "top_logprobs", "truncation", "metadata", "user", "safety_identifier", "prompt_cache_key", "store", "service_tier") {
		return nil, "", false, errInvalidRequest
	}
	model, ok := validModel(p["model"])
	if !ok || p["input"] == nil {
		return nil, "", false, errInvalidRequest
	}
	tools, ok := validResponsesTools(p["tools"])
	if !ok {
		return nil, "", false, errInvalidRequest
	}
	for key, raw := range p {
		valid := true
		switch key {
		case "model", "tools":
		case "input":
			if _, isString := jsonString(raw, 0, 1<<30); !isString {
				items, ok := jsonArray(raw, 1, a.limits.MaxMessages)
				valid = ok
				for _, item := range items {
					valid = valid && validResponsesItem(item)
				}
			}
		case "instructions":
			_, valid = jsonString(raw, 0, 1<<30)
		case "max_output_tokens":
			valid = a.outputLimit(raw)
		case "temperature":
			valid = jsonNumber(raw, 0, 2)
		case "top_p":
			valid = jsonNumber(raw, 0, 1)
		case "stream", "parallel_tool_calls":
			valid = jsonBool(raw)
		case "tool_choice":
			valid = jsonEnum(raw, "none", "auto", "required")
			if !valid {
				c, ok := strictObject(raw)
				name, nameOK := jsonString(c["name"], 1, 64)
				valid = ok && onlyKeys(c, "type", "name") && jsonEnum(c["type"], "function") && nameOK && tools[name]
			}
		case "text":
			valid = validResponsesText(raw)
		case "reasoning":
			r, ok := strictObject(raw)
			valid = ok && onlyKeys(r, "effort", "summary") && (r["effort"] == nil || jsonEnum(r["effort"], "minimal", "low", "medium", "high")) &&
				(r["summary"] == nil || jsonEnum(r["summary"], "auto", "concise", "detailed"))
		case "include":
			items, ok := jsonArray(raw, 0, 2)
			valid = ok
			for _, item := range items {
				valid = valid && jsonEnum(item, "reasoning.encrypted_content", "message.output_text.logprobs")
			}
		case "top_logprobs":
			_, valid = jsonInt(raw, 0, 20)
		case "truncation":
			valid = jsonEnum(raw, "auto", "disabled")
		case "metadata":
			valid = validMetadata(raw)
		case "user", "safety_identifier", "prompt_cache_key":
			_, valid = jsonString(raw, 1, maxIdentifierBytes)
		case "store":
			valid = string(bytes.TrimSpace(raw)) == "false"
		case "service_tier":
			valid = jsonEnum(raw, "auto", "default")
		default:
			valid = false
		}
		if !valid {
			return nil, "", false, errInvalidRequest
		}
	}
	if p["tool_choice"] != nil && len(tools) == 0 && !jsonEnum(p["tool_choice"], "none", "auto") {
		return nil, "", false, errInvalidRequest
	}
	// Never let the provider keep the response under the shared key.
	p["store"] = json.RawMessage("false")
	if _, ok := p["max_output_tokens"]; !ok {
		p["max_output_tokens"] = json.RawMessage(strconv.Itoa(a.defaultOutputTokens(model)))
	}
	out, err := json.Marshal(p)
	if err != nil {
		return nil, "", false, errInvalidRequest
	}
	return out, model, string(bytes.TrimSpace(p["stream"])) == "true", nil
}

func validResponsesTools(raw json.RawMessage) (map[string]bool, bool) {
	names := map[string]bool{}
	if raw == nil {
		return names, true
	}
	items, ok := jsonArray(raw, 0, maxToolCount)
	if !ok || len(bytes.TrimSpace(raw)) > maxAllToolsBytes {
		return nil, false
	}
	for _, item := range items {
		t, ok := strictObject(item)
		// Function tools only: built-in provider tools are refused.
		if !ok || !onlyKeys(t, "type", "name", "description", "parameters", "strict") || !jsonEnum(t["type"], "function") {
			return nil, false
		}
		name, ok := jsonString(t["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) || names[name] {
			return nil, false
		}
		if t["description"] != nil {
			if _, ok := jsonString(t["description"], 0, maxToolDescription); !ok {
				return nil, false
			}
		}
		if t["parameters"] != nil && !boundedObject(t["parameters"], maxSchemaBytes) {
			return nil, false
		}
		if t["strict"] != nil && !jsonBool(t["strict"]) {
			return nil, false
		}
		names[name] = true
	}
	return names, true
}

func validResponsesText(raw json.RawMessage) bool {
	t, ok := strictObject(raw)
	if !ok || !onlyKeys(t, "format", "verbosity") || (t["verbosity"] != nil && !jsonEnum(t["verbosity"], "low", "medium", "high")) {
		return false
	}
	if t["format"] == nil {
		return true
	}
	f, ok := strictObject(t["format"])
	if !ok {
		return false
	}
	switch {
	case jsonEnum(f["type"], "text", "json_object"):
		return onlyKeys(f, "type")
	case jsonEnum(f["type"], "json_schema"):
		name, ok := jsonString(f["name"], 1, 64)
		if !ok || !toolNamePattern.MatchString(name) || !onlyKeys(f, "type", "name", "description", "schema", "strict") || !boundedObject(f["schema"], maxSchemaBytes) {
			return false
		}
		if f["description"] != nil {
			if _, ok := jsonString(f["description"], 0, maxToolDescription); !ok {
				return false
			}
		}
		return f["strict"] == nil || jsonBool(f["strict"])
	}
	return false
}

func validResponsesItem(raw json.RawMessage) bool {
	it, ok := strictObject(raw)
	if !ok {
		return false
	}
	kind := "message"
	if it["type"] != nil {
		var s string
		if s, ok = jsonString(it["type"], 1, 32); !ok {
			return false
		}
		kind = s
	}
	if it["id"] != nil {
		if _, ok := jsonString(it["id"], 1, maxIdentifierBytes); !ok {
			return false
		}
	}
	if it["status"] != nil && !jsonEnum(it["status"], "in_progress", "completed", "incomplete") {
		return false
	}
	switch kind {
	case "message":
		role, ok := jsonString(it["role"], 1, 16)
		if !ok || !onlyKeys(it, "type", "id", "status", "role", "content") || it["content"] == nil {
			return false
		}
		if _, isString := jsonString(it["content"], 0, 1<<30); isString {
			return contains([]string{"user", "assistant", "system", "developer"}, role)
		}
		switch role {
		case "user", "system", "developer":
			return validResponsesParts(it["content"], "input_text", "input_image")
		case "assistant":
			return validResponsesParts(it["content"], "output_text", "refusal")
		}
		return false
	case "function_call":
		_, callOK := jsonString(it["call_id"], 1, maxIdentifierBytes)
		name, nameOK := jsonString(it["name"], 1, 64)
		_, argsOK := jsonString(it["arguments"], 0, maxToolArguments)
		return onlyKeys(it, "type", "id", "status", "call_id", "name", "arguments") && callOK && nameOK && toolNamePattern.MatchString(name) && argsOK
	case "function_call_output":
		_, callOK := jsonString(it["call_id"], 1, maxIdentifierBytes)
		_, outOK := jsonString(it["output"], 0, 1<<30)
		return onlyKeys(it, "type", "id", "status", "call_id", "output") && callOK && outOK
	case "reasoning":
		if !onlyKeys(it, "type", "id", "status", "summary", "encrypted_content") || it["summary"] == nil {
			return false
		}
		items, ok := jsonArray(it["summary"], 0, maxContentParts)
		if !ok {
			return false
		}
		for _, item := range items {
			s, ok := strictObject(item)
			_, textOK := jsonString(s["text"], 0, 1<<24)
			if !ok || !onlyKeys(s, "type", "text") || !jsonEnum(s["type"], "summary_text") || !textOK {
				return false
			}
		}
		if it["encrypted_content"] != nil {
			if _, ok := jsonString(it["encrypted_content"], 1, 1<<24); !ok {
				return false
			}
		}
		return true
	}
	return false
}

func validResponsesParts(raw json.RawMessage, kinds ...string) bool {
	items, ok := jsonArray(raw, 1, maxContentParts)
	if !ok {
		return false
	}
	for _, item := range items {
		p, ok := strictObject(item)
		if !ok {
			return false
		}
		kind, ok := jsonString(p["type"], 1, 32)
		if !ok || !contains(kinds, kind) {
			return false
		}
		switch kind {
		case "input_text":
			_, ok = jsonString(p["text"], 0, 1<<30)
			ok = ok && onlyKeys(p, "type", "text")
		case "output_text":
			_, ok = jsonString(p["text"], 0, 1<<30)
			if ok && p["annotations"] != nil {
				_, ok = jsonArray(p["annotations"], 0, 0)
			}
			ok = ok && onlyKeys(p, "type", "text", "annotations")
		case "refusal":
			_, ok = jsonString(p["refusal"], 0, 1<<20)
			ok = ok && onlyKeys(p, "type", "refusal")
		case "input_image":
			url, urlOK := jsonString(p["image_url"], 1, 1<<30)
			ok = onlyKeys(p, "type", "image_url", "detail") && urlOK && validDataImage(url) && (p["detail"] == nil || jsonEnum(p["detail"], "auto", "low", "high"))
		}
		if !ok {
			return false
		}
	}
	return true
}
