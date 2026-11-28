package aigateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const pngData = "data:image/png;base64,iVBORw0KGgo="

func compatAdapter(t *testing.T) *Adapter {
	t.Helper()
	a, err := NewAdapter("http://127.0.0.1:1", fixture)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func chatBody(extra string, messages string) string {
	if messages == "" {
		messages = `[{"role":"user","content":"hi"}]`
	}
	return `{"model":"openrouter/allowed","messages":` + messages + extra + `}`
}

const weatherTool = `{"type":"function","function":{"name":"get_weather","description":"Weather.","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}`

// Exact payloads captured from langchain-openai 0.3.35, the OpenAI SDK and
// LangGraph create_react_agent against a local fake server.
func TestChatAcceptsFrameworkPayloads(t *testing.T) {
	a := compatAdapter(t)
	for name, body := range map[string]string{
		"invoke":           chatBody(`,"stream":false`, `[{"content":"sys","role":"system"},{"content":"hi","role":"user"}]`),
		"stream_usage":     chatBody(`,"stream":true,"stream_options":{"include_usage":true}`, ""),
		"tools":            chatBody(`,"stream":false,"tools":[`+weatherTool+`]`, ""),
		"tool_round_trip":  chatBody(`,"stream":false,"tools":[`+weatherTool+`]`, `[{"content":"w","role":"user"},{"content":null,"role":"assistant","tool_calls":[{"type":"function","id":"call_1","function":{"name":"get_weather","arguments":"{\"city\": \"Pune\"}"}}]},{"content":"sunny","role":"tool","tool_call_id":"call_1"}]`),
		"json_schema":      chatBody(`,"response_format":{"type":"json_schema","json_schema":{"schema":{"type":"object","properties":{"city":{"type":"string"}},"additionalProperties":false},"name":"Answer","strict":true}}`, ""),
		"function_calling": chatBody(`,"parallel_tool_calls":false,"tool_choice":{"type":"function","function":{"name":"get_weather"}},"tools":[`+weatherTool+`]`, ""),
		"json_mode":        chatBody(`,"response_format":{"type":"json_object"}`, ""),
		"image":            chatBody("", `[{"content":[{"type":"text","text":"what"},{"type":"image_url","image_url":{"url":"`+pngData+`","detail":"low"}}],"role":"user"}]`),
		"audio":            chatBody("", `[{"content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}],"role":"user"}]`),
		"reasoning":        chatBody(`,"max_completion_tokens":6000,"reasoning_effort":"low"`, ""),
		"sampling":         chatBody(`,"temperature":0,"top_p":0.5,"frequency_penalty":-1,"presence_penalty":1.5,"stop":["a","b","c","d"],"seed":7,"n":1,"user":"u-1","logprobs":true,"top_logprobs":5,"logit_bias":{"50256":-100},"metadata":{"k":"v"},"service_tier":"auto","store":false,"verbosity":"low","safety_identifier":"s","prompt_cache_key":"p"`, ""),
		"stop_string":      chatBody(`,"stop":"END"`, ""),
		"developer_named":  chatBody("", `[{"role":"developer","content":[{"type":"text","text":"rules"}],"name":"policy_1"},{"role":"user","content":"hi","name":"ravi"}]`),
		"assistant_parts":  chatBody("", `[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"text","text":"x"},{"type":"refusal","refusal":"no"}]}]`),
		"tool_choice_auto": chatBody(`,"tool_choice":"required","tools":[`+weatherTool+`]`, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, model, _, err := a.normalizeChat([]byte(body)); err != nil || model != "openrouter/allowed" {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestChatRefusesMalformedAndOversizedFields(t *testing.T) {
	a := compatAdapter(t)
	big := strings.Repeat("a", maxSchemaBytes)
	tools129 := strings.TrimSuffix(strings.Repeat(weatherTool+",", 129), ",")
	for name, body := range map[string]string{
		"unknown_field":         chatBody(`,"fallbacks":["x"]`, ""),
		"functions":             chatBody(`,"functions":[]`, ""),
		"web_search":            chatBody(`,"web_search_options":{}`, ""),
		"top_level_system":      chatBody(`,"system":"x"`, ""),
		"n_two":                 chatBody(`,"n":2`, ""),
		"store_true":            chatBody(`,"store":true`, ""),
		"priority_tier":         chatBody(`,"service_tier":"priority"`, ""),
		"stop_five":             chatBody(`,"stop":["a","b","c","d","e"]`, ""),
		"stop_long":             chatBody(`,"stop":"`+strings.Repeat("a", 257)+`"`, ""),
		"top_p_high":            chatBody(`,"top_p":1.5`, ""),
		"penalty_low":           chatBody(`,"frequency_penalty":-3`, ""),
		"top_logprobs":          chatBody(`,"top_logprobs":21`, ""),
		"logit_bias_value":      chatBody(`,"logit_bias":{"1":101}`, ""),
		"logit_bias_key":        chatBody(`,"logit_bias":{"x":1}`, ""),
		"metadata_nested":       chatBody(`,"metadata":{"k":{"a":1}}`, ""),
		"reasoning_effort":      chatBody(`,"reasoning_effort":"max"`, ""),
		"stream_options_extra":  chatBody(`,"stream_options":{"include_usage":true,"x":1}`, ""),
		"stream_null":           chatBody(`,"stream":null`, ""),
		"tool_name":             chatBody(`,"tools":[{"type":"function","function":{"name":"bad name"}}]`, ""),
		"tool_type":             chatBody(`,"tools":[{"type":"web_search"}]`, ""),
		"tool_duplicate":        chatBody(`,"tools":[`+weatherTool+`,`+weatherTool+`]`, ""),
		"tool_too_many":         chatBody(`,"tools":[`+tools129+`]`, ""),
		"tool_schema_large":     chatBody(`,"tools":[{"type":"function","function":{"name":"a","parameters":{"d":"`+big+`"}}}]`, ""),
		"tool_schema_not_obj":   chatBody(`,"tools":[{"type":"function","function":{"name":"a","parameters":[1]}}]`, ""),
		"tool_choice_unknown":   chatBody(`,"tool_choice":{"type":"function","function":{"name":"other"}},"tools":[`+weatherTool+`]`, ""),
		"tool_choice_no_tools":  chatBody(`,"tool_choice":"auto"`, ""),
		"format_schema_large":   chatBody(`,"response_format":{"type":"json_schema","json_schema":{"name":"A","schema":{"d":"`+big+`"}}}`, ""),
		"format_type":           chatBody(`,"response_format":{"type":"grammar"}`, ""),
		"format_extra":          chatBody(`,"response_format":{"type":"json_object","schema":{}}`, ""),
		"remote_image":          chatBody("", `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a.png"}}]}]`),
		"svg_image":             chatBody("", `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/svg+xml;base64,AAAA"}}]}]`),
		"bad_base64":            chatBody("", `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,***"}}]}]`),
		"audio_format":          chatBody("", `[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"flac"}}]}]`),
		"image_in_system":       chatBody("", `[{"role":"system","content":[{"type":"image_url","image_url":{"url":"`+pngData+`"}}]}]`),
		"assistant_null_alone":  chatBody("", `[{"role":"assistant","content":null}]`),
		"tool_without_id":       chatBody("", `[{"role":"tool","content":"x"}]`),
		"tool_with_name":        chatBody("", `[{"role":"tool","content":"x","tool_call_id":"1","name":"n"}]`),
		"tool_call_type":        chatBody("", `[{"role":"assistant","tool_calls":[{"id":"1","type":"custom","function":{"name":"a","arguments":"{}"}}]}]`),
		"tool_call_args_object": chatBody("", `[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"a","arguments":{}}}]}]`),
		"function_call_legacy":  chatBody("", `[{"role":"assistant","content":"x","function_call":{"name":"a"}}]`),
		"user_tool_calls":       chatBody("", `[{"role":"user","content":"x","tool_calls":[]}]`),
		"assistant_audio":       chatBody("", `[{"role":"assistant","content":"x","audio":{"id":"a"}}]`),
		"trailing":              chatBody("", "") + `{}`,
		"duplicate_top":         `{"model":"openrouter/allowed","model":"x","messages":[{"role":"user","content":"hi"}]}`,
		"model_missing":         `{"messages":[{"role":"user","content":"hi"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := a.normalizeChat([]byte(body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestMessageHistoryLimit(t *testing.T) {
	a := compatAdapter(t)
	limits := DefaultAdapterLimits()
	limits.MaxMessages = 3
	if err := a.ConfigureLimits(limits); err != nil {
		t.Fatal(err)
	}
	msg := `{"role":"user","content":"hi"}`
	if _, _, _, err := a.normalizeChat([]byte(chatBody("", "["+strings.Repeat(msg+",", 2)+msg+"]"))); err != nil {
		t.Fatal("three messages refused")
	}
	if _, _, _, err := a.normalizeChat([]byte(chatBody("", "["+strings.Repeat(msg+",", 3)+msg+"]"))); err == nil {
		t.Fatal("four messages accepted")
	}
	// The default allows long agent histories.
	if DefaultAdapterLimits().MaxMessages != 2048 {
		t.Fatal("unexpected default")
	}
}

func TestOutputDefaultsFromCatalog(t *testing.T) {
	a := compatAdapter(t)
	cases := map[string]string{
		"openrouter/openai/gpt-4o-mini":       "16384", // catalog 16384
		"openrouter/anthropic/claude-3-haiku": "4096",  // catalog 4096
		"anthropic/claude-haiku-4-5":          "32768", // catalog 64000, capped by the ceiling
		"openrouter/unknown-model":            "4096",  // not in the catalog
	}
	for model, want := range cases {
		out, _, _, err := a.normalizeChat([]byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]json.RawMessage
		_ = json.Unmarshal(out, &p)
		if string(p["max_tokens"]) != want {
			t.Errorf("%s max_tokens=%s want %s", model, p["max_tokens"], want)
		}
	}
	// max_completion_tokens is forwarded as the engine's max_tokens.
	out, _, _, _ := a.normalizeChat([]byte(chatBody(`,"max_completion_tokens":6000`, "")))
	if !strings.Contains(string(out), `"max_tokens":6000`) || strings.Contains(string(out), "max_completion_tokens") {
		t.Fatalf("output limit not normalized: %s", out)
	}
}

const messagesTool = `{"name":"get_weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}}},"description":"Weather."}`

func messagesBody(extra, messages string) string {
	if messages == "" {
		messages = `[{"role":"user","content":"hi"}]`
	}
	return `{"model":"anthropic/claude-haiku-4-5","max_tokens":1024,"messages":` + messages + extra + `}`
}

// Payloads captured from langchain-anthropic 0.3.22 and the Messages SDK.
func TestMessagesAcceptsFrameworkPayloads(t *testing.T) {
	a := compatAdapter(t)
	for name, body := range map[string]string{
		"invoke":        messagesBody(`,"system":"sys"`, ""),
		"stream":        messagesBody(`,"stream":true`, ""),
		"tools":         messagesBody(`,"tools":[`+messagesTool+`]`, ""),
		"round_trip":    messagesBody(`,"tools":[`+messagesTool+`]`, `[{"role":"user","content":"w"},{"role":"assistant","content":[{"type":"tool_use","name":"get_weather","input":{"city":"Pune"},"id":"toolu_1"}]},{"role":"user","content":[{"type":"tool_result","content":"sunny","tool_use_id":"toolu_1","is_error":false}]}]`),
		"structured":    messagesBody(`,"tool_choice":{"type":"tool","name":"get_weather"},"tools":[`+messagesTool+`]`, ""),
		"thinking":      `{"model":"m","max_tokens":5000,"messages":[{"role":"user","content":"x"}],"thinking":{"type":"enabled","budget_tokens":2000}}`,
		"thinking_hist": strings.Replace(messagesBody(`,"thinking":{"type":"enabled","budget_tokens":1024},"tools":[`+messagesTool+`]`, `[{"role":"user","content":"w"},{"role":"assistant","content":[{"type":"thinking","thinking":"hmm","signature":"sig"},{"type":"redacted_thinking","data":"enc"},{"type":"tool_use","name":"get_weather","input":{},"id":"t1"}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"ok"}]}]}]`), `"max_tokens":1024`, `"max_tokens":4096`, 1),
		"image":         messagesBody("", `[{"role":"user","content":[{"type":"text","text":"what"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]`),
		"sdk_cache":     messagesBody(`,"system":[{"type":"text","text":"s","cache_control":{"type":"ephemeral"}}],"tools":[{"name":"get_weather","description":"d","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"1h"}}]`, ""),
		"sampling":      messagesBody(`,"temperature":0.5,"top_p":0.9,"top_k":40,"stop_sequences":["END"],"metadata":{"user_id":"u1"},"tool_choice":{"type":"auto","disable_parallel_tool_use":true},"tools":[`+messagesTool+`]`, ""),
		"no_max_tokens": `{"model":"anthropic/claude-haiku-4-5","messages":[{"role":"user","content":"hi"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := a.normalizeMessages([]byte(body)); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestMessagesRefusesUnqualifiedShapes(t *testing.T) {
	a := compatAdapter(t)
	for name, body := range map[string]string{
		"server_tool":        messagesBody(`,"tools":[{"type":"web_search_20250305","name":"web_search"}]`, ""),
		"mcp_servers":        messagesBody(`,"mcp_servers":[]`, ""),
		"container":          messagesBody(`,"container":"x"`, ""),
		"max_tokens_high":    `{"model":"m","max_tokens":32769,"messages":[{"role":"user","content":"x"}]}`,
		"budget_too_high":    `{"model":"m","max_tokens":1024,"messages":[{"role":"user","content":"x"}],"thinking":{"type":"enabled","budget_tokens":1024}}`,
		"budget_too_low":     `{"model":"m","max_tokens":5000,"messages":[{"role":"user","content":"x"}],"thinking":{"type":"enabled","budget_tokens":100}}`,
		"temperature":        messagesBody(`,"temperature":1.5`, ""),
		"stop_many":          messagesBody(`,"stop_sequences":[`+strings.TrimSuffix(strings.Repeat(`"a",`, 17), ",")+`]`, ""),
		"metadata_extra":     messagesBody(`,"metadata":{"x":"y"}`, ""),
		"url_image":          messagesBody("", `[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.invalid/a.png"}}]}]`),
		"tool_use_by_user":   messagesBody("", `[{"role":"user","content":[{"type":"tool_use","id":"1","name":"a","input":{}}]}]`),
		"result_by_asst":     messagesBody("", `[{"role":"assistant","content":[{"type":"tool_result","tool_use_id":"1"}]}]`),
		"citations":          messagesBody("", `[{"role":"user","content":[{"type":"text","text":"x","citations":[]}]}]`),
		"document":           messagesBody("", `[{"role":"user","content":[{"type":"document","source":{}}]}]`),
		"choice_unknown":     messagesBody(`,"tool_choice":{"type":"tool","name":"other"},"tools":[`+messagesTool+`]`, ""),
		"cache_control_type": messagesBody(`,"system":[{"type":"text","text":"s","cache_control":{"type":"persistent"}}]`, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := a.normalizeMessages([]byte(body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestResponsesAllowlist(t *testing.T) {
	a := compatAdapter(t)
	fn := `{"type":"function","name":"get_weather","parameters":{"type":"object"}}`
	for name, body := range map[string]string{
		"string_input": `{"model":"m","input":"hi"}`,
		"langchain":    `{"input":[{"content":"x","role":"user"}],"model":"m","stream":false}`,
		"tools":        `{"model":"m","input":"w","tools":[` + fn + `],"tool_choice":{"type":"function","name":"get_weather"},"parallel_tool_calls":true}`,
		"round_trip":   `{"model":"m","tools":[` + fn + `],"input":[{"role":"user","content":[{"type":"input_text","text":"w"},{"type":"input_image","image_url":"` + pngData + `"}]},{"type":"function_call","call_id":"c1","name":"get_weather","arguments":"{}","id":"fc_1","status":"completed"},{"type":"function_call_output","call_id":"c1","output":"sunny"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[]}]}]}`,
		"reasoning":    `{"model":"m","input":[{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"t"}],"encrypted_content":"enc"},{"role":"user","content":"x"}],"reasoning":{"effort":"low","summary":"auto"},"include":["reasoning.encrypted_content"],"store":false}`,
		"text_format":  `{"model":"m","input":"x","text":{"format":{"type":"json_schema","name":"A","schema":{"type":"object"},"strict":true},"verbosity":"low"},"max_output_tokens":6000,"truncation":"auto","metadata":{"a":"b"},"instructions":"be brief"}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, _, _, err := a.normalizeResponses([]byte(body))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !strings.Contains(string(out), `"store":false`) || !strings.Contains(string(out), `"max_output_tokens":`) {
				t.Fatalf("store/limit not enforced: %s", out)
			}
		})
	}
	for name, body := range map[string]string{
		"previous_id":    `{"model":"m","input":"x","previous_response_id":"resp_1"}`,
		"conversation":   `{"model":"m","input":"x","conversation":"c"}`,
		"background":     `{"model":"m","input":"x","background":true}`,
		"store_true":     `{"model":"m","input":"x","store":true}`,
		"web_search":     `{"model":"m","input":"x","tools":[{"type":"web_search"}]}`,
		"file_search":    `{"model":"m","input":"x","tools":[{"type":"file_search","vector_store_ids":["vs"]}]}`,
		"mcp":            `{"model":"m","input":"x","tools":[{"type":"mcp","server_url":"https://x"}]}`,
		"item_reference": `{"model":"m","input":[{"type":"item_reference","id":"msg_1"}]}`,
		"file_id_image":  `{"model":"m","input":[{"role":"user","content":[{"type":"input_image","file_id":"f"}]}]}`,
		"input_file":     `{"model":"m","input":[{"role":"user","content":[{"type":"input_file","file_data":"x"}]}]}`,
		"remote_image":   `{"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x/a.png"}]}]}`,
		"include_search": `{"model":"m","input":"x","include":["file_search_call.results"]}`,
		"tier":           `{"model":"m","input":"x","service_tier":"priority"}`,
		"output_high":    `{"model":"m","input":"x","max_output_tokens":32769}`,
	} {
		t.Run("refuse_"+name, func(t *testing.T) {
			if _, _, _, err := a.normalizeResponses([]byte(body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestEmbeddingInputs(t *testing.T) {
	a := compatAdapter(t)
	for _, input := range []string{`"a"`, `["a","b"]`, `[64,65]`, `[[64],[65,66]]`} {
		if _, _, err := a.normalizedModeJSON([]byte(`{"model":"openai/text-embedding-3-small","input":`+input+`,"encoding_format":"base64"}`), ModeEmbedding); err != nil {
			t.Errorf("input %s refused", input)
		}
	}
	tooMany := "[" + strings.TrimSuffix(strings.Repeat(`"a",`, maxEmbeddingInputs+1), ",") + "]"
	longTokens := "[[" + strings.TrimSuffix(strings.Repeat(`1,`, maxEmbeddingTokens+1), ",") + "]]"
	for _, input := range []string{`""`, `[]`, `[[]]`, `[-1]`, `[1.5]`, `["a",1]`, `[[1],"a"]`, `[[100000000]]`, tooMany, longTokens, `{"a":1}`, `null`} {
		if _, _, err := a.normalizedModeJSON([]byte(`{"model":"openai/text-embedding-3-small","input":`+input+`}`), ModeEmbedding); err == nil {
			t.Errorf("input %.40s accepted", input)
		}
	}
}

func TestLoadAdapterLimits(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := LoadAdapterLimits(env(nil))
	if err != nil || l != DefaultAdapterLimits() {
		t.Fatal("defaults not applied")
	}
	l, err = LoadAdapterLimits(env(map[string]string{
		"TUNNEX_AI_MAX_OUTPUT_TOKENS": "65536", "TUNNEX_AI_MAX_REQUEST_BYTES": "16MiB", "TUNNEX_AI_STREAM_TIMEOUT": "20m",
		"TUNNEX_AI_IDLE_TIMEOUT": "300", "TUNNEX_AI_MAX_CONCURRENT_PER_SUBJECT": "4", "TUNNEX_AI_DEFAULT_OUTPUT_TOKENS": "8192",
	}))
	if err != nil || l.MaxOutputTokens != 65536 || l.MaxRequestBytes != 16<<20 || l.StreamTimeout != 20*time.Minute || l.IdleTimeout != 300*time.Second || l.MaxConcurrentPerSubj != 4 || l.DefaultOutputTokens != 8192 {
		t.Fatalf("settings not applied: %+v %v", l, err)
	}
	for k, v := range map[string]string{
		"TUNNEX_AI_MAX_OUTPUT_TOKENS": "10", "TUNNEX_AI_MAX_REQUEST_BYTES": "64MiB", "TUNNEX_AI_STREAM_TIMEOUT": "2h",
		"TUNNEX_AI_IDLE_TIMEOUT": "abc", "TUNNEX_AI_MAX_CONCURRENT": "0", "TUNNEX_AI_MAX_MESSAGES": "-1",
		"TUNNEX_AI_DEFAULT_OUTPUT_TOKENS": "40000", "TUNNEX_AI_MAX_CONCURRENT_PER_ORG": "1.5",
	} {
		if _, err := LoadAdapterLimits(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}

func TestUpstreamErrorsAreStatic(t *testing.T) {
	for status, want := range map[int][2]any{400: {400, "ai_provider_rejected"}, 404: {400, "ai_provider_rejected"}, 413: {400, "ai_provider_rejected"}, 422: {400, "ai_provider_rejected"}, 429: {429, "ai_provider_rate_limited"}, 401: {502, "ai_engine_unavailable"}, 500: {502, "ai_engine_unavailable"}} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":{"message":"private-message fixture-internal"}}`, status)
		}))
		a, _ := NewAdapter(up.URL, fixture)
		server := httptest.NewServer(a)
		req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(chatBody("", "")))
		req.Header.Set("Authorization", "Bearer fixture-agent-a")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != want[0].(int) || !strings.Contains(string(body), want[1].(string)) || strings.Contains(string(body), "private-message") {
			t.Errorf("upstream %d → %d %s", status, res.StatusCode, body)
		}
		server.Close()
		up.Close()
	}
}

func streamUpstream(t *testing.T, gap time.Duration, events int) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < events; i++ {
			fmt.Fprintf(w, "data: {\"i\":%d}\n\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-time.After(gap):
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(up.Close)
	return up
}

func streamThrough(t *testing.T, a *Adapter) (string, error) {
	t.Helper()
	server := httptest.NewServer(a)
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(chatBody(`,"stream":true`, "")))
	req.Header.Set("Authorization", "Bearer fixture-agent-a")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	return string(data), err
}

// A stream longer than the 30-second-style lease survives when each renewal
// succeeds, and renewal never repeats cost admission (it has its own path).
func TestLeaseRenewalKeepsLongStreamAlive(t *testing.T) {
	up := streamUpstream(t, 50*time.Millisecond, 20) // ~1 s, lease 200 ms
	var renewals atomic.Int32
	a, _ := NewAdapter(up.URL, func(ctx context.Context, token, model string) (Grant, error) {
		g, err := fixture(ctx, token, model)
		g.Expires = time.Now().Add(200 * time.Millisecond)
		g.Renew = func(context.Context) (Grant, error) {
			renewals.Add(1)
			next := g
			next.Renew = nil
			next.Expires = time.Now().Add(200 * time.Millisecond)
			return next, nil
		}
		return g, err
	})
	body, err := streamThrough(t, a)
	if err != nil || !strings.Contains(body, "[DONE]") {
		t.Fatalf("stream did not complete: err=%v", err)
	}
	if renewals.Load() < 3 {
		t.Fatalf("renewals=%d", renewals.Load())
	}
}

func TestLeaseRenewalFailureCutsStream(t *testing.T) {
	for name, renew := range map[string]func(Grant) (Grant, error){
		"revoked": func(Grant) (Grant, error) { return Grant{}, errors.New("revoked") },
		"other_key": func(g Grant) (Grant, error) {
			g.VirtualKey = "fixture-other"
			g.Expires = time.Now().Add(time.Second)
			return g, nil
		},
		"other_mode": func(g Grant) (Grant, error) {
			g.Mode = ModeEmbedding
			g.Expires = time.Now().Add(time.Second)
			return g, nil
		},
		"other_tenant": func(g Grant) (Grant, error) { g.Tenant = "x"; g.Expires = time.Now().Add(time.Second); return g, nil },
	} {
		t.Run(name, func(t *testing.T) {
			up := streamUpstream(t, 50*time.Millisecond, 40)
			a, _ := NewAdapter(up.URL, func(ctx context.Context, token, model string) (Grant, error) {
				g, err := fixture(ctx, token, model)
				g.Expires = time.Now().Add(150 * time.Millisecond)
				g.Renew = func(context.Context) (Grant, error) { return renew(g) }
				return g, err
			})
			start := time.Now()
			body, err := streamThrough(t, a)
			if err == nil || strings.Contains(body, "[DONE]") || time.Since(start) > 1500*time.Millisecond {
				t.Fatalf("stream not cut: err=%v elapsed=%s", err, time.Since(start))
			}
		})
	}
}

func TestIdleUpstreamIsCut(t *testing.T) {
	up := streamUpstream(t, 2*time.Second, 3)
	a, _ := NewAdapter(up.URL, fixture)
	limits := DefaultAdapterLimits()
	limits.IdleTimeout = 200 * time.Millisecond
	_ = a.ConfigureLimits(limits)
	start := time.Now()
	body, err := streamThrough(t, a)
	if err == nil || strings.Contains(body, "[DONE]") || time.Since(start) > time.Second {
		t.Fatalf("idle stream not cut: err=%v elapsed=%s", err, time.Since(start))
	}
	// Steady events inside the idle window are not cut.
	up = streamUpstream(t, 50*time.Millisecond, 10)
	a, _ = NewAdapter(up.URL, fixture)
	_ = a.ConfigureLimits(limits)
	if body, err := streamThrough(t, a); err != nil || !strings.Contains(body, "[DONE]") {
		t.Fatalf("active stream cut: %v", err)
	}
}

func TestNonStreamingUsesRequestTimeout(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	limits := DefaultAdapterLimits()
	limits.RequestTimeout = 200 * time.Millisecond
	_ = a.ConfigureLimits(limits)
	server := httptest.NewServer(a)
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(chatBody("", "")))
	req.Header.Set("Authorization", "Bearer fixture-agent-a")
	start := time.Now()
	res, err := http.DefaultClient.Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != 502 {
			t.Fatalf("status=%d", res.StatusCode)
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("request timeout not enforced")
	}
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRedisLeasesAcquireReleaseExpire(t *testing.T) {
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	defer c.Close()
	l := NewRedisLeases(c)
	ctx := context.Background()
	keys := []string{"ai:cc:org:o", "ai:cc:sub:o//a"}
	var leases []string
	for i := 0; i < 2; i++ {
		lease, ok, err := l.Acquire(ctx, keys, []int{10, 2})
		if err != nil || !ok {
			t.Fatalf("acquire %d: ok=%v err=%v", i, ok, err)
		}
		leases = append(leases, lease)
	}
	if _, ok, _ := l.Acquire(ctx, keys, []int{10, 2}); ok {
		t.Fatal("subject limit exceeded")
	}
	// The organization limit applies across subjects.
	if _, ok, _ := l.Acquire(ctx, []string{"ai:cc:org:o", "ai:cc:sub:o//b"}, []int{2, 5}); ok {
		t.Fatal("organization limit exceeded")
	}
	if err := l.Release(ctx, keys, leases[0]); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := l.Acquire(ctx, keys, []int{10, 2}); !ok {
		t.Fatal("released slot not reusable")
	}
	if ok, err := l.Renew(ctx, keys, leases[1]); err != nil || !ok {
		t.Fatal("held lease not renewable")
	}
	if ok, _ := l.Renew(ctx, keys, leases[0]); ok {
		t.Fatal("released lease renewed")
	}
	// A crashed holder's leases expire with the TTL (Redis server time).
	m.SetTime(time.Now().Add(2 * time.Minute))
	m.FastForward(2 * time.Minute)
	if ok, _ := l.Renew(ctx, keys, leases[1]); ok {
		t.Fatal("expired lease renewed")
	}
	for i := 0; i < 2; i++ {
		if _, ok, err := l.Acquire(ctx, keys, []int{10, 2}); !ok || err != nil {
			t.Fatalf("expired slots not reclaimed: %v", err)
		}
	}
}

// Two adapters (two API replicas) share one subject limit through Redis.
func TestSharedLeasesAcrossAdapters(t *testing.T) {
	c := newTestRedis(t)
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: x\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer up.Close()
	defer close(release)
	limits := DefaultAdapterLimits()
	limits.MaxConcurrentPerSubj = 2
	var servers []*httptest.Server
	for i := 0; i < 2; i++ {
		a, _ := NewAdapter(up.URL, fixture)
		_ = a.ConfigureLimits(limits)
		a.ConfigureSharedLeases(NewRedisLeases(c))
		s := httptest.NewServer(a)
		defer s.Close()
		servers = append(servers, s)
	}
	open := func(s *httptest.Server) (int, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "POST", s.URL+"/v1/chat/completions", strings.NewReader(chatBody(`,"stream":true`, "")))
		req.Header.Set("Authorization", "Bearer fixture-agent-a")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		return res.StatusCode, func() { cancel(); res.Body.Close() }
	}
	s1, c1 := open(servers[0])
	s2, c2 := open(servers[1])
	defer c2()
	s3, c3 := open(servers[0])
	c3()
	s4, c4 := open(servers[1])
	c4()
	if s1 != 200 || s2 != 200 || s3 != 429 || s4 != 429 {
		t.Fatalf("shared limit statuses %d %d %d %d", s1, s2, s3, s4)
	}
	c1()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s, done := open(servers[1])
		done()
		if s == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("released shared slot not reusable")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSharedLeasesFailClosed(t *testing.T) {
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr(), MaxRetries: -1})
	defer c.Close()
	var arrivals atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) }))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	a.ConfigureSharedLeases(NewRedisLeases(c))
	m.Close()
	server := httptest.NewServer(a)
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(chatBody("", "")))
	req.Header.Set("Authorization", "Bearer fixture-agent-a")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 || arrivals.Load() != 0 {
		t.Fatalf("status=%d arrivals=%d", res.StatusCode, arrivals.Load())
	}
}

// A lost shared lease (for example expired while Redis was unreachable)
// ends the request so the shared limit stays true.
func TestLostSharedLeaseEndsStream(t *testing.T) {
	c := newTestRedis(t)
	up := streamUpstream(t, 50*time.Millisecond, 40)
	a, _ := NewAdapter(up.URL, fixture)
	leases := NewRedisLeases(c)
	leases.every = 100 * time.Millisecond
	a.ConfigureSharedLeases(leases)
	go func() {
		time.Sleep(250 * time.Millisecond)
		c.FlushAll(context.Background())
	}()
	body, err := streamThrough(t, a)
	if err == nil || strings.Contains(body, "[DONE]") {
		t.Fatal("stream continued without its shared lease")
	}
}

func TestResponsesRouteIsChatMode(t *testing.T) {
	if mode, ok := InferencePathMode("/v1/responses"); !ok || mode != ModeChat {
		t.Fatal("responses route not chat mode")
	}
}
