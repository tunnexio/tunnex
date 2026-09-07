package aigateway

import (
	"encoding/json"
	"fmt"
	"mime"
	"strings"
	"testing"
)

func assertQualifiedSSE(t *testing.T, path, contentType, body string) {
	t.Helper()
	if err := qualifiedSSE(path, contentType, body); err != nil {
		t.Fatal(err)
	}
}

func qualifiedSSE(path, contentType, body string) error {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || media != "text/event-stream" {
		return fmt.Errorf("%s: expected SSE Content-Type, got %q", path, contentType)
	}
	anthropic := strings.Contains(path, "messages")
	delta, terminal, finish := false, false, false
	frames := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n")
	for index, frame := range frames {
		var data []string
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "event:") && strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "error" {
				return fmt.Errorf("%s: SSE error event", path)
			}
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		if len(data) == 0 {
			continue
		}
		// EOF does not dispatch an SSE event: data is complete only when a
		// blank line terminated its frame. The last Split element is always
		// the unterminated remainder (empty after a well-formed final event).
		if index == len(frames)-1 {
			return fmt.Errorf("%s: unterminated SSE data frame", path)
		}
		raw := strings.Join(data, "\n")
		if terminal {
			return fmt.Errorf("%s: payload after terminal event", path)
		}
		if raw == "[DONE]" {
			if anthropic || !delta || !finish {
				return fmt.Errorf("%s: unexpected or premature DONE", path)
			}
			terminal = true
			continue
		}
		var event struct {
			Type  string          `json:"type"`
			Error json.RawMessage `json:"error"`
			Delta struct {
				Type       string  `json:"type"`
				Text       string  `json:"text"`
				StopReason *string `json:"stop_reason"`
			} `json:"delta"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return fmt.Errorf("%s: invalid SSE JSON: %w", path, err)
		}
		if (len(event.Error) > 0 && string(event.Error) != "null") || event.Type == "error" {
			return fmt.Errorf("%s: SSE error payload", path)
		}
		if anthropic {
			if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				delta = true
			}
			if event.Type == "message_delta" && event.Delta.StopReason != nil && *event.Delta.StopReason != "" {
				finish = true
			}
			if event.Type == "message_stop" {
				if !delta || !finish {
					return fmt.Errorf("%s: premature message_stop", path)
				}
				terminal = true
			}
		} else {
			for _, choice := range event.Choices {
				if choice.Delta.Content != "" {
					delta = true
				}
				if choice.FinishReason != nil && *choice.FinishReason != "" {
					finish = true
				}
			}
		}
	}
	if !delta || !finish || !terminal {
		return fmt.Errorf("%s: incomplete SSE: text_delta=%t finish=%t terminal=%t", path, delta, finish, terminal)
	}
	return nil
}

func TestQualifiedSSERejectsFalseProof(t *testing.T) {
	chat := "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	if err := qualifiedSSE("/v1/chat/completions", "text/event-stream", chat); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, contentType, body string }{
		{"wrong media", "application/json", chat},
		{"error containing OK", "text/event-stream", "data: {\"error\":{\"message\":\"OK failed\"}}\n\n"},
		{"missing terminal", "text/event-stream", strings.ReplaceAll(chat, "data: [DONE]\n\n", "")},
		{"unterminated terminal", "text/event-stream", strings.TrimSuffix(chat, "\n\n")},
		{"terminal missing blank line", "text/event-stream", strings.TrimSuffix(chat, "\n")},
		{"missing delta", "text/event-stream", "data: [DONE]\n\n"},
		{"late error", "text/event-stream", chat + "event: error\ndata: {}\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if qualifiedSSE("/v1/chat/completions", tc.contentType, tc.body) == nil {
				t.Fatal("accepted invalid stream")
			}
		})
	}
}

func TestQualifiedSSEAnthropic(t *testing.T) {
	body := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"OK\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n"
	if err := qualifiedSSE("/anthropic/v1/messages", "text/event-stream; charset=utf-8", body); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.TrimSuffix(body, "\n\n"),
		strings.TrimSuffix(body, "\n"),
		strings.ReplaceAll(body, "data: {\"type\":\"message_stop\"}\n\n", ""),
		strings.ReplaceAll(body, "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n", ""),
		body + "data: {\"type\":\"error\",\"error\":{\"message\":\"failed\"}}\n\n",
	} {
		if qualifiedSSE("/anthropic/v1/messages", "text/event-stream", bad) == nil {
			t.Fatal("accepted incomplete or errored Anthropic stream")
		}
	}
}
