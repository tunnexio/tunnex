package aigateway

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const leakedMetadata = `{"provider":"openrouter","routing_info":{"key":"tnx-managed-00000000-0000-0000-0000-000000000001-r1"},"provider_response_headers":{"Cf-Ray":"x","X-Request-Id":"y"},"latency":12}`

func TestStripEngineMetadataSplicesBytes(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"absent", `{"id":"a",  "choices":[1.50]}`, `{"id":"a",  "choices":[1.50]}`},
		{"first", `{"extra_fields":` + leakedMetadata + `,"id":"a","n":1.0}`, `{"id":"a","n":1.0}`},
		{"middle", `{"id":"a", "extra_fields": ` + leakedMetadata + `, "n":1.0}`, `{"id":"a", "n":1.0}`},
		{"last", `{"id":"a","n":1.0,"extra_fields":` + leakedMetadata + `}`, `{"id":"a","n":1.0}`},
		{"only", `{ "extra_fields":` + leakedMetadata + ` }`, `{ }`},
		{"duplicate", `{"extra_fields":{},"id":"a","extra_fields":{}}`, `{"id":"a"}`},
		{"pretty", "{\n  \"extra_fields\": {},\n  \"id\": \"a\"\n}", "{\n  \"id\": \"a\"\n}"},
		{"escaped key", `{"id":"a","extra_fields":{"k":1}}`, `{"id":"a"}`},
		{"nested kept", `{"choices":[{"extra_fields":1}],"x":{"extra_fields":2}}`, `{"choices":[{"extra_fields":1}],"x":{"extra_fields":2}}`},
		{"content mention", `{"content":"extra_fields"}`, `{"content":"extra_fields"}`},
		{"not object", `["extra_fields"]`, `["extra_fields"]`},
		{"not json", `[DONE]`, `[DONE]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stripEngineMetadata([]byte(tc.in))
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q err=%v want %q", got, err, tc.want)
			}
		})
	}
}

func adapterResponse(t *testing.T, contentType, body string, stream bool) *deadlineRecorder {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		io.WriteString(w, body)
	}))
	defer up.Close()
	a, err := NewAdapter(up.URL, fixture)
	if err != nil {
		t.Fatal(err)
	}
	req := `{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}]` + map[bool]string{true: `,"stream":true`}[stream] + `}`
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(req))
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	w := newDeadlineRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestAdapterJSONResponseOmitsEngineMetadata(t *testing.T) {
	body := `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],"usage":{"total_tokens":3},"extra_fields":` + leakedMetadata + `}`
	w := adapterResponse(t, "application/json", body, false)
	want := `{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],"usage":{"total_tokens":3}}`
	if w.Code != 200 || w.Body.String() != want {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	// Without metadata the engine bytes are relayed unchanged.
	plain := `{"id":"x",  "n": 1.50}`
	if w := adapterResponse(t, "application/json", plain, false); w.Body.String() != plain {
		t.Fatalf("unchanged body was rewritten: %q", w.Body.String())
	}
}

func TestAdapterStreamOmitsEngineMetadata(t *testing.T) {
	chunk := func(content string) string {
		return `{"id":"c","object":"chat.completion.chunk","choices":[{"delta":{"content":"` + content + `"}}],"extra_fields":` + leakedMetadata + `}`
	}
	clean := func(content string) string {
		return `{"id":"c","object":"chat.completion.chunk","choices":[{"delta":{"content":"` + content + `"}}]}`
	}
	for _, tc := range []struct{ name, in, want string }{
		{"lf", "data: " + chunk("a") + "\n\n: keep-alive\n\ndata: " + chunk("b") + "\n\ndata: [DONE]\n\n",
			"data: " + clean("a") + "\n\n: keep-alive\n\ndata: " + clean("b") + "\n\ndata: [DONE]\n\n"},
		{"crlf", "event: message\r\ndata:" + chunk("a") + "\r\nid: 7\r\n\r\ndata: [DONE]\r\n\r\n",
			"event: message\r\ndata: " + clean("a") + "\r\nid: 7\r\n\r\ndata: [DONE]\r\n\r\n"},
		{"multi-line data", "data: {\"id\":\"c\",\ndata: \"extra_fields\":{\"k\":1}}\n\n",
			"data: {\"id\":\"c\"}\n\n"},
		{"unchanged", "data: " + clean("a") + "\n\ndata: [DONE]\n\n", "data: " + clean("a") + "\n\ndata: [DONE]\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := adapterResponse(t, "text/event-stream", tc.in, true)
			if w.Code != 200 || w.Body.String() != tc.want || strings.Contains(w.Body.String(), "extra_fields") {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestSSEStripRefusesUnparsableMetadataAndBoundsEvents(t *testing.T) {
	var out bytes.Buffer
	noFlush := func() error { return nil }
	if err := copySSEStripped(&out, noFlush, strings.NewReader(`data: {"id":"c","extra_fields":{"k"`), 1<<20); err != errInvalidStrip {
		t.Fatalf("truncated metadata relayed: %v %q", err, out.String())
	}
	out.Reset()
	if err := copySSEStripped(&out, noFlush, strings.NewReader("data: "+strings.Repeat("x", 64<<10)), 32<<10); err != errResponseTooLarge {
		t.Fatalf("unbounded event: %v", err)
	}
}

func TestStrippedEventArrivesBeforeCompletion(t *testing.T) {
	release := make(chan struct{})
	first := `{"id":"c","extra_fields":` + leakedMetadata + `}`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// One event split across two upstream writes.
		io.WriteString(w, "data: "+first[:20])
		w.(http.Flusher).Flush()
		io.WriteString(w, first[20:]+"\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer up.Close()
	a, _ := NewAdapter(up.URL, fixture)
	server := httptest.NewServer(a)
	defer server.Close()
	defer close(release)
	r, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"OK"}],"stream":true}`))
	r.Header.Set("Authorization", "Bearer fixture-agent-a")
	res, err := (&http.Client{Timeout: 2 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	if err != nil || line != "data: {\"id\":\"c\"}\n" {
		t.Fatalf("first stripped event not delivered before completion: %q %v", line, err)
	}
}
