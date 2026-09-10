package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const modeWireModel = "openai/fixture-model"

func modeWireServer(t *testing.T, mode ModelMode, handler http.HandlerFunc) (*Adapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	a, err := NewAdapter(upstream.URL, func(_ context.Context, token, model string) (Grant, error) {
		if token != "fixture-caller" || model != modeWireModel {
			return Grant{}, fmt.Errorf("invalid fixture identity")
		}
		return Grant{Tenant: "fixture-org", Agent: "fixture-agent", VirtualKey: "fixture-private-key", Mode: mode, Expires: time.Now().Add(time.Minute)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(a)
	t.Cleanup(server.Close)
	return a, server
}

func modeWireRequest(t *testing.T, server *httptest.Server, path, ct string, body []byte) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fixture-caller")
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Bf-Vk", "caller-injected-key")
	req.Header.Set("X-Api-Key", "caller-injected-secret")
	req.Header.Set("Cookie", "caller-session=secret")
	req.Header.Set("X-Provider", "caller-route")
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data, res.Header
}

type modeAudioPart struct {
	name, filename, ct string
	data               []byte
}

func modeAudioBody(t *testing.T, parts ...modeAudioPart) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q`, p.name))
		if p.filename != "" {
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, p.name, p.filename))
		}
		if p.ct != "" {
			h.Set("Content-Type", p.ct)
		}
		h.Set("X-Api-Key", "part-injected-secret")
		h.Set("X-Bf-Vk", "part-injected-key")
		dst, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = dst.Write(p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), w.FormDataContentType()
}

func TestAdapterModesSixRoutesOnWire(t *testing.T) {
	for _, tc := range []struct {
		mode                               ModelMode
		path, body, responseType, response string
	}{
		{ModeCompletion, "/v1/completions", `{"model":"openai/fixture-model","prompt":"hello"}`, "application/json", `{"choices":[]}`},
		{ModeEmbedding, "/v1/embeddings", `{"model":"openai/fixture-model","input":["hello","world"],"dimensions":8}`, "application/json", `{"data":[]}`},
		{ModeAudioSpeech, "/v1/audio/speech", `{"model":"openai/fixture-model","input":"hello","voice":"alloy","response_format":"mp3"}`, "audio/mpeg", "fixture-audio"},
		{ModeAudioTranscription, "/v1/audio/transcriptions", "", "application/json", `{"text":"hello"}`},
		{ModeImageGeneration, "/v1/images/generations", `{"model":"openai/fixture-model","prompt":"hello"}`, "application/json", `{"data":[{"url":"https://unfetched.invalid/result"}]}`},
		{ModeRerank, "/v1/rerank", `{"model":"openai/fixture-model","query":"hello","documents":["world"],"top_n":1}`, "application/json", `{"results":[]}`},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			var arrivals atomic.Int32
			_, server := modeWireServer(t, tc.mode, func(w http.ResponseWriter, r *http.Request) {
				arrivals.Add(1)
				if r.URL.Path != tc.path || r.Method != http.MethodPost {
					t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-Bf-Vk") != "fixture-private-key" {
					t.Error("trusted key missing")
				}
				for _, k := range []string{"Authorization", "X-Api-Key", "Cookie", "X-Provider"} {
					if r.Header.Get(k) != "" {
						t.Errorf("caller header forwarded: %s", k)
					}
				}
				if tc.mode == ModeAudioTranscription {
					mr, err := r.MultipartReader()
					if err != nil {
						t.Error(err)
						return
					}
					files := 0
					for {
						p, err := mr.NextPart()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Error(err)
							return
						}
						data, _ := io.ReadAll(p)
						if p.Header.Get("X-Api-Key") != "" || p.Header.Get("X-Bf-Vk") != "" {
							t.Error("caller part headers forwarded")
						}
						if p.FormName() == "file" {
							files++
							if p.Header.Get("Content-Type") != "audio/wav" {
								t.Error("validated audio MIME lost")
							}
							if p.FileName() != "audio.wav" || string(data) != "fixture-wave" {
								t.Error("audio bytes/normalized filename changed")
							}
						}
						if p.FormName() == "response_format" && string(data) != "json" {
							t.Error("transcription response format missing")
						}
					}
					if files != 1 {
						t.Errorf("files=%d", files)
					}
				} else {
					var body map[string]json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid upstream JSON")
					}
					if tc.mode == ModeCompletion && string(body["max_tokens"]) != "1024" {
						t.Error("completion default bound missing")
					}
					if tc.mode == ModeImageGeneration && string(body["n"]) != "1" {
						t.Error("image count bound missing")
					}
				}
				w.Header().Set("Content-Type", tc.responseType)
				w.Header().Set("Set-Cookie", "provider=secret")
				w.Header().Set("X-Api-Key", "provider-secret")
				io.WriteString(w, tc.response)
			})
			body, ct := []byte(tc.body), "application/json"
			if tc.mode == ModeAudioTranscription {
				body, ct = modeAudioBody(t, modeAudioPart{name: "model", data: []byte(modeWireModel)}, modeAudioPart{name: "file", filename: "unsafe-original.wav", ct: "audio/wav", data: []byte("fixture-wave")})
			}
			status, data, h := modeWireRequest(t, server, tc.path, ct, body)
			if status != 200 || string(data) != tc.response || arrivals.Load() != 1 {
				t.Fatalf("status=%d body=%q arrivals=%d", status, data, arrivals.Load())
			}
			if h.Get("Set-Cookie") != "" || h.Get("X-Api-Key") != "" || h.Get("Cache-Control") != "no-store" {
				t.Fatal("response headers leaked or cache enabled")
			}
		})
	}
}

func TestAdapterModesRejectControlsBeforeAuthorization(t *testing.T) {
	cases := []struct {
		mode       ModelMode
		path, base string
		invalid    []string
	}{
		{ModeCompletion, "/v1/completions", `"prompt":"hello"`, []string{`"prompt":{"api_key":"secret"}`, `"prompt":"hello","max_tokens":0`, `"prompt":"hello","max_tokens":1.5`, `"prompt":"hello","max_tokens":4097`, `"prompt":"hello","stream":"true"`, `"prompt":"hello","temperature":3`, `"prompt":"hello","prompt max_tokens":1`}},
		{ModeEmbedding, "/v1/embeddings", `"input":"hello"`, []string{`"input":[]`, `"input":[{"text":"hello","api_base":"https://evil.invalid"}]`, `"input":"hello","dimensions":0`, `"input":"hello","encoding_format":"url"`}},
		{ModeAudioSpeech, "/v1/audio/speech", `"input":"hello","voice":"alloy"`, []string{`"input":"hello","voice":{"id":"alloy"}`, `"input":"hello","voice":"../alloy"`, `"input":"hello","voice":"alloy","speed":0`, `"input":"hello","voice":"alloy","response_format":"url"`}},
		{ModeImageGeneration, "/v1/images/generations", `"prompt":"hello"`, []string{`"prompt":"hello","n":2`, `"prompt":"hello","size":"1x1"`, `"prompt":"hello","quality":null`, `"prompt":"hello","response_format":"binary"`}},
		{ModeRerank, "/v1/rerank", `"query":"hello","documents":["one"]`, []string{`"query":"hello","documents":[]`, `"query":"hello","documents":["one"],"top_n":2`, `"query":"hello","documents":[{"text":"one"}]`, `"query":"hello","documents":["one"],"return_documents":null`}},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			var authorized, arrivals atomic.Int32
			a, s := modeWireServer(t, tc.mode, func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1); w.WriteHeader(200) })
			original := a.authorize
			a.authorize = func(ctx context.Context, token, model string) (Grant, error) {
				authorized.Add(1)
				return original(ctx, token, model)
			}
			payloads := []string{`null`, `[]`, `{"model":"openai/fixture-model",` + tc.base + `,"model":"openai/fixture-model"}`, `{"model":"openai/fixture-model",` + tc.base + `,"api_key":"secret"}`, `{"model":"openai/fixture-model",` + tc.base + `,"provider":{"api_base":"https://evil.invalid"}}`, `{"model":null,` + tc.base + `}`, `{"model":"openai/fixture-model",` + tc.base + `} {}`}
			for _, bad := range tc.invalid {
				payloads = append(payloads, `{"model":"openai/fixture-model",`+bad+`}`)
			}
			for i, p := range payloads {
				status, _, _ := modeWireRequest(t, s, tc.path, "application/json", []byte(p))
				if status != 400 {
					t.Errorf("case %d status=%d payload=%s", i, status, p)
				}
			}
			status, _, _ := modeWireRequest(t, s, tc.path, "application/json", bytes.Repeat([]byte("x"), MaxBodyBytes+1))
			if status != 413 {
				t.Errorf("JSON bound status=%d", status)
			}
			if authorized.Load() != 0 || arrivals.Load() != 0 {
				t.Fatalf("invalid requests authorized=%d upstream=%d", authorized.Load(), arrivals.Load())
			}
		})
	}
}

func TestAdapterModesPathMismatchNeverArrives(t *testing.T) {
	for _, mode := range []ModelMode{ModeChat, ModeCompletion, ModeEmbedding, ModeAudioSpeech, ModeAudioTranscription, ModeImageGeneration, ModeRerank} {
		t.Run(string(mode), func(t *testing.T) {
			var arrivals atomic.Int32
			_, s := modeWireServer(t, mode, func(w http.ResponseWriter, r *http.Request) { arrivals.Add(1) })
			path, body := "/v1/embeddings", `{"model":"openai/fixture-model","input":"hello"}`
			if mode == ModeEmbedding {
				path, body = "/v1/completions", `{"model":"openai/fixture-model","prompt":"hello"}`
			}
			status, _, _ := modeWireRequest(t, s, path, "application/json", []byte(body))
			if status != 403 || arrivals.Load() != 0 {
				t.Fatalf("status=%d arrivals=%d", status, arrivals.Load())
			}
		})
	}
}

func TestAdapterModesMultipartBoundsAndControls(t *testing.T) {
	model := modeAudioPart{name: "model", data: []byte(modeWireModel)}
	audio := modeAudioPart{name: "file", filename: "caller.wav", ct: "audio/wav", data: []byte("audio")}
	for _, tc := range []struct {
		name    string
		parts   []modeAudioPart
		success bool
	}{
		{"max_audio", []modeAudioPart{model, {name: "file", filename: "max.wav", ct: "audio/wav", data: bytes.Repeat([]byte("a"), MaxAudioBytes)}}, true},
		{"too_large", []modeAudioPart{model, {name: "file", filename: "max.wav", ct: "audio/wav", data: bytes.Repeat([]byte("a"), MaxAudioBytes+1)}}, false},
		{"two_files", []modeAudioPart{model, audio, audio}, false},
		{"empty_file", []modeAudioPart{model, {name: "file", filename: "empty.wav", ct: "audio/wav"}}, false},
		{"wrong_mime", []modeAudioPart{model, {name: "file", filename: "audio.wav", ct: "text/html", data: []byte("audio")}}, false},
		{"missing_file", []modeAudioPart{model}, false},
		{"duplicate_model", []modeAudioPart{model, model, audio}, false},
		{"remote_url", []modeAudioPart{model, audio, {name: "file_url", data: []byte("https://evil.invalid")}}, false},
		{"provider_key", []modeAudioPart{model, audio, {name: "api_key", data: []byte("secret")}}, false},
		{"response_sse", []modeAudioPart{model, audio, {name: "response_format", data: []byte("sse")}}, false},
		{"null_temperature", []modeAudioPart{model, audio, {name: "temperature", data: []byte(" null ")}}, false},
		{"large_field", []modeAudioPart{model, audio, {name: "prompt", data: bytes.Repeat([]byte("a"), 4097)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var arrivals atomic.Int32
			_, s := modeWireServer(t, ModeAudioTranscription, func(w http.ResponseWriter, r *http.Request) {
				arrivals.Add(1)
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"text":"ok"}`)
			})
			b, ct := modeAudioBody(t, tc.parts...)
			status, _, _ := modeWireRequest(t, s, "/v1/audio/transcriptions", ct, b)
			if tc.success {
				if status != 200 || arrivals.Load() != 1 {
					t.Fatalf("status=%d arrivals=%d", status, arrivals.Load())
				}
			} else if status < 400 || status >= 500 || arrivals.Load() != 0 {
				t.Fatalf("status=%d arrivals=%d", status, arrivals.Load())
			}
		})
	}
}

func TestAdapterModesFiniteResponsesOnWire(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		mode                    ModelMode
		path, request, ct, body string
		want                    int
	}{
		{"invalid_json", ModeEmbedding, "/v1/embeddings", `"input":"hello"`, "application/json", "{", 502},
		{"empty_json", ModeEmbedding, "/v1/embeddings", `"input":"hello"`, "application/json", "", 502},
		{"json_limit", ModeEmbedding, "/v1/embeddings", `"input":"hello"`, "application/json", `"` + strings.Repeat("a", 2<<20) + `"`, 502},
		{"embedding_sse", ModeEmbedding, "/v1/embeddings", `"input":"hello"`, "text/event-stream", "data: fake\n\n", 502},
		{"speech_json", ModeAudioSpeech, "/v1/audio/speech", `"input":"hello","voice":"alloy"`, "application/json", `{"url":"https://evil.invalid"}`, 502},
		{"speech_html", ModeAudioSpeech, "/v1/audio/speech", `"input":"hello","voice":"alloy"`, "text/html", "audio", 502},
		{"speech_limit", ModeAudioSpeech, "/v1/audio/speech", `"input":"hello","voice":"alloy"`, "audio/mpeg", strings.Repeat("a", MaxMediaResponseBytes+1), 502},
		{"image_limit", ModeImageGeneration, "/v1/images/generations", `"prompt":"hello"`, "application/json", `"` + strings.Repeat("a", MaxMediaResponseBytes) + `"`, 502},
		{"completion_sse", ModeCompletion, "/v1/completions", `"prompt":"hello","stream":true`, "text/event-stream", "data: {\"text\":\"ok\"}\n\ndata: [DONE]\n\n", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, s := modeWireServer(t, tc.mode, func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", tc.ct)
				io.WriteString(w, tc.body)
			})
			status, data, _ := modeWireRequest(t, s, tc.path, "application/json", []byte(`{"model":"openai/fixture-model",`+tc.request+`}`))
			if status != tc.want {
				t.Fatalf("status=%d want=%d", status, tc.want)
			}
			if tc.want == 200 && string(data) != tc.body {
				t.Fatal("qualified response changed")
			}
			if tc.want == 502 && len(data) > 2048 {
				t.Fatal("oversized/invalid response leaked")
			}
		})
	}
}

func TestAdapterModesCompletionStreamBoundOnWire(t *testing.T) {
	_, s := modeWireServer(t, ModeCompletion, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		io.WriteString(w, strings.Repeat("data: x\n\n", 300000))
	})
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/v1/completions", strings.NewReader(`{"model":"openai/fixture-model","prompt":"hello","stream":true}`))
	req.Header.Set("Authorization", "Bearer fixture-caller")
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err == nil || len(data) > 2<<20 {
		t.Fatalf("stream bound not enforced: bytes=%d error=%v", len(data), err)
	}
}

func TestAdapterModesNonchatLeaseAndAdmission(t *testing.T) {
	var arrivals atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	_, s := modeWireServer(t, ModeEmbedding, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		arrivals.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[]}`)
	})
	statuses := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func() {
			req, _ := http.NewRequest(http.MethodPost, s.URL+"/v1/embeddings", strings.NewReader(`{"model":"openai/fixture-model","input":"hello"}`))
			req.Header.Set("Authorization", "Bearer fixture-caller")
			res, err := s.Client().Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			statuses <- res.StatusCode
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("requests did not occupy admission")
		}
	}
	status, _, _ := modeWireRequest(t, s, "/v1/embeddings", "application/json", []byte(`{"model":"openai/fixture-model","input":"hello"}`))
	close(release)
	if status != 429 || arrivals.Load() != 4 {
		t.Fatalf("saturation status=%d upstream=%d", status, arrivals.Load())
	}
	for i := 0; i < 4; i++ {
		select {
		case got := <-statuses:
			if got != 200 {
				t.Errorf("admitted request status=%d", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("admitted request stuck")
		}
	}
	status, _, _ = modeWireRequest(t, s, "/v1/embeddings", "application/json", []byte(`{"model":"openai/fixture-model","input":"hello"}`))
	if status != 200 || arrivals.Load() != 5 {
		t.Fatalf("admission not released: status=%d upstream=%d", status, arrivals.Load())
	}
}

func TestAdapterModesSpeechLeaseCancelsUpstream(t *testing.T) {
	canceled := make(chan struct{}, 1)
	a, s := modeWireServer(t, ModeAudioSpeech, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "audio/mpeg")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		canceled <- struct{}{}
	})
	original := a.authorize
	a.authorize = func(ctx context.Context, token, model string) (Grant, error) {
		g, e := original(ctx, token, model)
		g.Expires = time.Now().Add(100 * time.Millisecond)
		return g, e
	}
	req, _ := http.NewRequest(http.MethodPost, s.URL+"/v1/audio/speech", strings.NewReader(`{"model":"openai/fixture-model","input":"hello","voice":"alloy"}`))
	req.Header.Set("Authorization", "Bearer fixture-caller")
	started := time.Now()
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(req)
	// The grant also bounds the downstream socket, so expiry may close it
	// before a sanitized 502 can be written. Neither path may return audio.
	if err == nil {
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 502 || len(data) > 2048 {
			t.Fatalf("expired speech response status=%d bytes=%d", res.StatusCode, len(data))
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("speech exceeded short authorization lease")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("lease did not cancel upstream speech")
	}
}
