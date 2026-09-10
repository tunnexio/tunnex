package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Uses the actual digest-pinned binary and only synthetic loopback destinations.
// The mandatory authenticated CONNECT proxy proves native egress participation.
func TestAdapterModesNative(t *testing.T) { adapterModesNative(t, false) }
func TestAdapterVideoNative(t *testing.T) { adapterModesNative(t, true) }
func adapterModesNative(t *testing.T, video bool) {
	binary := os.Getenv("AI0_BIFROST_BINARY")
	if binary == "" {
		t.Skip("explicit pinned native binary required")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != binarySHA256 {
		t.Fatal("native binary pin mismatch")
	}
	var arrivals, tunnels, videoCreates, videoReads, videoDownloads atomic.Int32
	videoBytes := []byte("synthetic-video-content")
	audio := []byte("RIFF\x04\x00\x00\x00WAVEfixture-audio")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-mode-provider-key" {
			t.Error("native upstream credential mismatch")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/videos" && r.Method == http.MethodPost {
			arrivals.Add(1)
			videoCreates.Add(1)
			if e := r.ParseMultipartForm(1 << 20); e != nil {
				t.Error(e)
				w.WriteHeader(400)
				return
			}
			defer r.MultipartForm.RemoveAll()
			if r.FormValue("model") != "video_generation" || r.FormValue("prompt") != "fixture" || r.FormValue("seconds") != "4" {
				t.Errorf("native video input changed model/prompt/duration")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"fixture-video","object":"video","model":"video_generation","status":"queued","created_at":1,"seconds":"4","size":"720x1280"}`)
			return
		}
		if r.URL.Path == "/v1/videos/fixture-video" && r.Method == http.MethodGet {
			arrivals.Add(1)
			videoReads.Add(1)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"fixture-video","object":"video","model":"video_generation","status":"completed","created_at":1,"seconds":"4","size":"720x1280"}`)
			return
		}
		if r.URL.Path == "/v1/videos/fixture-video/content" && r.Method == http.MethodGet {
			arrivals.Add(1)
			videoDownloads.Add(1)
			w.Header().Set("Content-Type", "video/mp4")
			w.Write(videoBytes)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[]}`)
			return
		}
		arrivals.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/audio/transcriptions" {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			defer r.MultipartForm.RemoveAll()
			f, _, e := r.FormFile("file")
			if e != nil {
				t.Error(e)
				w.WriteHeader(400)
				return
			}
			defer f.Close()
			got, _ := io.ReadAll(f)
			if !bytes.Equal(got, audio) || r.FormValue("model") != "audio_transcription" {
				t.Errorf("transcription native multipart changed file/model: %q", r.FormValue("model"))
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"text":"qualified transcription"}`)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			if body["model"] != "chat" {
				t.Errorf("chat model: %v", body["model"])
			}
			io.WriteString(w, `{"id":"fixture","object":"chat.completion","model":"chat","choices":[{"index":0,"message":{"role":"assistant","content":"qualified chat"},"finish_reason":"stop"}]}`)
		case "/v1/completions":
			if body["model"] != "completion" || body["prompt"] != "fixture" {
				t.Errorf("completion shape: %v", body)
			}
			io.WriteString(w, `{"id":"fixture","object":"text_completion","model":"completion","choices":[{"index":0,"text":"qualified completion","finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
		case "/v1/embeddings":
			if body["model"] != "embedding" {
				t.Errorf("embedding model: %v", body["model"])
			}
			io.WriteString(w, `{"object":"list","model":"embedding","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":1,"total_tokens":1}}`)
		case "/v1/audio/speech":
			if body["model"] != "audio_speech" || body["input"] != "fixture" || body["response_format"] != "wav" {
				t.Errorf("speech shape: %v", body)
			}
			w.Header().Set("Content-Type", "audio/wav")
			w.Write(audio)
		case "/v1/images/generations":
			if body["model"] != "image_generation" {
				t.Errorf("image model: %v", body["model"])
			}
			io.WriteString(w, `{"created":1,"data":[{"b64_json":"c3ludGhldGljLWltYWdl"}]}`)
		case "/v1/rerank", "/rerank":
			if body["model"] != "rerank" {
				t.Errorf("rerank model: %v", body["model"])
			}
			io.WriteString(w, `{"id":"fixture","results":[{"index":0,"relevance_score":0.9}],"meta":{"billed_units":{"search_units":1}}}`)
		default:
			t.Errorf("unexpected native operation %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != target.Host || r.Header.Get("Proxy-Authorization") != "Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcGFzc3dvcmQ=" {
			w.WriteHeader(403)
			return
		}
		conn, e := net.Dial("tcp", target.Host)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer conn.Close()
		client, buf, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer client.Close()
		tunnels.Add(1)
		buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		done := make(chan struct{})
		go func() { io.Copy(conn, buf); close(done) }()
		io.Copy(client, conn)
		client.Close()
		conn.Close()
		<-done
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("fixture-user", "fixture-password")
	dir := t.TempDir()
	write := func(name string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("prices.json", map[string]any{})
	write("params.json", map[string]any{})
	write("config.json", map[string]any{"encryption_key": "fixture-encryption-key-32-bytes-only", "client": map[string]any{"enforce_auth_on_inference": true, "disable_content_logging": true}, "config_store": map[string]any{"enabled": true, "type": "sqlite", "config": map[string]any{"path": filepath.Join(dir, "config.db")}}, "framework": map[string]any{"pricing": map[string]any{"pricing_url": "file://" + filepath.Join(dir, "prices.json"), "model_parameters_url": "file://" + filepath.Join(dir, "params.json"), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}}, "governance": map[string]any{"auth_config": map[string]any{"is_enabled": true, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": false}}})
	base, stop := startEngine(t, binary, dir, "TUNNEX_AI_CUSTOM_PROXY_URL="+proxyURL.String())
	defer stop()
	engine, e := NewEngine(base, "fixture-admin", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.ConfigureCustomProxy(proxyURL.String()); e != nil {
		t.Fatal(e)
	}
	provider := "custom-" + uuid.NewString()
	ctx := context.Background()
	if e = engine.EnsureProvider(ctx, provider, upstream.URL); e != nil {
		t.Fatal(e)
	}
	modes := []ModelMode{ModeChat, ModeCompletion, ModeEmbedding, ModeAudioSpeech, ModeAudioTranscription, ModeImageGeneration, ModeRerank}
	if video {
		modes = append(modes, ModeVideoGeneration)
	}
	models := []string{}
	rawModels := []string{}
	modeMap := map[string]ModelMode{}
	for _, mode := range modes {
		model := provider + "/" + string(mode)
		models = append(models, model)
		rawModels = append(rawModels, string(mode))
		modeMap[model] = mode
	}
	spec := ProviderKeySpec{Provider: provider, BaseURL: upstream.URL, ID: "tnx-managed-" + uuid.NewString(), Revision: 1, Models: models, Enabled: true}
	secret := "synthetic-mode-provider-key"
	if e = engine.PutProviderKey(ctx, spec, &secret); e != nil {
		t.Fatal(e)
	}
	key, e := engine.EnsureKey(ctx, "mode-fixture-key", provider, rawModels, []string{spec.ID})
	if e != nil {
		t.Fatal(e)
	}
	tenant, agent := "fixture-tenant", "fixture-agent"
	var revoked atomic.Bool
	adapter, e := NewAdapter(base, func(_ context.Context, token, model string) (Grant, error) {
		mode, ok := modeMap[model]
		if !ok || (token != "synthetic-agent-key" && token != "other-tenant-key") || revoked.Load() {
			return Grant{}, errors.New("denied")
		}
		if mode == ModeChat {
			mode = ""
		} // Compatibility for legacy grants.
		resolvedTenant := tenant
		if token == "other-tenant-key" {
			resolvedTenant = uuid.NewString()
		}
		return Grant{Tenant: resolvedTenant, Agent: agent, Mode: mode, VirtualKey: key.Value, Expires: time.Now().Add(time.Minute)}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if video {
		dbctx, pool := testpostgres.New(t)
		f := newAICredentialFixture(t, dbctx, pool)
		tenant, agent = f.org.String(), f.device.String()
		adapter.ConfigureVideoStore(pool)
	}
	server := httptest.NewServer(adapter)
	defer server.Close()
	cases := []struct {
		mode                    ModelMode
		path, payload, contains string
	}{
		{ModeChat, "/v1/chat/completions", `"messages":[{"role":"user","content":"fixture"}]`, "qualified chat"},
		{ModeCompletion, "/v1/completions", `"prompt":"fixture","max_tokens":8`, "qualified completion"},
		{ModeEmbedding, "/v1/embeddings", `"input":"fixture"`, "0.1"},
		{ModeAudioSpeech, "/v1/audio/speech", `"input":"fixture","voice":"alloy","response_format":"wav"`, string(audio)},
		{ModeAudioTranscription, "/v1/audio/transcriptions", "", "qualified transcription"},
		{ModeImageGeneration, "/v1/images/generations", `"prompt":"fixture","n":1,"response_format":"b64_json"`, "c3ludGhldGljLWltYWdl"},
		{ModeRerank, "/v1/rerank", `"query":"fixture","documents":["fixture","other"],"top_n":1`, "0.9"},
	}
	if video {
		cases = nil
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			for _, wrong := range []bool{false, true} {
				model := provider + "/" + string(tc.mode)
				if wrong {
					model = provider + "/chat"
					if tc.mode == ModeChat {
						model = provider + "/embedding"
					}
				}
				body := []byte(`{"model":"` + model + `",` + tc.payload + `}`)
				ct := "application/json"
				if tc.mode == ModeAudioTranscription {
					var b bytes.Buffer
					mw := multipart.NewWriter(&b)
					mw.WriteField("model", model)
					h := textproto.MIMEHeader{}
					h.Set("Content-Disposition", `form-data; name="file"; filename="synthetic.wav"`)
					h.Set("Content-Type", "audio/wav")
					f, e := mw.CreatePart(h)
					if e != nil {
						t.Fatal(e)
					}
					f.Write(audio)
					mw.Close()
					body = b.Bytes()
					ct = mw.FormDataContentType()
				}
				before := arrivals.Load()
				req, _ := http.NewRequest("POST", server.URL+tc.path, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer synthetic-agent-key")
				req.Header.Set("Content-Type", ct)
				res, e := (&http.Client{Timeout: 15 * time.Second}).Do(req)
				if e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
				res.Body.Close()
				if e != nil {
					t.Fatal(e)
				}
				if wrong {
					if res.StatusCode != 403 || arrivals.Load() != before {
						t.Fatalf("wrong mode status=%d arrivals=%d", res.StatusCode, arrivals.Load()-before)
					}
					continue
				}
				if res.StatusCode != 200 || !bytes.Contains(got, []byte(tc.contains)) || arrivals.Load() != before+1 {
					t.Errorf("native %s status=%d arrivals=%d body=%s", tc.mode, res.StatusCode, arrivals.Load()-before, got)
				}
				if tc.mode == ModeAudioSpeech && (res.Header.Get("Content-Type") != "audio/wav" || !bytes.Equal(got, audio)) {
					t.Errorf("binary speech content mismatch: %s", res.Header.Get("Content-Type"))
				}
			}
		})
	}
	if video {
		call := func(method, path, token, keyID, payload string) (int, []byte, http.Header) {
			t.Helper()
			r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(payload))
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Content-Type", "application/json")
			if keyID != "" {
				r.Header.Set("Idempotency-Key", keyID)
			}
			res, e := (&http.Client{Timeout: 15 * time.Second}).Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			if e != nil {
				t.Fatal(e)
			}
			return res.StatusCode, body, res.Header
		}
		wrongStatus, _, _ := call("POST", "/v1/videos", "synthetic-agent-key", "native-wrong-mode-key", `{"model":"`+provider+`/chat","prompt":"fixture"}`)
		if wrongStatus != 403 || videoCreates.Load() != 0 {
			t.Fatal("wrong model mode admitted a video create")
		}
		rawStatus, _, _ := call("GET", "/v1/videos/fixture-video:"+provider, "synthetic-agent-key", "", "")
		if rawStatus != 404 || videoReads.Load() != 0 {
			t.Fatal("raw provider handle accepted by public video route")
		}
		payload := `{"model":"` + provider + `/video_generation","prompt":"fixture","seconds":"4","size":"720x1280"}`
		status, body, _ := call("POST", "/v1/videos", "synthetic-agent-key", "native-video-idempotency", payload)
		var job struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Model  string `json:"model"`
		}
		if status != 200 || json.Unmarshal(body, &job) != nil || job.Status != "queued" || job.Model != provider+"/video_generation" {
			t.Fatalf("native video create: status=%d body=%s arrivals=%d", status, body, videoCreates.Load())
		}
		if _, e := uuid.Parse(job.ID); e != nil || bytes.Contains(body, []byte("fixture-video")) {
			t.Fatalf("provider ID exposed: %s", body)
		}
		status, replay, _ := call("POST", "/v1/videos", "synthetic-agent-key", "native-video-idempotency", payload)
		if status != 200 || !bytes.Equal(replay, body) || videoCreates.Load() != 1 {
			t.Fatal("idempotent create resubmitted native job")
		}
		status, _, _ = call("GET", "/v1/videos/"+job.ID+"/content", "synthetic-agent-key", "", "")
		if status != 409 || videoDownloads.Load() != 0 {
			t.Fatal("content fetched before completion")
		}
		status, body, _ = call("GET", "/v1/videos/"+job.ID, "synthetic-agent-key", "", "")
		if status != 200 || json.Unmarshal(body, &job) != nil || job.Status != "completed" || bytes.Contains(body, []byte("fixture-video")) || videoReads.Load() != 1 {
			t.Fatalf("native video retrieval: status=%d body=%s reads=%d", status, body, videoReads.Load())
		}
		status, body, headers := call("GET", "/v1/videos/"+job.ID+"/content", "synthetic-agent-key", "", "")
		if status != 200 || headers.Get("Content-Type") != "video/mp4" || !bytes.Equal(body, videoBytes) || videoDownloads.Load() != 1 {
			t.Fatalf("native video content status=%d type=%s body=%s", status, headers.Get("Content-Type"), body)
		}
		before := arrivals.Load()
		status, _, _ = call("GET", "/v1/videos/"+job.ID, "other-tenant-key", "", "")
		if status != 404 || arrivals.Load() != before {
			t.Fatal("other tenant read reached native provider")
		}
		revoked.Store(true)
		status, _, _ = call("GET", "/v1/videos/"+job.ID+"/content", "synthetic-agent-key", "", "")
		if status != 404 || arrivals.Load() != before {
			t.Fatal("revoked video read reached native provider")
		}
	}
	if tunnels.Load() == 0 {
		t.Fatal("native requests bypassed CONNECT proxy")
	}
}
