package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/aigateway"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestAIModeSocketRouting(t *testing.T) {
	var arrivals atomic.Int32
	audio := []byte("RIFFsynthetic-route-audio")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Method != "POST" || r.Header.Get("X-Bf-Vk") != "sk-bf-mode-route" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("routing altered method or scoped credentials")
		}
		mode, ok := aigateway.InferencePathMode(r.URL.Path)
		if !ok {
			t.Errorf("invalid downstream mode path: %s", r.URL.Path)
		}
		if mode == aigateway.ModeAudioTranscription {
			if e := r.ParseMultipartForm(1 << 20); e != nil {
				t.Error(e)
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
			got, _ := io.ReadAll(f)
			f.Close()
			if !bytes.Equal(got, audio) || r.FormValue("model") != "openai/audio_transcription" {
				t.Error("multipart content was lost in router")
			}
		} else {
			var payload map[string]any
			if json.NewDecoder(r.Body).Decode(&payload) != nil || payload["model"] != "openai/"+string(mode) {
				t.Error("JSON mode/model changed in router")
			}
		}
		if mode == aigateway.ModeAudioSpeech {
			w.Header().Set("Content-Type", "audio/mpeg")
			w.Write(audio)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"result":"route-qualified"}`)
	}))
	defer upstream.Close()
	adapter, e := aigateway.NewAdapter(upstream.URL, func(_ context.Context, token, model string) (aigateway.Grant, error) {
		if token != "scoped-mode-token" && token != "wrong-mode-token" {
			return aigateway.Grant{}, errors.New("PRIVATE_RESOLVER_SECRET")
		}
		mode := aigateway.ModelMode(strings.TrimPrefix(model, "openai/"))
		if token == "wrong-mode-token" {
			if mode == aigateway.ModeChat {
				mode = aigateway.ModeEmbedding
			} else {
				mode = aigateway.ModeChat
			}
		}
		return aigateway.Grant{Tenant: "tenant", Agent: "agent", VirtualKey: "sk-bf-mode-route", Mode: mode, Expires: time.Now().Add(time.Minute)}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	srv := aiSocketServer(t, Deps{AIAdapter: adapter})
	cases := []struct {
		mode          aigateway.ModelMode
		path, payload string
	}{
		{aigateway.ModeChat, "/ai/v1/chat/completions", `"messages":[{"role":"user","content":"fixture"}]`},
		{aigateway.ModeCompletion, "/ai/v1/completions", `"prompt":"fixture"`},
		{aigateway.ModeEmbedding, "/ai/v1/embeddings", `"input":"fixture"`},
		{aigateway.ModeAudioSpeech, "/ai/v1/audio/speech", `"input":"fixture","voice":"alloy","response_format":"wav"`},
		{aigateway.ModeAudioTranscription, "/ai/v1/audio/transcriptions", ""},
		{aigateway.ModeImageGeneration, "/ai/v1/images/generations", `"prompt":"fixture"`},
		{aigateway.ModeRerank, "/ai/v1/rerank", `"query":"fixture","documents":["fixture"]`},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			for _, auth := range []struct {
				token  string
				status int
			}{{"", 401}, {"wrong-mode-token", 403}, {"invalid-token", 403}, {"scoped-mode-token", 200}} {
				body := []byte(`{"model":"openai/` + string(tc.mode) + `",` + tc.payload + `}`)
				ct := "application/json"
				if tc.mode == aigateway.ModeAudioTranscription {
					var b bytes.Buffer
					mw := multipart.NewWriter(&b)
					mw.WriteField("model", "openai/audio_transcription")
					h := textproto.MIMEHeader{}
					h.Set("Content-Disposition", `form-data; name="file"; filename="source.wav"`)
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
				req, _ := http.NewRequest("POST", srv.URL+tc.path, bytes.NewReader(body))
				req.Header.Set("Content-Type", ct)
				req.Header.Set("Cookie", "session=must-not-forward")
				if auth.token != "" {
					req.Header.Set("Authorization", "Bearer "+auth.token)
				}
				before := arrivals.Load()
				res, e := (&http.Client{Timeout: 4 * time.Second}).Do(req)
				if e != nil {
					t.Fatal(e)
				}
				got, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != auth.status {
					t.Fatalf("token=%q status=%d body=%s", auth.token, res.StatusCode, got)
				}
				if bytes.Contains(got, []byte("PRIVATE_RESOLVER_SECRET")) {
					t.Fatal("resolver secret reflected")
				}
				if auth.status != 200 {
					if arrivals.Load() != before {
						t.Fatal("refused route reached engine")
					}
					continue
				}
				if arrivals.Load() != before+1 {
					t.Fatal("accepted route missing engine arrival")
				}
				if tc.mode == aigateway.ModeAudioSpeech {
					if res.Header.Get("Content-Type") != "audio/wav" || !bytes.Equal(got, audio) {
						t.Fatal("binary audio route corrupted bytes or media type")
					}
				} else if !bytes.Contains(got, []byte("route-qualified")) {
					t.Fatal("JSON response lost")
				}
			}
		})
	}
}

func TestAIModelModeOpenAPISchemas(t *testing.T) {
	org := uuid.New()
	srv := aiSocketServer(t, Deps{AuthFn: func(r *http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: "owner"}}
	}})
	base := "/api/v1/organizations/" + org.String() + "/ai-gateway/"
	marker := "MODE_SCHEMA_SECRET_NEVER_RETURN"
	for _, mode := range []string{"chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank", "unknown-mode"} {
		t.Run(mode, func(t *testing.T) {
			want := 503
			if mode == "unknown-mode" {
				want = 400
			}
			create := `{"provider":"openai","name":"fixture","models":["openai/model"],"model_modes":{"openai/model":"` + mode + `"},"enabled":true,"api_key":"` + marker + `"}`
			update := strings.TrimSuffix(create, "}") + `,"expected_revision":1}`
			probe := `{"provider":"openai","model":"openai/model","mode":"` + mode + `","api_key":"` + marker + `"}`
			catalog := `{"provider":"custom","endpoint_url":"https://public.example","mode":"` + mode + `","api_key":"` + marker + `"}`
			for _, request := range []struct{ method, path, body string }{{"POST", base + "providers", create}, {"PUT", base + "providers/" + uuid.NewString(), update}, {"POST", base + "providers/test-connection", probe}, {"POST", base + "providers/model-catalog", catalog}, {"GET", base + "models?provider=openai&mode=" + mode, ""}} {
				res := aiSocketRequest(t, srv, request.method, request.path, request.body, "", "owner")
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != want {
					t.Errorf("%s %s status=%d want=%d body=%s", request.method, request.path, res.StatusCode, want, body)
				}
				if bytes.Contains(body, []byte(marker)) {
					t.Fatal("mode schema reflected provider secret")
				}
			}
		})
	}
}

func TestAIVideoSocketRoutingPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, user, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Video route',$2)`, []any{org, org.String()}},
		{`INSERT INTO users(id,email) VALUES($1,$2)`, []any{user, user.String() + "@fixture.test"}},
		{`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'fixture',$3)`, []any{node, org, node.String()}},
		{`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,status,kind) VALUES($1,$2,$3,$4,'Video fixture',$5,'active','agent')`, []any{device, org, user, node, device.String()}},
	}
	for _, s := range statements {
		if _, e := pool.Exec(ctx, s.sql, s.args...); e != nil {
			t.Fatal(e)
		}
	}
	var arrivals atomic.Int32
	video := []byte("synthetic-video-route")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		if r.Header.Get("X-Bf-Vk") != "sk-bf-video-route" || r.Header.Get("Authorization") != "" {
			t.Error("video scoped key lost")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/videos":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["model"] != "openai/video-fixture" {
				t.Error("video model lost")
			}
			io.WriteString(w, `{"id":"fixture-video:openai","status":"queued"}`)
		case r.Method == "GET" && r.URL.Path == "/v1/videos/fixture-video:openai":
			io.WriteString(w, `{"id":"fixture-video:openai","status":"completed"}`)
		case r.Method == "GET" && r.URL.Path == "/v1/videos/fixture-video:openai/content":
			w.Header().Set("Content-Type", "video/mp4")
			w.Write(video)
		default:
			t.Errorf("unexpected video downstream route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	adapter, e := aigateway.NewAdapter(upstream.URL, func(_ context.Context, token, model string) (aigateway.Grant, error) {
		if token != "video-scoped-token" {
			return aigateway.Grant{}, errors.New("PRIVATE_VIDEO_SECRET")
		}
		mode := aigateway.ModeVideoGeneration
		if model != "openai/video-fixture" {
			mode = aigateway.ModeChat
		}
		return aigateway.Grant{Tenant: org.String(), Agent: device.String(), Mode: mode, VirtualKey: "sk-bf-video-route", Expires: time.Now().Add(time.Minute)}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	adapter.ConfigureVideoStore(pool)
	srv := aiSocketServer(t, Deps{AIAdapter: adapter})
	call := func(method, path, token, body string) (int, []byte, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "video-router-fixture-key")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, e := (&http.Client{Timeout: 4 * time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if bytes.Contains(raw, []byte("PRIVATE_VIDEO_SECRET")) {
			t.Fatal("video secret reflected")
		}
		return res.StatusCode, raw, res.Header.Get("Content-Type")
	}
	payload := `{"model":"openai/video-fixture","prompt":"fixture"}`
	status, _, _ := call("POST", "/ai/v1/videos", "", payload)
	if status != 401 {
		t.Fatalf("missing video bearer=%d", status)
	}
	status, _, _ = call("POST", "/ai/v1/videos", "wrong-token", payload)
	if status != 403 {
		t.Fatalf("invalid video bearer=%d", status)
	}
	status, _, _ = call("POST", "/ai/v1/videos", "video-scoped-token", `{"model":"openai/chat-fixture","prompt":"fixture"}`)
	if status != 403 || arrivals.Load() != 0 {
		t.Fatal("wrong mode video reached engine")
	}
	status, raw, _ := call("POST", "/ai/v1/videos", "video-scoped-token", payload)
	var job struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if status != 200 || json.Unmarshal(raw, &job) != nil || job.Status != "queued" {
		t.Fatalf("video create=%d %s", status, raw)
	}
	if _, e := uuid.Parse(job.ID); e != nil {
		t.Fatal("video ID is not opaque")
	}
	status, raw, _ = call("GET", "/ai/v1/videos/"+job.ID, "video-scoped-token", "")
	if status != 200 || json.Unmarshal(raw, &job) != nil || job.Status != "completed" {
		t.Fatalf("video status=%d %s", status, raw)
	}
	status, raw, ct := call("GET", "/ai/v1/videos/"+job.ID+"/content", "video-scoped-token", "")
	if status != 200 || ct != "video/mp4" || !bytes.Equal(raw, video) || arrivals.Load() != 3 {
		t.Fatalf("video content=%d type=%s arrivals=%d", status, ct, arrivals.Load())
	}
}
