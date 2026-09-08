package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestVideoNativeScopeAndShape(t *testing.T) {
	for _, body := range []string{`{"id":"v:foreign","status":"queued"}`, `{"id":"v:custom-owned","status":"unknown"}`, `{"id":"..%2Fsecret:custom-owned","status":"completed"}`, `{"id":"v%253Fsecret:custom-owned","status":"completed"}`, `{"id":"v?secret:custom-owned","status":"completed"}`} {
		if _, _, err := videoNative([]byte(body), "custom-owned/model"); err == nil {
			t.Fatal("unsafe video admitted", body)
		}
	}
	if id, state, err := videoNative([]byte(`{"id":"operations%2Fvideo1:custom-owned","status":"queued","prompt":"private","videos":[{"url":"https://never-fetch"}]}`), "custom-owned/model"); err != nil || id != "operations%2Fvideo1:custom-owned" || state != "queued" {
		t.Fatal(id, state, err)
	}
}

func TestVideoJobsPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newAICredentialFixture(t, ctx, pool)
	store := videoStore{pool}
	g := Grant{Tenant: f.org.String(), Agent: f.device.String(), Mode: ModeVideoGeneration, VirtualKey: "sk-bf-video-fixture", Expires: time.Now().Add(time.Minute)}
	t.Run("concurrent reservation and mismatch", func(t *testing.T) {
		var count atomic.Int32
		var wg sync.WaitGroup
		ids := make(chan uuid.UUID, 24)
		for range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				j, fresh, err := store.reserve(ctx, g, "openai/video", "concurrent-video-0001", []byte(`{"model":"openai/video"}`))
				if err != nil {
					t.Error(err)
					return
				}
				if fresh {
					count.Add(1)
				}
				ids <- j.ID
			}()
		}
		wg.Wait()
		close(ids)
		var first uuid.UUID
		for id := range ids {
			if first == uuid.Nil {
				first = id
			}
			if id != first {
				t.Fatal("multiple handles")
			}
		}
		if count.Load() != 1 {
			t.Fatal("multiple submit owners", count.Load())
		}
		if _, _, err := store.reserve(ctx, g, "openai/video", "concurrent-video-0001", []byte(`{"different":true}`)); !errors.Is(err, errVideoConflict) {
			t.Fatal("hash mismatch accepted", err)
		}
		j, err := store.lookup(ctx, first)
		if err != nil || j.State != "uncertain" || j.ProviderID != "" || j.Expires.Sub(j.Created) != videoRetention {
			t.Fatal(j, err)
		}
	})
	t.Run("bounded cleanup and capacity", func(t *testing.T) {
		_, err := pool.Exec(ctx, `INSERT INTO ai_video_jobs(id,org_id,device_id,model,idempotency_key,request_hash,state,expires_at) SELECT gen_random_uuid(),$1,$2,'openai/video','expired-video-'||lpad(i::text,16,'0'),decode(repeat('00',32),'hex'),'failed',now()-interval '1 second' FROM generate_series(1,130) i`, f.org, f.device)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = store.reserve(ctx, g, "openai/video", "cleanup-video-0001", []byte("body")); err != nil {
			t.Fatal(err)
		}
		var n int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_video_jobs WHERE expires_at<=now()`).Scan(&n); err != nil || n != 2 {
			t.Fatal("cleanup unbounded", n, err)
		}
		_, err = pool.Exec(ctx, `INSERT INTO ai_video_jobs(id,org_id,device_id,model,idempotency_key,request_hash,state) SELECT gen_random_uuid(),$1,$2,'openai/video','quota-video-'||lpad(i::text,16,'0'),decode(repeat('00',32),'hex'),'queued' FROM generate_series(1,62) i`, f.org, f.device)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = store.reserve(ctx, g, "openai/video", "overquota-video-01", []byte("body")); !errors.Is(err, errVideoQuota) {
			t.Fatal("nonterminal cap ignored", err)
		}
		if _, err = pool.Exec(ctx, `UPDATE ai_video_jobs SET state='failed' WHERE org_id=$1`, f.org); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO ai_video_jobs(id,org_id,device_id,model,idempotency_key,request_hash,state) SELECT gen_random_uuid(),$1,$2,'openai/video','global-video-'||lpad(i::text,16,'0'),decode(repeat('00',32),'hex'),'failed' FROM generate_series(1,4032) i`, f.org, f.device); err != nil {
			t.Fatal(err)
		}
		if _, _, err = store.reserve(ctx, g, "openai/video", "global-cap-video01", []byte("body")); !errors.Is(err, errVideoQuota) {
			t.Fatal("global cap ignored", err)
		}
		if _, err = pool.Exec(ctx, `DELETE FROM ai_video_jobs WHERE org_id=$1`, f.org); err != nil {
			t.Fatal(err)
		}
	})

	var creates, reads, downloads atomic.Int32
	var deny atomic.Bool
	var holdContent atomic.Bool
	contentCancelled := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Bf-Vk") != g.VirtualKey {
			t.Error("virtual key missing")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/videos":
			creates.Add(1)
			io.WriteString(w, `{"id":"video_fixture:openai","status":"queued","prompt":"must-not-leak","videos":[{"url":"https://never-fetch"}]}`)
		case "GET /v1/videos/video_fixture:openai":
			reads.Add(1)
			io.WriteString(w, `{"id":"video_fixture:openai","status":"completed","prompt":"must-not-leak"}`)
		case "GET /v1/videos/video_fixture:openai/content":
			downloads.Add(1)
			if holdContent.Load() {
				select {
				case <-r.Context().Done():
					contentCancelled <- struct{}{}
				case <-time.After(time.Second):
					t.Error("expired job did not cancel upstream download")
				}
			}
			w.Header().Set("Content-Type", "video/mp4")
			w.Write([]byte("synthetic-video-content"))
		default:
			t.Error("unexpected upstream request", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer up.Close()
	a, err := NewAdapter(up.URL, func(_ context.Context, token, model string) (Grant, error) {
		if deny.Load() || model != "openai/video" {
			return Grant{}, errors.New("revoked")
		}
		out := g
		switch token {
		case "owner":
		case "foreign-agent":
			out.Agent = uuid.NewString()
		case "foreign-org":
			out.Tenant = uuid.NewString()
		default:
			return Grant{}, errors.New("invalid")
		}
		return out, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a.ConfigureVideoStore(pool)
	server := httptest.NewServer(a.video)
	defer server.Close()
	request := func(method, path, token, key, body string) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequest(method, server.URL+path, bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		res, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}
	code, raw := request("POST", "/v1/videos", "owner", "wire-video-key-0001", `{"model":"openai/video","prompt":"test"}`)
	if code != 200 || bytes.Contains(raw, []byte("video_fixture")) || bytes.Contains(raw, []byte("must-not-leak")) {
		t.Fatal(code, string(raw))
	}
	var public struct{ ID, Status string }
	if json.Unmarshal(raw, &public) != nil || public.Status != "queued" {
		t.Fatal(string(raw))
	}
	if _, err := uuid.Parse(public.ID); err != nil {
		t.Fatal("handle not opaque uuid")
	}
	code, _ = request("POST", "/v1/videos", "owner", "wire-video-key-0001", `{ "prompt":"test", "model":"openai/video", "seconds":"4" }`)
	if code != 200 || creates.Load() != 1 {
		t.Fatal("retry resubmitted", code, creates.Load())
	}
	code, _ = request("POST", "/v1/videos", "owner", "wire-video-key-0001", `{"model":"openai/video","prompt":"different"}`)
	if code != 409 || creates.Load() != 1 {
		t.Fatal("conflict resubmitted", code)
	}
	for _, token := range []string{"foreign-agent", "foreign-org", "invalid"} {
		code, _ = request("GET", "/v1/videos/"+public.ID, token, "", "")
		if code != 404 || reads.Load() != 0 {
			t.Fatal("foreign access", token, code)
		}
	}
	code, _ = request("GET", "/v1/videos/"+public.ID+"/content", "owner", "", "")
	if code != 409 || downloads.Load() != 0 {
		t.Fatal("unfinished content", code)
	}
	code, raw = request("GET", "/v1/videos/"+public.ID, "owner", "", "")
	if code != 200 || !bytes.Contains(raw, []byte(`"status":"completed"`)) || reads.Load() != 1 {
		t.Fatal(code, string(raw))
	}
	code, raw = request("GET", "/v1/videos/"+public.ID+"/content", "owner", "", "")
	if code != 200 || string(raw) != "synthetic-video-content" || downloads.Load() != 1 {
		t.Fatal(code)
	}
	deny.Store(true)
	for _, suffix := range []string{"", "/content"} {
		code, _ = request("GET", "/v1/videos/"+public.ID+suffix, "owner", "", "")
		if code != 404 {
			t.Fatal("revocation ignored", code)
		}
	}
	if reads.Load() != 1 || downloads.Load() != 1 || creates.Load() != 1 {
		t.Fatal("revoked service arrival")
	}
	deny.Store(false)
	holdContent.Store(true)
	if _, err = pool.Exec(ctx, `UPDATE ai_video_jobs SET expires_at=now()+interval '150 milliseconds' WHERE org_id=$1 AND id=$2`, f.org, public.ID); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", server.URL+"/v1/videos/"+public.ID+"/content", nil)
	r.Header.Set("Authorization", "Bearer owner")
	res, downloadErr := server.Client().Do(r)
	if downloadErr == nil {
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if bytes.Contains(data, []byte("synthetic-video-content")) {
			t.Fatal("content delivered beyond job retention")
		}
	}
	select {
	case <-contentCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("missing expiry cancellation")
	}
	if _, err = pool.Exec(ctx, `UPDATE ai_video_jobs SET expires_at=now()-interval '1 second' WHERE org_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	code, _ = request("GET", "/v1/videos/"+public.ID, "owner", "", "")
	if code != 404 {
		t.Fatal("expired job admitted", code)
	}
}

func TestVideoUncertainPostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newAICredentialFixture(t, ctx, pool)
	for _, kind := range []string{"upstream-error", "invalid-json", "wrong-provider", "oversized", "persist-failure", "lease-expired"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			if kind == "persist-failure" {
				_, err := pool.Exec(ctx, `CREATE FUNCTION video_fixture_update_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic persistence failure'; END $$; CREATE TRIGGER video_fixture_update_failure BEFORE UPDATE ON ai_video_jobs FOR EACH ROW EXECUTE FUNCTION video_fixture_update_failure()`)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Exec(ctx, `DROP TRIGGER video_fixture_update_failure ON ai_video_jobs; DROP FUNCTION video_fixture_update_failure()`)
			}
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "upstream-error":
					w.WriteHeader(502)
					io.WriteString(w, "provider key and private error")
				case "invalid-json":
					io.WriteString(w, "invalid private response")
				case "wrong-provider":
					io.WriteString(w, `{"id":"video:foreign","status":"queued"}`)
				case "oversized":
					io.WriteString(w, strings.Repeat("x", (2<<20)+1))
				case "lease-expired":
					select {
					case <-r.Context().Done():
					case <-time.After(500 * time.Millisecond):
					}
				default:
					io.WriteString(w, `{"id":"video:openai","status":"queued"}`)
				}
			}))
			defer up.Close()
			var authCalls atomic.Int32
			a, _ := NewAdapter(up.URL, func(context.Context, string, string) (Grant, error) {
				expiry := time.Now().Add(time.Minute)
				if authCalls.Add(1) == 1 && kind == "lease-expired" {
					expiry = time.Now().Add(100 * time.Millisecond)
				}
				return Grant{Tenant: f.org.String(), Agent: f.device.String(), Mode: ModeVideoGeneration, VirtualKey: "sk-bf-video-fixture", Expires: expiry}, nil
			})
			a.ConfigureVideoStore(pool)
			server := httptest.NewServer(a.video)
			defer server.Close()
			var firstID string
			for attempt := range 2 {
				r, _ := http.NewRequest("POST", server.URL+"/v1/videos", strings.NewReader(`{"model":"openai/video","prompt":"test"}`))
				r.Header.Set("Authorization", "Bearer owner")
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Idempotency-Key", "uncertain-video-"+kind)
				res, err := server.Client().Do(r)
				if err != nil {
					if kind == "lease-expired" && attempt == 0 {
						continue
					}
					t.Fatal(err)
				}
				raw, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != 200 || !bytes.Contains(raw, []byte(`"status":"uncertain"`)) || bytes.Contains(raw, []byte("private")) {
					t.Fatal(res.StatusCode, string(raw))
				}
				var job struct{ ID string }
				if json.Unmarshal(raw, &job) != nil {
					t.Fatal("missing retained handle")
				}
				if _, err := uuid.Parse(job.ID); err != nil {
					t.Fatal(err)
				}
				if firstID != "" && firstID != job.ID {
					t.Fatal("retry changed handle")
				}
				firstID = job.ID
			}
			if calls.Load() != 1 {
				t.Fatal(fmt.Sprint("uncertain submission retried ", calls.Load()))
			}
		})
	}
}
