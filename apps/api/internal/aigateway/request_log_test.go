package aigateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

const secretPrompt = "PROMPT-NEVER-STORED-7f3a"

type logEngine struct {
	mu      sync.Mutex
	entries map[string]EngineRequestLog
}

func (e *logEngine) RequestLogEntry(_ context.Context, id string) (EngineRequestLog, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.entries[id]
	return v, ok, nil
}

func waitRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ai_request_log WHERE org_id=$1`, org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d request log rows, have %d", want, n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// AI-READY-1: one adapter call is logged with its subject, group, status and
// the engine's request ID; the prompt and response never reach the table.
func TestRequestLogRecordsMetadataOnly(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, user, group := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Log',$2)`, org, "log-"+org.String()); err != nil {
		t.Fatal(err)
	}
	var upstreamID string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamID = r.Header.Get("X-Request-Id")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"RESPONSE-NEVER-STORED"}}],"usage":{"prompt_tokens":5,"completion_tokens":7}}`)
	}))
	defer up.Close()
	a, err := NewAdapter(up.URL, func(context.Context, string, string) (Grant, error) { return Grant{}, aiUnauthorized() })
	if err != nil {
		t.Fatal(err)
	}
	engine := &logEngine{entries: map[string]EngineRequestLog{}}
	log := NewRequestLog(pool, nil, nil)
	log.engine = func() RequestLogEngine { return engine }
	a.ConfigureRequestLog(log)
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go log.Run(runCtx)

	limited := false
	serve := func(body string) int {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw, traced, trace, finish := a.RequestLog().Begin(w, r, IngressPublic, "req-123")
			defer finish()
			trace.SetSubject(org, "user", user)
			a.ServeAuthorized(tw, traced, TraceAuthorize(func(ctx context.Context, _ string, model string) (Grant, error) {
				if limited {
					return Grant{}, apierr.Forbidden("ai_daily_threshold_reached", "AI daily soft usage threshold reached")
				}
				noteRequestGroup(ctx, "user_group", group)
				return Grant{Tenant: org.String(), Agent: user.String(), SubjectKind: "user", VirtualKey: "sk-bf-fixture", Mode: ModeChat, Expires: time.Now().Add(time.Minute)}, nil
			}))
		})
		srv := httptest.NewServer(h)
		defer srv.Close()
		res, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := serve(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"` + secretPrompt + `"}]}`); code != 200 {
		t.Fatalf("served %d", code)
	}
	limited = true
	if code := serve(`{"model":"openrouter/allowed","messages":[{"role":"user","content":"` + secretPrompt + `"}]}`); code != 403 {
		t.Fatalf("refusal served %d", code)
	}
	waitRows(t, ctx, pool, org, 2)

	var dump string
	if err := pool.QueryRow(ctx, `SELECT string_agg(row_to_json(l)::text, ' ') FROM ai_request_log l WHERE org_id=$1`, org).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, secretPrompt) || strings.Contains(dump, "RESPONSE-NEVER-STORED") || strings.Contains(dump, "sk-bf-fixture") {
		t.Fatalf("request content or key stored: %s", dump)
	}

	var p Policies
	p.pool = pool
	page, next, err := p.ListRequests(ctx, org, RequestLogFilter{}, 50, "")
	if err != nil || len(page) != 2 || next != "" {
		t.Fatalf("list: %+v %q %v", page, next, err)
	}
	refused, ok := page[0], page[1]
	if ok.Outcome != "ok" || ok.StatusCode != 200 || ok.SubjectKind != "user" || *ok.SubjectID != user || ok.GroupID == nil || *ok.GroupID != group || ok.Ingress != "public" || ok.Model != "openrouter/allowed" || ok.Mode != "chat" || ok.CostState != "pending" || *ok.RequestID != "req-123" {
		t.Fatalf("ok row: %+v", ok)
	}
	if upstreamID != ok.ID.String() {
		t.Fatalf("engine request id %q is not the log id %s", upstreamID, ok.ID)
	}
	if refused.Outcome != "refused" || refused.RefusalCode == nil || *refused.RefusalCode != "ai_daily_threshold_reached" || refused.CostState != "not_applicable" || *refused.SubjectID != user {
		t.Fatalf("refused row: %+v", refused)
	}

	// Enrichment fills tokens and cost from the engine's entry for this id.
	cost := 0.0012
	pt, ct := int64(5), int64(7)
	engine.mu.Lock()
	engine.entries[ok.ID.String()] = EngineRequestLog{Status: "success", PromptTokens: &pt, CompletionTokens: &ct, Cost: &cost}
	engine.mu.Unlock()
	if _, err := pool.Exec(ctx, `UPDATE ai_request_log SET occurred_at=occurred_at-interval '10 seconds' WHERE org_id=$1`, org); err != nil {
		t.Fatal(err)
	}
	if n, err := log.Enrich(ctx); err != nil || n != 1 {
		t.Fatalf("enrich: %d %v", n, err)
	}
	page, _, _ = p.ListRequests(ctx, org, RequestLogFilter{Outcome: "ok"}, 50, "")
	if len(page) != 1 || page[0].CostState != "costed" || *page[0].CostUSD != cost || *page[0].PromptTokens != 5 || *page[0].CompletionTokens != 7 {
		t.Fatalf("enriched row: %+v", page)
	}

	// Filters and the cursor.
	page, next, err = p.ListRequests(ctx, org, RequestLogFilter{}, 1, "")
	if err != nil || len(page) != 1 || next == "" {
		t.Fatalf("first page: %+v %q %v", page, next, err)
	}
	page2, next2, err := p.ListRequests(ctx, org, RequestLogFilter{}, 1, next)
	if err != nil || len(page2) != 1 || next2 != "" || page2[0].ID == page[0].ID {
		t.Fatalf("second page: %+v %q %v", page2, next2, err)
	}
	if _, _, err := p.ListRequests(ctx, org, RequestLogFilter{}, 1, "not-a-cursor"); err == nil {
		t.Fatal("a forged cursor was accepted")
	}
	if rows, _, _ := p.ListRequests(ctx, org, RequestLogFilter{SubjectID: &group}, 50, ""); len(rows) != 1 {
		t.Fatalf("group filter: %+v", rows)
	}
	if rows, _, _ := p.ListRequests(ctx, uuid.New(), RequestLogFilter{}, 50, ""); len(rows) != 0 {
		t.Fatal("another organization read this log")
	}

	// Retention: the default 30 days, then the organization's own setting.
	if _, err := pool.Exec(ctx, `UPDATE ai_request_log SET occurred_at=now()-interval '10 days' WHERE org_id=$1 AND outcome='refused'`, org); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := log.Prune(ctx); err != nil || deleted != 0 {
		t.Fatalf("default retention deleted %d %v", deleted, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ai_gateway_cost_settings(org_id,request_log_retention_days) VALUES($1,7)`, org); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := log.Prune(ctx); err != nil || deleted != 1 {
		t.Fatalf("7-day retention deleted %d %v", deleted, err)
	}
}

// A full queue drops records instead of waiting, and a request no one could
// be identified for is not logged.
func TestRequestLogNeverBlocks(t *testing.T) {
	log := &RequestLog{queue: make(chan requestRecord, 1)}
	org := uuid.New()
	for i := 0; i < 3; i++ {
		tr := &RequestTrace{id: uuid.New(), start: time.Now(), ingress: IngressAgent, org: org, subjectKind: "agent"}
		log.record(tr, 200)
	}
	if log.Dropped() != 2 || len(log.queue) != 1 {
		t.Fatalf("dropped %d, queued %d", log.Dropped(), len(log.queue))
	}
	<-log.queue
	log.record(&RequestTrace{id: uuid.New(), start: time.Now(), ingress: IngressAgent, refusal: "ai_unauthorized"}, 401)
	if len(log.queue) != 0 {
		t.Fatal("an unattributed refusal was logged")
	}
	var nilLog *RequestLog
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	gotW, gotR, trace, finish := nilLog.Begin(w, r, IngressAgent, "")
	finish()
	if gotW != w || gotR != r || trace != nil {
		t.Fatal("a missing log changed the request")
	}
}

func TestEngineRequestLogEntryWire(t *testing.T) {
	id := uuid.NewString()
	engine, _ := newEngineFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/logs/"+id {
			writeEngineJSON(w, map[string]any{"id": id, "status": "success", "cost": 0.002, "token_usage": map[string]any{"prompt_tokens": 11, "completion_tokens": 3}, "input_history": []any{"ignored"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	entry, found, err := engine.RequestLogEntry(context.Background(), id)
	if err != nil || !found || entry.Status != "success" || *entry.Cost != 0.002 || *entry.PromptTokens != 11 || *entry.CompletionTokens != 3 {
		t.Fatalf("entry: %+v %v %v", entry, found, err)
	}
	if _, found, err := engine.RequestLogEntry(context.Background(), uuid.NewString()); found || err != nil {
		t.Fatalf("missing entry: %v %v", found, err)
	}
	if _, _, err := engine.RequestLogEntry(context.Background(), "../governance/virtual-keys"); err == nil {
		t.Fatal("a non-uuid id reached the engine")
	}
}
