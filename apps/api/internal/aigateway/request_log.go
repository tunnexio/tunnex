package aigateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AI-READY-1 per-request log. Metadata only: time, organization, subject,
// group, model, mode, ingress, status, refusal code, latency, tokens, cost and
// request id. Never prompts, completions, bodies, headers, keys or tokens.
//
// The inference entry points start a trace in the request context. Every
// authorize callback receives a context derived from it, so the trace sees
// the grant or the internal refusal code without changing the adapter. Tokens
// and cost come later from the engine's own log entry, whose ID is the trace
// ID (sent upstream as X-Request-Id by the adapter's wrapped transport).
// Writes go through a bounded queue and never delay or fail inference.

const (
	requestLogQueue         = 4096
	requestLogBatch         = 200
	RequestLogRetentionTick = 15 * time.Minute
	RequestLogEnrichTick    = 5 * time.Second
	requestLogEnrichDelay   = 3 * time.Second
	requestLogEnrichGiveUp  = time.Hour
	requestLogDeleteBatch   = 5000
	requestLogMaxBatches    = 40
)

// Ingress paths recorded in the log.
const (
	IngressPublic   = "public"
	IngressVPN      = "vpn"
	IngressAgent    = "agent"
	IngressWorkload = "workload"
	IngressInternal = "internal" // a workload static key through a gateway's internal endpoint
)

type requestTraceKey struct{}

// RequestTrace is the per-request recorder. Only its own fields are kept;
// nothing from the request or response body is ever copied into it.
type RequestTrace struct {
	mu          sync.Mutex
	id          uuid.UUID
	start       time.Time
	ingress     string
	requestID   string
	mode        ModelMode
	org         uuid.UUID
	subjectKind string
	subjectID   uuid.UUID
	groupKind   string
	groupID     uuid.UUID
	instance    uuid.UUID
	model       string
	refusal     string
	authorized  bool
	status      int
}

func traceFrom(ctx context.Context) *RequestTrace {
	t, _ := ctx.Value(requestTraceKey{}).(*RequestTrace)
	return t
}

// SetSubject records an identity the entry point already established (the
// signed-in user and organization), so a refusal is still attributed.
func (t *RequestTrace) SetSubject(org uuid.UUID, kind string, id uuid.UUID) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.org, t.subjectKind, t.subjectID = org, kind, id
}

// SetOrganization records the organization only (VPN: the gateway's).
func (t *RequestTrace) SetOrganization(org uuid.UUID, kind string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.org, t.subjectKind = org, kind
}

// noteRequestGroup records the group that admitted a request (resolvers).
func noteRequestGroup(ctx context.Context, kind string, id uuid.UUID) {
	t := traceFrom(ctx)
	if t == nil || id == uuid.Nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.groupKind, t.groupID = kind, id
}

var refusalCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// TraceAuthorize records the model, the grant's subject or the internal
// refusal code. The client still sees only the adapter's static error.
func TraceAuthorize(next Authorize) Authorize {
	if next == nil {
		return nil
	}
	return func(ctx context.Context, token, model string) (Grant, error) {
		g, err := next(ctx, token, model)
		t := traceFrom(ctx)
		if t == nil {
			return g, err
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		if engineModel.MatchString(model) {
			t.model = model
		}
		if err != nil {
			code := "ai_refused"
			var domain *apierr.Error
			if errors.As(err, &domain) && refusalCode.MatchString(domain.Code) {
				code = domain.Code
			}
			t.refusal = code
			return g, err
		}
		if org, e := uuid.Parse(g.Tenant); e == nil {
			t.org = org
		}
		kind := g.SubjectKind
		if kind == "" {
			kind = "agent"
		}
		t.subjectKind = kind
		if id, e := uuid.Parse(g.Agent); e == nil {
			t.subjectID = id
		}
		if id, e := uuid.Parse(g.Instance); e == nil {
			t.instance = id
		}
		if g.Mode != "" {
			t.mode = g.Mode
		}
		t.authorized = true
		return g, err
	}
}

// traceTransport sends the trace ID as the engine's request ID. The adapter
// never forwards client headers, so a caller cannot choose it.
type traceTransport struct{ next http.RoundTripper }

func (tt traceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t := traceFrom(r.Context()); t != nil {
		r = r.Clone(r.Context())
		r.Header.Set("X-Request-Id", t.id.String())
	}
	return tt.next.RoundTrip(r)
}

// ConfigureRequestLog attaches the request log and wraps the upstream
// transport so each forwarded request carries its trace ID. Call before
// serving.
func (a *Adapter) ConfigureRequestLog(log *RequestLog) {
	if a == nil || log == nil || a.client == nil {
		return
	}
	next := a.client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	a.client.Transport = traceTransport{next: next}
	adapterLogs.Store(a, log)
}

// adapterLogs keeps the log beside each adapter without changing its type.
var adapterLogs sync.Map

// RequestLog returns the attached log, or nil.
func (a *Adapter) RequestLog() *RequestLog {
	if a == nil {
		return nil
	}
	if v, ok := adapterLogs.Load(a); ok {
		return v.(*RequestLog)
	}
	return nil
}

// statusWriter records the status code only; body writes go straight to the
// embedded writer, so this wrapper never handles response bytes. A response
// written without WriteHeader is 200 (status 0 is read as 200 at finish).
// Unwrap keeps ResponseController (deadlines, flush) working through it.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Begin starts a trace for one inference request. Call the returned finish
// in a defer; it also records an aborted stream before re-panicking. With a
// nil log it returns the request unchanged and a no-op finish.
func (l *RequestLog) Begin(w http.ResponseWriter, r *http.Request, ingress, requestID string) (http.ResponseWriter, *http.Request, *RequestTrace, func()) {
	// Video jobs have their own handler and engine calls; they are not logged.
	if l == nil || r.URL.Path == "/v1/videos" || strings.HasPrefix(r.URL.Path, "/v1/videos/") {
		return w, r, nil, func() {}
	}
	mode, _ := InferencePathMode(r.URL.Path)
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	t := &RequestTrace{id: uuid.New(), start: time.Now(), ingress: ingress, requestID: requestID, mode: mode}
	sw := &statusWriter{ResponseWriter: w}
	r = r.WithContext(context.WithValue(r.Context(), requestTraceKey{}, t))
	return sw, r, t, func() {
		recovered := recover()
		status := sw.status
		if recovered != nil && status < 300 {
			status = http.StatusBadGateway // the stream was aborted after headers
		}
		if status == 0 {
			status = http.StatusOK
		}
		l.record(t, status)
		if recovered != nil {
			panic(recovered)
		}
	}
}

type requestRecord struct {
	id, org                    uuid.UUID
	occurred                   time.Time
	subjectKind                string
	subjectID, group, instance uuid.UUID
	groupKind                  string
	model, mode, ingress       string
	status                     int
	outcome, refusal           string
	latencyMS                  int64
	costState, requestID       string
}

// RequestLog is the bounded asynchronous writer. One per API process.
type RequestLog struct {
	pool     *pgxpool.Pool
	engine   func() RequestLogEngine
	queue    chan requestRecord
	dropped  atomic.Int64
	reported atomic.Int64
	logger   *slog.Logger
}

// RequestLogEngine reads one engine log entry by its request ID.
type RequestLogEngine interface {
	RequestLogEntry(ctx context.Context, id string) (EngineRequestLog, bool, error)
}

func NewRequestLog(pool *pgxpool.Pool, policies *Policies, logger *slog.Logger) *RequestLog {
	l := &RequestLog{pool: pool, queue: make(chan requestRecord, requestLogQueue), logger: logger}
	l.engine = func() RequestLogEngine {
		if policies == nil {
			return nil
		}
		e, _ := policies.engine.(RequestLogEngine)
		return e
	}
	return l
}

// Dropped is the number of records dropped because the queue was full.
func (l *RequestLog) Dropped() int64 {
	if l == nil {
		return 0
	}
	return l.dropped.Load()
}

func (l *RequestLog) record(t *RequestTrace, status int) {
	if l == nil || t == nil {
		return
	}
	t.mu.Lock()
	rec := requestRecord{id: t.id, org: t.org, occurred: t.start.UTC(), subjectKind: t.subjectKind, subjectID: t.subjectID, groupKind: t.groupKind, group: t.groupID, instance: t.instance, model: t.model, mode: string(DefaultModelMode(t.mode)), ingress: t.ingress, status: status, refusal: t.refusal, latencyMS: time.Since(t.start).Milliseconds(), requestID: t.requestID}
	authorized := t.authorized
	t.mu.Unlock()
	// No organization means the request was refused before anyone could be
	// identified (missing or invalid bearer): nothing to attribute it to.
	if rec.org == uuid.Nil || rec.subjectKind == "" {
		return
	}
	if rec.model == "" {
		rec.model = "unknown"
	}
	switch {
	case status >= 200 && status < 300:
		rec.outcome = "ok"
	case rec.refusal != "" || status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests:
		rec.outcome = "refused"
	default:
		rec.outcome = "error"
	}
	rec.costState = "not_applicable"
	if authorized {
		rec.costState = "pending"
	}
	select {
	case l.queue <- rec:
	default:
		l.dropped.Add(1)
	}
}

// Run writes queued records in batches until ctx ends. Each API process runs
// one writer.
func (l *RequestLog) Run(ctx context.Context) {
	if l == nil {
		return
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batch := make([]requestRecord, 0, requestLogBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := l.insert(wctx, batch); err != nil && l.logger != nil {
			l.logger.Warn("ai_request_log_write_failed", slog.Int("rows", len(batch)))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case rec := <-l.queue:
			batch = append(batch, rec)
			if len(batch) >= requestLogBatch {
				flush()
			}
		case <-tick.C:
			flush()
			if d := l.dropped.Load(); d != l.reported.Load() && l.logger != nil {
				l.reported.Store(d)
				l.logger.Warn("ai_request_log_dropped", slog.Int64("total", d))
			}
		}
	}
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
func nullText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (l *RequestLog) insert(ctx context.Context, batch []requestRecord) error {
	b := &pgx.Batch{}
	for _, r := range batch {
		latency := r.latencyMS
		if latency > 1<<31-1 {
			latency = 1<<31 - 1
		}
		b.Queue(`INSERT INTO ai_request_log(id,org_id,occurred_at,subject_kind,subject_id,group_kind,group_id,instance_id,model,mode,ingress,status_code,outcome,refusal_code,latency_ms,cost_state,request_id)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17 WHERE EXISTS (SELECT 1 FROM organizations WHERE id=$2) ON CONFLICT (id) DO NOTHING`,
			r.id, r.org, r.occurred, r.subjectKind, nullUUID(r.subjectID), nullText(r.groupKind), nullUUID(r.group), nullUUID(r.instance), truncate(r.model, 512), r.mode, r.ingress, r.status, r.outcome, nullText(r.refusal), latency, r.costState, nullText(r.requestID))
	}
	return l.pool.SendBatch(ctx, b).Close()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// EngineRequestLog is the part of one engine log entry the request log keeps.
type EngineRequestLog struct {
	Status                         string
	PromptTokens, CompletionTokens *int64
	Cost                           *float64
}

// RequestLogEntry reads one engine log entry. Only status, token counts and
// cost are decoded; nothing else in the entry is retained.
func (e *Engine) RequestLogEntry(ctx context.Context, id string) (EngineRequestLog, bool, error) {
	if _, err := uuid.Parse(id); err != nil {
		return EngineRequestLog{}, false, errEngineScope
	}
	var raw struct {
		ID     string   `json:"id"`
		Status string   `json:"status"`
		Cost   *float64 `json:"cost"`
		Usage  *struct {
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
		} `json:"token_usage"`
	}
	status, err := e.request(ctx, http.MethodGet, "/api/logs/"+id, nil, nil, &raw)
	if status == http.StatusNotFound {
		return EngineRequestLog{}, false, nil
	}
	if err != nil || raw.ID != id {
		return EngineRequestLog{}, false, errEngine
	}
	out := EngineRequestLog{Status: raw.Status}
	if raw.Cost != nil && validEngineCost(*raw.Cost) {
		out.Cost = raw.Cost
	}
	if raw.Usage != nil {
		if raw.Usage.PromptTokens != nil && *raw.Usage.PromptTokens >= 0 {
			out.PromptTokens = raw.Usage.PromptTokens
		}
		if raw.Usage.CompletionTokens != nil && *raw.Usage.CompletionTokens >= 0 {
			out.CompletionTokens = raw.Usage.CompletionTokens
		}
	}
	return out, true, nil
}

// Enrich fills tokens and cost for pending rows from the engine's log. Rows
// the engine never logged become unavailable after an hour. Leader only.
func (l *RequestLog) Enrich(ctx context.Context) (int, error) {
	if l == nil || l.pool == nil {
		return 0, nil
	}
	engine := l.engine()
	if engine == nil {
		return 0, nil
	}
	rows, err := l.pool.Query(ctx, `SELECT id,occurred_at FROM ai_request_log WHERE cost_state='pending' AND occurred_at < now() - $1::interval ORDER BY occurred_at LIMIT $2`, requestLogEnrichDelay.String(), requestLogBatch)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id uuid.UUID
		at time.Time
	}
	var list []pending
	for rows.Next() {
		var p pending
		if rows.Scan(&p.id, &p.at) != nil {
			rows.Close()
			return 0, errEngine
		}
		list = append(list, p)
	}
	rows.Close()
	done := atomic.Int64{}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, p := range list {
		sem <- struct{}{}
		wg.Add(1)
		go func(p pending) {
			defer func() { <-sem; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			entry, found, err := engine.RequestLogEntry(cctx, p.id.String())
			if err != nil {
				return
			}
			if !found || entry.Status == "processing" {
				if time.Since(p.at) > requestLogEnrichGiveUp {
					if _, err := l.pool.Exec(ctx, `UPDATE ai_request_log SET cost_state='unavailable' WHERE id=$1 AND cost_state='pending'`, p.id); err == nil {
						done.Add(1)
					}
				}
				return
			}
			state := "uncosted"
			if entry.Cost != nil {
				state = "costed"
			}
			if _, err := l.pool.Exec(ctx, `UPDATE ai_request_log SET cost_state=$2,cost_usd=$3,prompt_tokens=$4,completion_tokens=$5 WHERE id=$1 AND cost_state='pending'`, p.id, state, entry.Cost, entry.PromptTokens, entry.CompletionTokens); err == nil {
				done.Add(1)
			}
		}(p)
	}
	wg.Wait()
	return int(done.Load()), nil
}

// Prune deletes rows older than each organization's retention (default 30
// days), in bounded batches. Leader only.
func (l *RequestLog) Prune(ctx context.Context) (int64, bool, error) {
	if l == nil || l.pool == nil {
		return 0, false, nil
	}
	rows, err := l.pool.Query(ctx, `SELECT o.id,COALESCE(s.request_log_retention_days,$1) FROM organizations o LEFT JOIN ai_gateway_cost_settings s ON s.org_id=o.id WHERE EXISTS (SELECT 1 FROM ai_request_log l WHERE l.org_id=o.id)`, DefaultRequestLogRetention)
	if err != nil {
		return 0, false, err
	}
	type org struct {
		id   uuid.UUID
		days int
	}
	var orgs []org
	for rows.Next() {
		var o org
		if rows.Scan(&o.id, &o.days) != nil {
			rows.Close()
			return 0, false, errEngine
		}
		orgs = append(orgs, o)
	}
	rows.Close()
	var deleted int64
	more := false
	for _, o := range orgs {
		cutoff := time.Now().UTC().Add(-time.Duration(o.days) * 24 * time.Hour)
		for batch := 0; ; batch++ {
			if batch == requestLogMaxBatches {
				more = true
				break
			}
			tag, err := l.pool.Exec(ctx, `DELETE FROM ai_request_log WHERE id IN (SELECT id FROM ai_request_log WHERE org_id=$1 AND occurred_at < $2 LIMIT $3 FOR UPDATE SKIP LOCKED)`, o.id, cutoff, requestLogDeleteBatch)
			if err != nil {
				return deleted, more, err
			}
			deleted += tag.RowsAffected()
			if tag.RowsAffected() < requestLogDeleteBatch {
				break
			}
		}
	}
	return deleted, more, nil
}

// RequestLogFilter narrows a page. Zero values keep everything.
type RequestLogFilter struct {
	From, To    *time.Time
	SubjectKind string
	SubjectID   *uuid.UUID
	Model       string
	Outcome     string
}

type RequestLogEntry struct {
	ID               uuid.UUID
	OccurredAt       time.Time
	SubjectKind      string
	SubjectID        *uuid.UUID
	SubjectName      string
	GroupKind        *string
	GroupID          *uuid.UUID
	GroupName        string
	InstanceID       *uuid.UUID
	Model, Mode      string
	Ingress          string
	StatusCode       int
	Outcome          string
	RefusalCode      *string
	LatencyMS        int
	PromptTokens     *int64
	CompletionTokens *int64
	CostUSD          *float64
	CostState        string
	RequestID        *string
}

var ErrRequestLogCursor = apierr.BadRequest("invalid_cursor", "invalid request log cursor")

func encodeRequestCursor(at time.Time, id uuid.UUID) string {
	raw, _ := json.Marshal([]string{at.UTC().Format(time.RFC3339Nano), id.String()})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func decodeRequestCursor(s string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	var parts []string
	if err != nil || len(raw) > 200 || json.Unmarshal(raw, &parts) != nil || len(parts) != 2 {
		return time.Time{}, uuid.Nil, ErrRequestLogCursor
	}
	at, err1 := time.Parse(time.RFC3339Nano, parts[0])
	id, err2 := uuid.Parse(parts[1])
	if err1 != nil || err2 != nil {
		return time.Time{}, uuid.Nil, ErrRequestLogCursor
	}
	return at, id, nil
}

// ListRequests returns one page, newest first, and the next cursor ("" at
// the end). Names are resolved at read time.
func (s *Policies) ListRequests(ctx context.Context, org uuid.UUID, f RequestLogFilter, limit int, cursor string) ([]RequestLogEntry, string, error) {
	if s == nil || s.pool == nil {
		return nil, "", aiUnavailable()
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	switch f.SubjectKind {
	case "", "user", "agent", "workload", "workload_key":
	default:
		return nil, "", apierr.BadRequest("invalid_filter", "subject_kind must be user, agent, workload or workload_key")
	}
	switch f.Outcome {
	case "", "ok", "refused", "error":
	default:
		return nil, "", apierr.BadRequest("invalid_filter", "outcome must be ok, refused or error")
	}
	if len(f.Model) > 512 || strings.ContainsAny(f.Model, "\r\n") {
		return nil, "", apierr.BadRequest("invalid_filter", "invalid model")
	}
	var beforeAt *time.Time
	var beforeID *uuid.UUID
	if cursor != "" {
		at, id, err := decodeRequestCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		beforeAt, beforeID = &at, &id
	}
	rows, err := s.pool.Query(ctx, `SELECT l.id,l.occurred_at,l.subject_kind,l.subject_id,
 COALESCE(CASE l.subject_kind WHEN 'user' THEN COALESCE(NULLIF(u.name,''),u.email) WHEN 'agent' THEN d.name WHEN 'workload' THEN w.name WHEN 'workload_key' THEN sk.name END,''),
 l.group_kind,l.group_id,COALESCE(CASE l.group_kind WHEN 'user_group' THEN ug.name WHEN 'agent_group' THEN ag.name END,''),
 l.instance_id,l.model,l.mode,l.ingress,l.status_code,l.outcome,l.refusal_code,l.latency_ms,l.prompt_tokens,l.completion_tokens,l.cost_usd,l.cost_state,l.request_id
 FROM ai_request_log l
 LEFT JOIN users u ON l.subject_kind='user' AND u.id=l.subject_id
 LEFT JOIN devices d ON l.subject_kind='agent' AND d.org_id=l.org_id AND d.id=l.subject_id
 LEFT JOIN ai_workloads w ON l.subject_kind='workload' AND w.org_id=l.org_id AND w.id=l.subject_id
 LEFT JOIN ai_workload_static_keys sk ON l.subject_kind='workload_key' AND sk.org_id=l.org_id AND sk.id=l.subject_id
 LEFT JOIN user_groups ug ON l.group_kind='user_group' AND ug.org_id=l.org_id AND ug.id=l.group_id
 LEFT JOIN agent_groups ag ON l.group_kind='agent_group' AND ag.org_id=l.org_id AND ag.id=l.group_id
 WHERE l.org_id=$1 AND ($2::timestamptz IS NULL OR l.occurred_at >= $2) AND ($3::timestamptz IS NULL OR l.occurred_at < $3)
 AND ($4::text = '' OR l.subject_kind=$4) AND ($5::uuid IS NULL OR l.subject_id=$5 OR l.group_id=$5) AND ($6::text = '' OR l.model=$6) AND ($7::text = '' OR l.outcome=$7)
 AND ($8::timestamptz IS NULL OR (l.occurred_at,l.id) < ($8,$9::uuid))
 ORDER BY l.occurred_at DESC,l.id DESC LIMIT $10`, org, f.From, f.To, f.SubjectKind, f.SubjectID, f.Model, f.Outcome, beforeAt, beforeID, limit+1)
	if err != nil {
		return nil, "", aiUnavailable()
	}
	defer rows.Close()
	out := []RequestLogEntry{}
	for rows.Next() {
		var e RequestLogEntry
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.SubjectKind, &e.SubjectID, &e.SubjectName, &e.GroupKind, &e.GroupID, &e.GroupName, &e.InstanceID, &e.Model, &e.Mode, &e.Ingress, &e.StatusCode, &e.Outcome, &e.RefusalCode, &e.LatencyMS, &e.PromptTokens, &e.CompletionTokens, &e.CostUSD, &e.CostState, &e.RequestID); err != nil {
			return nil, "", aiUnavailable()
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, "", aiUnavailable()
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeRequestCursor(last.OccurredAt, last.ID)
	}
	return out, next, nil
}
