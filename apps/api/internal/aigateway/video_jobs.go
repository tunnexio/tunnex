package aigateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const videoRetention = 24 * time.Hour

var videoIdempotency = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)
var videoProviderID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.%/-]{0,767}:[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)
var errVideoConflict = errors.New("video idempotency conflict")
var errVideoQuota = errors.New("video job limit")

type videoJob struct {
	ID, Org, Agent           uuid.UUID
	Model, ProviderID, State string
	SubjectKind              string
	Created, Expires         time.Time
}

type videoStore struct{ pool *pgxpool.Pool }

// ConfigureVideoStore is called at startup only, before serving requests.
func (a *Adapter) ConfigureVideoStore(pool *pgxpool.Pool) {
	a.video = NewVideoHandler(a, pool)
}

// NewVideoHandler shares the adapter's admission, scoped resolver and private
// engine transport. It must be dispatched before the ordinary adapter admission.
func NewVideoHandler(a *Adapter, pool *pgxpool.Pool) http.Handler {
	return &videoHandler{adapter: a, store: videoStore{pool: pool}}
}

type videoHandler struct {
	adapter *Adapter
	store   videoStore
}

func scanVideo(row pgx.Row) (videoJob, error) {
	var j videoJob
	err := row.Scan(&j.ID, &j.Org, &j.Agent, &j.SubjectKind, &j.Model, &j.ProviderID, &j.State, &j.Created, &j.Expires)
	return j, err
}

const videoColumns = `id,org_id,coalesce(device_id,user_id,workload_id),CASE WHEN user_id IS NOT NULL THEN 'user' WHEN workload_id IS NOT NULL THEN 'workload' ELSE '' END,model,provider_id,state,created_at,expires_at`

func (s videoStore) reserve(ctx context.Context, g Grant, model, key string, body []byte) (videoJob, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return videoJob{}, false, err
	}
	defer tx.Rollback(ctx)
	// One short database critical section makes the global retained-row cap and
	// scoped idempotency reservation atomic across processes; no network I/O here.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(148,1)`); err != nil {
		return videoJob{}, false, err
	}
	// lint:cross-org bounded expiry maintenance owns only this feature's records.
	if _, err = tx.Exec(ctx, `DELETE FROM ai_video_jobs WHERE id IN (SELECT id FROM ai_video_jobs WHERE expires_at<=now() ORDER BY expires_at LIMIT 128)`); err != nil {
		return videoJob{}, false, err
	}
	hash := sha256.Sum256(body)
	var oldHash []byte
	var j videoJob
	err = tx.QueryRow(ctx, `SELECT `+videoColumns+`,request_hash FROM ai_video_jobs WHERE org_id=$1 AND coalesce(device_id,user_id,workload_id)=$2 AND (CASE WHEN user_id IS NOT NULL THEN 'user' WHEN workload_id IS NOT NULL THEN 'workload' ELSE '' END)=$4 AND idempotency_key=$3`, g.Tenant, g.Agent, key, g.SubjectKind).Scan(&j.ID, &j.Org, &j.Agent, &j.SubjectKind, &j.Model, &j.ProviderID, &j.State, &j.Created, &j.Expires, &oldHash)
	if err == nil {
		if !bytes.Equal(oldHash, hash[:]) || j.Model != model {
			return videoJob{}, false, errVideoConflict
		}
		if !time.Now().Before(j.Expires) {
			return videoJob{}, false, errVideoQuota
		}
		return j, false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return videoJob{}, false, err
	}
	var total, active int
	// lint:cross-org global capacity admission counts this feature's retained rows only.
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_video_jobs`).Scan(&total); err != nil {
		return videoJob{}, false, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_video_jobs WHERE org_id=$1 AND coalesce(device_id,user_id,workload_id)=$2 AND (CASE WHEN user_id IS NOT NULL THEN 'user' WHEN workload_id IS NOT NULL THEN 'workload' ELSE '' END)=$3 AND state IN ('uncertain','queued','in_progress') AND expires_at>now()`, g.Tenant, g.Agent, g.SubjectKind).Scan(&active); err != nil {
		return videoJob{}, false, err
	}
	if total >= 4096 || active >= 64 {
		return videoJob{}, false, errVideoQuota
	}
	var device, user, workload *string
	if g.SubjectKind == "user" {
		user = &g.Agent
	} else if g.SubjectKind == "workload" {
		workload = &g.Agent
	} else if g.SubjectKind == "" {
		device = &g.Agent
	}
	j, err = scanVideo(tx.QueryRow(ctx, `INSERT INTO ai_video_jobs(id,org_id,device_id,model,idempotency_key,request_hash,state,user_id,workload_id) VALUES($1,$2,$3,$4,$5,$6,'uncertain',$7,$8) RETURNING `+videoColumns, uuid.New(), g.Tenant, device, model, key, hash[:], user, workload))
	if err != nil {
		return videoJob{}, false, err
	}
	return j, true, tx.Commit(ctx)
}

func (s videoStore) lookup(ctx context.Context, id uuid.UUID) (videoJob, error) {
	// lint:cross-org opaque UUID lookup supplies only the model to the resolver;
	// no fields or upstream calls are exposed before exact org/device reauthorization.
	return scanVideo(s.pool.QueryRow(ctx, `SELECT `+videoColumns+` FROM ai_video_jobs WHERE id=$1 AND expires_at>now()`, id))
}

func (s videoStore) update(ctx context.Context, j videoJob, providerID, state string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE ai_video_jobs SET provider_id=$4,state=$5 WHERE id=$1 AND org_id=$2 AND coalesce(device_id,user_id,workload_id)=$3 AND (CASE WHEN user_id IS NOT NULL THEN 'user' WHEN workload_id IS NOT NULL THEN 'workload' ELSE '' END)=$6 AND expires_at>now() AND (provider_id='' OR provider_id=$4) AND (state NOT IN ('completed','failed') OR state=$5)`, j.ID, j.Org, j.Agent, providerID, state, j.SubjectKind)
	if err == nil && tag.RowsAffected() != 1 {
		return errors.New("video update refused")
	}
	return err
}

func videoPublic(w http.ResponseWriter, j videoJob) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": j.ID.String(), "object": "video", "model": j.Model, "status": j.State, "created_at": j.Created.Unix(), "expires_at": j.Expires.Unix()})
}

func videoFailure(w http.ResponseWriter, r *http.Request, j videoJob, submitted bool, status int) {
	if submitted {
		// The durable reservation already owns this attempt. Preserve its handle
		// even when the upstream response or final database write is uncertain.
		videoPublic(w, j)
		return
	}
	writeAdapterError(w, r, status)
}

func videoNative(body []byte, model string) (string, string, error) {
	var p struct {
		ID    string `json:"id"`
		State string `json:"status"`
	}
	if json.Unmarshal(body, &p) != nil || !videoProviderID.MatchString(p.ID) {
		return "", "", errors.New("invalid video response")
	}
	raw, provider, _ := strings.Cut(p.ID, ":")
	decoded, decodeErr := url.PathUnescape(raw)
	if decodeErr != nil || strings.ContainsAny(decoded, "%?#\\:") {
		return "", "", errors.New("invalid video id")
	}
	for _, part := range strings.Split(decoded, "/") {
		if part == "" || part == "." || part == ".." {
			return "", "", errors.New("invalid video id")
		}
	}
	want, _, _ := strings.Cut(model, "/")
	if provider != want {
		return "", "", errors.New("video provider mismatch")
	}
	switch p.State {
	case "queued", "in_progress", "completed", "failed":
		return p.ID, p.State, nil
	}
	return "", "", errors.New("invalid video state")
}

func (h *videoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.serve(w, r, nil) }
func (h *videoHandler) serve(w http.ResponseWriter, r *http.Request, authorize Authorize) {
	a := h.adapter
	w.Header().Set("Cache-Control", "no-store")
	if a == nil || h.store.pool == nil {
		writeAdapterError(w, r, 503)
		return
	}
	select {
	case a.admission <- struct{}{}:
		defer func() { <-a.admission }()
	default:
		writeAdapterError(w, r, 429)
		return
	}
	deadline := time.Now().Add(a.requestTimeout)
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		writeAdapterError(w, r, 500)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeAdapterError(w, r, 400)
		return
	}
	headers := r.Header.Values("Authorization")
	if authorize == nil && (len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") || strings.TrimSpace(strings.TrimPrefix(headers[0], "Bearer ")) == "") {
		writeAdapterError(w, r, 401)
		return
	}
	create := r.Method == http.MethodPost && r.URL.Path == "/v1/videos"
	var j videoJob
	var body []byte
	var model string
	var err error
	var content bool
	if create {
		if len(r.Header.Values("Idempotency-Key")) != 1 || !videoIdempotency.MatchString(r.Header.Get("Idempotency-Key")) {
			writeAdapterError(w, r, 400)
			return
		}
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if ct != "application/json" {
			writeAdapterError(w, r, 400)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		body, err = io.ReadAll(r.Body)
		if err == nil {
			body, model, err = normalizedModeJSON(body, ModeVideoGeneration)
		}
		if err != nil {
			writeAdapterError(w, r, 400)
			return
		}
	} else {
		path := strings.TrimPrefix(r.URL.Path, "/v1/videos/")
		content = strings.HasSuffix(path, "/content")
		if content {
			path = strings.TrimSuffix(path, "/content")
		}
		id, parseErr := uuid.Parse(path)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/videos/") || parseErr != nil || id.String() != path {
			writeAdapterError(w, r, 404)
			return
		}
		j, err = h.store.lookup(ctx, id)
		if err != nil {
			writeAdapterError(w, r, 404)
			return
		}
		model = j.Model
	}
	token := ""
	if authorize == nil {
		authorize = a.authorize
		token = strings.TrimPrefix(headers[0], "Bearer ")
	}
	g, err := authorize(ctx, token, model)
	if err != nil || DefaultModelMode(g.Mode) != ModeVideoGeneration || g.Tenant == "" || g.Agent == "" || !validKey(g.VirtualKey) || !time.Now().Before(g.Expires) {
		if create {
			writeAdapterError(w, r, 403)
		} else {
			writeAdapterError(w, r, 404)
		}
		return
	}
	if !create && (g.Tenant != j.Org.String() || g.Agent != j.Agent.String() || g.SubjectKind != j.SubjectKind) {
		writeAdapterError(w, r, 404)
		return
	}
	key := g.Tenant + "/" + g.SubjectKind + "/" + g.Agent
	a.mu.Lock()
	if a.active[key] >= 4 {
		a.mu.Unlock()
		writeAdapterError(w, r, 429)
		return
	}
	a.active[key]++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.active[key]--
		if a.active[key] == 0 {
			delete(a.active, key)
		}
		a.mu.Unlock()
	}()
	lease := g.Expires
	if !create && j.Expires.Before(lease) {
		lease = j.Expires
	}
	ctx, expire := context.WithDeadline(ctx, lease)
	defer expire()
	if lease.Before(deadline) && rc.SetWriteDeadline(lease) != nil {
		writeAdapterError(w, r, 500)
		return
	}
	if create {
		var fresh bool
		j, fresh, err = h.store.reserve(ctx, g, model, r.Header.Get("Idempotency-Key"), body)
		if err != nil {
			status := 503
			if errors.Is(err, errVideoConflict) {
				status = 409
			}
			if errors.Is(err, errVideoQuota) {
				status = 429
			}
			writeAdapterError(w, r, status)
			return
		}
		if !fresh {
			videoPublic(w, j)
			return
		}
	} else if j.ProviderID == "" {
		if content {
			writeAdapterError(w, r, 409)
		} else {
			videoPublic(w, j)
		}
		return
	}
	if content && j.State != "completed" {
		writeAdapterError(w, r, 409)
		return
	}
	path := "/v1/videos"
	method := http.MethodPost
	if !create {
		method = http.MethodGet
		path += "/" + url.PathEscape(j.ProviderID)
		if content {
			path += "/content"
		}
	}
	up, err := http.NewRequestWithContext(ctx, method, a.upstream+path, bytes.NewReader(body))
	if err != nil {
		videoFailure(w, r, j, create, 502)
		return
	}
	up.Header.Set("X-Bf-Vk", g.VirtualKey)
	up.Header.Set("Content-Type", "application/json")
	up.Header.Set("Accept", "application/json")
	if content {
		up.Header.Set("Accept", "video/mp4, video/webm")
	}
	res, err := a.client.Do(up)
	if err != nil {
		if create {
			videoPublic(w, j)
		} else {
			writeAdapterError(w, r, 502)
		}
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if create {
			videoPublic(w, j)
		} else {
			writeAdapterError(w, r, 502)
		}
		return
	}
	ct, _, parseErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	limit := int64(2 << 20)
	if content {
		limit = MaxMediaResponseBytes
	}
	data, readErr := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if parseErr != nil || readErr != nil || int64(len(data)) > limit || len(data) == 0 {
		videoFailure(w, r, j, create, 502)
		return
	}
	if content {
		if ct != "video/mp4" && ct != "video/webm" {
			writeAdapterError(w, r, 502)
			return
		}
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(data)
		return
	}
	if ct != "application/json" {
		videoFailure(w, r, j, create, 502)
		return
	}
	providerID, state, err := videoNative(data, model)
	if err != nil || (!create && providerID != j.ProviderID) {
		videoFailure(w, r, j, create, 502)
		return
	}
	if err = h.store.update(ctx, j, providerID, state); err != nil {
		videoFailure(w, r, j, create, 503)
		return
	}
	j.ProviderID, j.State = providerID, state
	videoPublic(w, j)
}
