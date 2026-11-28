// Package aigateway authenticates scoped AI access and forwards bounded inference
// requests to the private execution engine.
package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const MaxBodyBytes = 256 << 10

// Grant comes only from a trusted identity/policy resolver. The resolver must
// check current enrollment, tenant, audience, expiry and model authorization.
// No caller-supplied headers establish identity or upstream authorization.
type Grant struct {
	Tenant, Agent, VirtualKey string
	SubjectKind               string // empty = agent; user = human; workload = independent application
	Instance                  string // registered workload replica; never the policy or billing owner
	Mode                      ModelMode
	Expires                   time.Time
	// Renew, when set by a trusted resolver, re-checks the same subject's live
	// identity and model grant and returns a fresh lease for an in-flight
	// request. It never repeats per-request cost admission. Nil means the
	// request ends when this lease ends.
	Renew func(context.Context) (Grant, error)
}

type Authorize func(context.Context, string, string) (Grant, error)

// Adapter admission: a process-wide in-memory bound (MaxConcurrent) and
// per-organization and per-subject limits held as leases in a store shared by
// every replica (Redis in the server; in-process when none is configured).
type Adapter struct {
	upstream  string
	authorize Authorize
	client    *http.Client
	limits    AdapterLimits
	admission chan struct{}
	leases    ConcurrencyLeases
	// Video jobs keep their own short bounds and per-subject count.
	mu     sync.Mutex
	active map[string]int
	video  http.Handler
}

const videoRequestTimeout = 30 * time.Second

func NewAdapter(upstream string, authorize Authorize) (*Adapter, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || authorize == nil {
		return nil, errors.New("invalid adapter configuration")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ((ip != nil && ip.IsLoopback()) || u.Hostname() == "bifrost")) {
		return nil, errors.New("upstream requires TLS or an approved private destination")
	}
	a := &Adapter{upstream: strings.TrimSuffix(upstream, "/"), authorize: authorize, active: map[string]int{}, leases: newMemoryLeases(), client: &http.Client{
		// No total client timeout: streams are bounded by the request deadline,
		// the authorization lease and the idle timeout instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Deliberately do not inherit HTTP_PROXY for scoped credentials.
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second,
			// Non-streaming providers send headers only after generation completes.
			MaxResponseHeaderBytes: 32 << 10, IdleConnTimeout: 30 * time.Second,
		},
	}}
	if err := a.ConfigureLimits(DefaultAdapterLimits()); err != nil {
		return nil, err
	}
	return a, nil
}

// ConfigureLimits applies administrator limits. Call it before serving.
func (a *Adapter) ConfigureLimits(l AdapterLimits) error {
	if !l.valid() {
		return errors.New("invalid adapter limits")
	}
	a.limits = l
	a.admission = make(chan struct{}, l.MaxConcurrent)
	t := a.client.Transport.(*http.Transport)
	t.ResponseHeaderTimeout = l.RequestTimeout
	if l.StreamTimeout > l.RequestTimeout {
		t.ResponseHeaderTimeout = l.StreamTimeout
	}
	t.MaxConnsPerHost = l.MaxConcurrent
	t.MaxIdleConnsPerHost = min(l.MaxConcurrent, 32)
	return nil
}

// ConfigureSharedLeases makes the per-organization and per-subject limits
// hold across API replicas.
func (a *Adapter) ConfigureSharedLeases(leases ConcurrencyLeases) {
	if leases != nil {
		a.leases = leases
	}
}

func (a *Adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.serve(w, r, nil) }

// ServeAuthorized accepts an authorizer from the authenticated HTTP composition only.
// It does not read an alternate identity or credential from client headers.
func (a *Adapter) ServeAuthorized(w http.ResponseWriter, r *http.Request, authorize Authorize) {
	if authorize == nil {
		writeAdapterError(w, r, 401)
		return
	}
	a.serve(w, r, authorize)
}

// requestGuard ends an in-flight request immediately: the upstream context is
// cancelled and both socket deadlines move to now, so a blocked downstream
// write is released as well.
type requestGuard struct {
	cancel  context.CancelFunc
	rc      *http.ResponseController
	mu      sync.Mutex
	aborted bool
	limit   time.Time // the request deadline; lease extensions never pass it
}

func (g *requestGuard) abort() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.aborted {
		return
	}
	g.aborted = true
	g.cancel()
	now := time.Now()
	_ = g.rc.SetWriteDeadline(now)
	_ = g.rc.SetReadDeadline(now)
}

func (g *requestGuard) extend(until time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.aborted {
		return
	}
	if until.After(g.limit) {
		until = g.limit
	}
	_ = g.rc.SetWriteDeadline(until)
}

func (g *requestGuard) wasAborted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.aborted
}

func (a *Adapter) serve(w http.ResponseWriter, r *http.Request, authorize Authorize) {
	if r.URL.Path == "/v1/videos" || strings.HasPrefix(r.URL.Path, "/v1/videos/") {
		if a.video != nil {
			if authorize != nil {
				a.video.(*videoHandler).serve(w, r, authorize)
			} else {
				a.video.ServeHTTP(w, r)
			}
		} else {
			writeAdapterError(w, r, 503)
		}
		return
	}
	select {
	case a.admission <- struct{}{}:
		defer func() { <-a.admission }()
	default:
		writeAdapterError(w, r, 429)
		return
	}
	start := time.Now()
	// Until the caller is authorized only a short body-read window is granted,
	// so slow uploads cannot hold admission slots for the request timeout.
	bodyDeadline := start.Add(a.limits.BodyReadTimeout)
	rc := http.NewResponseController(w)
	// A hosting middleware must preserve ResponseController support (Unwrap).
	// Refuse unsupported writers rather than silently dropping socket bounds.
	if rc.SetReadDeadline(bodyDeadline) != nil || rc.SetWriteDeadline(bodyDeadline) != nil {
		writeAdapterError(w, r, http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	mode, routeOK := InferencePathMode(r.URL.Path)
	if r.Method != http.MethodPost || !routeOK || mode == ModeVideoGeneration {
		writeAdapterError(w, r, http.StatusNotFound)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeAdapterError(w, r, 400)
		return
	}
	auth := r.Header.Values("Authorization")
	if authorize == nil && (len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth[0], "Bearer ")) == "") {
		writeAdapterError(w, r, 401)
		return
	}
	bodyLimit := a.limits.MaxRequestBytes
	if mode == ModeAudioTranscription {
		bodyLimit = MaxAudioBytes + (64 << 10)
	}
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	var body []byte
	var model string
	var stream bool
	var err error
	contentType := "application/json"
	if mode == ModeAudioTranscription {
		body, model, contentType, err = normalizedTranscription(r)
	} else {
		body, err = io.ReadAll(r.Body)
		if err == nil {
			body, model, stream, err = a.normalizeJSON(r.URL.Path, mode, body)
		}
	}
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeAdapterError(w, r, 413)
		} else {
			writeAdapterError(w, r, 400)
		}
		return
	}
	token := ""
	if authorize == nil {
		authorize = a.authorize
		token = strings.TrimPrefix(auth[0], "Bearer ")
	}
	authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
	grant, err := authorize(authCtx, token, model)
	authCancel()
	if err != nil {
		status := http.StatusForbidden
		var domain *apierr.Error
		if errors.Is(err, ErrRequestLimited) {
			// A per-key rate limit (AI-KEYS-1) uses the same fixed 429 body as
			// the concurrency limit; the key page shows which one refused.
			status = http.StatusTooManyRequests
		} else if errors.As(err, &domain) {
			switch {
			case domain.Status == http.StatusUnauthorized:
				status = http.StatusUnauthorized
			case domain.Status == http.StatusServiceUnavailable:
				status = http.StatusServiceUnavailable
			// The caller's own spending state, so they know what to do next. Only these
			// two exact codes; every other refusal stays the generic 403.
			case domain.Status == http.StatusForbidden && domain.Code == "ai_daily_threshold_reached":
				status = statusDailyLimitReached
			case domain.Status == http.StatusForbidden && domain.Code == "ai_price_unavailable":
				status = statusModelPriceUnknown
			}
		}
		// Do not propagate resolver codes, messages, details or wrapped causes:
		// these can carry internal provider or database information.
		writeAdapterError(w, r, status)
		return
	}
	if DefaultModelMode(grant.Mode) != mode || grant.Tenant == "" || grant.Agent == "" || !validKey(grant.VirtualKey) || !time.Now().Before(grant.Expires) {
		writeAdapterError(w, r, 403)
		return
	}
	keys := []string{"ai:cc:org:" + grant.Tenant, "ai:cc:sub:" + grant.Tenant + "/" + grant.SubjectKind + "/" + grant.Agent}
	leaseCtx, leaseCancel := context.WithTimeout(ctx, 5*time.Second)
	lease, admitted, err := a.leases.Acquire(leaseCtx, keys, []int{a.limits.MaxConcurrentPerOrg, a.limits.MaxConcurrentPerSubj})
	leaseCancel()
	if err != nil {
		// The shared limiter is unavailable: fail closed.
		writeAdapterError(w, r, 503)
		return
	}
	if !admitted {
		writeAdapterError(w, r, 429)
		return
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.leases.Release(releaseCtx, keys, lease)
		releaseCancel()
	}()
	// Authorized: the socket and context deadlines become the request's own.
	timeout := a.limits.RequestTimeout
	if stream {
		timeout = a.limits.StreamTimeout
	}
	deadline := start.Add(timeout)
	ctx, deadlineCancel := context.WithDeadline(ctx, deadline)
	defer deadlineCancel()
	guard := &requestGuard{cancel: cancel, rc: rc, limit: deadline}
	writeUntil := deadline
	if grant.Expires.Before(writeUntil) {
		writeUntil = grant.Expires
	}
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(writeUntil) != nil {
		writeAdapterError(w, r, 500)
		return
	}
	done := make(chan struct{})
	var watchers sync.WaitGroup
	defer func() { close(done); watchers.Wait() }()
	watchers.Add(1)
	go func() { defer watchers.Done(); a.keepLease(ctx, done, guard, grant, mode) }()
	if every := a.leases.RenewEvery(); every > 0 {
		watchers.Add(1)
		go func() { defer watchers.Done(); a.keepConcurrencyLease(done, guard, keys, lease, every) }()
	}
	up, err := http.NewRequestWithContext(ctx, http.MethodPost, a.upstream+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		writeAdapterError(w, r, 502)
		return
	}
	up.Header.Set("Content-Type", contentType)
	up.Header.Set("Accept", "application/json, text/event-stream")
	if mode == ModeAudioSpeech {
		up.Header.Set("Accept", "audio/*, application/octet-stream")
	}
	up.Header.Set("X-Bf-Vk", grant.VirtualKey)
	if r.URL.Path == "/anthropic/v1/messages" {
		up.Header.Set("Anthropic-Version", "2023-06-01")
	}
	res, err := a.client.Do(up)
	if err != nil {
		writeAdapterError(w, r, 502)
		return
	}
	defer res.Body.Close()
	// No upstream byte for the idle timeout ends the request.
	idle := newIdleReader(res.Body, a.limits.IdleTimeout, guard.abort)
	defer idle.stop()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// Only a bounded prefix of the engine's error is read, to classify it;
		// no provider text reaches the caller.
		head, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
		status := upstreamErrorStatus(res.StatusCode, head)
		if status == statusProviderRateLimited || status == statusProviderUnavailable {
			if after, ok := boundedRetryAfter(res.Header.Get("Retry-After"), time.Now()); ok {
				w.Header().Set("Retry-After", after)
			}
		}
		writeAdapterError(w, r, status)
		return
	}
	ct, _, parseErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if parseErr != nil || !modeResponseAllowed(mode, ct) {
		writeAdapterError(w, r, 502)
		return
	}
	// Non-streaming responses are bounded before headers are committed. No
	// provider headers, cookies, redirects or credentials reach the client.
	responseLimit := int64(MaxMediaResponseBytes)
	if mode != ModeAudioSpeech && mode != ModeImageGeneration {
		responseLimit = a.limits.MaxResponseBytes
	}
	if ct != "text/event-stream" {
		data, err := io.ReadAll(io.LimitReader(idle, responseLimit+1))
		if err != nil || int64(len(data)) > responseLimit || len(data) == 0 || ct == "application/json" && !json.Valid(data) {
			writeAdapterError(w, r, 502)
			return
		}
		if mode == ModeAudioSpeech {
			// Pinned native speech handler labels all binary formats audio/mpeg.
			// Use the validated format passed to the provider for response metadata.
			var speech struct {
				Format string `json:"response_format"`
			}
			_ = json.Unmarshal(body, &speech)
			ct = map[string]string{"": "audio/mpeg", "mp3": "audio/mpeg", "opus": "audio/ogg", "aac": "audio/aac", "flac": "audio/flac", "wav": "audio/wav", "pcm": "audio/pcm"}[speech.Format]
		}
		if ct == "application/json" {
			// Engine diagnostics (internal key names, provider headers) never
			// reach the caller; everything else is passed through byte for byte.
			if data, err = stripEngineMetadata(data); err != nil {
				writeAdapterError(w, r, 502)
				return
			}
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(res.StatusCode)
	// One SSE event at a time, engine metadata removed from each event. The
	// stream cap counts every upstream byte. Any early end other than the
	// upstream's own clean finish aborts the client connection, so a cut stream
	// never looks complete.
	err = copySSEStripped(w, rc.Flush, idle, a.limits.MaxStreamBytes)
	if r.Context().Err() == nil && (err != nil || guard.wasAborted() || ctx.Err() != nil) {
		panic(http.ErrAbortHandler)
	}
}

// keepLease renews the authorization lease of an in-flight request before it
// ends. A failed or changed renewal, or a lease without a renewal function,
// ends the request when the lease does.
func (a *Adapter) keepLease(ctx context.Context, done <-chan struct{}, guard *requestGuard, grant Grant, mode ModelMode) {
	issued, expires := time.Now(), grant.Expires
	for {
		wait := time.Until(expires)
		if grant.Renew != nil {
			wait = time.Until(issued.Add(expires.Sub(issued) * 2 / 3))
		}
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-done:
			timer.Stop()
			return
		case <-timer.C:
		}
		if grant.Renew == nil {
			guard.abort()
			return
		}
		renewCtx, renewCancel := context.WithDeadline(ctx, expires)
		next, err := grant.Renew(renewCtx)
		renewCancel()
		if err != nil || next.Tenant != grant.Tenant || next.Agent != grant.Agent || next.SubjectKind != grant.SubjectKind ||
			next.Instance != grant.Instance || DefaultModelMode(next.Mode) != mode || next.VirtualKey != grant.VirtualKey || !time.Now().Before(next.Expires) {
			select {
			case <-done:
			default:
				guard.abort()
			}
			return
		}
		issued, expires = time.Now(), next.Expires
		guard.extend(expires)
	}
}

// keepConcurrencyLease renews the shared concurrency lease. Transient store
// errors are retried; a lease that is lost, or cannot be renewed within its
// lifetime, ends the request so the shared limit stays true.
func (a *Adapter) keepConcurrencyLease(done <-chan struct{}, guard *requestGuard, keys []string, lease string, every time.Duration) {
	lastOK := time.Now()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), every/2)
		ok, err := a.leases.Renew(ctx, keys, lease)
		cancel()
		switch {
		case err == nil && ok:
			lastOK = time.Now()
		case err == nil && !ok:
			guard.abort()
			return
		case time.Since(lastOK) >= a.leases.TTL():
			guard.abort()
			return
		}
	}
}

// upstreamErrorStatus maps engine failures to static public statuses so the
// caller can tell its own request, the provider and Tunnex apart:
//   - a provider refusal of the request (400/404/413/422) is the caller's 400;
//   - billing or credit refusal (402) is 402;
//   - provider rate limiting (429) is 429;
//   - provider overload or outage (503, 529, or an "overloaded" error type on
//     another 5xx) is 503;
//   - anything else is an engine or transport failure (502).
func upstreamErrorStatus(status int, body []byte) int {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return statusProviderRejected
	case http.StatusPaymentRequired:
		return statusProviderPayment
	case http.StatusTooManyRequests:
		return statusProviderRateLimited
	case http.StatusServiceUnavailable, 529:
		return statusProviderUnavailable
	}
	if status >= 500 && upstreamOverloaded(body) {
		return statusProviderUnavailable
	}
	return http.StatusBadGateway
}

// upstreamOverloaded reports an engine error whose type names provider
// overload (for example the Messages API's overloaded_error).
func upstreamOverloaded(body []byte) bool {
	var e struct {
		Type  string `json:"type"`
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	return strings.Contains(strings.ToLower(e.Error.Type), "overloaded") || strings.Contains(strings.ToLower(e.Type), "overloaded")
}

// boundedRetryAfter passes a provider's Retry-After as whole seconds between
// 1 and 300. A delta or an HTTP date is accepted; anything else is dropped.
func boundedRetryAfter(raw string, now time.Time) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	seconds := 0
	if n, err := strconv.Atoi(raw); err == nil {
		seconds = n
	} else if at, err := http.ParseTime(raw); err == nil {
		seconds = int(at.Sub(now).Round(time.Second) / time.Second)
	} else {
		return "", false
	}
	seconds = max(1, min(seconds, 300))
	return strconv.Itoa(seconds), true
}

// Internal markers for writeAdapterError; never sent as-is.
const (
	statusProviderRejected    = 1400
	statusProviderPayment     = 1402
	statusProviderRateLimited = 1429
	statusProviderUnavailable = 1503
	statusDailyLimitReached   = 2403
	statusModelPriceUnknown   = 2404
)

// idleReader cuts a read side that produces no bytes for the idle timeout.
type idleReader struct {
	r     io.Reader
	d     time.Duration
	timer *time.Timer
}

func newIdleReader(r io.Reader, d time.Duration, onIdle func()) *idleReader {
	return &idleReader{r: r, d: d, timer: time.AfterFunc(d, onIdle)}
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	if n > 0 {
		i.timer.Reset(i.d)
	}
	return n, err
}

func (i *idleReader) stop() { i.timer.Stop() }

// writeAdapterError renders only static, public error descriptions. It is used
// before response streaming starts; never pass resolver or provider errors here.
func writeAdapterError(w http.ResponseWriter, r *http.Request, status int) {
	code, message := "internal_error", "an unexpected error occurred"
	switch status {
	case http.StatusBadRequest:
		code, message = "invalid_request", "invalid inference request"
	case http.StatusUnauthorized:
		code, message = "unauthenticated", "authentication required"
	case http.StatusForbidden:
		code, message = "ai_policy_denied", "AI access is not available under the current policy"
	case http.StatusConflict:
		code, message = "ai_request_conflict", "AI request conflicts with existing work"
	case http.StatusNotFound:
		code, message = "not_found", "inference route not found"
	case http.StatusRequestEntityTooLarge:
		code, message = "request_too_large", "inference request is too large"
	case http.StatusTooManyRequests:
		code, message = "ai_request_limit", "AI request limit reached"
	case http.StatusBadGateway:
		code, message = "ai_engine_unavailable", "AI engine is unavailable"
	case statusProviderRejected:
		status, code, message = http.StatusBadRequest, "ai_provider_rejected", "The AI provider refused this request."
	case statusProviderPayment:
		status, code, message = http.StatusPaymentRequired, "ai_provider_payment_required", "The AI provider refused the request for billing or credit reasons. Check the provider account."
	case statusProviderUnavailable:
		status, code, message = http.StatusServiceUnavailable, "ai_provider_unavailable", "The AI provider is temporarily unavailable. Try again later."
	case statusProviderRateLimited:
		status, code, message = http.StatusTooManyRequests, "ai_provider_rate_limited", "The AI provider is limiting requests. Try again later."
	case statusDailyLimitReached:
		status, code, message = http.StatusForbidden, "ai_daily_threshold_reached", "The daily AI spending limit for this group, workload or key has been reached. It resets at 00:00 UTC."
	case statusModelPriceUnknown:
		status, code, message = http.StatusForbidden, "ai_price_unavailable", "This model has no price and a spending limit applies. Ask an administrator to set the model price."
	case http.StatusServiceUnavailable:
		code, message = "ai_gateway_unavailable", "AI gateway is unavailable"
	default:
		status = http.StatusInternalServerError
	}
	w.Header().Set("Cache-Control", "no-store")
	apierr.Write(w, r, apierr.New(status, code, message))
}

func validKey(key string) bool {
	if key == "" || len(key) > 4096 {
		return false
	}
	for _, c := range key {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
