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
}

type Authorize func(context.Context, string, string) (Grant, error)

// Adapter admission limits apply to this process: four active requests per
// tenant/agent and 64 total. The supported deployment is one adapter instance;
// these limits are not shared quota reservations across replicas.
type Adapter struct {
	upstream       string
	authorize      Authorize
	client         *http.Client
	requestTimeout time.Duration
	admission      chan struct{}
	mu             sync.Mutex
	active         map[string]int
	video          http.Handler
}

func NewAdapter(upstream string, authorize Authorize) (*Adapter, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || authorize == nil {
		return nil, errors.New("invalid adapter configuration")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ((ip != nil && ip.IsLoopback()) || u.Hostname() == "bifrost")) {
		return nil, errors.New("upstream requires TLS or an approved private destination")
	}
	return &Adapter{upstream: strings.TrimSuffix(upstream, "/"), authorize: authorize, requestTimeout: 30 * time.Second, admission: make(chan struct{}, 64), active: map[string]int{}, client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Deliberately do not inherit HTTP_PROXY for scoped credentials.
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			MaxResponseHeaderBytes: 32 << 10, IdleConnTimeout: 30 * time.Second,
			MaxConnsPerHost: 64, MaxIdleConnsPerHost: 8,
		},
	}}, nil
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
	deadline := time.Now().Add(a.requestTimeout)
	rc := http.NewResponseController(w)
	// A hosting middleware must preserve ResponseController support (Unwrap).
	// Refuse unsupported writers rather than silently dropping socket bounds.
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		writeAdapterError(w, r, http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
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
	bodyLimit := int64(MaxBodyBytes)
	if mode == ModeAudioTranscription {
		bodyLimit = MaxAudioBytes + (64 << 10)
	}
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	var body []byte
	var model string
	var err error
	contentType := "application/json"
	if mode == ModeAudioTranscription {
		body, model, contentType, err = normalizedTranscription(r)
	} else {
		body, err = io.ReadAll(r.Body)
		if err == nil {
			if mode == ModeChat {
				model, err = requestModelForPath(body, r.URL.Path)
				if err == nil {
					var payload map[string]json.RawMessage
					err = json.Unmarshal(body, &payload)
					if err == nil {
						if _, ok := payload["max_tokens"]; !ok {
							payload["max_tokens"] = json.RawMessage("1024")
						}
						body, err = json.Marshal(payload)
					}
				}
			} else {
				body, model, err = normalizedModeJSON(body, mode)
			}
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
	grant, err := authorize(ctx, token, model)
	if err != nil {
		status := http.StatusForbidden
		var domain *apierr.Error
		if errors.As(err, &domain) {
			switch domain.Status {
			case http.StatusUnauthorized:
				status = http.StatusUnauthorized
			case http.StatusServiceUnavailable:
				status = http.StatusServiceUnavailable
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
	key := grant.Tenant + "/" + grant.SubjectKind + "/" + grant.Agent
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
	// Bound the active request by its authorization lease as well.
	ctx, expire := context.WithDeadline(ctx, grant.Expires)
	defer expire()
	if grant.Expires.Before(deadline) && rc.SetWriteDeadline(grant.Expires) != nil {
		writeAdapterError(w, r, 500)
		return
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
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		writeAdapterError(w, r, 502)
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
		responseLimit = 2 << 20
	}
	if ct != "text/event-stream" {
		data, err := io.ReadAll(io.LimitReader(res.Body, responseLimit+1))
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
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(res.StatusCode)
	buf := make([]byte, 8<<10)
	var delivered int64
	for {
		n, readErr := res.Body.Read(buf)
		if n > 0 {
			delivered += int64(n)
			if delivered > responseLimit {
				panic(http.ErrAbortHandler)
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

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

// Inference supports only the qualified text/streaming payload. Unknown
// fields are refused so provider keys, fallbacks or engine-specific overrides
// cannot create a second route around the selected model. Broader SDK payloads
// need their own compatibility qualification before they are accepted.
func requestModel(body []byte) (string, error) {
	return requestModelForPath(body, "/v1/chat/completions")
}

func requestModelForPath(body []byte, path string) (string, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return "", errors.New("object required")
	}
	seen := map[string]bool{}
	model := ""
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return "", err
		}
		key, ok := t.(string)
		if !ok || seen[key] {
			return "", errors.New("duplicate field")
		}
		seen[key] = true
		switch key {
		case "model", "messages", "stream", "max_tokens", "temperature", "system":
		default:
			return "", errors.New("unsupported field")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return "", err
		}
		if key == "model" {
			if err := json.Unmarshal(raw, &model); err != nil {
				return "", err
			}
		}
		switch key {
		case "max_tokens":
			var n int
			if json.Unmarshal(raw, &n) != nil || n < 1 || n > 4096 {
				return "", errors.New("invalid output limit")
			}
		case "stream":
			var b bool
			if json.Unmarshal(raw, &b) != nil || string(raw) == "null" {
				return "", errors.New("invalid stream")
			}
		case "temperature":
			var n float64
			if json.Unmarshal(raw, &n) != nil || string(raw) == "null" || n < 0 || n > 2 {
				return "", errors.New("invalid temperature")
			}
		case "system":
			var s string
			if json.Unmarshal(raw, &s) != nil || string(raw) == "null" || len(s) > 65536 {
				return "", errors.New("invalid system")
			}
		case "messages":
			var messages []json.RawMessage
			if json.Unmarshal(raw, &messages) != nil || len(messages) < 1 || len(messages) > 128 {
				return "", errors.New("invalid messages")
			}
			for _, message := range messages {
				if err := validateTextMessage(message, path); err != nil {
					return "", err
				}
			}
		}
	}
	if _, err := d.Token(); err != nil {
		return "", err
	}
	if _, err := d.Token(); err != io.EOF {
		return "", errors.New("trailing data")
	}
	if model == "" || len(model) > 256 || !seen["messages"] {
		return "", errors.New("model required")
	}
	return model, nil
}

// Validate before authorization so unqualified modalities and nested routing
// controls cannot reach either cost admission or the upstream engine. Decode
// fields individually to refuse duplicate keys rather than silently overwrite.
func validateTextMessage(raw json.RawMessage, path string) error {
	invalid := errors.New("invalid text message")
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return invalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return invalid
		}
		key, ok := token.(string)
		if !ok || seen[key] || (key != "role" && key != "content") {
			return invalid
		}
		seen[key] = true
		// Token preserves the distinction between JSON null and an empty string.
		token, err = d.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return invalid
		}
		if key == "role" {
			switch value {
			case "user", "assistant":
			case "system":
				if path == "/anthropic/v1/messages" {
					return invalid
				}
			default:
				return invalid
			}
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid
	}
	if !seen["role"] || !seen["content"] {
		return invalid
	}
	return nil
}
