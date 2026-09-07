// Package ai0 contains an experimental qualification adapter. It is not wired
// into the control plane and does not define production AI authentication.
package ai0

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxBodyBytes = 256 << 10

// Grant comes only from a trusted identity/policy resolver. The resolver must
// check current enrollment, tenant, audience, expiry and model authorization.
// The qualification tests inject synthetic identities, not CP-issued identity.
type Grant struct {
	Tenant, Agent, VirtualKey string
	Expires                   time.Time
}

type Authorize func(context.Context, string, string) (Grant, error)

type Adapter struct {
	upstream  string
	authorize Authorize
	client    *http.Client
}

func NewAdapter(upstream string, authorize Authorize) (*Adapter, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || authorize == nil {
		return nil, errors.New("invalid adapter configuration")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("upstream requires TLS or loopback IP")
	}
	return &Adapter{upstream: strings.TrimSuffix(upstream, "/"), authorize: authorize, client: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Deliberately do not inherit HTTP_PROXY for scoped credentials.
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			MaxResponseHeaderBytes: 32 << 10, IdleConnTimeout: 30 * time.Second,
			MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4,
		},
	}}, nil
}

func (a *Adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || (r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/anthropic/v1/messages") {
		http.Error(w, "unsupported inference route", http.StatusNotFound)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, "invalid request", 400)
		return
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth[0], "Bearer ")) == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			http.Error(w, "request too large", 413)
		} else {
			http.Error(w, "invalid request", 400)
		}
		return
	}
	model, err := requestModel(body)
	if err != nil {
		http.Error(w, "invalid inference request", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	grant, err := a.authorize(ctx, strings.TrimPrefix(auth[0], "Bearer "), model)
	if err != nil || grant.Tenant == "" || grant.Agent == "" || !validKey(grant.VirtualKey) || !time.Now().Before(grant.Expires) {
		http.Error(w, "access denied", 403)
		return
	}
	// Bound this experimental request by the authorization lease as well.
	ctx, expire := context.WithDeadline(ctx, grant.Expires)
	defer expire()
	up, err := http.NewRequestWithContext(ctx, http.MethodPost, a.upstream+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	up.Header.Set("Content-Type", "application/json")
	up.Header.Set("Accept", "application/json, text/event-stream")
	up.Header.Set("X-Bf-Vk", grant.VirtualKey)
	if r.URL.Path == "/anthropic/v1/messages" {
		up.Header.Set("Anthropic-Version", "2023-06-01")
	}
	res, err := a.client.Do(up)
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		http.Error(w, "upstream request refused", 502)
		return
	}
	ct := res.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") && !strings.HasPrefix(ct, "text/event-stream") {
		http.Error(w, "invalid upstream response", 502)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(res.StatusCode)
	buf := make([]byte, 8<<10)
	for {
		n, readErr := res.Body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
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

// Qualification supports only the narrow smoke/streaming payload. Unknown
// fields are refused so provider keys, fallbacks or engine-specific overrides
// cannot create a second route around the selected model. Broader SDK payloads
// need their own compatibility qualification before they are accepted.
func requestModel(body []byte) (string, error) {
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
	}
	if _, err := d.Token(); err != nil {
		return "", err
	}
	if _, err := d.Token(); err != io.EOF {
		return "", errors.New("trailing data")
	}
	if model == "" || len(model) > 256 {
		return "", errors.New("model required")
	}
	return model, nil
}
