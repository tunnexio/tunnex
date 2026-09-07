package aigateway

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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type ProviderProbeInput struct {
	Provider, Model, Secret string
	EndpointURL             *string
}
type ProviderProbeResult struct {
	Status     string
	DurationMS int64
}
type probeWindow struct {
	start    time.Time
	attempts int
	active   bool
}
type providerBridge struct {
	url, token string
	client     *http.Client
	mu         sync.Mutex
	active     int
	windows    map[uuid.UUID]probeWindow
}

// ConfigureLiteLLMBridge is installation-only. Neither its origin nor token is supplied by a request.
func (s *Policies) ConfigureLiteLLMBridge(raw, token string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(token) < 16 || len(token) > 4096 || strings.ContainsAny(token, " \r\n\t") {
		return errors.New("invalid AI bridge configuration")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "litellm-bridge" || ip != nil && ip.IsLoopback())) {
		return errors.New("invalid AI bridge configuration")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	s.bridge = &providerBridge{url: strings.TrimRight(raw, "/") + "/test-connection", token: token, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, windows: map[uuid.UUID]probeWindow{}}
	return nil
}
func (s *Policies) LiteLLMBridgeAvailable() bool {
	return s != nil && s.providerManagement && s.bridge != nil
}
func (b *providerBridge) admit(org uuid.UUID, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, w := range b.windows {
		if !w.active && now.Sub(w.start) >= time.Minute {
			delete(b.windows, id)
		}
	}
	w, exists := b.windows[org]
	if b.active >= 8 || w.active || w.attempts >= 6 || (!exists && len(b.windows) >= 4096) {
		return false
	}
	if !exists {
		w.start = now
	}
	w.attempts++
	w.active = true
	b.windows[org] = w
	b.active++
	return true
}
func (b *providerBridge) release(org uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.windows[org]
	w.active = false
	b.windows[org] = w
	b.active--
}
func (s *Policies) ProbeProvider(ctx context.Context, org, actor uuid.UUID, in ProviderProbeInput) (ProviderProbeResult, error) {
	if !s.LiteLLMBridgeAvailable() {
		return ProviderProbeResult{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return ProviderProbeResult{}, policyDenied()
	}
	_, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Probe", Models: []string{in.Model}, Secret: &in.Secret, EndpointURL: in.EndpointURL}, true)
	if err != nil {
		return ProviderProbeResult{}, providerInvalid()
	}
	if endpointProvider(in.Provider) {
		if in.EndpointURL == nil || !s.endpointEligible(in.Provider, *in.EndpointURL) {
			return ProviderProbeResult{}, providerInvalid()
		}
		// A draft has no connection-owned namespace yet; only an upstream model is admissible.
		if prefix, _, ok := strings.Cut(in.Model, "/"); ok && customProviderName(prefix) {
			return ProviderProbeResult{}, providerInvalid()
		}
	}
	b := s.bridge
	if !b.admit(org, time.Now()) {
		return ProviderProbeResult{}, apierr.New(429, "ai_provider_probe_limited", "AI provider connection test limit reached")
	}
	defer b.release(org)
	payload := struct {
		Provider    string  `json:"provider"`
		Model       string  `json:"model"`
		Secret      string  `json:"api_key"`
		EndpointURL *string `json:"endpoint_url,omitempty"`
	}{in.Provider, in.Model, in.Secret, in.EndpointURL}
	body, err := json.Marshal(payload)
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	res, err := b.client.Do(req)
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(data) > 4096 || res.StatusCode != 200 {
		return ProviderProbeResult{}, aiUnavailable()
	}
	var result struct {
		Status     string `json:"status"`
		DurationMS int64  `json:"duration_ms"`
	}
	if json.Unmarshal(data, &result) != nil || (result.Status != "success" && result.Status != "error") {
		return ProviderProbeResult{}, aiUnavailable()
	}
	return ProviderProbeResult{Status: result.Status, DurationMS: time.Since(start).Milliseconds()}, nil
}
