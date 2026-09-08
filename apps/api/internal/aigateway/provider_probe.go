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
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type ProviderProbeInput struct {
	Mode                    ModelMode
	Provider, Model, Secret string
	EndpointURL             *string
	ConnectionID            *uuid.UUID
	ExpectedRevision        *int64
}
type ProviderProbeResult struct {
	Status     string                `json:"status"`
	DurationMS int64                 `json:"duration_ms"`
	Failure    *ProviderProbeFailure `json:"failure,omitempty"`
}
type ProviderProbeFailure struct {
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	HTTPStatus *int   `json:"http_status,omitempty"`
}

func safeProbeFailure(f *ProviderProbeFailure) *ProviderProbeFailure {
	if f == nil || (f.Source != "provider" && f.Source != "proxy" && f.Source != "gateway") {
		return nil
	}
	switch f.Kind {
	case "http_error":
		if f.HTTPStatus == nil || *f.HTTPStatus < 400 || *f.HTTPStatus > 599 {
			return nil
		}
	case "network_error", "timeout", "configuration_error", "invalid_response", "unknown":
		if f.HTTPStatus != nil {
			return nil
		}
	default:
		return nil
	}
	return f
}

func probeTimeout(start time.Time) ProviderProbeResult {
	return ProviderProbeResult{Status: "error", DurationMS: time.Since(start).Milliseconds(), Failure: &ProviderProbeFailure{Kind: "timeout", Source: "gateway"}}
}

func isProbeTimeout(err error) bool {
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
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
	if in.ConnectionID != nil {
		return s.probeSavedProvider(ctx, org, actor, in)
	}
	if in.ExpectedRevision != nil {
		return ProviderProbeResult{}, providerInvalid()
	}
	in.Mode = DefaultModelMode(in.Mode)
	if !ValidModelMode(in.Mode) {
		return ProviderProbeResult{}, providerInvalid()
	}
	_, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Probe", Models: []string{in.Model}, ModelModes: map[string]ModelMode{in.Model: in.Mode}, Secret: &in.Secret, EndpointURL: in.EndpointURL}, true)
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
		Mode        ModelMode `json:"mode"`
		Provider    string    `json:"provider"`
		Model       string    `json:"model"`
		Secret      string    `json:"api_key"`
		EndpointURL *string   `json:"endpoint_url,omitempty"`
	}{in.Mode, in.Provider, in.Model, in.Secret, in.EndpointURL}
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
		if isProbeTimeout(err) {
			return probeTimeout(start), nil
		}
		return ProviderProbeResult{}, aiUnavailable()
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if isProbeTimeout(err) {
		return probeTimeout(start), nil
	}
	if err != nil || len(data) > 4096 || res.StatusCode != 200 {
		return ProviderProbeResult{}, aiUnavailable()
	}
	var result ProviderProbeResult
	if json.Unmarshal(data, &result) != nil || (result.Status != "success" && result.Status != "error") {
		return ProviderProbeResult{}, aiUnavailable()
	}
	if result.Status == "success" {
		result.Failure = nil
	} else {
		result.Failure = safeProbeFailure(result.Failure)
	}
	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// SavedProviderProbeEngine exposes no secret-bearing result or key readback.
type SavedProviderProbeEngine interface {
	ProbeSavedProviderKey(context.Context, ProviderKeySpec, string, string, ModelMode) (ProviderProbeResult, error)
}

func (s *Policies) probeSavedProvider(ctx context.Context, org, actor uuid.UUID, in ProviderProbeInput) (ProviderProbeResult, error) {
	if in.ConnectionID == nil || *in.ConnectionID == uuid.Nil || in.ExpectedRevision == nil || *in.ExpectedRevision < 1 || in.Secret != "" || in.EndpointURL != nil {
		return ProviderProbeResult{}, providerInvalid()
	}
	engine, ok := s.engine.(SavedProviderProbeEngine)
	if !ok || s.pool == nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	b := s.bridge
	if !b.admit(org, time.Now()) {
		return ProviderProbeResult{}, apierr.New(429, "ai_provider_probe_limited", "AI provider connection test limit reached")
	}
	defer b.release(org)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	// Hold the credential lock through the bounded test: rotation, deletion and
	// disable cannot race a test accepted at this exact revision.
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, org, *in.ConnectionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderProbeResult{}, providerMissing()
	}
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	if p.Provider != in.Provider {
		return ProviderProbeResult{}, providerInvalid()
	}
	if p.Revision != *in.ExpectedRevision || p.AppliedRevision != p.Revision || p.Status != "applied" || !p.Enabled {
		return ProviderProbeResult{}, providerConflict()
	}
	if endpointProvider(p.Provider) && !s.customConnectionEligible(p) {
		return ProviderProbeResult{}, providerMissing()
	}
	in.Mode = DefaultModelMode(in.Mode)
	model := in.Model
	if endpointProvider(p.Provider) {
		model = strings.TrimPrefix(model, nativeConnectionProvider(p)+"/")
	}
	if _, err = validateProviderInput(ProviderInput{Provider: p.Provider, Name: "Probe", Models: []string{model}, ModelModes: map[string]ModelMode{model: in.Mode}, EndpointURL: p.EndpointURL}, false); err != nil {
		return ProviderProbeResult{}, providerInvalid()
	}
	if prefix, _, ok := strings.Cut(model, "/"); ok && customProviderName(prefix) {
		return ProviderProbeResult{}, providerInvalid()
	}
	result, err := engine.ProbeSavedProviderKey(ctx, providerSpec(p), p.Provider, model, in.Mode)
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	if auditPolicy(ctx, tx, org, actor, p.ID, "ai_provider.probed", p.Revision) != nil || tx.Commit(ctx) != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	return result, nil
}
