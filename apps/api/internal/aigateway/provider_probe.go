package aigateway

import (
	"context"
	"errors"
	"net"
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
type providerOperations struct {
	mu      sync.Mutex
	active  int
	windows map[uuid.UUID]probeWindow
}

// ConfigureNativeProviderOperations enables bounded private Bifrost operations.
// There is no second runtime, administrator token or caller-selected origin.
func (s *Policies) ConfigureNativeProviderOperations() error {
	if s == nil || s.engine == nil {
		return errors.New("AI engine is not configured")
	}
	s.probes = &providerOperations{windows: map[uuid.UUID]probeWindow{}}
	return nil
}
func (s *Policies) NativeProviderOperationsAvailable() bool {
	return s != nil && s.providerManagement && s.probes != nil
}

type DraftProviderOperationsEngine interface {
	ProbeDraftProvider(context.Context, ProviderProbeInput) (ProviderProbeResult, error)
	DraftProviderCatalog(context.Context, ProviderCatalogInput) (ProviderModelPage, error)
}

func (b *providerOperations) admit(org uuid.UUID, now time.Time) bool {
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
func (b *providerOperations) release(org uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.windows[org]
	w.active = false
	b.windows[org] = w
	b.active--
}
func (s *Policies) ProbeProvider(ctx context.Context, org, actor uuid.UUID, in ProviderProbeInput) (ProviderProbeResult, error) {
	if !s.NativeProviderOperationsAvailable() {
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
	validated, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Probe", Models: []string{in.Model}, ModelModes: map[string]ModelMode{in.Model: in.Mode}, Secret: &in.Secret, EndpointURL: in.EndpointURL}, true)
	if err != nil {
		return ProviderProbeResult{}, providerInvalid()
	}
	if endpointProvider(in.Provider) {
		in.EndpointURL = validated.EndpointURL
		if in.EndpointURL == nil {
			return ProviderProbeResult{}, providerInvalid()
		}
		if err := s.probeEndpointAccess(in.Provider, *in.EndpointURL); err != nil {
			return ProviderProbeResult{}, err
		}
		// A draft has no connection-owned namespace yet; only an upstream model is admissible.
		if prefix, _, ok := strings.Cut(in.Model, "/"); ok && customProviderName(prefix) {
			return ProviderProbeResult{}, providerInvalid()
		}
	}
	b := s.probes
	if !b.admit(org, time.Now()) {
		return ProviderProbeResult{}, apierr.New(429, "ai_provider_probe_limited", "AI provider connection test limit reached")
	}
	defer b.release(org)
	engine, ok := s.engine.(DraftProviderOperationsEngine)
	if !ok {
		return ProviderProbeResult{}, aiUnavailable()
	}
	result, err := engine.ProbeDraftProvider(ctx, in)
	if err != nil {
		return ProviderProbeResult{}, aiUnavailable()
	}
	return result, nil
}

// A test may be requested before installation network access exists. Report the
// setup verdict without invoking the engine or sending a provider credential.
func (s *Policies) probeEndpointAccess(provider, endpoint string) error {
	engine, native := s.engine.(*Engine)
	if s.customPolicy == nil || native && engine.customProxy == nil {
		return apierr.New(503, "ai_provider_egress_unavailable", "Provider endpoint network access is not configured")
	}
	if !s.endpointEligible(provider, endpoint) {
		return apierr.New(403, "ai_provider_endpoint_denied", "Provider endpoint is not permitted by the installation network policy")
	}
	return nil
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
	b := s.probes
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
	if endpointProvider(p.Provider) {
		if p.EndpointURL == nil {
			return ProviderProbeResult{}, providerInvalid()
		}
		if err := s.probeEndpointAccess(p.Provider, *p.EndpointURL); err != nil {
			return ProviderProbeResult{}, err
		}
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
