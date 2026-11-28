package aigateway

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type ProviderCatalogInput struct {
	Mode        ModelMode `json:"mode,omitempty"`
	Provider    string    `json:"provider"`
	Secret      string    `json:"api_key"`
	EndpointURL string    `json:"endpoint_url"`
	Query       string    `json:"query"`
	Limit       int       `json:"limit"`
	Offset      int       `json:"offset"`
}

// SearchProviderCatalog uses the draft key only for this bounded native engine request.
// A catalog request never creates a connection, persists a key or runs inference.
func (s *Policies) SearchProviderCatalog(ctx context.Context, org, actor uuid.UUID, in ProviderCatalogInput) (ProviderModelPage, error) {
	if !s.NativeProviderOperationsAvailable() {
		return ProviderModelPage{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return ProviderModelPage{}, policyDenied()
	}
	in.Mode = DefaultModelMode(in.Mode)
	if !ValidModelMode(in.Mode) || (!supportedProvider(in.Provider) && !endpointProvider(in.Provider)) || utf8.RuneCountInString(in.Query) > 100 || in.Limit < 1 || in.Limit > 100 || in.Offset < 0 || in.Offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	if endpointProvider(in.Provider) {
		validated, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Catalog", Models: []string{"catalog"}, Secret: &in.Secret, EndpointURL: &in.EndpointURL}, true)
		if err != nil || validated.EndpointURL == nil || !s.endpointEligible(in.Provider, *validated.EndpointURL) {
			return ProviderModelPage{}, providerInvalid()
		}
		in.EndpointURL = *validated.EndpointURL
	} else {
		if in.EndpointURL != "" {
			return ProviderModelPage{}, providerInvalid()
		}
		if _, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Catalog", Models: []string{in.Provider + "/catalog"}, Secret: &in.Secret}, true); err != nil {
			return ProviderModelPage{}, providerInvalid()
		}
	}
	b := s.probes
	if !b.admit(org, time.Now()) {
		return ProviderModelPage{}, apierr.New(429, "ai_provider_probe_limited", "AI provider connection test limit reached")
	}
	defer b.release(org)
	engine, ok := s.engine.(DraftProviderOperationsEngine)
	if !ok {
		return ProviderModelPage{}, aiUnavailable()
	}
	out, err := engine.DraftProviderCatalog(ctx, in)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	return out, nil
}

// SavedProviderModels lists models for a saved standard-provider connection.
// It reads the provider's live list with the key the engine stores for that
// connection (live=true). When that cannot run or fails, it returns the same
// list as a connection-less search (live=false): merged for chat, reference
// otherwise. A connection of another organization or provider is refused
// before any engine call.
func (s *Policies) SavedProviderModels(ctx context.Context, org, id uuid.UUID, provider string, mode ModelMode, query string, limit, offset int) (ProviderModelPage, bool, error) {
	if !s.ProviderManagementAvailable() {
		return ProviderModelPage{}, false, aiUnavailable()
	}
	if org == uuid.Nil || id == uuid.Nil || !supportedProvider(provider) || !ValidModelMode(mode) || utf8.RuneCountInString(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, false, providerInvalid()
	}
	if s.pool == nil {
		return ProviderModelPage{}, false, aiUnavailable()
	}
	p, err := scanProvider(s.pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderModelPage{}, false, providerMissing()
	}
	if err != nil {
		return ProviderModelPage{}, false, aiUnavailable()
	}
	if p.Provider != provider {
		return ProviderModelPage{}, false, providerInvalid()
	}
	if page, ok := s.liveSavedCatalog(ctx, org, p, mode, query, limit, offset); ok {
		return page, true, nil
	}
	var page ProviderModelPage
	if mode == ModeChat {
		page, err = mergedProviderCatalog(ctx, s.engine.(ProviderEngine), provider, ModeChat, false, nil, query, limit, offset)
	} else {
		page, err = ProviderReferenceModels(provider, mode, query, limit, offset)
	}
	return page, false, err
}

func (s *Policies) liveSavedCatalog(ctx context.Context, org uuid.UUID, p ProviderConnection, mode ModelMode, query string, limit, offset int) (ProviderModelPage, bool) {
	if !p.Enabled || p.Status != "applied" || p.AppliedRevision != p.Revision || !s.NativeProviderOperationsAvailable() {
		return ProviderModelPage{}, false
	}
	engine, ok := s.engine.(SavedProviderCatalogEngine)
	if !ok {
		return ProviderModelPage{}, false
	}
	// The draft catalog's limiter: a full window falls back instead of failing.
	b := s.probes
	if !b.admit(org, time.Now()) {
		return ProviderModelPage{}, false
	}
	defer b.release(org)
	page, err := engine.SavedProviderCatalog(ctx, providerSpec(p), mode, query, limit, offset)
	if err != nil {
		return ProviderModelPage{}, false
	}
	return page, true
}
