package aigateway

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
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
