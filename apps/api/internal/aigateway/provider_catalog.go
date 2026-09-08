package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// SearchProviderCatalog uses the draft key only for this bounded bridge request.
// A catalog request never creates a connection, persists a key or runs inference.
func (s *Policies) SearchProviderCatalog(ctx context.Context, org, actor uuid.UUID, in ProviderCatalogInput) (ProviderModelPage, error) {
	if !s.LiteLLMBridgeAvailable() {
		return ProviderModelPage{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return ProviderModelPage{}, policyDenied()
	}
	in.Mode = DefaultModelMode(in.Mode)
	if !ValidModelMode(in.Mode) || !endpointProvider(in.Provider) || utf8.RuneCountInString(in.Query) > 100 || in.Limit < 1 || in.Limit > 100 || in.Offset < 0 || in.Offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	validated, err := validateProviderInput(ProviderInput{Provider: in.Provider, Name: "Catalog", Models: []string{"catalog"}, Secret: &in.Secret, EndpointURL: &in.EndpointURL}, true)
	if err != nil || validated.EndpointURL == nil || !s.endpointEligible(in.Provider, *validated.EndpointURL) {
		return ProviderModelPage{}, providerInvalid()
	}
	in.EndpointURL = *validated.EndpointURL
	b := s.bridge
	if !b.admit(org, time.Now()) {
		return ProviderModelPage{}, apierr.New(429, "ai_provider_probe_limited", "AI provider connection test limit reached")
	}
	defer b.release(org)
	body, err := json.Marshal(in)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(b.url, "/test-connection")+"/model-catalog", bytes.NewReader(body))
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := b.client.Do(req)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 || res.StatusCode != 200 {
		return ProviderModelPage{}, aiUnavailable()
	}
	var result struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	if json.Unmarshal(data, &result) != nil || result.Items == nil || result.Limit != in.Limit || result.Offset != in.Offset || result.Total < 0 || result.Total > 10000 || len(result.Items) > in.Limit || len(result.Items) > 0 && result.Total < in.Offset+len(result.Items) {
		return ProviderModelPage{}, aiUnavailable()
	}
	out := ProviderModelPage{Models: []ProviderModel{}, Total: result.Total}
	previous := ""
	query := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, in.Query)
	for _, m := range result.Items {
		prefix, _, _ := strings.Cut(m.ID, "/")
		if !engineModel.MatchString(m.ID) || len(m.ID) > 255 || m.Name != m.ID || m.ID <= previous || customProviderName(prefix) || strings.Contains(m.ID, in.Secret) || !strings.Contains(strings.ToLower(m.ID), query) {
			return ProviderModelPage{}, aiUnavailable()
		}
		previous = m.ID
		out.Models = append(out.Models, ProviderModel{ID: m.ID, Name: m.ID})
	}
	return out, nil
}
