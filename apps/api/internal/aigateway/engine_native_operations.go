package aigateway

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Native operations use the same private administrator boundary as owned keys.
// Draft keys are transient request values and are never added to engine storage.
func (e *Engine) ProbeDraftProvider(ctx context.Context, in ProviderProbeInput) (ProviderProbeResult, error) {
	payload := struct {
		Mode     ModelMode `json:"mode"`
		Provider string    `json:"provider"`
		Model    string    `json:"model"`
		Secret   string    `json:"api_key"`
		Endpoint *string   `json:"endpoint_url,omitempty"`
	}{in.Mode, in.Provider, in.Model, in.Secret, in.EndpointURL}
	var result ProviderProbeResult
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	probe := e.nativeOperationEngine()
	if transport, ok := probe.client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	status, err := probe.request(ctx, http.MethodPost, "/api/tunnex/test-connection", nil, payload, &result)
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return probeTimeout(start), nil
	}
	if err != nil || status != 200 || (result.Status != "success" && result.Status != "error") || result.DurationMS < 0 {
		return ProviderProbeResult{}, errEngine
	}
	result.DurationMS = time.Since(start).Milliseconds()
	if result.Status == "success" {
		result.Failure = nil
	} else {
		result.Failure = safeProbeFailure(result.Failure)
	}
	return result, nil
}

func (e *Engine) nativeOperationEngine() *Engine {
	probe := *e
	client := *e.client
	client.Timeout = 15 * time.Second
	// A provider operation can take longer than a normal metadata read. Keep
	// the same private origin/authentication while allowing its bounded deadline.
	if transport, ok := client.Transport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.ResponseHeaderTimeout = 15 * time.Second
		client.Transport = clone
	}
	probe.client = &client
	return &probe
}

func (e *Engine) DraftProviderCatalog(ctx context.Context, in ProviderCatalogInput) (ProviderModelPage, error) {
	return e.nativeCatalog(ctx, "/api/tunnex/model-catalog", in, "", in.Secret, in.Query, in.Limit, in.Offset)
}

// SavedProviderCatalogEngine lists a standard provider's models with the key
// the engine already stores. No key travels in the request or the result.
type SavedProviderCatalogEngine interface {
	SavedProviderCatalog(ctx context.Context, s ProviderKeySpec, mode ModelMode, query string, limit, offset int) (ProviderModelPage, error)
}

func (e *Engine) SavedProviderCatalog(ctx context.Context, s ProviderKeySpec, mode ModelMode, query string, limit, offset int) (ProviderModelPage, error) {
	if !supportedProvider(s.Provider) || s.BaseURL != "" || (!s.Enabled && len(s.Models) > 0) || !ValidModelMode(mode) {
		return ProviderModelPage{}, errEngineScope
	}
	name, _, err := nativeProviderSpec(s)
	if err != nil {
		return ProviderModelPage{}, err
	}
	// The stored key must still be exactly this revision before it is used.
	if err = e.VerifyProviderKey(ctx, s); err != nil {
		return ProviderModelPage{}, err
	}
	payload := struct {
		Provider string    `json:"provider"`
		KeyID    string    `json:"key_id"`
		KeyName  string    `json:"key_name"`
		Mode     ModelMode `json:"mode"`
		Query    string    `json:"query"`
		Limit    int       `json:"limit"`
		Offset   int       `json:"offset"`
	}{s.Provider, s.ID, name, mode, query, limit, offset}
	return e.nativeCatalog(ctx, "/api/tunnex/saved-model-catalog", payload, s.Provider, "", query, limit, offset)
}

// nativeCatalog accepts only a bounded, sorted, unique page that matches the
// request. provider, when set, is the prefix every returned model must carry.
func (e *Engine) nativeCatalog(ctx context.Context, path string, payload any, provider, secret, query string, limit, offset int) (ProviderModelPage, error) {
	var result struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	probe := e.nativeOperationEngine()
	if transport, ok := probe.client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	_, err := probe.request(ctx, http.MethodPost, path, nil, payload, &result)
	if err != nil || result.Items == nil || result.Limit != limit || result.Offset != offset || result.Total < 0 || result.Total > 10000 || len(result.Items) > limit || len(result.Items) > 0 && result.Total < offset+len(result.Items) {
		return ProviderModelPage{}, errEngine
	}
	out := ProviderModelPage{Models: []ProviderModel{}, Total: result.Total}
	previous := ""
	query = strings.ToLower(query)
	for _, m := range result.Items {
		prefix, _, _ := strings.Cut(m.ID, "/")
		if !engineModel.MatchString(m.ID) || len(m.ID) > 255 || m.Name != m.ID || m.ID <= previous || customProviderName(prefix) || secret != "" && strings.Contains(m.ID, secret) || !strings.Contains(strings.ToLower(m.ID), query) || provider != "" && (prefix != provider || m.ID == prefix) {
			return ProviderModelPage{}, errEngine
		}
		previous = m.ID
		out.Models = append(out.Models, ProviderModel{ID: m.ID, Name: m.ID})
	}
	return out, nil
}
