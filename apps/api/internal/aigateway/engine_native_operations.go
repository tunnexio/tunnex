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
	_, err := probe.request(ctx, http.MethodPost, "/api/tunnex/model-catalog", nil, in, &result)
	if err != nil || result.Items == nil || result.Limit != in.Limit || result.Offset != in.Offset || result.Total < 0 || result.Total > 10000 || len(result.Items) > in.Limit || len(result.Items) > 0 && result.Total < in.Offset+len(result.Items) {
		return ProviderModelPage{}, errEngine
	}
	out := ProviderModelPage{Models: []ProviderModel{}, Total: result.Total}
	previous := ""
	query := strings.ToLower(in.Query)
	for _, m := range result.Items {
		prefix, _, _ := strings.Cut(m.ID, "/")
		if !engineModel.MatchString(m.ID) || len(m.ID) > 255 || m.Name != m.ID || m.ID <= previous || customProviderName(prefix) || strings.Contains(m.ID, in.Secret) || !strings.Contains(strings.ToLower(m.ID), query) {
			return ProviderModelPage{}, errEngine
		}
		previous = m.ID
		out.Models = append(out.Models, ProviderModel{ID: m.ID, Name: m.ID})
	}
	return out, nil
}
