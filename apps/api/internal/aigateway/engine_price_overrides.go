package aigateway

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// PriceOverrideEngine is the private engine's pricing-override boundary
// (AI-READY-1). Overrides are always scoped to one Tunnex-managed provider key,
// which belongs to exactly one organization connection. Global, provider and
// virtual-key scopes are never written: one engine serves every organization.
type PriceOverrideEngine interface {
	ListPriceOverrides(ctx context.Context, providerKeyID string) ([]EnginePriceOverride, error)
	CreatePriceOverride(ctx context.Context, desired EnginePriceOverride) error
	UpdatePriceOverride(ctx context.Context, id string, desired EnginePriceOverride) error
	DeletePriceOverride(ctx context.Context, id string) error
}

// EnginePriceOverride is one exact-model, provider-key-scoped override. ID is
// assigned by the engine; Tunnex identifies its own overrides by Name.
type EnginePriceOverride struct {
	ID            string
	Name          string
	ProviderKeyID string
	Pattern       string
	RequestTypes  []string
	Input, Output *float64
}

const priceOverrideNamePrefix = "tnx-price-"

var managedProviderKeyID = regexp.MustCompile(`^tnx-managed-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var priceOverrideName = regexp.MustCompile(`^tnx-price-[0-9a-f]{24}$`)
var engineOverrideID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// Request types an override covers, by the model's mode. Only modes that cost
// admission prices (chat, completion, embedding) are overridden.
func priceOverrideRequestTypes(mode ModelMode) ([]string, bool) {
	switch mode {
	case ModeChat, ModeCompletion:
		return []string{"chat_completion", "text_completion", "responses"}, true
	case ModeEmbedding:
		return []string{"embedding"}, true
	}
	return nil, false
}

func validOverrideRate(v *float64) bool {
	return v == nil || (*v >= 0 && *v <= maxModelPricePerToken && !math.IsNaN(*v) && !math.IsInf(*v, 0))
}

func validEnginePriceOverride(o EnginePriceOverride) bool {
	if !priceOverrideName.MatchString(o.Name) || !managedProviderKeyID.MatchString(o.ProviderKeyID) || !engineModel.MatchString(o.Pattern) || strings.Contains(o.Pattern, "*") || len(o.RequestTypes) == 0 || o.Input == nil || !validOverrideRate(o.Input) || !validOverrideRate(o.Output) {
		return false
	}
	for _, rt := range o.RequestTypes {
		if !slices.Contains([]string{"chat_completion", "text_completion", "responses", "embedding"}, rt) {
			return false
		}
	}
	return true
}

type enginePricingPatch struct {
	InputCostPerToken  *float64 `json:"input_cost_per_token,omitempty"`
	OutputCostPerToken *float64 `json:"output_cost_per_token,omitempty"`
}
type enginePricingOverrideBody struct {
	Name          string             `json:"name"`
	ScopeKind     string             `json:"scope_kind"`
	ProviderKeyID string             `json:"provider_key_id"`
	MatchType     string             `json:"match_type"`
	Pattern       string             `json:"pattern"`
	RequestTypes  []string           `json:"request_types"`
	Patch         enginePricingPatch `json:"patch"`
}

func pricingOverrideBody(o EnginePriceOverride) enginePricingOverrideBody {
	return enginePricingOverrideBody{Name: o.Name, ScopeKind: "provider_key", ProviderKeyID: o.ProviderKeyID, MatchType: "exact", Pattern: o.Pattern, RequestTypes: o.RequestTypes, Patch: enginePricingPatch{InputCostPerToken: o.Input, OutputCostPerToken: o.Output}}
}

// ListPriceOverrides reads every override scoped to one managed provider key.
// Entries of another scope or key in the answer are a readback mismatch.
func (e *Engine) ListPriceOverrides(ctx context.Context, providerKeyID string) ([]EnginePriceOverride, error) {
	if !managedProviderKeyID.MatchString(providerKeyID) {
		return nil, errEngineScope
	}
	var raw struct {
		Overrides []struct {
			ID            string   `json:"id"`
			Name          string   `json:"name"`
			ScopeKind     string   `json:"scope_kind"`
			ProviderKeyID *string  `json:"provider_key_id"`
			MatchType     string   `json:"match_type"`
			Pattern       string   `json:"pattern"`
			RequestTypes  []string `json:"request_types"`
			Patch         string   `json:"pricing_patch"`
		} `json:"pricing_overrides"`
	}
	if _, err := e.request(ctx, http.MethodGet, "/api/governance/pricing-overrides", url.Values{"provider_key_id": {providerKeyID}}, nil, &raw); err != nil {
		return nil, errEngine
	}
	if raw.Overrides == nil {
		return nil, errEngine
	}
	out := make([]EnginePriceOverride, 0, len(raw.Overrides))
	for _, o := range raw.Overrides {
		// Overrides Tunnex did not name are someone else's: never read, changed or deleted.
		if !strings.HasPrefix(o.Name, priceOverrideNamePrefix) {
			continue
		}
		var patch enginePricingPatch
		if o.ProviderKeyID == nil || *o.ProviderKeyID != providerKeyID || o.ScopeKind != "provider_key" || o.MatchType != "exact" || !engineOverrideID.MatchString(o.ID) || json.Unmarshal([]byte(o.Patch), &patch) != nil {
			return nil, errEngineScope
		}
		out = append(out, EnginePriceOverride{ID: o.ID, Name: o.Name, ProviderKeyID: providerKeyID, Pattern: o.Pattern, RequestTypes: o.RequestTypes, Input: patch.InputCostPerToken, Output: patch.OutputCostPerToken})
	}
	return out, nil
}

func (e *Engine) CreatePriceOverride(ctx context.Context, desired EnginePriceOverride) error {
	if !validEnginePriceOverride(desired) {
		return errEngineScope
	}
	if _, err := e.request(ctx, http.MethodPost, "/api/governance/pricing-overrides", nil, pricingOverrideBody(desired), nil); err != nil {
		return errEngine
	}
	return nil
}

func (e *Engine) UpdatePriceOverride(ctx context.Context, id string, desired EnginePriceOverride) error {
	if !engineOverrideID.MatchString(id) || !validEnginePriceOverride(desired) {
		return errEngineScope
	}
	if _, err := e.request(ctx, http.MethodPut, "/api/governance/pricing-overrides/"+id, nil, pricingOverrideBody(desired), nil); err != nil {
		return errEngine
	}
	return nil
}

func (e *Engine) DeletePriceOverride(ctx context.Context, id string) error {
	if !engineOverrideID.MatchString(id) {
		return errEngineScope
	}
	if status, err := e.request(ctx, http.MethodDelete, "/api/governance/pricing-overrides/"+id, nil, nil, nil); err != nil && status != http.StatusNotFound {
		return errEngine
	}
	return nil
}
