package aigateway

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// These data artifacts are generated from a checksum-verified, commit-pinned
// source during CI. No source SDK, provider credential, or HTTP fetch is used.
//
//go:embed reference/model-catalog.json
var modelCatalogJSON []byte

// Include the license in the API artifact as well as the engine image.
//
//go:embed reference/LiteLLM-LICENSE
var modelCatalogLicense string

type CatalogProvenance struct {
	SchemaVersion    int    `json:"schema_version"`
	Repository       string `json:"repository"`
	Commit           string `json:"commit"`
	SourceDate       string `json:"source_date"`
	SourcePath       string `json:"source_path"`
	SourceSHA256     string `json:"source_sha256"`
	LicensePath      string `json:"license_path"`
	License          string `json:"license"`
	LicenseSHA256    string `json:"license_sha256"`
	SourceEntries    int    `json:"source_entries"`
	ReferenceEntries int    `json:"reference_entries"`
}

type ModelReference struct {
	ID       string                     `json:"id"`
	SourceID string                     `json:"source_id"`
	Provider string                     `json:"provider"`
	Mode     ModelMode                  `json:"mode"`
	Metadata map[string]json.RawMessage `json:"metadata"`
	Prices   map[string]json.RawMessage `json:"prices"`
}

type modelCatalog struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      CatalogProvenance `json:"provenance"`
	PricingCurrency string            `json:"pricing_currency"`
	PricingUnits    map[string]string `json:"pricing_units"`
	Entries         []ModelReference  `json:"entries"`
}

var catalogOnce sync.Once
var bakedCatalog modelCatalog
var bakedCatalogErr error
var bakedCatalogIndex map[string][]ModelReference

func loadModelCatalog() error {
	catalogOnce.Do(func() {
		if json.Unmarshal(modelCatalogJSON, &bakedCatalog) != nil || bakedCatalog.SchemaVersion != 1 || bakedCatalog.PricingCurrency != "USD" || len(bakedCatalog.Entries) != bakedCatalog.Provenance.ReferenceEntries || bakedCatalog.Provenance.License != "MIT" || modelCatalogLicense == "" {
			bakedCatalogErr = errEngine
			return
		}
		bakedCatalogIndex = make(map[string][]ModelReference, len(bakedCatalog.Entries))
		for _, row := range bakedCatalog.Entries {
			if !engineModel.MatchString(row.ID) || row.Provider == "" || !ValidModelMode(row.Mode) {
				bakedCatalogErr = errEngine
				return
			}
			bakedCatalogIndex[row.ID] = append(bakedCatalogIndex[row.ID], row)
		}
	})
	return bakedCatalogErr
}

// ReferenceCatalogProvenance identifies the exact static estimate shipped in
// this release. Static names/capabilities do not prove account entitlement or
// current provider availability, and prices are not a provider invoice.
func ReferenceCatalogProvenance() (CatalogProvenance, error) {
	if err := loadModelCatalog(); err != nil {
		return CatalogProvenance{}, err
	}
	return bakedCatalog.Provenance, nil
}

// ReferencePrice returns exact-provider, exact-model base USD/token estimates.
// Input/output pointers preserve absent rates, including an explicitly priced
// zero. Media, per-request, tier, cache and tool prices are retained separately
// in the snapshot and never converted to a token price. Endpoint deployment
// aliases and conflicting upstream aliases remain unknown.
func ReferencePrice(provider, model string) (Price, error) {
	if !engineIdentifier.MatchString(provider) || !engineModel.MatchString(model) {
		return Price{}, errEngineScope
	}
	if err := loadModelCatalog(); err != nil {
		return Price{}, err
	}
	rows := bakedCatalogIndex[provider+"/"+model]
	var result Price
	for i, row := range rows {
		if row.Provider != provider {
			return Price{}, errEngineScope
		}
		next := Price{
			InputCostPerToken:  referenceRate(row.Prices["input_cost_per_token"]),
			OutputCostPerToken: referenceRate(row.Prices["output_cost_per_token"]),
		}
		next.Known = next.InputCostPerToken != nil && next.OutputCostPerToken != nil
		if i > 0 && (row.Mode != rows[0].Mode || !sameReferenceRate(result.InputCostPerToken, next.InputCostPerToken) || !sameReferenceRate(result.OutputCostPerToken, next.OutputCostPerToken)) {
			return Price{}, nil
		}
		result = next
	}
	return result, nil
}

func referenceRate(raw json.RawMessage) *float64 {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var value float64
	if json.Unmarshal(raw, &value) != nil || !validEngineCost(value) {
		return nil
	}
	return &value
}

func sameReferenceRate(a, b *float64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
