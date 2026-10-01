package aigateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

func TestReferenceCatalogProvenanceAndCompleteness(t *testing.T) {
	provenance, err := ReferenceCatalogProvenance()
	if err != nil || provenance.Commit != "eeb7732fc11fd47762ca84cc3fb7cc74235d7097" || provenance.SourceDate != "2026-09-06T01:12:56Z" || provenance.SourceSHA256 != "f68d88c12610ea31ab355a1293fde55aeed6fa78a1f4b182c67be47d80b1d202" || provenance.ReferenceEntries != 969 || provenance.SourceEntries != 3818 || provenance.License != "MIT" {
		t.Fatal("unqualified source provenance", provenance, err)
	}
	manifestJSON, err := os.ReadFile("reference/catalog-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Artifacts map[string]string `json:"artifacts"`
	}
	if json.Unmarshal(manifestJSON, &manifest) != nil {
		t.Fatal("invalid artifact manifest")
	}
	for name, expected := range manifest.Artifacts {
		data, err := os.ReadFile("reference/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			t.Fatal("catalog artifact checksum drift", name)
		}
	}
	if !strings.Contains(modelCatalogLicense, "Copyright (c) 2023 Berri AI") {
		t.Fatal("source license missing from binary")
	}
	for _, provider := range ProviderDefinitions() {
		if !supportedProvider(provider.ID) {
			continue
		}
		page, err := ProviderReferenceModels(provider.ID, ModeChat, "", 100, 0)
		if err != nil || page.Total == 0 {
			t.Fatal("supported provider missing from baked reference", provider.ID, err)
		}
	}
}

func TestReferencePriceExactUnknownConflictsAndUnits(t *testing.T) {
	for _, tc := range []struct {
		provider, model string
		known           bool
		input, output   float64
	}{
		{"openai", "gpt-4o-mini", true, 1.5e-7, 6e-7},
		{"openrouter", "openai/gpt-4o-mini", true, 1.5e-7, 6e-7},
		{"openai", "text-embedding-3-small", true, 2e-8, 0},
		{"gemini", "gemini-exp-1114", true, 0, 0},
		{"openai", "not-in-release", false, 0, 0},
		{"openai", "gpt-4o-mini-other-region", false, 0, 0},
		{"anthropic", "gpt-4o-mini", false, 0, 0},
		{"gemini", "gemini-exp-1206", false, 0, 0},
		{"openai", "dall-e-3", false, 0, 0},
		{"custom-00000000-0000-4000-8000-000000000001", "deployment-alias", false, 0, 0},
	} {
		price, err := ReferencePrice(tc.provider, tc.model)
		if err != nil || price.Known != tc.known {
			t.Fatal(tc, price, err)
		}
		if tc.known && (price.InputCostPerToken == nil || *price.InputCostPerToken != tc.input || price.OutputCostPerToken == nil || *price.OutputCostPerToken != tc.output) {
			t.Fatal("USD/token rates changed units", tc, price)
		}
		if !tc.known && (price.InputCostPerToken != nil || price.OutputCostPerToken != nil) {
			t.Fatal("unknown price acquired a token rate", tc, price)
		}
	}
	if bakedCatalog.PricingUnits["output_cost_per_image"] != "USD/image" || bakedCatalog.PricingUnits["input_cost_per_second"] != "USD/second" {
		t.Fatal("media units missing")
	}
}

func TestReferenceRateInvalidNeverBecomesFree(t *testing.T) {
	for _, raw := range []string{"null", "", "-1", `"0"`, "1e9999", "{}"} {
		if referenceRate(json.RawMessage(raw)) != nil {
			t.Fatal("invalid/missing rate accepted", raw)
		}
	}
	if rate := referenceRate(json.RawMessage("0")); rate == nil || *rate != 0 || math.Signbit(*rate) {
		t.Fatal("explicit zero price lost")
	}
	if _, err := ReferencePrice("provider/bad", "model"); err != errEngineScope {
		t.Fatal("invalid provider accepted", err)
	}
}
