package aiegress

import "testing"

func TestFoundryEndpointBoundary(t *testing.T) {
	good := []string{"https://my-resource.services.ai.azure.com/openai", "https://my-resource.openai.azure.com/openai", "https://r.openai.azure.com:443/openai"}
	bad := []string{"http://r.openai.azure.com/openai", "https://r.openai.azure.com:8443/openai", "https://r.openai.azure.com/models", "https://r.openai.azure.com/openai/v1", "https://r.openai.azure.com/openai?api-version=v1", "https://r.openai.azure.com/openai#fragment", "https://user:pass@r.openai.azure.com/openai", "https://r.openai.azure.com.evil.example/openai", "https://r.evil.openai.azure.com/openai", "https://-r.openai.azure.com/openai", "https://r-.openai.azure.com/openai", "https://r.openai.azure.com./openai", "https://127.0.0.1/openai"}
	for _, raw := range good {
		if !FoundryEndpoint(raw) {
			t.Errorf("valid base refused: %s", raw)
		}
	}
	for _, raw := range bad {
		if FoundryEndpoint(raw) {
			t.Errorf("invalid base allowed: %s", raw)
		}
	}
	for _, raw := range append(good, bad...) {
		p := Policy{Endpoints: []Endpoint{{Provider: "azure_foundry", Name: "Foundry", URL: raw, AllowedCIDRs: []string{"20.0.0.0/8"}}}, ProtectedHosts: []string{"control.invalid"}}
		_, normalErr := NormalizeEndpoint(raw)
		err := p.validate()
		if normalErr != nil || !FoundryEndpoint(raw) {
			if err == nil {
				t.Errorf("policy accepted invalid base: %s", raw)
			}
		} else if err != nil {
			t.Errorf("policy rejected base: %s", raw)
		}
	}
}
