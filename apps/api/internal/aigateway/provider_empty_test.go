package aigateway

import (
	"github.com/google/uuid"
	"testing"
)

func TestEmptyCredentialIsStoredButNotEnabledInEngine(t *testing.T) {
	key := "synthetic-test-key"
	for _, provider := range []string{"openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek", "custom", "sagemaker", "azure_foundry"} {
		in := ProviderInput{Provider: provider, Name: "Saved credential", Secret: &key, Models: []string{}}
		if endpointProvider(provider) {
			endpoint := "https://example.com"
			if provider == "azure_foundry" {
				endpoint = "https://example.openai.azure.com/openai"
			}
			in.EndpointURL = &endpoint
		}
		if _, err := validateProviderInput(in, true); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
	}
	p := ProviderConnection{Provider: "openai", KeyID: "tnx-managed-" + uuid.NewString(), Revision: 1, Enabled: true, Models: []string{}}
	spec := providerSpec(p)
	if spec.Enabled {
		t.Fatal("unconfigured credential must not route inference")
	}
	if _, _, err := nativeProviderSpec(spec); err != nil {
		t.Fatal(err)
	}
	spec.Enabled = true
	if _, _, err := nativeProviderSpec(spec); err == nil {
		t.Fatal("enabled unscoped key accepted")
	}
}

func TestEmptyEndpointCredentialNeedsNoNetworkPolicy(t *testing.T) {
	endpoint := "https://example.services.ai.azure.com/anthropic"
	in := ProviderInput{Provider: "azure_foundry", EndpointURL: &endpoint}
	s := &Policies{}
	if err := s.normalizeCustomModels(&in, uuid.New()); err != nil {
		t.Fatal(err)
	}
	in.Models = []string{"claude"}
	if err := s.normalizeCustomModels(&in, uuid.New()); err == nil {
		t.Fatal("model activation must still require network policy")
	}
}
