package aigateway

import "testing"

func TestFoundryInputRequiresV1ResourceBase(t *testing.T) {
	key := "fixture-key"
	base := "https://example.services.ai.azure.com/openai"
	in := ProviderInput{Provider: "azure_foundry", Name: "Foundry", EndpointURL: &base, Models: []string{"my-deployment"}, Secret: &key, Enabled: true}
	if _, err := validateProviderInput(in, true); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://example.services.ai.azure.com/openai", "https://example.services.ai.azure.com/models", "https://example.services.ai.azure.com/openai/v1", "https://example.openai.azure.com.evil.example/openai"} {
		in.EndpointURL = &raw
		if _, err := validateProviderInput(in, true); err == nil {
			t.Errorf("invalid Azure endpoint accepted: %s", raw)
		}
	}
	in.EndpointURL = nil
	if _, err := validateProviderInput(in, true); err == nil {
		t.Fatal("missing endpoint accepted")
	}
	if _, _, ok := splitProviderModel("azure_foundry/my-deployment"); ok {
		t.Fatal("unscoped Azure model accepted")
	}
}

func TestFoundryAnthropicInput(t *testing.T) {
	key, base := "fixture-key", "https://resource.services.ai.azure.com/anthropic"
	in := ProviderInput{Provider: "azure_foundry", Name: "Claude", EndpointURL: &base, Models: []string{"claude-opus-5"}, Secret: &key, Enabled: true}
	if _, err := validateProviderInput(in, true); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"custom", "sagemaker"} {
		wrong := in
		wrong.Provider = provider
		if _, err := validateProviderInput(wrong, true); err == nil {
			t.Fatal("Anthropic URL accepted under", provider)
		}
	}
	in.ModelModes = map[string]ModelMode{"claude-opus-5": ModeEmbedding}
	if _, err := validateProviderInput(in, true); err == nil {
		t.Fatal("non-chat mode accepted on Anthropic endpoint")
	}
}
