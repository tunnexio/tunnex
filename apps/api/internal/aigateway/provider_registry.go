package aigateway

import "strings"

type ProviderDefinition struct{ ID, Name, CredentialLabel, ModelPlaceholder string }

func ProviderDefinitions() []ProviderDefinition {
	return []ProviderDefinition{
		{"openai", "OpenAI", "OpenAI API key", "openai/gpt-4o-mini"},
		{"anthropic", "Anthropic", "Anthropic API key", "anthropic/claude-sonnet-4-20250514"},
		{"gemini", "Gemini", "Gemini API key", "gemini/gemini-2.5-flash"},
		{"openrouter", "OpenRouter", "OpenRouter API key", "openrouter/openai/gpt-4o-mini"},
	}
}
func supportedProvider(provider string) bool {
	switch provider {
	case "openai", "anthropic", "gemini", "openrouter":
		return true
	}
	return false
}
func splitProviderModel(value string) (provider, model string, ok bool) {
	provider, model, ok = strings.Cut(value, "/")
	return provider, model, ok && supportedProvider(provider) && model != "" && engineModel.MatchString(value) && engineModel.MatchString(model)
}
