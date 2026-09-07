package aigateway

import (
	"github.com/google/uuid"
	"strings"
)

type ProviderDefinition struct{ ID, Name, CredentialLabel, ModelPlaceholder string }

func ProviderDefinitions() []ProviderDefinition {
	return []ProviderDefinition{
		{"openai", "OpenAI", "OpenAI API key", "openai/gpt-4o-mini"},
		{"anthropic", "Anthropic", "Anthropic API key", "anthropic/claude-sonnet-4-20250514"},
		{"gemini", "Gemini", "Gemini API key", "gemini/gemini-2.5-flash"},
		{"openrouter", "OpenRouter", "OpenRouter API key", "openrouter/openai/gpt-4o-mini"},
		{"groq", "Groq", "Groq API key", "groq/llama-3.3-70b-versatile"},
		{"mistral", "Mistral", "Mistral API key", "mistral/mistral-small-latest"},
		{"cerebras", "Cerebras", "Cerebras API key", "cerebras/llama-3.3-70b"},
		{"xai", "xAI", "xAI API key", "xai/grok-3-mini"},
		{"deepseek", "DeepSeek", "DeepSeek API key", "deepseek/deepseek-chat"},
		{"sagemaker", "AWS SageMaker", "Bridge client key", "operator-model-alias"},
		{"custom", "Custom provider", "API key", "upstream-model"},
	}
}
func supportedProvider(provider string) bool {
	switch provider {
	case "openai", "anthropic", "gemini", "openrouter", "groq", "mistral", "cerebras", "xai", "deepseek":
		return true
	}
	return false
}
func customProviderName(value string) bool {
	if !strings.HasPrefix(value, "custom-") {
		return false
	}
	id, err := uuid.Parse(strings.TrimPrefix(value, "custom-"))
	return err == nil && id != uuid.Nil && value == "custom-"+id.String()
}
func splitProviderModel(value string) (provider, model string, ok bool) {
	provider, model, ok = strings.Cut(value, "/")
	return provider, model, ok && (supportedProvider(provider) || customProviderName(provider)) && model != "" && engineModel.MatchString(value) && engineModel.MatchString(model)
}
