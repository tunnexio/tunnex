package aigateway

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Source and MIT attribution accompany the embedded snapshot. This catalog is
// only a model-name reference, never Azure deployment discovery or billing data.
//
//go:embed reference/litellm_azure_models.json
var foundryReferenceJSON []byte

type referenceModel struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Mode     string `json:"mode"`
}

type referenceSnapshot struct {
	SourceCommit string           `json:"source_commit"`
	SourceSHA256 string           `json:"source_sha256"`
	SourcePath   string           `json:"source_path"`
	Entries      []referenceModel `json:"entries"`
}

var foundryChatFamily = regexp.MustCompile(`^(gpt-|o[134]($|-))`)

func foundryReferenceName(row referenceModel) (string, bool) {
	if row.Provider != "azure" || row.Mode != "chat" || !strings.HasPrefix(row.ID, "azure/") {
		return "", false
	}
	name := strings.TrimPrefix(row.ID, "azure/")
	// Nested paths are regional/pricing aliases, not names for deployments.
	if strings.Contains(name, "/") || !foundryChatFamily.MatchString(name) || !engineModel.MatchString(name) || strings.Contains(name, "audio") || strings.Contains(name, "realtime") {
		return "", false
	}
	return name, true
}

// FoundryReferenceModels returns static LiteLLM reference names without needing
// an endpoint, credentials or network access. The actual Azure deployment name
// can differ; only an explicit connection test checks that resource and key.
func FoundryReferenceModels(query string, limit, offset int) (ProviderModelPage, error) {
	return FoundryReferenceModelsForMode(ModeChat, query, limit, offset)
}
func FoundryReferenceModelsForMode(mode ModelMode, query string, limit, offset int) (ProviderModelPage, error) {
	mode = DefaultModelMode(mode)
	if !ValidModelMode(mode) {
		return ProviderModelPage{}, providerInvalid()
	}
	if utf8.RuneCountInString(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	var snapshot referenceSnapshot
	if json.Unmarshal(foundryReferenceJSON, &snapshot) != nil || len(snapshot.Entries) == 0 {
		return ProviderModelPage{}, aiUnavailable()
	}
	names := []string{}
	query = strings.ToLower(query)
	for _, row := range snapshot.Entries {
		if name, ok := foundryReferenceModeName(row, mode); ok && strings.Contains(strings.ToLower(name), query) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	page := ProviderModelPage{Models: []ProviderModel{}, Total: len(names)}
	for _, name := range names[min(offset, len(names)):min(offset+limit, len(names))] {
		page.Models = append(page.Models, ProviderModel{ID: name, Name: name})
	}
	return page, nil
}

func foundryReferenceModeName(row referenceModel, mode ModelMode) (string, bool) {
	if mode == ModeChat {
		return foundryReferenceName(row)
	}
	if row.Provider != "azure" || row.Mode != string(mode) || !strings.HasPrefix(row.ID, "azure/") {
		return "", false
	}
	name := strings.TrimPrefix(row.ID, "azure/")
	if strings.Contains(name, "/") || !engineModel.MatchString(name) {
		return "", false
	}
	return name, true
}

//go:embed reference/litellm_provider_models.json
var providerReferenceJSON []byte

// ProviderReferenceModels supplies mode-specific names from the same pinned
// LiteLLM source. These are suggestions, never evidence of key/model access.
func ProviderReferenceModels(provider string, mode ModelMode, query string, limit, offset int) (ProviderModelPage, error) {
	if !ValidModelMode(mode) || !supportedProvider(provider) || endpointProvider(provider) || utf8.RuneCountInString(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	var snapshot referenceSnapshot
	if json.Unmarshal(providerReferenceJSON, &snapshot) != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	names := []string{}
	query = strings.ToLower(query)
	for _, row := range snapshot.Entries {
		if row.Provider == provider && row.Mode == string(mode) && strings.HasPrefix(row.ID, provider+"/") && len(row.ID) <= 255 && strings.Contains(strings.ToLower(row.ID), query) {
			names = append(names, row.ID)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	page := ProviderModelPage{Models: []ProviderModel{}, Total: len(names)}
	for _, name := range names[min(offset, len(names)):min(offset+limit, len(names))] {
		page.Models = append(page.Models, ProviderModel{ID: name, Name: strings.TrimPrefix(name, provider+"/")})
	}
	return page, nil
}
