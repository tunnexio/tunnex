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
		if name, ok := foundryReferenceName(row); ok && strings.Contains(strings.ToLower(name), query) {
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
