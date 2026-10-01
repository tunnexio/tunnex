package aigateway

import (
	"reflect"
	"strings"
	"testing"
)

func TestFoundryReferenceSearchAndPagination(t *testing.T) {
	page, err := FoundryReferenceModels("GPT-5", 100, 0)
	if err != nil || page.Total == 0 || len(page.Models) != page.Total {
		t.Fatal(page, err)
	}
	want := map[string]bool{"gpt-5": false, "gpt-5-mini": false, "gpt-5.1": false}
	previous := ""
	for _, model := range page.Models {
		if model.ID <= previous || model.Name != model.ID || !strings.Contains(model.ID, "gpt-5") || strings.Contains(model.ID, "/") {
			t.Fatal("invalid reference result", model)
		}
		if _, exists := want[model.ID]; exists {
			want[model.ID] = true
		}
		previous = model.ID
	}
	for model, found := range want {
		if !found {
			t.Errorf("verified upstream model missing: %s", model)
		}
	}
	paged, err := FoundryReferenceModels("gpt-5", 3, 1)
	if err != nil || paged.Total != page.Total || !reflect.DeepEqual(paged.Models, page.Models[1:4]) {
		t.Fatal("pagination differs from complete filtered reference", paged, err)
	}
	empty, err := FoundryReferenceModels("gpt-5", 50, 10000)
	if err != nil || empty.Models == nil || len(empty.Models) != 0 || empty.Total != page.Total {
		t.Fatal(empty, err)
	}
	missing, err := FoundryReferenceModels("unknown-deployment-name", 50, 0)
	if err != nil || missing.Total != 0 || len(missing.Models) != 0 {
		t.Fatal(missing, err)
	}
	all, err := FoundryReferenceModels("", 100, 0)
	if err != nil || all.Total < page.Total {
		t.Fatal(all, err)
	}
	for _, model := range all.Models {
		if strings.Contains(model.ID, "audio") || strings.Contains(model.ID, "realtime") || strings.Contains(model.ID, "codex") || strings.Contains(model.ID, "embedding") || strings.Contains(model.ID, "/") {
			t.Fatal("unsupported mode/provider alias advertised", model)
		}
	}
}

func TestFoundryReferenceNonOpenAIDeployments(t *testing.T) {
	for _, name := range []string{"Llama-3.3-70B-Instruct", "deepseek-r1", "Phi-4", "mistral-large-latest"} {
		page, err := FoundryReferenceModels(name, 100, 0)
		found := false
		for _, model := range page.Models {
			if model.ID == name {
				found = true
			}
		}
		if err != nil || !found {
			t.Errorf("Foundry reference missing %s: %v", name, err)
		}
	}
}

func TestFoundryReferenceModeAndProviderBoundary(t *testing.T) {
	for _, tc := range []struct {
		row      referenceModel
		accepted bool
	}{
		{referenceModel{"azure/gpt-5", "azure", "chat"}, true},
		{referenceModel{"azure/o3-mini", "azure", "chat"}, true},
		{referenceModel{"azure/gpt-5", "azure_ai", "chat"}, false},
		{referenceModel{"azure_ai/claude-sonnet", "azure_ai", "chat"}, true},
		{referenceModel{"azure/gpt-5-pro", "azure", "responses"}, false},
		{referenceModel{"azure/gpt-image-1", "azure", "image_generation"}, false},
		{referenceModel{"azure/text-embedding-3-large", "azure", "embedding"}, false},
		{referenceModel{"azure/us/gpt-5", "azure", "chat"}, false},
		{referenceModel{"azure/global/gpt-5", "azure", "chat"}, false},
		{referenceModel{"azure/gpt-audio-mini", "azure", "chat"}, false},

		{referenceModel{"azure/mistral-large-latest", "azure", "chat"}, true},
		{referenceModel{"azure_ai/Llama-3.3-70B-Instruct", "azure_ai", "chat"}, true},
		{referenceModel{"gpt-5", "azure", "chat"}, false},
	} {
		name, ok := foundryReferenceName(tc.row)
		if ok != tc.accepted || ok && name != strings.TrimPrefix(tc.row.ID, tc.row.Provider+"/") {
			t.Errorf("%+v -> %q %v", tc.row, name, ok)
		}
	}
}

func TestFoundryReferenceBounds(t *testing.T) {
	for _, tc := range []struct {
		query         string
		limit, offset int
	}{
		{"", 0, 0}, {"", 101, 0}, {"", 50, -1}, {"", 50, 10001}, {strings.Repeat("x", 101), 50, 0}, {strings.Repeat("界", 101), 50, 0},
	} {
		if _, err := FoundryReferenceModels(tc.query, tc.limit, tc.offset); usageStatus(err) != 400 {
			t.Errorf("invalid query accepted: %+v %v", tc, err)
		}
	}
	if page, err := FoundryReferenceModels(strings.Repeat("界", 100), 50, 0); err != nil || page.Total != 0 {
		t.Fatal("query character bound", page, err)
	}
}

func TestProviderReferenceModeCatalog(t *testing.T) {
	for _, tc := range []struct {
		provider string
		mode     ModelMode
		query    string
		want     string
	}{
		{"openai", ModeEmbedding, "text-embedding-3", "openai/text-embedding-3-small"},
		{"openai", ModeAudioSpeech, "tts-1", "openai/tts-1"},
		{"openai", ModeAudioTranscription, "whisper", "openai/whisper-1"},
		{"openai", ModeImageGeneration, "dall-e-3", "openai/dall-e-3"},
		{"groq", ModeAudioTranscription, "whisper", "groq/whisper-large-v3"},
	} {
		page, err := ProviderReferenceModels(tc.provider, tc.mode, tc.query, 100, 0)
		found := false
		for _, m := range page.Models {
			if m.ID == tc.want {
				found = true
			}
		}
		if err != nil || !found {
			t.Errorf("%+v: %v %v", tc, page, err)
		}
	}
	page, err := ProviderReferenceModels("openai", ModeEmbedding, "dall-e", 100, 0)
	if err != nil || page.Total != 0 {
		t.Fatal("cross-mode catalog", page, err)
	}
	if _, err := ProviderReferenceModels("openai", ModelMode("unknown"), "", 100, 0); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := ProviderReferenceModels("custom", ModeEmbedding, "", 100, 0); err == nil {
		t.Fatal("custom incorrectly used public catalog")
	}

}
func TestFoundryReferenceSelectedMode(t *testing.T) {
	for _, mode := range []ModelMode{ModeEmbedding, ModeImageGeneration, ModeAudioSpeech, ModeAudioTranscription} {
		page, err := FoundryReferenceModelsForMode(mode, "", 100, 0)
		if err != nil || page.Total == 0 {
			t.Fatalf("%s %v %v", mode, page, err)
		}
		for _, m := range page.Models {
			if strings.Contains(m.ID, "/") {
				t.Fatal("regional alias advertised", m)
			}
		}
	}
}

func TestFoundryClaudeCatalog(t *testing.T) {
	page, err := FoundryReferenceModels("claude-opus-5", 50, 0)
	if err != nil || len(page.Models) != 1 || page.Models[0].ID != "claude-opus-5" {
		t.Fatalf("missing deployed Claude suggestion: %+v %v", page, err)
	}
}
