package aigateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFoundryReferenceSnapshotProvenance(t *testing.T) {
	var snapshot referenceSnapshot
	if err := json.Unmarshal(foundryReferenceJSON, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceCommit != "eeb7732fc11fd47762ca84cc3fb7cc74235d7097" || snapshot.SourceSHA256 != "f68d88c12610ea31ab355a1293fde55aeed6fa78a1f4b182c67be47d80b1d202" || snapshot.SourcePath != "model_prices_and_context_window.json" || len(snapshot.Entries) != 230 {
		t.Fatal("snapshot provenance changed without qualification")
	}
	sum := sha256.Sum256(foundryReferenceJSON)
	if hex.EncodeToString(sum[:]) != "d5cbd48d1ef1dcb2eb852e5cb90eb8ac55b24deabf929a6e18e922904cbfe137" {
		t.Fatal("derived source changed: review source pin and metadata")
	}
}

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
		if strings.Contains(model.ID, "audio") || strings.Contains(model.ID, "realtime") || strings.Contains(model.ID, "codex") || strings.Contains(model.ID, "embedding") || strings.Contains(model.ID, "claude") || strings.Contains(model.ID, "/") {
			t.Fatal("unsupported mode/provider alias advertised", model)
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
		{referenceModel{"azure_ai/claude-sonnet", "azure_ai", "chat"}, false},
		{referenceModel{"azure/gpt-5-pro", "azure", "responses"}, false},
		{referenceModel{"azure/gpt-image-1", "azure", "image_generation"}, false},
		{referenceModel{"azure/text-embedding-3-large", "azure", "embedding"}, false},
		{referenceModel{"azure/us/gpt-5", "azure", "chat"}, false},
		{referenceModel{"azure/global/gpt-5", "azure", "chat"}, false},
		{referenceModel{"azure/gpt-audio-mini", "azure", "chat"}, false},
		{referenceModel{"azure/container", "azure", "chat"}, false},
		{referenceModel{"azure/computer-use-preview", "azure", "chat"}, false},
		{referenceModel{"azure/mistral-large-latest", "azure", "chat"}, false},
		{referenceModel{"gpt-5", "azure", "chat"}, false},
	} {
		name, ok := foundryReferenceName(tc.row)
		if ok != tc.accepted || ok && name != strings.TrimPrefix(tc.row.ID, "azure/") {
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
