package http

import "testing"

func TestAIInferencePathsSkipGenericTimeout(t *testing.T) {
	for path, want := range map[string]bool{
		"/ai/v1/chat/completions":       true,
		"/ai/v1/responses":              true,
		"/ai/anthropic/v1/messages":     true,
		"/ai/v1/embeddings":             true,
		"/ai/v1/audio/transcriptions":   true,
		"/ai/v1/videos":                 false,
		"/ai/v1/videos/x":               false,
		"/ai/v1/models":                 false,
		"/ai/v1/chat/completions/extra": false,
		"/api/v1/workload/token":        false,
		"/api/v1/organizations/o/ai-gateway/inference/v1/chat/completions": true,
		"/api/v1/organizations/o/ai-gateway/inference/v1/videos":           false,
		"/api/v1/organizations/o/ai-gateway/teams":                         false,
		"/api/v1/organizations/o/devices":                                  false,
	} {
		if isAIInferencePath(path) != want {
			t.Errorf("%s: want %v", path, want)
		}
	}
}
