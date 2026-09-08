package aigateway

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ModelMode string

const (
	ModeChat               ModelMode = "chat"
	ModeCompletion         ModelMode = "completion"
	ModeEmbedding          ModelMode = "embedding"
	ModeAudioSpeech        ModelMode = "audio_speech"
	ModeAudioTranscription ModelMode = "audio_transcription"
	ModeImageGeneration    ModelMode = "image_generation"
	ModeVideoGeneration    ModelMode = "video_generation"
	ModeRerank             ModelMode = "rerank"
)

func ValidModelMode(mode ModelMode) bool {
	switch mode {
	case ModeChat, ModeCompletion, ModeEmbedding, ModeAudioSpeech, ModeAudioTranscription, ModeImageGeneration, ModeVideoGeneration, ModeRerank:
		return true
	}
	return false
}
func DefaultModelMode(mode ModelMode) ModelMode {
	if mode == "" {
		return ModeChat
	}
	return mode
}

func validModelModes(models []string, modes map[string]ModelMode) bool {
	for model, mode := range modes {
		if !slices.Contains(models, model) || !ValidModelMode(mode) {
			return false
		}
	}
	return true
}
func completeModelModes(models []string, modes, previous map[string]ModelMode) map[string]ModelMode {
	out := make(map[string]ModelMode, len(models))
	for _, model := range models {
		mode, exists := modes[model]
		if !exists {
			mode = previous[model]
		}
		out[model] = DefaultModelMode(mode)
	}
	return out
}

// The caller already holds the policy/provider scope locks through admission.
// No credential material is read, and operator-owned keys retain chat semantics.
func selectedModelMode(ctx context.Context, tx pgx.Tx, org uuid.UUID, keyIDs []string, model string) (ModelMode, error) {
	mode := ModelMode("")
	for _, key := range keyIDs {
		if !strings.HasPrefix(key, "tnx-managed-") && strings.HasPrefix(model, "openrouter/") {
			mode = ModeChat
		}
	}
	rows, err := tx.Query(ctx, `SELECT model_modes FROM ai_provider_connections WHERE org_id=$1 AND key_id=ANY($2) AND $3=ANY(models) AND deleted_at IS NULL`, org, keyIDs, model)
	if err != nil {
		return "", aiUnavailable()
	}
	defer rows.Close()
	for rows.Next() {
		var modes map[string]ModelMode
		if rows.Scan(&modes) != nil {
			return "", aiUnavailable()
		}
		next := DefaultModelMode(modes[model])
		if !ValidModelMode(next) || mode != "" && mode != next {
			return "", policyDenied()
		}
		mode = next
	}
	if rows.Err() != nil {
		return "", aiUnavailable()
	}
	if mode == "" {
		return "", policyDenied()
	}
	return mode, nil
}
