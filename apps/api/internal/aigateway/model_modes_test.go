package aigateway

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestModelModesDefaultsAndValidation(t *testing.T) {
	models := []string{"openai/a", "openai/b"}
	previous := map[string]ModelMode{"openai/a": ModeEmbedding, "openai/removed": ModeRerank}
	got := completeModelModes(models, nil, previous)
	if !reflect.DeepEqual(got, map[string]ModelMode{"openai/a": ModeEmbedding, "openai/b": ModeChat}) {
		t.Fatal(got)
	}
	got = completeModelModes(models, map[string]ModelMode{"openai/a": ModeCompletion}, previous)
	if got["openai/a"] != ModeCompletion || previous["openai/a"] != ModeEmbedding {
		t.Fatal("update mutated prior state", got)
	}
	for _, modes := range []map[string]ModelMode{{"openai/a": ""}, {"openai/a": "unknown"}, {"openai/other": ModeChat}} {
		if validModelModes(models, modes) {
			t.Fatal("invalid mode map accepted", modes)
		}
	}
	for _, mode := range []ModelMode{ModeChat, ModeCompletion, ModeEmbedding, ModeAudioSpeech, ModeAudioTranscription, ModeImageGeneration, ModeVideoGeneration, ModeRerank} {
		if !ValidModelMode(mode) {
			t.Fatal(mode)
		}
	}
	if ValidModelMode("") || DefaultModelMode("") != ModeChat {
		t.Fatal("default boundary")
	}
}

func TestModeSpecificMonetaryReadiness(t *testing.T) {
	one := 1.0
	p := &Policies{engine: usageEngineFixture{
		price: func(context.Context, string, string) (Price, error) { return Price{InputCostPerToken: &one}, nil },
		usage: func(context.Context, []string, time.Time, time.Time) (Usage, error) { return Usage{}, nil },
	}}
	tx := usageTxFixture{query: func(context.Context, string, ...any) (pgx.Rows, error) {
		return &usageRowsFixture{ids: []string{"fixture-key"}}, nil
	}}
	for _, mode := range []ModelMode{ModeChat, ModeCompletion, ModeEmbedding, ModeAudioSpeech, ModeAudioTranscription, ModeImageGeneration, ModeVideoGeneration, ModeRerank} {
		want := 403
		if mode == ModeEmbedding {
			want = 0
		}
		if err := p.enforceCostMode(context.Background(), tx, uuid.New(), uuid.New(), "openai/model", mode, &one); usageStatus(err) != want {
			t.Errorf("%s -> %v", mode, err)
		}
		if err := p.enforceCostMode(context.Background(), nil, uuid.Nil, uuid.Nil, "openai/model", mode, nil); err != nil {
			t.Fatal("no-policy request incorrectly queries pricing", err)
		}
	}
}
