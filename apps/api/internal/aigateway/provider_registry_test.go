package aigateway

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestProviderRegistryModelAndCostIsolation(t *testing.T) {
	if len(ProviderDefinitions()) != 11 {
		t.Fatal("registry")
	}
	for _, canonical := range []string{"openai/gpt-4o-mini", "anthropic/claude-fixture", "gemini/gemini-fixture", "openrouter/openai/gpt-4o-mini", "groq/fixture", "mistral/fixture", "cerebras/fixture", "xai/fixture", "deepseek/fixture"} {
		provider, model, ok := splitProviderModel(canonical)
		if !ok {
			t.Fatal(canonical)
		}
		if canonical == "openrouter/openai/gpt-4o-mini" && (provider != "openrouter" || model != "openai/gpt-4o-mini") {
			t.Fatal("vendor routed directly")
		}
		secret := "fixture"
		if _, err := validateProviderInput(ProviderInput{Provider: provider, Name: "fixture", Models: []string{canonical}, Secret: &secret}, true); err != nil {
			t.Fatal(err)
		}
		if _, err := validateProviderInput(ProviderInput{Provider: "openrouter", Name: "fixture", Models: []string{canonical}, Secret: &secret}, true); provider != "openrouter" && err == nil {
			t.Fatal("connection model mismatch")
		}
		tx := usageTxFixture{query: func(context.Context, string, ...any) (pgx.Rows, error) {
			return &usageRowsFixture{ids: []string{"owned-key"}}, nil
		}}
		one := 1.0
		p := Policies{engine: usageEngineFixture{price: func(_ context.Context, p, m string) (Price, error) {
			if p != provider || m != model {
				t.Fatalf("wrong price scope %s/%s", p, m)
			}
			return Price{true, &one, &one}, nil
		}, usage: func(context.Context, []string, time.Time, time.Time) (Usage, error) { return Usage{}, nil }}}
		if err := p.enforceCost(context.Background(), tx, uuid.New(), uuid.New(), canonical, &one); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"gpt-4o", "unknown/a", "together/a", "perplexity/a", "openai/", "openai/*", "openai/a b"} {
		if _, _, ok := splitProviderModel(bad); ok {
			t.Fatalf("bad model %q", bad)
		}
	}
}
