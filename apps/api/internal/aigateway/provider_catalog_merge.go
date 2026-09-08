package aigateway

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Merge before paging so an older native match cannot hide a newer reference
// model, or a reference name hide a customer's actual deployment alias.
func mergedProviderCatalog(ctx context.Context, engine ProviderEngine, provider string, mode ModelMode, foundry bool, configured []ProviderModel, query string, limit, offset int) (ProviderModelPage, error) {
	if !ValidModelMode(mode) || utf8.RuneCountInString(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	names := map[string]ProviderModel{}
	add := func(model ProviderModel) {
		if strings.HasPrefix(model.ID, provider+"/") && engineModel.MatchString(model.ID) && strings.Contains(strings.ToLower(model.ID), strings.ToLower(query)) {
			names[model.ID] = model
		}
	}
	for start := 0; ; start += 100 {
		var reference ProviderModelPage
		var err error
		if foundry {
			reference, err = FoundryReferenceModelsForMode(mode, query, 100, start)
		} else {
			reference, err = ProviderReferenceModels(provider, mode, query, 100, start)
		}
		if err != nil {
			return ProviderModelPage{}, err
		}
		for _, model := range reference.Models {
			if foundry {
				model.ID = provider + "/" + model.ID
			}
			add(model)
		}
		if start+100 >= reference.Total {
			break
		}
	}
	// Read retained native pages within the existing client limits and one shared
	// deadline. This never refreshes upstream models or sends a provider key.
	native, err := retainedNativeCatalog(ctx, engine, provider, query)
	if err == nil {
		for _, model := range native {
			add(model)
		}
	} else if len(names) == 0 && len(configured) == 0 {
		return ProviderModelPage{}, aiUnavailable()
	}
	for _, model := range configured {
		add(model)
	}
	ids := make([]string, 0, len(names))
	for id := range names {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := ProviderModelPage{Models: []ProviderModel{}, Total: len(ids)}
	for _, id := range ids[min(offset, len(ids)):min(offset+limit, len(ids))] {
		out.Models = append(out.Models, names[id])
	}
	return out, nil
}

func retainedNativeCatalog(ctx context.Context, engine ProviderEngine, provider, query string) ([]ProviderModel, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	models := []ProviderModel{}
	total := -1
	for offset := 0; offset < 10000; {
		page, err := engine.ProviderModels(ctx, provider, query, 100, offset)
		if err != nil || page.Total < 0 || page.Total > 10000 || (total >= 0 && page.Total != total) || len(page.Models) > 100 || offset+len(page.Models) > page.Total {
			return nil, errEngine
		}
		total = page.Total
		models = append(models, page.Models...)
		offset += len(page.Models)
		if offset == total {
			return models, nil
		}
		if len(page.Models) == 0 {
			return nil, errEngine
		}
	}
	return nil, errEngine
}
