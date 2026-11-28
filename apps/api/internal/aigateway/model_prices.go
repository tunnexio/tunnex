package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AI-READY-1: operator model prices. The control-plane row is the source of
// truth; the engine receives provider-key-scoped overrides (see
// docs/AI-READY-1-decisions.md). Admission uses a price only once the engine
// has confirmed it (applied_revision = revision), so the two never disagree.

const (
	maxModelPricePerToken  = 0.01
	maxModelPricesPerOrg   = 500
	maxModelPriceLookups   = 200
	ModelPriceSourceCustom = "override"
	ModelPriceSourceBundle = "catalog"
	ModelPriceSourceNone   = "unknown"
)

type ModelPrice struct {
	Model              string
	InputCostPerToken  *float64
	OutputCostPerToken *float64
	Removed            bool
	Revision           int64
	AppliedRevision    int64
	Status             string
	UpdatedAt          time.Time
}

type EffectiveModelPrice struct {
	Model              string
	Source             string
	InputCostPerToken  *float64
	OutputCostPerToken *float64
}

func modelPriceInvalid() error {
	return apierr.BadRequest("invalid_model_price", "model price must be a provider-qualified model and finite USD per-token values between 0 and 0.01")
}
func modelPriceConflict() error {
	return apierr.New(409, "ai_model_price_revision_conflict", "Model price changed; refresh and retry")
}

const modelPriceColumns = `model,input_cost_per_token,output_cost_per_token,removed,revision,applied_revision,status,updated_at`

func scanModelPrice(row pgx.Row) (ModelPrice, error) {
	var p ModelPrice
	err := row.Scan(&p.Model, &p.InputCostPerToken, &p.OutputCostPerToken, &p.Removed, &p.Revision, &p.AppliedRevision, &p.Status, &p.UpdatedAt)
	return p, err
}

// modelModeForPrice is the mode a configured connection declares for the
// model, else the bundled catalog's, else chat.
func modelModeForPrice(ctx context.Context, tx pgx.Tx, org uuid.UUID, model string) (ModelMode, error) {
	rows, err := tx.Query(ctx, `SELECT model_modes->>$2 FROM ai_provider_connections WHERE org_id=$1 AND deleted_at IS NULL AND $2=ANY(models)`, org, model)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var mode *string
		if rows.Scan(&mode) != nil {
			return "", errEngine
		}
		if mode != nil && ValidModelMode(ModelMode(*mode)) {
			return ModelMode(*mode), nil
		}
		return ModeChat, nil
	}
	if rows.Err() != nil {
		return "", rows.Err()
	}
	if loadModelCatalog() == nil {
		if refs := bakedCatalogIndex[model]; len(refs) > 0 && ValidModelMode(refs[0].Mode) {
			return refs[0].Mode, nil
		}
	}
	return ModeChat, nil
}

// ListModelPrices returns the organization's prices (removed ones omitted)
// and, for each requested model, the price admission would use and its source.
func (s *Policies) ListModelPrices(ctx context.Context, org uuid.UUID, models []string) ([]ModelPrice, []EffectiveModelPrice, error) {
	if s == nil || s.pool == nil {
		return nil, nil, aiUnavailable()
	}
	if len(models) > maxModelPriceLookups {
		return nil, nil, modelPriceInvalid()
	}
	for _, m := range models {
		if _, _, ok := splitProviderModel(m); !ok {
			return nil, nil, modelPriceInvalid()
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT `+modelPriceColumns+` FROM ai_model_price_overrides WHERE org_id=$1 AND NOT removed ORDER BY model LIMIT 501`, org)
	if err != nil {
		return nil, nil, aiUnavailable()
	}
	defer rows.Close()
	prices := []ModelPrice{}
	byModel := map[string]ModelPrice{}
	for rows.Next() {
		p, err := scanModelPrice(rows)
		if err != nil {
			return nil, nil, aiUnavailable()
		}
		prices = append(prices, p)
		byModel[p.Model] = p
	}
	if rows.Err() != nil {
		return nil, nil, aiUnavailable()
	}
	effective := make([]EffectiveModelPrice, 0, len(models))
	seen := map[string]bool{}
	for _, m := range models {
		if seen[m] {
			continue
		}
		seen[m] = true
		if p, ok := byModel[m]; ok && p.AppliedRevision == p.Revision {
			effective = append(effective, EffectiveModelPrice{Model: m, Source: ModelPriceSourceCustom, InputCostPerToken: p.InputCostPerToken, OutputCostPerToken: p.OutputCostPerToken})
			continue
		}
		provider, native, _ := splitProviderModel(m)
		ref, err := ReferencePrice(provider, native)
		if err == nil && ref.InputCostPerToken != nil {
			effective = append(effective, EffectiveModelPrice{Model: m, Source: ModelPriceSourceBundle, InputCostPerToken: ref.InputCostPerToken, OutputCostPerToken: ref.OutputCostPerToken})
			continue
		}
		effective = append(effective, EffectiveModelPrice{Model: m, Source: ModelPriceSourceNone})
	}
	return prices, effective, nil
}

// PutModelPrice sets one model's price. expected is the current revision (0
// when the model has never had a price). The engine is reconciled at once;
// a failed reconcile leaves the price pending (admission keeps the bundled
// price) and the leader retries.
func (s *Policies) PutModelPrice(ctx context.Context, org, actor uuid.UUID, model string, input, output *float64, expected int64) (ModelPrice, error) {
	if s == nil || s.pool == nil {
		return ModelPrice{}, aiUnavailable()
	}
	if _, _, ok := splitProviderModel(model); !ok || input == nil || !validOverrideRate(input) || !validOverrideRate(output) || expected < 0 || expected == math.MaxInt64 {
		return ModelPrice{}, modelPriceInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	mode, err := modelModeForPrice(ctx, tx, org, model)
	if err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	if _, ok := priceOverrideRequestTypes(mode); !ok {
		return ModelPrice{}, apierr.BadRequest("model_price_mode_unsupported", "prices can be set for chat, completion and embedding models")
	}
	if mode != ModeEmbedding && output == nil {
		return ModelPrice{}, modelPriceInvalid()
	}
	var p ModelPrice
	if expected == 0 {
		var count int
		if tx.QueryRow(ctx, `SELECT count(*) FROM ai_model_price_overrides WHERE org_id=$1 AND NOT removed`, org).Scan(&count) != nil {
			return ModelPrice{}, aiUnavailable()
		}
		if count >= maxModelPricesPerOrg {
			return ModelPrice{}, apierr.New(409, "ai_model_price_limit", "an organization can set at most 500 model prices")
		}
		// 0 means "no live price": a new row, or a removed one set again (its
		// revision keeps increasing).
		p, err = scanModelPrice(tx.QueryRow(ctx, `INSERT INTO ai_model_price_overrides AS o(org_id,model,input_cost_per_token,output_cost_per_token,updated_by) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT (org_id,model) DO UPDATE SET input_cost_per_token=EXCLUDED.input_cost_per_token,output_cost_per_token=EXCLUDED.output_cost_per_token,removed=false,revision=o.revision+1,status='pending',updated_by=EXCLUDED.updated_by WHERE o.removed
 RETURNING o.model,o.input_cost_per_token,o.output_cost_per_token,o.removed,o.revision,o.applied_revision,o.status,o.updated_at`, org, model, input, output, actor))
	} else {
		p, err = scanModelPrice(tx.QueryRow(ctx, `UPDATE ai_model_price_overrides SET input_cost_per_token=$3,output_cost_per_token=$4,removed=false,revision=revision+1,status='pending',updated_by=$5 WHERE org_id=$1 AND model=$2 AND revision=$6 RETURNING `+modelPriceColumns, org, model, input, output, actor, expected))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ModelPrice{}, modelPriceConflict()
	}
	if err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_model_price.changed','ai_model_price',$3,jsonb_build_object('revision',$4::bigint,'input_cost_per_token',$5::double precision,'output_cost_per_token',$6::double precision))`, org, actor, model, p.Revision, input, output); err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return ModelPrice{}, aiUnavailable()
	}
	return s.modelPriceAfterReconcile(ctx, org, p), nil
}

// RemoveModelPrice keeps a tombstone so the revision only increases.
func (s *Policies) RemoveModelPrice(ctx context.Context, org, actor uuid.UUID, model string, expected int64) (ModelPrice, error) {
	if s == nil || s.pool == nil {
		return ModelPrice{}, aiUnavailable()
	}
	if _, _, ok := splitProviderModel(model); !ok || expected < 1 || expected == math.MaxInt64 {
		return ModelPrice{}, modelPriceInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanModelPrice(tx.QueryRow(ctx, `UPDATE ai_model_price_overrides SET input_cost_per_token=NULL,output_cost_per_token=NULL,removed=true,revision=revision+1,status='pending',updated_by=$3 WHERE org_id=$1 AND model=$2 AND revision=$4 AND NOT removed RETURNING `+modelPriceColumns, org, model, actor, expected))
	if errors.Is(err, pgx.ErrNoRows) {
		return ModelPrice{}, modelPriceConflict()
	}
	if err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_model_price.removed','ai_model_price',$3,jsonb_build_object('revision',$4::bigint))`, org, actor, model, p.Revision); err != nil {
		return ModelPrice{}, aiUnavailable()
	}
	if tx.Commit(ctx) != nil {
		return ModelPrice{}, aiUnavailable()
	}
	return s.modelPriceAfterReconcile(ctx, org, p), nil
}

func (s *Policies) modelPriceAfterReconcile(ctx context.Context, org uuid.UUID, p ModelPrice) ModelPrice {
	workCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_ = s.ReconcileModelPrices(workCtx, org)
	if fresh, err := scanModelPrice(s.pool.QueryRow(ctx, `SELECT `+modelPriceColumns+` FROM ai_model_price_overrides WHERE org_id=$1 AND model=$2`, org, p.Model)); err == nil {
		return fresh
	}
	return p
}

// priceOverrideNameFor is deterministic per managed key and model, so the
// engine-assigned ID is never needed to find Tunnex's own override.
func priceOverrideNameFor(keyID, model string) string {
	sum := sha256.Sum256([]byte(keyID + "\x00" + model))
	return priceOverrideNamePrefix + hex.EncodeToString(sum[:])[:24]
}

func sameRate(a, b *float64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// ReconcileModelPrices converges the engine's Tunnex-named overrides on every
// live connection key of the organization, reads them back, and marks the
// confirmed revisions applied. Overrides not named by Tunnex are never touched.
func (s *Policies) ReconcileModelPrices(ctx context.Context, org uuid.UUID) error {
	if s == nil || s.pool == nil || org == uuid.Nil {
		return aiUnavailable()
	}
	engine, ok := s.engine.(PriceOverrideEngine)
	if !ok {
		return aiUnavailable()
	}
	// One reconcile per organization at a time, across replicas.
	lock, err := s.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(lock)
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_xact_lock(71410002, hashtext($1::text))`, org); err != nil {
		return aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT `+modelPriceColumns+` FROM ai_model_price_overrides WHERE org_id=$1 ORDER BY model LIMIT 2000`, org)
	if err != nil {
		return aiUnavailable()
	}
	var prices []ModelPrice
	for rows.Next() {
		p, err := scanModelPrice(rows)
		if err != nil {
			rows.Close()
			return aiUnavailable()
		}
		prices = append(prices, p)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	if len(prices) == 0 {
		return nil
	}
	crows, err := s.pool.Query(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND deleted_at IS NULL ORDER BY key_id LIMIT 200`, org)
	if err != nil {
		return aiUnavailable()
	}
	var conns []ProviderConnection
	for crows.Next() {
		p, err := scanProvider(crows)
		if err != nil {
			crows.Close()
			return aiUnavailable()
		}
		conns = append(conns, p)
	}
	crows.Close()
	if crows.Err() != nil {
		return aiUnavailable()
	}
	failed := false
	for _, c := range conns {
		if !managedProviderKeyID.MatchString(c.KeyID) {
			continue
		}
		provider := nativeConnectionProvider(c)
		desired := map[string]EnginePriceOverride{}
		for _, p := range prices {
			mprov, native, ok := splitProviderModel(p.Model)
			if !ok || p.Removed || mprov != provider || p.InputCostPerToken == nil {
				continue
			}
			mode := ModeChat
			if slices.Contains(c.Models, p.Model) {
				mode = DefaultModelMode(c.ModelModes[p.Model])
			} else if loadModelCatalog() == nil {
				if refs := bakedCatalogIndex[p.Model]; len(refs) > 0 {
					mode = refs[0].Mode
				}
			}
			types, ok := priceOverrideRequestTypes(mode)
			if !ok {
				continue
			}
			o := EnginePriceOverride{Name: priceOverrideNameFor(c.KeyID, p.Model), ProviderKeyID: c.KeyID, Pattern: native, RequestTypes: types, Input: p.InputCostPerToken, Output: p.OutputCostPerToken}
			desired[o.Name] = o
		}
		if err := convergePriceOverrides(ctx, engine, c.KeyID, desired); err != nil {
			failed = true
		}
	}
	status := "applied"
	if failed {
		status = "error"
	}
	for _, p := range prices {
		if p.AppliedRevision == p.Revision && p.Status == status {
			continue
		}
		if failed {
			_, _ = s.pool.Exec(ctx, `UPDATE ai_model_price_overrides SET status='error' WHERE org_id=$1 AND model=$2 AND revision=$3 AND applied_revision<revision`, org, p.Model, p.Revision)
			continue
		}
		if _, err := s.pool.Exec(ctx, `UPDATE ai_model_price_overrides SET status='applied',applied_revision=revision WHERE org_id=$1 AND model=$2 AND revision=$3`, org, p.Model, p.Revision); err != nil {
			return aiUnavailable()
		}
	}
	if failed {
		return aiUnavailable()
	}
	return nil
}

func convergePriceOverrides(ctx context.Context, engine PriceOverrideEngine, keyID string, desired map[string]EnginePriceOverride) error {
	current, err := engine.ListPriceOverrides(ctx, keyID)
	if err != nil {
		return err
	}
	have := map[string]EnginePriceOverride{}
	for _, o := range current {
		if !priceOverrideName.MatchString(o.Name) {
			continue // not Tunnex's: never touched
		}
		if _, dup := have[o.Name]; dup || desired[o.Name].Name == "" {
			if err := engine.DeletePriceOverride(ctx, o.ID); err != nil {
				return err
			}
			continue
		}
		have[o.Name] = o
	}
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want := desired[name]
		got, ok := have[name]
		switch {
		case !ok:
			err = engine.CreatePriceOverride(ctx, want)
		case got.Pattern != want.Pattern || !slices.Equal(got.RequestTypes, want.RequestTypes) || !sameRate(got.Input, want.Input) || !sameRate(got.Output, want.Output):
			err = engine.UpdatePriceOverride(ctx, got.ID, want)
		}
		if err != nil {
			return err
		}
	}
	// Read back: exactly the desired Tunnex overrides, with the desired values.
	after, err := engine.ListPriceOverrides(ctx, keyID)
	if err != nil {
		return err
	}
	matched := 0
	for _, o := range after {
		if !priceOverrideName.MatchString(o.Name) {
			continue
		}
		want, ok := desired[o.Name]
		if !ok || o.Pattern != want.Pattern || !slices.Equal(o.RequestTypes, want.RequestTypes) || !sameRate(o.Input, want.Input) || !sameRate(o.Output, want.Output) {
			return errEngineScope
		}
		matched++
	}
	if matched != len(desired) {
		return errEngineScope
	}
	return nil
}

// ReconcileAllModelPrices is the leader's bounded pass: organizations with a
// pending price first, then every organization that has prices (new
// connections and engine data loss converge here).
func (s *Policies) ReconcileAllModelPrices(ctx context.Context, limit int) (int, error) {
	if s == nil || s.pool == nil {
		return 0, aiUnavailable()
	}
	if _, ok := s.engine.(PriceOverrideEngine); !ok {
		return 0, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT org_id FROM ai_model_price_overrides GROUP BY org_id ORDER BY bool_or(applied_revision<revision) DESC, org_id LIMIT $1`, limit)
	if err != nil {
		return 0, aiUnavailable()
	}
	var orgs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			rows.Close()
			return 0, aiUnavailable()
		}
		orgs = append(orgs, id)
	}
	rows.Close()
	done := 0
	var last error
	for _, org := range orgs {
		if err := s.ReconcileModelPrices(ctx, org); err != nil {
			last = err
			continue
		}
		done++
	}
	return done, last
}

// admissionPrice is the price cost admission uses: an engine-confirmed
// operator price first, then the bundled catalog's exact price.
func (s *Policies) admissionPrice(ctx context.Context, tx pgx.Tx, org uuid.UUID, provider, native string) (Price, error) {
	var input, output *float64
	err := tx.QueryRow(ctx, `SELECT input_cost_per_token,output_cost_per_token FROM ai_model_price_overrides WHERE org_id=$1 AND model=$2 AND NOT removed AND applied_revision=revision`, org, provider+"/"+native).Scan(&input, &output)
	if err == nil {
		return Price{Known: input != nil && output != nil, InputCostPerToken: input, OutputCostPerToken: output}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Price{}, err
	}
	return s.engine.Price(ctx, provider, native)
}
