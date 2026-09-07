package aigateway

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type ProviderConnection struct {
	ID                        uuid.UUID
	EndpointURL               *string
	KeyID, Provider, Name     string
	Models                    []string
	Enabled                   bool
	Revision, AppliedRevision int64
	Status, LastTestStatus    string
	LastTestAt                *time.Time
	DeletedAt                 *time.Time
}
type ProviderInput struct {
	Name, Provider string
	EndpointURL    *string
	Models         []string
	Enabled        bool
	Secret         *string
}

const providerColumns = `id,key_id,provider,name,models,enabled,revision,applied_revision,status,last_test_status,last_test_at,deleted_at,endpoint_url`

func scanProvider(row pgx.Row) (ProviderConnection, error) {
	var p ProviderConnection
	err := row.Scan(&p.ID, &p.KeyID, &p.Provider, &p.Name, &p.Models, &p.Enabled, &p.Revision, &p.AppliedRevision, &p.Status, &p.LastTestStatus, &p.LastTestAt, &p.DeletedAt, &p.EndpointURL)
	return p, err
}
func (s *Policies) EnableProviderManagement(enabled bool) { s.providerManagement = enabled }
func (s *Policies) ProviderManagementAvailable() bool {
	if s == nil || s.pool == nil || !s.providerManagement {
		return false
	}
	_, ok := s.engine.(ProviderEngine)
	return ok
}
func providerMissing() error {
	return apierr.New(404, "ai_provider_not_found", "AI provider connection is unavailable")
}
func providerInvalid() error {
	return apierr.New(400, "invalid_ai_provider", "AI provider configuration is not acceptable")
}
func providerConflict() error {
	return apierr.New(409, "ai_provider_conflict", "AI provider configuration changed or is still referenced; refresh and retry")
}
func validateProviderInput(in ProviderInput, required bool) (ProviderInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if (!supportedProvider(in.Provider) && !endpointProvider(in.Provider)) || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 80 {
		return in, providerInvalid()
	}
	if endpointProvider(in.Provider) {
		if in.EndpointURL == nil || len(*in.EndpointURL) > 2048 {
			return in, providerInvalid()
		}
		normalized, err := aiegress.NormalizeEndpoint(*in.EndpointURL)
		if err != nil {
			return in, providerInvalid()
		}
		in.EndpointURL = &normalized
		if len(in.Models) < 1 || len(in.Models) > 32 {
			return in, providerInvalid()
		}
		for _, model := range in.Models {
			if !engineModel.MatchString(model) {
				return in, providerInvalid()
			}
		}
	} else {
		if in.EndpointURL != nil {
			return in, providerInvalid()
		}
		var ok bool
		in.Models, ok = canonicalModels(in.Models, false)
		if !ok {
			return in, providerInvalid()
		}
		for _, model := range in.Models {
			if provider, _, ok := splitProviderModel(model); !ok || provider != in.Provider {
				return in, providerInvalid()
			}
		}
	}
	if required && in.Secret == nil {
		return in, providerInvalid()
	}
	if in.Secret != nil && (len(*in.Secret) < 1 || len(*in.Secret) > 4096 || strings.IndexFunc(*in.Secret, unicode.IsSpace) >= 0 || strings.IndexFunc(*in.Secret, unicode.IsControl) >= 0) {
		return in, providerInvalid()
	}
	return in, nil
}
func providerSpec(p ProviderConnection) ProviderKeySpec {
	base := ""
	if p.EndpointURL != nil {
		base = *p.EndpointURL
	}
	return ProviderKeySpec{Provider: nativeConnectionProvider(p), BaseURL: base, ID: p.KeyID, Revision: p.Revision, Models: p.Models, Enabled: p.Enabled}
}

// validateProviderAccess is called under the team lock. Sorted provider locks are
// held through policy mutation/admission; writers never acquire team locks.
func (s *Policies) validateProviderAccess(ctx context.Context, tx pgx.Tx, org uuid.UUID, ids, models []string) error {
	_, err := s.providerScopes(ctx, tx, org, ids, models)
	return err
}

// providerScopes derives routing solely from authenticated ownership rows and
// retains sorted locks through the caller's transaction. Legacy keys cover only
// OpenRouter; a model vendor component never selects a direct provider.
func (s *Policies) providerScopes(ctx context.Context, tx pgx.Tx, org uuid.UUID, ids, models []string) ([]EngineProviderScope, error) {
	sorted := append([]string(nil), ids...)
	slices.Sort(sorted)
	covered := map[string]bool{}
	keys := map[string][]string{}
	legacy := false
	for _, id := range sorted {
		if !strings.HasPrefix(id, "tnx-managed-") {
			var ok bool
			if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ai_provider_legacy_keys WHERE org_id=$1 AND key_id=$2)`, org, id).Scan(&ok) != nil {
				return nil, aiUnavailable()
			}
			if !ok {
				return nil, policyDenied()
			}
			legacy = true
			keys["openrouter"] = append(keys["openrouter"], id)
			continue
		}
		p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND key_id=$2 FOR SHARE`, org, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, policyDenied()
			}
			return nil, aiUnavailable()
		}
		if p.DeletedAt != nil || !p.Enabled || p.Status != "applied" || p.Revision != p.AppliedRevision || (!supportedProvider(p.Provider) && !endpointProvider(p.Provider)) {
			return nil, policyDenied()
		}
		nativeProvider := nativeConnectionProvider(p)
		if endpointProvider(p.Provider) && !s.customConnectionEligible(p) {
			return nil, policyDenied()
		}
		keys[nativeProvider] = append(keys[nativeProvider], id)
		for _, m := range p.Models {
			provider, _, ok := splitProviderModel(m)
			if !ok || provider != nativeProvider {
				return nil, policyDenied()
			}
			covered[m] = true
		}
	}
	selected := map[string][]string{}
	for _, m := range models {
		provider, native, ok := splitProviderModel(m)
		if !ok || (!covered[m] && !(legacy && provider == "openrouter")) {
			return nil, policyDenied()
		}
		selected[provider] = append(selected[provider], native)
	}
	providers := []string{}
	for provider := range selected {
		providers = append(providers, provider)
	}
	slices.Sort(providers)
	scopes := []EngineProviderScope{}
	for _, provider := range providers {
		slices.Sort(selected[provider])
		if len(keys[provider]) == 0 {
			return nil, policyDenied()
		}
		scopes = append(scopes, EngineProviderScope{Provider: provider, Models: selected[provider], KeyIDs: keys[provider]})
	}
	return scopes, nil
}
func (s *Policies) ListProviders(ctx context.Context, org uuid.UUID) ([]ProviderConnection, []string, error) {
	if s == nil || s.pool == nil {
		return nil, nil, aiUnavailable()
	}
	rows, err := s.pool.Query(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND deleted_at IS NULL ORDER BY created_at,id`, org)
	if err != nil {
		return nil, nil, aiUnavailable()
	}
	items := []ProviderConnection{}
	for rows.Next() {
		p, e := scanProvider(rows)
		if e != nil {
			rows.Close()
			return nil, nil, aiUnavailable()
		}
		items = append(items, p)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, nil, aiUnavailable()
	}
	rows, err = s.pool.Query(ctx, `SELECT key_id FROM ai_provider_legacy_keys WHERE org_id=$1 ORDER BY key_id`, org)
	if err != nil {
		return nil, nil, aiUnavailable()
	}
	legacy := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return nil, nil, aiUnavailable()
		}
		legacy = append(legacy, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, nil, aiUnavailable()
	}
	return items, legacy, nil
}
func (s *Policies) CreateProvider(ctx context.Context, org, actor uuid.UUID, in ProviderInput) (ProviderConnection, error) {
	if !s.ProviderManagementAvailable() {
		return ProviderConnection{}, aiUnavailable()
	}
	in, err := validateProviderInput(in, true)
	if err != nil {
		return ProviderConnection{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	// Dedicated org advisory lock serializes the cap without inverting the
	// device/team/provider/org reconciliation row-lock order.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7141))`, org.String()); err != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM ai_provider_connections WHERE org_id=$1`, org).Scan(&count) != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	if count >= 32 {
		return ProviderConnection{}, providerConflict()
	}
	id := uuid.New()
	if err = s.normalizeCustomModels(&in, id); err != nil {
		return ProviderConnection{}, err
	}
	p, err := scanProvider(tx.QueryRow(ctx, `INSERT INTO ai_provider_connections(id,org_id,key_id,provider,name,models,enabled,revision,status,endpoint_url) VALUES($1,$2,$3,$7,$4,$5,$6,1,'pending',$8) RETURNING `+providerColumns, id, org, "tnx-managed-"+id.String(), in.Name, in.Models, in.Enabled, in.Provider, in.EndpointURL))
	if err != nil {
		return p, aiUnavailable()
	}
	if auditPolicy(ctx, tx, org, actor, id, "ai_provider.created", 1) != nil || tx.Commit(ctx) != nil {
		return p, aiUnavailable()
	}
	return s.syncProvider(ctx, org, p.ID, p.Revision, in.Secret, false)
}
func (s *Policies) UpdateProvider(ctx context.Context, org, actor, id uuid.UUID, in ProviderInput, expected int64) (ProviderConnection, error) {
	if !s.ProviderManagementAvailable() {
		return ProviderConnection{}, aiUnavailable()
	}
	in, err := validateProviderInput(in, false)
	if err != nil || expected < 1 || expected == math.MaxInt64 {
		return ProviderConnection{}, providerInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return p, providerMissing()
	}
	if err != nil {
		return p, aiUnavailable()
	}
	if err = s.normalizeCustomModels(&in, id); err != nil {
		return p, err
	}
	if (p.EndpointURL == nil) != (in.EndpointURL == nil) || (p.EndpointURL != nil && *p.EndpointURL != *in.EndpointURL) {
		return p, providerInvalid()
	}
	if p.Provider != in.Provider {
		return p, providerInvalid()
	}
	if p.Revision != expected {
		return p, providerConflict()
	}
	if (p.Status == "error" || p.Status == "pending") && in.Secret == nil {
		return p, apierr.New(409, "ai_provider_secret_required", "Resubmit the provider API key to recover this connection")
	}
	removed := []string{}
	for _, model := range p.Models {
		if !slices.Contains(in.Models, model) {
			removed = append(removed, model)
		}
	}
	var referenced bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ai_gateway_team_policies WHERE org_id=$1 AND $2=ANY(key_ids) AND models && $3::text[])`, org, p.KeyID, removed).Scan(&referenced) != nil {
		return p, aiUnavailable()
	}
	if referenced {
		return p, providerConflict()
	}
	p, err = scanProvider(tx.QueryRow(ctx, `UPDATE ai_provider_connections SET name=$3,models=$4,enabled=$5,revision=revision+1,status='pending',last_test_status=CASE WHEN $6 THEN 'untested' ELSE last_test_status END,last_test_at=CASE WHEN $6 THEN NULL ELSE last_test_at END WHERE org_id=$1 AND id=$2 RETURNING `+providerColumns, org, id, in.Name, in.Models, in.Enabled, in.Secret != nil))
	if err != nil {
		return p, aiUnavailable()
	}
	if auditPolicy(ctx, tx, org, actor, id, "ai_provider.updated", p.Revision) != nil || tx.Commit(ctx) != nil {
		return p, aiUnavailable()
	}
	return s.syncProvider(ctx, org, id, p.Revision, in.Secret, false)
}
func (s *Policies) syncProvider(ctx context.Context, org, id uuid.UUID, revision int64, secret *string, remove bool) (ProviderConnection, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if err != nil {
		return p, aiUnavailable()
	}
	if p.Revision != revision {
		return p, providerConflict()
	}
	engine := s.engine.(ProviderEngine)
	// Shared provider initialization is serialized across CP replicas.
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(71410001)`)
	if err == nil {
		err = engine.EnsureProvider(ctx, providerSpec(p).Provider, providerSpec(p).BaseURL)
	}
	deleted := false
	if err == nil && remove {
		// Recover an uncertain prior deletion without recreating the native key.
		deleted = engine.DeleteProviderKey(ctx, providerSpec(p)) == nil
	}
	if err == nil && !deleted {
		err = engine.PutProviderKey(ctx, providerSpec(p), secret)
	}
	if err == nil && !deleted {
		err = engine.VerifyProviderKey(ctx, providerSpec(p))
	}
	if err == nil && remove && !deleted {
		err = engine.DeleteProviderKey(ctx, providerSpec(p))
	}
	status := "applied"
	if !p.Enabled {
		status = "disabled"
	}
	applied := p.Revision
	if err != nil {
		status = "error"
		applied = p.AppliedRevision
	}
	// A timeout leaves the already committed pending state in place; no secret
	// is retained for background retry. Public response never contains cause.
	p, e := scanProvider(tx.QueryRow(ctx, `UPDATE ai_provider_connections SET status=$3,applied_revision=$4,deleted_at=CASE WHEN $5 THEN statement_timestamp() ELSE deleted_at END WHERE org_id=$1 AND id=$2 RETURNING `+providerColumns, org, id, status, applied, remove && err == nil))
	if e != nil || tx.Commit(ctx) != nil {
		return p, aiUnavailable()
	}
	if remove && err != nil {
		return p, aiUnavailable()
	}
	return p, nil
}
func (s *Policies) DeleteProvider(ctx context.Context, org, actor, id uuid.UUID, expected int64) error {
	if !s.ProviderManagementAvailable() {
		return aiUnavailable()
	}
	if expected < 1 || expected == math.MaxInt64 {
		return providerInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return providerMissing()
	}
	if err != nil {
		return aiUnavailable()
	}
	if p.Revision != expected {
		return providerConflict()
	}
	var refs bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ai_gateway_team_policies WHERE org_id=$1 AND $2=ANY(key_ids))`, org, p.KeyID).Scan(&refs) != nil {
		return aiUnavailable()
	}
	if refs {
		return providerConflict()
	}
	_, err = tx.Exec(ctx, `UPDATE ai_provider_connections SET enabled=false,status='pending',revision=revision+1 WHERE org_id=$1 AND id=$2`, org, id)
	if err != nil || auditPolicy(ctx, tx, org, actor, id, "ai_provider.deleted", p.Revision+1) != nil || tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	_, err = s.syncProvider(ctx, org, id, p.Revision+1, nil, true)
	return err
}
func (s *Policies) TestProvider(ctx context.Context, org, actor, id uuid.UUID, expected int64) (ProviderConnection, error) {
	if !s.ProviderManagementAvailable() {
		return ProviderConnection{}, aiUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderConnection{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return p, providerMissing()
	}
	if err != nil {
		return p, aiUnavailable()
	}
	if p.Revision != expected || p.AppliedRevision != expected || p.Status == "pending" || p.Status == "error" {
		return p, providerConflict()
	}
	if endpointProvider(p.Provider) && !s.customConnectionEligible(p) {
		return p, providerMissing()
	}
	ok, testErr := s.engine.(ProviderEngine).TestProviderKey(ctx, providerSpec(p))
	status := "failed"
	if testErr == nil && ok {
		status = "success"
	}
	p, err = scanProvider(tx.QueryRow(ctx, `UPDATE ai_provider_connections SET last_test_status=$3,last_test_at=statement_timestamp() WHERE org_id=$1 AND id=$2 RETURNING `+providerColumns, org, id, status))
	if err != nil || auditPolicy(ctx, tx, org, actor, id, "ai_provider.tested", p.Revision) != nil || tx.Commit(ctx) != nil {
		return p, aiUnavailable()
	}
	return p, nil
}
func (s *Policies) ProviderModels(ctx context.Context, provider, query string, limit, offset int) (ProviderModelPage, error) {
	if !s.ProviderManagementAvailable() {
		return ProviderModelPage{}, aiUnavailable()
	}
	if !supportedProvider(provider) || utf8.RuneCountInString(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	p, err := s.engine.(ProviderEngine).ProviderModels(ctx, provider, query, limit, offset)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	return p, nil
}

// ConfigureCustomProviders is called at startup only after the engine's
// authenticated proxy has been configured. No request can modify these rules.
func (s *Policies) ConfigureCustomProviders(policy *aiegress.Policy) { s.customPolicy = policy }
func endpointProvider(provider string) bool                          { return provider == "custom" || provider == "sagemaker" }
func (s *Policies) approvedEndpoints(provider string) []aiegress.Endpoint {
	out := []aiegress.Endpoint{}
	if s == nil || !s.ProviderManagementAvailable() || s.customPolicy == nil {
		return out
	}
	for _, e := range s.customPolicy.Endpoints {
		kind := e.Provider
		if kind == "" {
			kind = "custom"
		}
		if kind == provider {
			out = append(out, aiegress.Endpoint{Name: e.Name, URL: e.URL, Provider: kind})
		}
	}
	return out
}
func (s *Policies) CustomAvailable() bool    { return len(s.approvedEndpoints("custom")) > 0 }
func (s *Policies) SageMakerAvailable() bool { return len(s.approvedEndpoints("sagemaker")) > 0 }
func (s *Policies) ApprovedCustomEndpoints() []aiegress.Endpoint {
	return s.approvedEndpoints("custom")
}
func (s *Policies) ApprovedSageMakerEndpoints() []aiegress.Endpoint {
	return s.approvedEndpoints("sagemaker")
}
func (s *Policies) endpointEligible(provider, raw string) bool {
	if s == nil || s.customPolicy == nil || !s.customPolicy.AllowsEndpoint(raw) {
		return false
	}
	normalized, err := aiegress.NormalizeEndpoint(raw)
	if err != nil {
		return false
	}
	for _, ep := range s.approvedEndpoints(provider) {
		if ep.URL == normalized {
			return true
		}
	}
	return false
}
func nativeConnectionProvider(p ProviderConnection) string {
	if endpointProvider(p.Provider) {
		return "custom-" + p.ID.String()
	}
	return p.Provider
}
func (s *Policies) customConnectionEligible(p ProviderConnection) bool {
	return p.EndpointURL != nil && s.endpointEligible(p.Provider, *p.EndpointURL)
}
func (s *Policies) normalizeCustomModels(in *ProviderInput, id uuid.UUID) error {
	if !endpointProvider(in.Provider) {
		return nil
	}
	if in.EndpointURL == nil || !s.endpointEligible(in.Provider, *in.EndpointURL) {
		return providerInvalid()
	}
	prefix := "custom-" + id.String() + "/"
	out := make([]string, 0, len(in.Models))
	for _, model := range in.Models {
		if namespace, _, hasSlash := strings.Cut(model, "/"); hasSlash && customProviderName(namespace) {
			if !strings.HasPrefix(model, prefix) {
				return providerInvalid()
			}
			model = strings.TrimPrefix(model, prefix)
		}
		if !engineModel.MatchString(model) {
			return providerInvalid()
		}
		out = append(out, prefix+model)
	}
	models, ok := canonicalModels(out, false)
	if !ok {
		return providerInvalid()
	}
	in.Models = models
	return nil
}
func (s *Policies) CustomProviderModels(ctx context.Context, org, id uuid.UUID, query string, limit, offset int) (ProviderModelPage, error) {
	if !s.CustomAvailable() && !s.SageMakerAvailable() {
		return ProviderModelPage{}, aiUnavailable()
	}
	if len(query) > 100 || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return ProviderModelPage{}, providerInvalid()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderModelPage{}, providerMissing()
	}
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	if !endpointProvider(p.Provider) || !p.Enabled || p.Status != "applied" || p.AppliedRevision != p.Revision || !s.customConnectionEligible(p) {
		return ProviderModelPage{}, providerMissing()
	}
	result, err := s.engine.(ProviderEngine).ProviderModels(ctx, nativeConnectionProvider(p), query, limit, offset)
	if err != nil {
		return ProviderModelPage{}, aiUnavailable()
	}
	return result, nil
}
