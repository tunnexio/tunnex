package fqdnresolver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresAudit records resolver lifecycle transitions after their generation
// transaction commits. Profile identity and the matched suffix are included so
// operators can prove which private DNS authority produced (or withdrew) an
// answer without exposing answer payloads or resolver credentials.
type PostgresAudit struct{ pool *pgxpool.Pool }

func NewPostgresAudit(pool *pgxpool.Pool) *PostgresAudit { return &PostgresAudit{pool: pool} }

func (a *PostgresAudit) FQDNPublished(ctx context.Context, work Work, generation Generation) {
	a.write(ctx, work, "fqdn_resource.answers_published", map[string]any{
		"outcome": "succeeded", "generation": work.ExpectedGeneration + 1,
		"answer_count": len(generation.Addresses), "effective_ttl_seconds": int(generation.TTL.Seconds()),
	})
}

func (a *PostgresAudit) FQDNWithdrawn(ctx context.Context, work Work, cause WithdrawalCause, _ time.Time) {
	a.write(ctx, work, "fqdn_resource.answers_withdrawn", map[string]any{
		"outcome": "fail_closed", "generation": work.ExpectedGeneration + 1, "failure_code": string(cause),
	})
}

func (a *PostgresAudit) write(ctx context.Context, work Work, action string, metadata map[string]any) {
	if a == nil || a.pool == nil {
		return
	}
	metadata["resolver_config_id"] = work.ResolverConfig.ID
	metadata["resolver_config_version"] = work.ResolverConfig.Version
	metadata["resolver_profile_id"] = work.ResolverConfig.ProfileID
	metadata["resolver_profile_name"] = work.ResolverConfig.ProfileName
	metadata["resolver_profile_provider"] = work.ResolverConfig.ProfileProvider
	metadata["resolver_match_suffix"] = work.ResolverConfig.MatchedSuffix
	metadata["resolver_site_id"] = work.Context.ResolverID
	metadata["resolver_gateway_id"] = work.Context.GatewayID
	body, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	_, _ = a.pool.Exec(ctx, `INSERT INTO audit_logs
		(org_id,actor_system,action,target_type,target_id,metadata)
		VALUES($1,'fqdn_resolver',$2,'fqdn_resource',$3,$4)`, work.OrgID, action, work.ResourceID.String(), body)
}
