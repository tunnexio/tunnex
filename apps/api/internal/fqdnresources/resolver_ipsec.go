package fqdnresources

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// This check occurs before retiring the preceding context. The connection lock
// serializes a concurrent Disable/Delete/rotation; activation has a DB mirror.
func validateIPsecResolverPath(ctx context.Context, tx pgx.Tx, org, site, gateway uuid.UUID, profile ResolverProfile) error {
	path := profile.IPsecPath
	var revision int64
	err := tx.QueryRow(ctx, `SELECT b.configuration_revision FROM ipsec_connections c JOIN ipsec_provider_bindings b ON b.connection_id=c.id AND b.org_id=c.org_id JOIN nodes n ON n.id=c.gateway_node_id AND n.org_id=c.org_id AND n.site_id=c.site_id
 WHERE c.id=$1 AND c.org_id=$2 AND c.site_id=$3 AND c.gateway_node_id=$4 AND c.desired_intent='enabled' AND c.deleted_at IS NULL AND c.finalized_at IS NULL AND NOT b.withdrawal_started AND n.status='active' AND n.revoked_at IS NULL AND n.capabilities->'dns_ipsec_resolve_version'='1'::jsonb AND n.capabilities->'dns_resolve_rpc_version'='2'::jsonb FOR UPDATE OF c,b`, path.ConnectionID, org, site, gateway).Scan(&revision)
	if err == pgx.ErrNoRows || (err == nil && revision != path.ConfigurationRevision) {
		return apierr.Conflict("resolver_ipsec_path_unavailable", "select an enabled IPsec connection in this Site/Gateway with its current revision and a DNS-over-IPsec capable gateway")
	}
	if err != nil {
		return err
	}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_aws_local_prefixes lp JOIN site_subnets ss ON ss.id=lp.subnet_id AND ss.site_id=lp.site_id AND ss.status='approved' WHERE lp.connection_id=$1 AND lp.org_id=$2 AND $3::inet <<= lp.cidr)`, path.ConnectionID, org, path.SourceAddress).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return apierr.Conflict("resolver_ipsec_source_unapproved", "DNS source must be inside an approved local IPsec prefix; the gateway verifies actual address ownership before querying")
	}
	for _, endpoint := range profile.Endpoints {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_aws_remote_prefixes WHERE connection_id=$1 AND org_id=$2 AND $3::inet <<= cidr)`, path.ConnectionID, org, endpoint.Address).Scan(&approved)
		if err != nil {
			return err
		}
		if !approved {
			return apierr.Conflict("resolver_ipsec_endpoint_unapproved", "DNS resolver endpoints must be inside the selected connection's approved remote prefixes")
		}
	}
	return nil
}
