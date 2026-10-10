package ipsec

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxRetainedGuardPredecessors = 256

type staticPredecessor struct{ connectionID, cleanupID uuid.UUID }

// Historical schemas retain their strict no-reuse SQL rule. Absence of this
// migration never grants recreation authority or removes a retained guard.
func staticRecreationSchema(ctx context.Context, tx pgx.Tx) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT to_regclass('ipsec_static_recreations') IS NOT NULL`).Scan(&exists)
	if err != nil {
		return false, createError(err)
	}
	return exists, nil
}
func equalPrefixDomains(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Candidates include every historical connection whose retained domain overlaps
// the request. None is ignored merely because its owner or prefix differs.
func staticRecreationCandidates(ctx context.Context, tx pgx.Tx, org, site, node uuid.UUID, cfg StaticConfig) ([]staticPredecessor, error) {
	supported, err := staticRecreationSchema(ctx, tx)
	if err != nil || !supported {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (g.connection_id) g.connection_id,g.cleanup_delivery_id,
 c.provider_profile,c.desired_intent,c.finalized_at IS NOT NULL,
 c.historical_site_id,c.historical_gateway_node_id,
 g.org_id=g_org.id AND g.site_id=c.historical_site_id AND g.gateway_node_id=c.historical_gateway_node_id
 AND d.kind='cleanup' AND d.ownership_digest=g.ownership_digest
 AND d.covers_delivery_revision=s.last_potentially_delivered_revision
 AND s.last_cleaned_delivery_revision=s.last_potentially_delivered_revision,
 ARRAY(SELECT cidr::text FROM ipsec_retained_local_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id ORDER BY cidr::text),
 ARRAY(SELECT cidr::text FROM ipsec_retained_remote_prefixes WHERE cleanup_delivery_id=g.cleanup_delivery_id ORDER BY cidr::text),
 jsonb_array_length(d.lineage)
 FROM ipsec_retained_guards g JOIN ipsec_connections c ON c.id=g.connection_id AND c.org_id=g.org_id
 JOIN organizations g_org ON g_org.id=g.org_id
 JOIN ipsec_runtime_deliveries d ON d.id=g.cleanup_delivery_id
 JOIN ipsec_runtime_state s ON s.connection_id=g.connection_id
 WHERE g.org_id=$1 AND EXISTS(SELECT 1 FROM ipsec_retained_remote_prefixes r WHERE r.connection_id=g.connection_id AND r.org_id=g.org_id AND r.cidr && ANY($2::cidr[]))
 ORDER BY g.connection_id,d.covers_delivery_revision DESC,d.desired_revision DESC,d.id DESC`, org, cfg.RemotePrefixes)
	if err != nil {
		return nil, createError(err)
	}
	defer rows.Close()
	var result []staticPredecessor
	total := 0
	for rows.Next() {
		var p staticPredecessor
		var profile, intent string
		var finalized, valid bool
		var oldSite, oldNode uuid.UUID
		var locals, remotes []string
		var count int
		if err = rows.Scan(&p.connectionID, &p.cleanupID, &profile, &intent, &finalized, &oldSite, &oldNode, &valid, &locals, &remotes, &count); err != nil {
			return nil, createError(err)
		}
		total += count
		if cfg.BGP != nil || cfg.Mode != "ipv4-static" || profile != providerProfile(cfg) || intent != "deleted" || !finalized || !valid || oldSite != site || oldNode != node || !equalPrefixDomains(locals, cfg.LocalPrefixes) || !equalPrefixDomains(remotes, cfg.RemotePrefixes) || count < 1 || total > maxRetainedGuardPredecessors {
			return nil, ErrConnectionConflict
		}
		result = append(result, p)
	}
	if err = rows.Err(); err != nil {
		return nil, createError(err)
	}
	return result, nil
}
func insertStaticRecreationBindings(ctx context.Context, tx pgx.Tx, c Connection, predecessors []staticPredecessor) error {
	for _, p := range predecessors {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_static_recreations(connection_id,org_id,predecessor_connection_id,cleanup_delivery_id) VALUES($1,$2,$3,$4)`, c.ID, c.OrgID, p.connectionID, p.cleanupID); err != nil {
			return createError(err)
		}
	}
	return nil
}
func attachStaticRecreation(ctx context.Context, tx pgx.Tx, m *RuntimeManifest) error {
	supported, err := staticRecreationSchema(ctx, tx)
	if err != nil || !supported {
		return err
	}
	// Latest finalized cleanup proves complete binding; per-apply cleanup identity
	// comes from the first successful retained acknowledgement, shared with the
	// database delivery trigger. Native journal history is never rewritten.
	var rawRefs []byte
	if err = tx.QueryRow(ctx, `SELECT ipsec_static_recreation_predecessors($1,$2)`, m.ConnectionID, m.OrgID).Scan(&rawRefs); err != nil {
		return createError(err)
	}
	var projected []RuntimeRetainedGuardPredecessor
	if len(rawRefs) > 0 && json.Unmarshal(rawRefs, &projected) != nil {
		return ErrConnectionConflict
	}
	if len(projected) > maxRetainedGuardPredecessors {
		return ErrConnectionConflict
	}
	byDelivery := make(map[uuid.UUID]RuntimeRetainedGuardPredecessor, len(projected))
	for _, ref := range projected {
		if ref.ConnectionID == uuid.Nil || ref.DeliveryID == uuid.Nil || ref.CleanupDeliveryID == uuid.Nil || !runtimeDigest(ref.OwnershipDigest) {
			return ErrConnectionConflict
		}
		if _, duplicate := byDelivery[ref.DeliveryID]; duplicate {
			return ErrConnectionConflict
		}
		byDelivery[ref.DeliveryID] = ref
	}
	rows, err := tx.Query(ctx, `SELECT b.predecessor_connection_id,d.lineage FROM ipsec_static_recreations b JOIN ipsec_runtime_deliveries d ON d.id=b.cleanup_delivery_id WHERE b.connection_id=$1 AND b.org_id=$2 ORDER BY b.predecessor_connection_id`, m.ConnectionID, m.OrgID)
	if err != nil {
		return createError(err)
	}
	defer rows.Close()
	var refs []RuntimeRetainedGuardPredecessor
	seen := map[uuid.UUID]bool{}
	for rows.Next() {
		var connection uuid.UUID
		var raw []byte
		if err = rows.Scan(&connection, &raw); err != nil {
			return createError(err)
		}
		if m.BGP != nil || m.BGPVersion != nil || (m.ProfileID != "aws-static-ipv4-v1" && m.ProfileID != GCPClassicProfile && !(isAzureProfile(m.ProfileID) && !azureBGP(m.ProfileID))) {
			return ErrConnectionConflict
		}
		var lineage []RuntimeDelivery
		if json.Unmarshal(raw, &lineage) != nil || len(lineage) == 0 {
			return ErrConnectionConflict
		}
		for _, d := range lineage {
			prior := d.Manifest
			if d.ID == uuid.Nil || seen[d.ID] || d.Kind != "apply" || !runtimeDigest(d.OwnershipDigest) || prior.ConnectionID != connection || prior.OrgID != m.OrgID || prior.SiteID != m.SiteID || prior.NodeID != m.NodeID || prior.BGP != nil || prior.BGPVersion != nil || prior.ProfileID != m.ProfileID || !equalPrefixDomains(prior.LocalPrefixes, m.LocalPrefixes) || !equalPrefixDomains(prior.RemotePrefixes, m.RemotePrefixes) {
				return ErrConnectionConflict
			}
			ref, present := byDelivery[d.ID]
			if !present || ref.ConnectionID != connection || ref.OwnershipDigest != d.OwnershipDigest {
				return ErrConnectionConflict
			}
			seen[d.ID] = true
			refs = append(refs, ref)
			if len(refs) > maxRetainedGuardPredecessors {
				return ErrConnectionConflict
			}
		}
	}
	if err = rows.Err(); err != nil {
		return createError(err)
	}
	if len(refs) != len(projected) {
		return ErrConnectionConflict
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].DeliveryID.String() < refs[j].DeliveryID.String() })
	m.RetainedGuardPredecessors = refs
	return nil
}

func retainedGuardCapability(raw []byte) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && string(fields["ipsec_config_version"]) == "1" && string(fields["ipsec_retained_guard_version"]) == "1"
}
func blockedStaticRecreations(ctx context.Context, tx pgx.Tx, org uuid.UUID, capable bool) ([]uuid.UUID, error) {
	blocked := []uuid.UUID{}
	if capable {
		return blocked, nil
	}
	available, err := staticRecreationSchema(ctx, tx)
	if err != nil || !available {
		return blocked, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT connection_id FROM ipsec_static_recreations WHERE org_id=$1 ORDER BY connection_id`, org)
	if err != nil {
		return nil, createError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, createError(err)
		}
		blocked = append(blocked, id)
	}
	if err = rows.Err(); err != nil {
		return nil, createError(err)
	}
	return blocked, nil
}
