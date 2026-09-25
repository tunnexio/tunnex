package ipsec

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func (s *ConnectionStore) Material(ctx context.Context, p RuntimePrincipal, id uuid.UUID, revision int64, sealer *crypto.Sealer) (RuntimeMaterial, error) {
	invalid := func(e error) (RuntimeMaterial, error) { return RuntimeMaterial{}, e }
	if revision <= 0 || sealer == nil {
		return invalid(ErrConnectionInvalid)
	}
	tx, locked, e := s.runtimeLock(ctx, p.OrgID, id, &p)
	if e != nil {
		return invalid(e)
	}
	defer tx.Rollback(ctx)
	c := locked.connection
	if c.DesiredIntent != "enabled" || c.DesiredRevision != revision {
		return invalid(ErrConnectionConflict)
	}
	if !locked.enabled || !locked.eligible || locked.state.cleanup != nil {
		return invalid(ErrConnectionIneligible)
	}
	cfg, tunnels, e := runtimeConfig(ctx, tx, c)
	if e != nil {
		return invalid(e)
	}
	policy, e := s.compileRuntime(ctx, tx, c, cfg)
	if e != nil {
		return invalid(e)
	}
	manifest := runtimeManifest(c, cfg, tunnels)
	delivery, _, e := scanDelivery(tx.QueryRow(ctx, `SELECT `+runtimeDeliveryColumns+` FROM ipsec_runtime_deliveries WHERE connection_id=$1 AND org_id=$2 AND desired_revision=$3 AND kind='apply'`, id, p.OrgID, revision))
	fresh := errors.Is(e, pgx.ErrNoRows)
	if !fresh && e != nil {
		return invalid(createError(e))
	}
	if fresh && locked.recoveryEligible {
		v := 1
		manifest.RecoveryVersion = &v
	}
	if !fresh {
		manifest.RecoveryVersion = delivery.Manifest.RecoveryVersion
	}
	if !runtimeRecoveryEligible(manifest, locked.recoveryEligible) {
		return invalid(ErrConnectionIneligible)
	}
	raw, digest := runtimeHash(manifest)
	if fresh {
		if e = runtimeCapacity(ctx, tx, c, manifest); e != nil {
			return invalid(e)
		}
		delivery = RuntimeDelivery{ID: uuid.New(), DesiredRevision: revision, Kind: "apply", OwnershipDigest: digest, Manifest: manifest}
	}
	if delivery.OwnershipDigest != digest {
		return invalid(ErrConnectionConflict)
	}
	result := RuntimeMaterial{RuntimeDelivery: delivery, Policy: policy}
	for i, t := range tunnels {
		var sealed string
		e = tx.QueryRow(ctx, `SELECT sealed_psk FROM ipsec_tunnel_secrets WHERE org_id=$1 AND connection_id=$2 AND tunnel_id=$3 AND secret_revision=$4 FOR UPDATE`, p.OrgID, id, t.ID, t.SecretRevision).Scan(&sealed)
		if e != nil {
			return invalid(ErrConnectionUnavailable)
		}
		secret, e := OpenPSK(sealer, PSKBinding{OrgID: p.OrgID, ConnectionID: id, TunnelID: t.ID, Revision: t.SecretRevision}, sealed)
		if e != nil {
			return invalid(ErrConnectionUnavailable)
		}
		result.Secrets[i] = RuntimeSecret{TunnelID: t.ID, Revision: t.SecretRevision, PSK: secret}
	}
	if fresh {
		_, e = tx.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,'apply',1,$7,$8,$9)`, delivery.ID, id, p.OrgID, p.NodeID, c.HistoricalSiteID, revision, digest, raw, p.CertificateSerial)
		if e != nil {
			return invalid(createError(e))
		}
		if e = runtimeAudit(ctx, tx, p.OrgID, nil, id, "ipsec.material_checkpoint", revision); e != nil {
			return invalid(e)
		}
	}
	// COMMIT precedes returning any credential-bearing value to the HTTP writer.
	if e = tx.Commit(ctx); e != nil {
		return invalid(createError(e))
	}
	return result, nil
}
func (s *ConnectionStore) Cleanup(ctx context.Context, p RuntimePrincipal, id uuid.UUID, revision int64) (RuntimeCleanup, error) {
	if revision <= 0 {
		return RuntimeCleanup{}, ErrConnectionInvalid
	}
	tx, locked, e := s.runtimeLock(ctx, p.OrgID, id, &p)
	if e != nil {
		return RuntimeCleanup{}, e
	}
	defer tx.Rollback(ctx)
	if locked.connection.DesiredRevision != revision || locked.connection.DesiredIntent == "enabled" || locked.state.cleanup == nil {
		return RuntimeCleanup{}, ErrConnectionConflict
	}
	d, lineage, e := scanDelivery(tx.QueryRow(ctx, `SELECT `+runtimeDeliveryColumns+` FROM ipsec_runtime_deliveries WHERE id=$1 AND connection_id=$2 AND org_id=$3 AND kind='cleanup'`, *locked.state.cleanup, id, p.OrgID))
	if e != nil {
		return RuntimeCleanup{}, createError(e)
	}
	if e = tx.Commit(ctx); e != nil {
		return RuntimeCleanup{}, createError(e)
	}
	return RuntimeCleanup{RuntimeDelivery: d, RetainGuard: true, Lineage: lineage}, nil
}
func (s *ConnectionStore) Acknowledge(ctx context.Context, p RuntimePrincipal, id uuid.UUID, ack RuntimeAcknowledgement) error {
	if ack.DeliveryID == uuid.Nil || ack.DesiredRevision <= 0 || !runtimeDigest(ack.OwnershipDigest) || (ack.Kind != "apply" && ack.Kind != "cleanup") || (ack.Kind == "apply" && (ack.Result != "applied" || ack.GuardRetained)) || (ack.Kind == "cleanup" && (ack.Result != "cleaned" || !ack.GuardRetained)) {
		return ErrConnectionInvalid
	}
	tx, locked, e := s.runtimeLock(ctx, p.OrgID, id, &p)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var prior RuntimeAcknowledgement
	e = tx.QueryRow(ctx, `SELECT delivery_id,desired_revision,kind,result,ownership_digest,guard_retained FROM ipsec_runtime_acknowledgements WHERE delivery_id=$1 AND connection_id=$2 AND org_id=$3 AND node_id=$4`, ack.DeliveryID, id, p.OrgID, p.NodeID).Scan(&prior.DeliveryID, &prior.DesiredRevision, &prior.Kind, &prior.Result, &prior.OwnershipDigest, &prior.GuardRetained)
	if e == nil {
		if prior != ack {
			return ErrConnectionConflict
		}
		if e = tx.Commit(ctx); e != nil {
			return createError(e)
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return createError(e)
	}
	c := locked.connection
	if c.DesiredRevision != ack.DesiredRevision || c.FinalizedAt != nil || (ack.Kind == "apply" && c.DesiredIntent != "enabled") || (ack.Kind == "cleanup" && (locked.state.cleanup == nil || *locked.state.cleanup != ack.DeliveryID)) {
		return ErrConnectionConflict
	}
	d, _, e := scanDelivery(tx.QueryRow(ctx, `SELECT `+runtimeDeliveryColumns+` FROM ipsec_runtime_deliveries WHERE id=$1 AND org_id=$2 AND connection_id=$3`, ack.DeliveryID, p.OrgID, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrConnectionConflict
	}
	if e != nil {
		return createError(e)
	}
	if d.Kind != ack.Kind || d.DesiredRevision != ack.DesiredRevision || d.OwnershipDigest != ack.OwnershipDigest {
		return ErrConnectionConflict
	}
	_, e = tx.Exec(ctx, `INSERT INTO ipsec_runtime_acknowledgements(delivery_id,connection_id,org_id,node_id,site_id,desired_revision,kind,result,ownership_digest,guard_retained,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, ack.DeliveryID, id, p.OrgID, p.NodeID, c.HistoricalSiteID, ack.DesiredRevision, ack.Kind, ack.Result, ack.OwnershipDigest, ack.GuardRetained, p.CertificateSerial)
	if e != nil {
		return createError(e)
	}
	if ack.Kind == "cleanup" && c.DesiredIntent == "deleted" {
		if e = finalizeRuntime(ctx, tx, c, false); e != nil {
			return e
		}
	}
	if e = runtimeAudit(ctx, tx, p.OrgID, nil, id, "ipsec.runtime_acknowledged", ack.DesiredRevision); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return createError(e)
	}
	return nil
}
func (s *ConnectionStore) Pending(ctx context.Context, p RuntimePrincipal, after *uuid.UUID, limit int) (RuntimePendingPage, error) {
	if s == nil || s.pool == nil {
		return RuntimePendingPage{}, ErrConnectionUnavailable
	}
	if p.OrgID == uuid.Nil || p.NodeID == uuid.Nil || p.CertificateSerial == "" || limit < 1 || limit > 100 {
		return RuntimePendingPage{}, ErrConnectionInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, p.OrgID.String()); e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	var valid bool
	e = tx.QueryRow(ctx, `SELECT true FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, p.OrgID).Scan(&valid)
	if e != nil {
		return RuntimePendingPage{}, ErrRuntimeUnauthorized
	}
	e = tx.QueryRow(ctx, `SELECT true FROM nodes WHERE id=$1 AND org_id=$2 AND cert_serial=$3 AND status='active' AND revoked_at IS NULL FOR UPDATE`, p.NodeID, p.OrgID, p.CertificateSerial).Scan(&valid)
	if e != nil {
		return RuntimePendingPage{}, ErrRuntimeUnauthorized
	}
	var optedIn bool
	if e = tx.QueryRow(ctx, `SELECT coalesce((SELECT enabled FROM ipsec_org_settings WHERE org_id=$1),false)`, p.OrgID).Scan(&optedIn); e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	rows, e := tx.Query(ctx, `SELECT c.id,c.desired_revision,CASE WHEN r.current_cleanup_id IS NOT NULL THEN 'cleanup' ELSE 'apply' END FROM ipsec_connections c LEFT JOIN ipsec_runtime_state r ON r.connection_id=c.id WHERE c.org_id=$1 AND c.historical_gateway_node_id=$2 AND c.finalized_at IS NULL AND (c.desired_intent='enabled' OR r.current_cleanup_id IS NOT NULL) AND ($3::uuid IS NULL OR c.id>$3) ORDER BY c.id LIMIT $4`, p.OrgID, p.NodeID, after, limit+1)
	if e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	out := RuntimePendingPage{IPsecEnabled: optedIn, OrgID: p.OrgID, NodeID: p.NodeID, Items: []RuntimePending{}}
	for rows.Next() {
		var item RuntimePending
		if e = rows.Scan(&item.ConnectionID, &item.DesiredRevision, &item.Kind); e != nil {
			rows.Close()
			return RuntimePendingPage{}, createError(e)
		}
		out.Items = append(out.Items, item)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	if len(out.Items) > limit {
		cursor := out.Items[limit-1].ConnectionID
		out.NextCursor = &cursor
		out.Items = out.Items[:limit]
	}
	if e = tx.Commit(ctx); e != nil {
		return RuntimePendingPage{}, createError(e)
	}
	return out, nil
}
func (s *ConnectionStore) PermitLease(ctx context.Context, p RuntimePrincipal, id uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
	if r.DeliveryID == uuid.Nil || r.DesiredRevision <= 0 || !runtimeDigest(r.PolicyHash) || !runtimeDigest(r.Nonce) {
		return RuntimeLease{}, ErrConnectionInvalid
	}
	tx, locked, e := s.runtimeLock(ctx, p.OrgID, id, &p)
	if e != nil {
		return RuntimeLease{}, e
	}
	defer tx.Rollback(ctx)
	c := locked.connection
	if c.DesiredIntent != "enabled" || c.DesiredRevision != r.DesiredRevision || locked.state.cleanup != nil {
		return RuntimeLease{}, ErrConnectionConflict
	}
	if !locked.enabled || !locked.eligible {
		return RuntimeLease{}, ErrConnectionIneligible
	}
	var manifestRaw []byte
	e = tx.QueryRow(ctx, `SELECT manifest FROM ipsec_runtime_deliveries WHERE id=$1 AND org_id=$2 AND connection_id=$3 AND node_id=$4 AND desired_revision=$5 AND kind='apply'`, r.DeliveryID, p.OrgID, id, p.NodeID, r.DesiredRevision).Scan(&manifestRaw)
	if errors.Is(e, pgx.ErrNoRows) {
		return RuntimeLease{}, ErrConnectionConflict
	}
	if e != nil {
		return RuntimeLease{}, createError(e)
	}
	var manifest RuntimeManifest
	if json.Unmarshal(manifestRaw, &manifest) != nil || !runtimeRecoveryEligible(manifest, locked.recoveryEligible) {
		return RuntimeLease{}, ErrConnectionIneligible
	}
	cfg, _, e := runtimeConfig(ctx, tx, c)
	if e != nil {
		return RuntimeLease{}, e
	}
	policy, e := s.compileRuntime(ctx, tx, c, cfg)
	if e != nil {
		return RuntimeLease{}, e
	}
	if policy.Hash != r.PolicyHash {
		return RuntimeLease{}, ErrConnectionConflict
	}
	if e = tx.Commit(ctx); e != nil {
		return RuntimeLease{}, createError(e)
	}
	return RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}, nil
}
