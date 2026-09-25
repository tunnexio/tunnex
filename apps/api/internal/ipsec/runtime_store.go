package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

var ErrRuntimeUnauthorized = errors.New("IPsec runtime identity unavailable")

func (s *ConnectionStore) ConfigureRuntimePolicy(compiler RuntimePolicyCompiler) {
	s.runtimePolicy = compiler
}

type runtimeState struct {
	delivered, cleaned, applied *int64
	cleanup                     *uuid.UUID
}
type runtimeLocked struct {
	connection       Connection
	state            runtimeState
	enabled          bool
	eligible         bool
	recoveryEligible bool
}

func runtimeRevision(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// Caller takes the common range lock before any mutable authority snapshot.
// Certificate rechecks occur on the same gateway tuple used by revoke/renew.
func (s *ConnectionStore) runtimeLock(ctx context.Context, org, id uuid.UUID, principal *RuntimePrincipal) (pgx.Tx, runtimeLocked, error) {
	var out runtimeLocked
	if s == nil || s.pool == nil {
		return nil, out, ErrConnectionUnavailable
	}
	if org == uuid.Nil || id == uuid.Nil {
		return nil, out, ErrConnectionInvalid
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, out, createError(e)
	}
	fail := func(err error) (pgx.Tx, runtimeLocked, error) { _ = tx.Rollback(ctx); return nil, runtimeLocked{}, err }
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, org.String()); e != nil {
		return fail(createError(e))
	}
	var live uuid.UUID
	e = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&live)
	if errors.Is(e, pgx.ErrNoRows) {
		return fail(ErrConnectionNotFound)
	}
	if e != nil {
		return fail(createError(e))
	}
	if _, e = tx.Exec(ctx, `UPDATE organizations SET updated_at=updated_at WHERE id=$1`, org); e != nil {
		return fail(createError(e))
	}
	e = tx.QueryRow(ctx, `SELECT enabled FROM ipsec_org_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&out.enabled)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fail(createError(e))
	}
	var site, node uuid.UUID
	e = tx.QueryRow(ctx, `SELECT historical_site_id,historical_gateway_node_id FROM ipsec_connections WHERE org_id=$1 AND id=$2`, org, id).Scan(&site, &node)
	if errors.Is(e, pgx.ErrNoRows) {
		return fail(ErrConnectionNotFound)
	}
	if e != nil {
		return fail(createError(e))
	}
	if principal != nil && (principal.OrgID != org || principal.NodeID != node || principal.CertificateSerial == "") {
		return fail(ErrRuntimeUnauthorized)
	}
	// Historical Site/node may have disappeared only for never-delivered finalized records.
	e = tx.QueryRow(ctx, `SELECT id FROM sites WHERE id=$1 AND org_id=$2 FOR UPDATE`, site, org).Scan(&live)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fail(createError(e))
	}
	var status, serial string
	var revoked, reported *time.Time
	var caps []byte
	e = tx.QueryRow(ctx, `SELECT status,cert_serial,revoked_at,policy_reported_at,capabilities FROM nodes WHERE id=$1 AND org_id=$2 AND site_id=$3 FOR UPDATE`, node, org, site).Scan(&status, &serial, &revoked, &reported, &caps)
	if principal != nil && (e != nil || status != "active" || revoked != nil || serial != principal.CertificateSerial) {
		return fail(ErrRuntimeUnauthorized)
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fail(createError(e))
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return fail(createError(e))
	}
	out.eligible = gatewayEligibilityReason(status, serial, revoked, reported, caps, now) == "eligible"
	var capability map[string]json.RawMessage
	out.recoveryEligible = out.eligible && json.Unmarshal(caps, &capability) == nil && string(capability["ipsec_recovery_version"]) == "1"
	out.connection, e = scanConnection(tx.QueryRow(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c WHERE c.org_id=$1 AND c.id=$2 FOR UPDATE`, org, id))
	if e != nil {
		return fail(createError(e))
	}
	e = tx.QueryRow(ctx, `SELECT last_potentially_delivered_revision,last_cleaned_delivery_revision,current_cleanup_id,applied_revision FROM ipsec_runtime_state WHERE connection_id=$1 FOR UPDATE`, id).Scan(&out.state.delivered, &out.state.cleaned, &out.state.cleanup, &out.state.applied)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fail(createError(e))
	}
	return tx, out, nil
}
func runtimeConfig(ctx context.Context, tx pgx.Tx, c Connection) (StaticConfig, [2]RuntimeTunnel, error) {
	cfg := StaticConfig{Mode: "ipv4-static", LocalPrefixes: []string{}, RemotePrefixes: []string{}, Tunnels: []StaticTunnel{}}
	var tunnels [2]RuntimeTunnel
	e := tx.QueryRow(ctx, `SELECT host(customer_outside_ipv4) FROM ipsec_aws_static_configs WHERE connection_id=$1 AND org_id=$2`, c.ID, c.OrgID).Scan(&cfg.CustomerOutsideAddress)
	if errors.Is(e, pgx.ErrNoRows) {
		return cfg, tunnels, ErrConnectionIneligible
	}
	if e != nil {
		return cfg, tunnels, createError(e)
	}
	for i, table := range []string{"ipsec_aws_local_prefixes", "ipsec_aws_remote_prefixes"} {
		rows, e := tx.Query(ctx, `SELECT cidr::text FROM `+table+` WHERE connection_id=$1 AND org_id=$2 ORDER BY cidr`, c.ID, c.OrgID)
		if e != nil {
			return cfg, tunnels, createError(e)
		}
		for rows.Next() {
			var p string
			if e = rows.Scan(&p); e != nil {
				rows.Close()
				return cfg, tunnels, createError(e)
			}
			if i == 0 {
				cfg.LocalPrefixes = append(cfg.LocalPrefixes, p)
			} else {
				cfg.RemotePrefixes = append(cfg.RemotePrefixes, p)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return cfg, tunnels, createError(e)
		}
	}
	rows, e := tx.Query(ctx, `SELECT t.tunnel_id,t.slot,s.secret_revision,host(t.aws_outside_ipv4),t.inside_cidr::text,host(t.customer_inside_ipv4),host(t.aws_inside_ipv4) FROM ipsec_aws_tunnel_configs t JOIN ipsec_tunnels s ON s.id=t.tunnel_id AND s.org_id=t.org_id AND s.connection_id=t.connection_id WHERE t.connection_id=$1 AND t.org_id=$2 ORDER BY t.slot FOR UPDATE OF s`, c.ID, c.OrgID)
	if e != nil {
		return cfg, tunnels, createError(e)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		if n >= 2 {
			return cfg, tunnels, ErrConnectionUnavailable
		}
		t := &tunnels[n]
		if e = rows.Scan(&t.ID, &t.Slot, &t.SecretRevision, &t.OutsideAddress, &t.InsideCIDR, &t.CustomerInsideAddress, &t.CloudInsideAddress); e != nil {
			return cfg, tunnels, createError(e)
		}
		if t.Slot != n+1 || t.SecretRevision <= 0 {
			return cfg, tunnels, ErrConnectionUnavailable
		}
		sum := sha256.Sum256(t.ID[:])
		t.LinkName = "tx" + hex.EncodeToString(sum[:6])
		t.XFRMID = binary.BigEndian.Uint32(sum[:4]) | 0x80000000
		t.ReqID = t.XFRMID
		t.RouteTable = 254
		t.RouteProtocol = 242
		t.RouteMetric = uint32(50000 + t.Slot)
		t.Selected = t.Slot == 1
		cfg.Tunnels = append(cfg.Tunnels, StaticTunnel{OutsideAddress: t.OutsideAddress, InsideCIDR: t.InsideCIDR, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress})
		n++
	}
	if rows.Err() != nil || n != 2 || tunnels[0].XFRMID == tunnels[1].XFRMID || tunnels[0].LinkName == tunnels[1].LinkName {
		return cfg, tunnels, ErrConnectionUnavailable
	}
	return cfg, tunnels, nil
}
func (s *ConnectionStore) compileRuntime(ctx context.Context, tx pgx.Tx, c Connection, cfg StaticConfig) (RuntimePolicy, error) {
	if s.runtimePolicy == nil {
		return RuntimePolicy{}, ErrConnectionIneligible
	}
	policy, e := s.runtimePolicy(ctx, sqlc.New(tx), RuntimePolicyInput{OrgID: c.OrgID, NodeID: c.HistoricalGatewayNodeID, SiteID: c.HistoricalSiteID, ConnectionID: c.ID, Config: cfg})
	if e != nil {
		return RuntimePolicy{}, ErrConnectionUnavailable
	}
	if !runtimeDigest(policy.Hash) || len(policy.Grants) > 128 {
		return RuntimePolicy{}, ErrConnectionUnavailable
	}
	for _, g := range policy.Grants {
		src, e := netip.ParsePrefix(g.Source)
		if e != nil || src != src.Masked() || !src.Addr().Is4() {
			return RuntimePolicy{}, ErrConnectionUnavailable
		}
		dst, e := netip.ParsePrefix(g.Destination)
		if e != nil || dst != dst.Masked() || !dst.Addr().Is4() {
			return RuntimePolicy{}, ErrConnectionUnavailable
		}
		if g.Protocol != "any" && g.Protocol != "tcp" && g.Protocol != "udp" || g.PortLow > g.PortHigh || (g.Protocol == "any" && (g.PortLow != 0 || g.PortHigh != 0)) {
			return RuntimePolicy{}, ErrConnectionUnavailable
		}
	}
	if policy.Grants == nil {
		policy.Grants = []RuntimeGrant{}
	}
	return policy, nil
}
func runtimeDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil && s == strings.ToLower(s)
}
func runtimeManifest(c Connection, cfg StaticConfig, tunnels [2]RuntimeTunnel) RuntimeManifest {
	return RuntimeManifest{OrgID: c.OrgID, NodeID: c.HistoricalGatewayNodeID, SiteID: c.HistoricalSiteID, ConnectionID: c.ID, DesiredRevision: c.DesiredRevision, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1", CustomerOutsideAddress: cfg.CustomerOutsideAddress, LocalPrefixes: cfg.LocalPrefixes, RemotePrefixes: cfg.RemotePrefixes, Tunnels: tunnels}
}
func runtimeHash(v any) ([]byte, string) {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}
func runtimeAudit(ctx context.Context, tx pgx.Tx, org uuid.UUID, actor *uuid.UUID, id uuid.UUID, action string, revision int64) error {
	metadata, _ := json.Marshal(struct {
		Revision int64 `json:"revision"`
	}{revision})
	_, e := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ipsec_connection',$4,$5)`, org, actor, action, id.String(), metadata)
	if e != nil {
		return ErrConnectionUnavailable
	}
	return nil
}
func (s *ConnectionStore) SetIntent(ctx context.Context, org, actor, id uuid.UUID, revision int64, intent string) (Connection, error) {
	if intent != "enabled" && intent != "disabled" {
		return Connection{}, ErrConnectionInvalid
	}
	return s.changeIntent(ctx, org, actor, id, revision, intent)
}
func (s *ConnectionStore) changeIntent(ctx context.Context, org, actor, id uuid.UUID, revision int64, intent string) (Connection, error) {
	if actor == uuid.Nil || revision <= 0 || revision == math.MaxInt64 {
		return Connection{}, ErrConnectionInvalid
	}
	tx, locked, e := s.runtimeLock(ctx, org, id, nil)
	if e != nil {
		return Connection{}, e
	}
	defer tx.Rollback(ctx)
	c := locked.connection
	if c.DesiredRevision != revision || c.DesiredIntent == "deleted" || c.DesiredIntent == intent {
		return Connection{}, ErrConnectionConflict
	}
	if intent == "enabled" {
		if !locked.enabled || !locked.eligible || locked.state.cleanup != nil {
			return Connection{}, ErrConnectionIneligible
		}
		cfg, tunnels, e := runtimeConfig(ctx, tx, c)
		if e != nil {
			return Connection{}, e
		}
		next := c
		next.DesiredRevision++
		if e = runtimeCapacity(ctx, tx, next, runtimeManifest(next, cfg, tunnels)); e != nil {
			return Connection{}, e
		}
		if _, e = s.compileRuntime(ctx, tx, c, cfg); e != nil {
			return Connection{}, e
		}
	}
	owed := runtimeRevision(locked.state.delivered) > runtimeRevision(locked.state.cleaned)
	if intent == "deleted" && !owed {
		if e = finalizeRuntime(ctx, tx, c, true); e != nil {
			return Connection{}, e
		}
	} else {
		_, e = tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent=$3,desired_revision=desired_revision+1,deleted_at=CASE WHEN $3='deleted' THEN now() ELSE NULL END WHERE org_id=$1 AND id=$2`, org, id, intent)
		if e != nil {
			return Connection{}, createError(e)
		}
		if intent != "enabled" && owed {
			if e = createCleanup(ctx, tx, c, revision+1, runtimeRevision(locked.state.delivered)); e != nil {
				return Connection{}, e
			}
		}
	}
	action := "ipsec.intent_changed"
	if intent == "deleted" {
		action = "ipsec.connection_deleted"
	}
	if e = runtimeAudit(ctx, tx, org, &actor, id, action, revision+1); e != nil {
		return Connection{}, e
	}
	result, e := scanConnection(tx.QueryRow(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c WHERE c.org_id=$1 AND c.id=$2`, org, id))
	if e != nil {
		return Connection{}, createError(e)
	}
	if e = tx.Commit(ctx); e != nil {
		return Connection{}, createError(e)
	}
	return result, nil
}
func finalizeRuntime(ctx context.Context, tx pgx.Tx, c Connection, advance bool) error {
	if e := removeProvider(ctx, tx, c.OrgID, c.ID); e != nil {
		return e
	}
	delta := 0
	if advance {
		delta = 1
	}
	_, e := tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=desired_revision+$3,deleted_at=coalesce(deleted_at,now()),finalized_at=now(),site_id=NULL,gateway_node_id=NULL WHERE org_id=$1 AND id=$2`, c.OrgID, c.ID, delta)
	if e != nil {
		return createError(e)
	}
	for _, table := range []string{"ipsec_tunnel_secrets", "ipsec_tunnels"} {
		if _, e = tx.Exec(ctx, `DELETE FROM `+table+` WHERE org_id=$1 AND connection_id=$2`, c.OrgID, c.ID); e != nil {
			return createError(e)
		}
	}
	return nil
}
func scanDelivery(row pgx.Row) (RuntimeDelivery, []RuntimeDelivery, error) {
	var d RuntimeDelivery
	var raw, lineage []byte
	var covers *int64
	e := row.Scan(&d.ID, &d.DesiredRevision, &d.Kind, &d.OwnershipDigest, &covers, &raw, &lineage)
	if e != nil {
		return d, nil, e
	}
	if covers != nil {
		d.CoversDeliveryRevision = *covers
	}
	if json.Unmarshal(raw, &d.Manifest) != nil {
		return d, nil, ErrConnectionUnavailable
	}
	var history []RuntimeDelivery
	if json.Unmarshal(lineage, &history) != nil {
		return d, nil, ErrConnectionUnavailable
	}
	return d, history, nil
}

const runtimeDeliveryColumns = `id,desired_revision,kind,ownership_digest,covers_delivery_revision,manifest,lineage`

func createCleanup(ctx context.Context, tx pgx.Tx, c Connection, newRevision, cover int64) error {
	rows, e := tx.Query(ctx, `SELECT `+runtimeDeliveryColumns+` FROM ipsec_runtime_deliveries WHERE connection_id=$1 AND org_id=$2 AND kind='apply' ORDER BY desired_revision`, c.ID, c.OrgID)
	if e != nil {
		return createError(e)
	}
	lineage := []RuntimeDelivery{}
	for rows.Next() {
		d, _, e := scanDelivery(rows)
		if e != nil {
			rows.Close()
			return createError(e)
		}
		lineage = append(lineage, d)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(lineage) == 0 {
		return ErrConnectionUnavailable
	}
	latest := lineage[len(lineage)-1]
	manifest, _ := runtimeHash(latest.Manifest)
	raw, digest := runtimeHash(lineage)
	_, e = tx.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,lineage,covers_delivery_revision) VALUES($1,$2,$3,$4,$5,$6,'cleanup',1,$7,$8,$9,$10)`, uuid.New(), c.ID, c.OrgID, c.HistoricalGatewayNodeID, c.HistoricalSiteID, newRevision, digest, manifest, raw, cover)
	if e != nil {
		return createError(e)
	}
	return nil
}

// Full immutable lineage is retained. Refuse new generations before exposing
// material if a later cleanup could exceed the bounded journal/wire envelope.
func runtimeCapacity(ctx context.Context, tx pgx.Tx, c Connection, manifest RuntimeManifest) error {
	_, digest := runtimeHash(manifest)
	candidate, _ := runtimeHash(RuntimeDelivery{ID: uuid.New(), DesiredRevision: c.DesiredRevision, Kind: "apply", OwnershipDigest: digest, Manifest: manifest})
	var count, size int
	e := tx.QueryRow(ctx, `SELECT count(*),coalesce(sum(octet_length(jsonb_build_object('delivery_id',id,'desired_revision',desired_revision,'kind',kind,'ownership_digest',ownership_digest,'manifest',manifest)::text)+2),0) FROM ipsec_runtime_deliveries WHERE connection_id=$1 AND org_id=$2 AND kind='apply'`, c.ID, c.OrgID).Scan(&count, &size)
	if e != nil {
		return createError(e)
	}
	if count >= 64 || size+len(candidate)+2 > 480*1024 {
		return ErrConnectionIneligible
	}
	return nil
}
