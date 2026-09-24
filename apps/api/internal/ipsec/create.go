package ipsec

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

var ErrConnectionIneligible = errors.New("IPsec connection prerequisites unavailable")

// CreateTunnel carries write-only input. Never log this struct or the request.
// No fingerprints or secret metadata are returned by CreateDisabled.
type CreateTunnel struct {
	ID  uuid.UUID
	PSK string `json:"-"`
}
type CreateDisabledRequest struct {
	ID        uuid.UUID
	SiteID    uuid.UUID
	GatewayID uuid.UUID
	Name      string
	Tunnels   [2]CreateTunnel
}

func validCreateRequest(org, actor uuid.UUID, r CreateDisabledRequest) bool {
	if org == uuid.Nil || actor == uuid.Nil || r.ID == uuid.Nil || r.SiteID == uuid.Nil || r.GatewayID == uuid.Nil || !utf8.ValidString(r.Name) || strings.TrimSpace(r.Name) == "" || utf8.RuneCountInString(r.Name) > 255 {
		return false
	}
	for _, c := range r.Name {
		if unicode.IsControl(c) {
			return false
		}
	}
	if r.Tunnels[0].ID == r.Tunnels[1].ID {
		return false
	}
	for _, t := range r.Tunnels {
		if t.ID == uuid.Nil || !validPSK(t.PSK) {
			return false
		}
	}
	return true
}
func createError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "23505" || pe.Code == "23503" || pe.Code == "40001" || pe.Code == "40P01" || pe.ConstraintName == "ipsec_provider_conflict" || pe.ConstraintName == "ipsec_runtime_binding") {
		return ErrConnectionConflict
	}
	return ErrConnectionUnavailable
}

// CreateDisabled reserves a never-delivered identity; it is not a public API or
// provider configuration. Caller must supply verified-human ipsec:manage scope.
// Lock order is org -> setting -> site -> gateway -> new connection -> slots.
// Production agents do not advertise version1 until runtime qualification; this
// gate is independent of licence tier and never treats WG support as IPsec.
func (s *ConnectionStore) CreateDisabled(ctx context.Context, org, actor uuid.UUID, sealer *crypto.Sealer, r CreateDisabledRequest) (Connection, error) {
	return s.createDisabled(ctx, org, actor, sealer, r, nil)
}

func (s *ConnectionStore) createDisabled(ctx context.Context, org, actor uuid.UUID, sealer *crypto.Sealer, r CreateDisabledRequest, provider *StaticConfig) (Connection, error) {
	if !validCreateRequest(org, actor, r) {
		return Connection{}, ErrConnectionInvalid
	}
	if s == nil || s.pool == nil || sealer == nil {
		return Connection{}, ErrConnectionUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Connection{}, createError(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if provider != nil {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, org.String()); err != nil {
			return Connection{}, createError(err)
		}
	}
	var locked uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrConnectionNotFound
	}
	if err != nil {
		return Connection{}, createError(err)
	}
	if provider != nil {
		if _, err = tx.Exec(ctx, `UPDATE organizations SET updated_at=updated_at WHERE id=$1`, org); err != nil {
			return Connection{}, createError(err)
		}
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT enabled FROM ipsec_org_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
		return Connection{}, ErrConnectionIneligible
	}
	if err != nil {
		return Connection{}, createError(err)
	}
	err = tx.QueryRow(ctx, `SELECT id FROM sites WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, r.SiteID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrConnectionIneligible
	}
	if err != nil {
		return Connection{}, createError(err)
	}
	var localSubnets []providerSubnet
	if provider != nil {
		localSubnets, err = lockProviderSubnets(ctx, tx, r.SiteID, provider.LocalPrefixes)
		if err != nil {
			return Connection{}, err
		}
	}
	var gateway, site uuid.UUID
	var status, serial string
	var revoked, reported *time.Time
	var capabilities []byte
	err = tx.QueryRow(ctx, `SELECT id,site_id,status,cert_serial,revoked_at,policy_reported_at,capabilities FROM nodes WHERE org_id=$1 AND id=$2 AND site_id=$3 FOR UPDATE`, org, r.GatewayID, r.SiteID).Scan(&gateway, &site, &status, &serial, &revoked, &reported, &capabilities)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrConnectionIneligible
	}
	if err != nil {
		return Connection{}, createError(err)
	}
	var clock time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&clock); err != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	if gatewayEligibilityReason(status, serial, revoked, reported, capabilities, clock) != "eligible" {
		return Connection{}, ErrConnectionIneligible
	}

	statement := `INSERT INTO ipsec_connections AS c(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,$3,$4,$5,$4,$5) RETURNING ` + connectionColumns
	if provider != nil {
		if err = checkProviderRanges(ctx, tx, org, *provider); err != nil {
			return Connection{}, err
		}
		statement = `INSERT INTO ipsec_connections AS c(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id,provider_profile) VALUES($1,$2,$3,$4,$5,$4,$5,'aws-static-ipv4-v1') RETURNING ` + connectionColumns
	}
	result, err := scanConnection(tx.QueryRow(ctx, statement, r.ID, org, r.Name, site, gateway))
	if err != nil {
		return Connection{}, createError(err)
	}
	for i, t := range r.Tunnels {
		if _, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, t.ID, org, result.ID, i+1); err != nil {
			return Connection{}, createError(err)
		}
		sealed, sealErr := SealPSK(sealer, PSKBinding{OrgID: result.OrgID, ConnectionID: result.ID, TunnelID: t.ID, Revision: 1}, t.PSK)
		if sealErr != nil {
			return Connection{}, ErrConnectionUnavailable
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,$4)`, t.ID, result.OrgID, result.ID, sealed); err != nil {
			return Connection{}, createError(err)
		}
	}
	if provider != nil {
		if err = insertProvider(ctx, tx, result, r, *provider, localSubnets); err != nil {
			return Connection{}, err
		}
	}
	metadata := []byte(`{"revision":1,"intent":"disabled"}`)
	if provider != nil {
		metadata = []byte(`{"revision":1,"intent":"disabled","profile":"aws-static-ipv4-v1","configuration_revision":1}`)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ipsec.connection_created','ipsec_connection',$3,$4)`, org, actor, result.ID.String(), metadata); err != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return Connection{}, createError(err)
	}
	return result, nil
}
