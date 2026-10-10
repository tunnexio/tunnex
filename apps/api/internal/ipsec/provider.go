package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetguard"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetsrc"
)

// CreateProviderRequest is write-only input. No renderer/log may serialize it.
// Config carries the single copy of the submitted PSKs; identities are separate.
type CreateProviderRequest struct {
	ID, SiteID, GatewayID uuid.UUID
	Name                  string
	TunnelIDs             [2]uuid.UUID
	Config                StaticConfig
}
type ProviderConfiguration struct {
	ProfileID             string        `json:"profile_id"`
	ConfigurationRevision int64         `json:"configuration_revision"`
	Config                *StaticConfig `json:"configuration,omitempty"`
}

func (s *ConnectionStore) CreateProviderDisabled(ctx context.Context, org, actor uuid.UUID, sealer *crypto.Sealer, r CreateProviderRequest) (Connection, error) {
	if r.Config.ProfileID == GCPClassicProfile && r.TunnelIDs[1] != uuid.Nil {
		return Connection{}, ErrConnectionInvalid
	}
	if ValidateProviderConfig(r.Config) != nil {
		return Connection{}, ErrConnectionInvalid
	}
	identity := CreateDisabledRequest{ID: r.ID, SiteID: r.SiteID, GatewayID: r.GatewayID, Name: r.Name, TunnelCount: activeTunnelCount(providerProfile(r.Config))}
	for i := range r.Config.Tunnels {
		identity.Tunnels[i] = CreateTunnel{ID: r.TunnelIDs[i], PSK: r.Config.Tunnels[i].PSK}
	}
	return s.createDisabled(ctx, org, actor, sealer, identity, &r.Config)
}

type providerSubnet struct {
	ID   uuid.UUID
	CIDR string
}

func lockProviderSubnets(ctx context.Context, tx pgx.Tx, site uuid.UUID, prefixes []string) ([]providerSubnet, error) {
	rows, err := tx.Query(ctx, `SELECT id,cidr::text FROM site_subnets WHERE site_id=$1 AND status='approved' AND cidr::text=ANY($2::text[]) ORDER BY id FOR UPDATE`, site, prefixes)
	if err != nil {
		return nil, createError(err)
	}
	defer rows.Close()
	result := make([]providerSubnet, 0, len(prefixes))
	for rows.Next() {
		var subnet providerSubnet
		if err = rows.Scan(&subnet.ID, &subnet.CIDR); err != nil {
			return nil, createError(err)
		}
		result = append(result, subnet)
	}
	if err = rows.Err(); err != nil {
		return nil, createError(err)
	}
	if len(result) != len(prefixes) {
		return nil, ErrConnectionIneligible
	}
	return result, nil
}
func checkProviderRanges(ctx context.Context, tx pgx.Tx, org uuid.UUID, config StaticConfig) error {
	ranges, err := subnetguard.Collect(ctx, subnetsrc.Source{Q: sqlc.New(tx)}, org)
	if err != nil {
		return createError(err)
	}
	for _, raw := range config.RemotePrefixes {
		prefix := netip.MustParsePrefix(raw)
		if _, ok := subnetguard.Check(prefix, ranges); !ok {
			return ErrConnectionConflict
		}
	}
	outside := []string{config.CustomerOutsideAddress}
	for _, tunnel := range config.Tunnels {
		outside = append(outside, tunnel.OutsideAddress)
		if tunnel.InsideCIDR != "" {
			if _, ok := subnetguard.CheckInside(netip.MustParsePrefix(tunnel.InsideCIDR), ranges); !ok {
				return ErrConnectionConflict
			}
		}
	}
	for _, address := range outside {
		if _, ok := subnetguard.CheckUnderlay(netip.PrefixFrom(netip.MustParseAddr(address), 32), ranges); !ok {
			return ErrConnectionConflict
		}
	}

	return nil
}
func insertProvider(ctx context.Context, tx pgx.Tx, c Connection, r CreateDisabledRequest, config StaticConfig, subnets []providerSubnet) error {
	if _, err := tx.Exec(ctx, `INSERT INTO ipsec_provider_bindings(connection_id,org_id,profile_id) VALUES($1,$2,$3)`, c.ID, c.OrgID, providerProfile(config)); err != nil {
		return createError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ipsec_aws_static_configs(connection_id,org_id,site_id,gateway_node_id,customer_outside_ipv4) VALUES($1,$2,$3,$4,$5::inet)`, c.ID, c.OrgID, r.SiteID, r.GatewayID, config.CustomerOutsideAddress); err != nil {
		return createError(err)
	}
	if config.BGP != nil {
		b := config.BGP
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_aws_bgp_configs(connection_id,org_id,local_asn,remote_asn,router_id,maximum_prefixes) VALUES($1,$2,$3,$4,$5::inet,$6)`, c.ID, c.OrgID, int64(b.LocalASN), int64(b.RemoteASN), b.RouterID, b.MaximumPrefixes); err != nil {
			return createError(err)
		}
	}
	for i, t := range config.Tunnels {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_aws_tunnel_configs(tunnel_id,org_id,connection_id,slot,gateway_node_id,aws_outside_ipv4,inside_cidr,customer_inside_ipv4,aws_inside_ipv4) VALUES($1,$2,$3,$4,$5,$6::inet,NULLIF($7,'')::cidr,NULLIF($8,'')::inet,NULLIF($9,'')::inet)`, r.Tunnels[i].ID, c.OrgID, c.ID, i+1, r.GatewayID, t.OutsideAddress, t.InsideCIDR, t.CustomerInsideAddress, t.CloudInsideAddress); err != nil {
			return createError(err)
		}
	}
	for _, subnet := range subnets {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_aws_local_prefixes(connection_id,org_id,site_id,subnet_id,cidr) VALUES($1,$2,$3,$4,$5::cidr)`, c.ID, c.OrgID, r.SiteID, subnet.ID, subnet.CIDR); err != nil {
			return createError(err)
		}
	}
	for _, prefix := range config.RemotePrefixes {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_aws_remote_prefixes(connection_id,org_id,cidr) VALUES($1,$2,$3::cidr)`, c.ID, c.OrgID, prefix); err != nil {
			return createError(err)
		}
	}
	return nil
}
func removeProvider(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) error {
	//159 precedes deployment of this service. No compatibility fallback may hide
	// a missing schema. Binding history remains after withdrawing live children.
	var profile string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(provider_profile,'') FROM ipsec_connections WHERE id=$1 AND org_id=$2`, id, org).Scan(&profile); err != nil {
		return createError(err)
	}
	tables := []string{"ipsec_aws_local_prefixes", "ipsec_aws_remote_prefixes", "ipsec_aws_tunnel_configs", "ipsec_aws_static_configs"}
	if isBGPProfile(profile) {
		tables = append([]string{"ipsec_aws_bgp_configs"}, tables...)
	}
	for _, table := range tables {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE org_id=$1 AND connection_id=$2`, org, id); err != nil {
			return createError(err)
		}
	}
	return nil
}

// ReadProvider is internal and scoped; even its explicit configuration projection
// never selects envelopes, secret existence or revisions. Tombstones retain only
// profile/revision metadata. Ordinary HTTP list/detail DTOs are unchanged.
func (s *ConnectionStore) ReadProvider(ctx context.Context, org, id uuid.UUID) (ProviderConfiguration, error) {
	if s == nil || s.pool == nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	defer tx.Rollback(ctx)
	var result ProviderConfiguration
	var finalized *time.Time
	err = tx.QueryRow(ctx, `SELECT b.profile_id,b.configuration_revision,c.finalized_at FROM ipsec_provider_bindings b JOIN ipsec_connections c ON c.id=b.connection_id AND c.org_id=b.org_id JOIN organizations o ON o.id=c.org_id WHERE b.org_id=$1 AND b.connection_id=$2 AND o.deleted_at IS NULL`, org, id).Scan(&result.ProfileID, &result.ConfigurationRevision, &finalized)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderConfiguration{}, ErrConnectionNotFound
	}
	if err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	if finalized != nil {
		if err = tx.Commit(ctx); err != nil {
			return ProviderConfiguration{}, ErrConnectionUnavailable
		}
		return result, nil
	}
	config := &StaticConfig{ProfileID: result.ProfileID, Mode: "ipv4-static", LocalPrefixes: []string{}, RemotePrefixes: []string{}, Tunnels: []StaticTunnel{}}
	if isBGPProfile(result.ProfileID) {
		config.Mode = "ipv4-bgp"
		config.BGP = &BGPConfig{}
		b := config.BGP
		if err = tx.QueryRow(ctx, `SELECT local_asn,remote_asn,host(router_id),maximum_prefixes FROM ipsec_aws_bgp_configs WHERE org_id=$1 AND connection_id=$2`, org, id).Scan(&b.LocalASN, &b.RemoteASN, &b.RouterID, &b.MaximumPrefixes); err != nil {
			return ProviderConfiguration{}, ErrConnectionUnavailable
		}
	}
	if err = tx.QueryRow(ctx, `SELECT host(customer_outside_ipv4) FROM ipsec_aws_static_configs WHERE org_id=$1 AND connection_id=$2`, org, id).Scan(&config.CustomerOutsideAddress); err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT host(aws_outside_ipv4),COALESCE(inside_cidr::text,''),COALESCE(host(customer_inside_ipv4),''),COALESCE(host(aws_inside_ipv4),'') FROM ipsec_aws_tunnel_configs WHERE org_id=$1 AND connection_id=$2 ORDER BY slot`, org, id)
	if err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	for rows.Next() {
		var t StaticTunnel
		if err = rows.Scan(&t.OutsideAddress, &t.InsideCIDR, &t.CustomerInsideAddress, &t.CloudInsideAddress); err != nil {
			rows.Close()
			return ProviderConfiguration{}, ErrConnectionUnavailable
		}
		config.Tunnels = append(config.Tunnels, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	for _, table := range []string{"ipsec_aws_local_prefixes", "ipsec_aws_remote_prefixes"} {
		rows, err := tx.Query(ctx, `SELECT cidr::text FROM `+table+` WHERE org_id=$1 AND connection_id=$2 ORDER BY cidr`, org, id)
		if err != nil {
			return ProviderConfiguration{}, ErrConnectionUnavailable
		}
		for rows.Next() {
			var prefix string
			if err = rows.Scan(&prefix); err != nil {
				rows.Close()
				return ProviderConfiguration{}, ErrConnectionUnavailable
			}
			if table == "ipsec_aws_local_prefixes" {
				config.LocalPrefixes = append(config.LocalPrefixes, prefix)
			} else {
				config.RemotePrefixes = append(config.RemotePrefixes, prefix)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ProviderConfiguration{}, ErrConnectionUnavailable
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ProviderConfiguration{}, ErrConnectionUnavailable
	}
	result.Config = config
	return result, nil
}
