package policy

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// The selected gateway's local WG address is the desktop resolver destination.
// The routed-ranges handler covers it with an exact route when needed. Upstream
// resolver endpoints remain private dependencies, not desktop destinations.
func (s *Service) devicePrivateDNSForwards(ctx context.Context, org, deviceID uuid.UUID) ([]policyspec.DNSForward, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := sqlc.New(tx)
	snapshot, err := BuildSnapshotWithQueries(ctx, q, org)
	if err != nil {
		return nil, err
	}
	device, err := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: org})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if device.Status != "active" || device.HealthBlocked || device.Transport != "wireguard" || device.Kind != "human" {
		return nil, nil
	}
	node, err := q.GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: device.NodeID, OrgID: org})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	var caps struct {
		Version int `json:"max_policy_version"`
		RPC     int `json:"dns_resolve_rpc_version"`
		IPsec   int `json:"dns_ipsec_resolve_version"`
	}
	if json.Unmarshal(node.Capabilities, &caps) != nil || caps.Version < 11 || node.Status != "active" || node.RevokedAt.Valid || node.CertSerial == "" || !node.SiteID.Valid || !node.PolicyReportedAt.Valid || node.PolicyReportedAt.Time.After(now) || now.Sub(node.PolicyReportedAt.Time) > 90*time.Second {
		return nil, nil
	}
	organization, err := q.GetOrganizationByID(ctx, org)
	if err != nil {
		return nil, err
	}
	cidr, err := ipalloc.GatewayCIDR(organization.PoolCidr)
	if err != nil {
		return nil, err
	}
	gateway := netip.MustParsePrefix(cidr).Addr().String()
	rows, err := q.ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil {
		return nil, err
	}
	profiles := []IPsecDNSProfile{}
	for _, row := range rows {
		if row.GatewayID != device.NodeID {
			continue
		}
		profile, err := DecodeIPsecDNSProfile(row)
		if err != nil {
			return nil, err
		}
		if len(profile.Profile.StaticRecords) > 0 {
			if caps.Version < 12 || (len(profile.Profile.Endpoints) > 0 && caps.Version < 14) {
				continue
			}
		} else if !profile.TransportAvailable || caps.RPC != 2 || caps.IPsec != 1 {
			continue
		}
		profiles = append(profiles, profile)
	}
	out := devicePrivateDNSForwardsFromSnapshot(snapshot, deviceID, device.NodeID, gateway, profiles)
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func devicePrivateDNSForwardsFromSnapshot(snapshot Snapshot, deviceID, nodeID uuid.UUID, gateway string, profiles []IPsecDNSProfile) []policyspec.DNSForward {
	out := []policyspec.DNSForward{}
	if snapshot.Mode != ModeEnforcing || deviceID == uuid.Nil || nodeID == uuid.Nil {
		return out
	}
	address, err := netip.ParseAddr(gateway)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
		return out
	}
	var selected *Device
	addresses := map[string]int{}
	for _, d := range snapshot.Devices {
		addresses[d.AssignedIP]++
		if d.ID == deviceID {
			if selected != nil {
				return out
			}
			copy := d
			selected = &copy
		}
	}
	if selected == nil || selected.Kind != "human" || selected.NodeID != nodeID || addresses[selected.AssignedIP] != 1 {
		return out
	}
	filtered := snapshot
	filtered.Rules = nil
	for _, rule := range snapshot.Rules {
		if !rule.Disabled && rule.DstKind == "resource" && (rule.SrcKind == "user" || rule.SrcKind == "group" || rule.SrcKind == "") {
			filtered.Rules = append(filtered.Rules, rule)
		}
	}
	allows := []policyspec.AllowEntry{}
	for _, allow := range Compile(filtered)[nodeID].Allow {
		if allow.SrcDeviceID == deviceID.String() && allow.SrcIP == selected.AssignedIP && !allow.FQDNManaged {
			allows = append(allows, allow)
		}
	}
	// Use only the selected gateway as the permission target here. Upstream
	// endpoint grants and LAN listener ranges cannot publish desktop suffixes.
	permission := IPsecDNSProfile{Profile: policyspec.DNSResolverProfile{Endpoints: []policyspec.DNSResolverEndpoint{{Address: gateway, Port: 53, Transport: "udp"}}}}
	if len(DNSProfileForAllowedTraffic(permission, allows).AllowedSources) != 1 {
		return out
	}
	zones := map[string]bool{}
	for _, profile := range profiles {
		if len(profile.Profile.StaticRecords) == 0 && !profile.TransportAvailable {
			continue
		}
		for _, zone := range profile.Profile.ZoneSuffixes {
			if normalized, ok := normalizeResolverMatchSuffix(zone); ok && normalized != "" {
				zones[normalized] = true
			}
		}
	}
	for zone := range zones {
		out = append(out, policyspec.DNSForward{Domain: zone, ResolverIP: gateway})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}
