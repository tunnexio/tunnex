package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"net/netip"
	"sort"
)

// Keys come from enrollment in the same authoritative snapshot; callers cannot
// turn a literal VPN CIDR policy into a device identity.
func loadIPsecDesktopKeys(ctx context.Context, q *sqlc.Queries, org uuid.UUID, snapshot *Snapshot) error {
	for i, d := range snapshot.Devices {
		if d.Kind != "human" {
			continue
		}
		row, err := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: d.ID, OrgID: org})
		if err != nil {
			return err
		}
		if row.Status == "active" && !row.HealthBlocked && row.Transport == "wireguard" && row.AssignedIp != nil && *row.AssignedIp == d.AssignedIP && row.UserID == d.UserID && row.NodeID == d.NodeID {
			snapshot.Devices[i].PublicKey = row.PublicKey
		}
	}
	return nil
}

// V1 intentionally enables AWS BGP only. Static/Azure/GCP require their own
// return-routing qualification; the identity and policy seam is provider-neutral.
func compileIPsecDesktopGrants(s Snapshot, in ipsec.RuntimePolicyInput) []ipsec.RuntimeDesktopGrant {
	if s.Mode != ModeEnforcing || in.DesktopTransitVersion != 1 || in.Config.ProfileID != "aws-bgp-ipv4-v1" || in.Config.BGP == nil {
		return nil
	}
	byID := map[string]Device{}
	addresses := map[string]int{}
	for _, d := range s.Devices {
		addresses[d.AssignedIP]++
	}
	for _, d := range s.Devices {
		a, err := netip.ParseAddr(d.AssignedIP)
		key, keyErr := base64.StdEncoding.DecodeString(d.PublicKey)
		if d.ID == uuid.Nil || d.UserID == uuid.Nil || d.NodeID != in.NodeID || d.Kind != "human" || err != nil || !a.Is4() || !a.IsGlobalUnicast() || keyErr != nil || len(key) != 32 || addresses[d.AssignedIP] != 1 {
			continue
		}
		source := netip.PrefixFrom(a, 32)
		if runtimePolicyWithin(source, in.Config.LocalPrefixes) || runtimePolicyWithin(source, in.Config.RemotePrefixes) {
			continue
		}
		byID[d.ID.String()] = d
	}
	filtered := s
	filtered.Rules = nil
	expiries := map[string]Rule{}
	for _, r := range s.Rules {
		if r.Disabled || r.ID == uuid.Nil || r.DstKind != "resource" || (r.SrcKind != "user" && r.SrcKind != "group" && r.SrcKind != "") {
			continue
		}
		if r.ExpiresAt != nil && (in.CompiledAt.IsZero() || !r.ExpiresAt.After(in.CompiledAt)) {
			continue
		}
		filtered.Rules = append(filtered.Rules, r)
		expiries[r.ID.String()] = r
	}
	var out []ipsec.RuntimeDesktopGrant
	for _, g := range Compile(filtered)[in.NodeID].Allow {
		d, ok := byID[g.SrcDeviceID]
		destination, valid := runtimePolicyPrefix(g.DstCIDR)
		rule, ruleOK := expiries[g.RuleID]
		if !ok || !ruleOK || g.SrcIP != d.AssignedIP || !valid || !runtimePolicyWithin(destination, in.Config.RemotePrefixes) || g.FQDNManaged || g.PortLow < 0 || g.PortHigh < 0 || g.PortLow > 65535 || g.PortHigh > 65535 {
			continue
		}
		out = append(out, ipsec.RuntimeDesktopGrant{RuntimeGrant: ipsec.RuntimeGrant{Source: d.AssignedIP + "/32", Destination: destination.String(), Protocol: string(g.Protocol), PortLow: uint16(g.PortLow), PortHigh: uint16(g.PortHigh), RuleID: g.RuleID}, DeviceID: d.ID.String(), PublicKey: d.PublicKey, ExpiresAt: rule.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	// Local exports share the existing 64-prefix bound; never silently truncate.
	seen := map[string]bool{}
	for _, g := range out {
		seen[g.Source] = true
	}
	if len(seen)+len(in.Config.LocalPrefixes) > 64 {
		return nil
	}
	return out
}

// DeviceIPsecRoutedRanges uses the existing authenticated desktop poll. Only an
// enabled, delivered same-gateway connection and an active explicit grant export
// a route. The gateway's independent lease remains the forwarding authority.
func (s *Service) DeviceIPsecRoutedRanges(ctx context.Context, org, device uuid.UUID) ([]string, error) {
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
	if err = loadIPsecDesktopKeys(ctx, q, org, &snapshot); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT d.manifest,clock_timestamp() FROM ipsec_runtime_deliveries d
 JOIN ipsec_connections c ON c.id=d.connection_id AND c.org_id=d.org_id AND c.desired_revision=d.desired_revision
 JOIN ipsec_org_settings s ON s.org_id=c.org_id AND s.enabled
 JOIN nodes n ON n.id=d.node_id AND n.org_id=d.org_id AND n.site_id=d.site_id
 WHERE c.org_id=$1 AND c.desired_intent='enabled' AND c.finalized_at IS NULL AND d.kind='apply'
 AND n.status='active' AND n.revoked_at IS NULL AND n.capabilities->'ipsec_desktop_transit_version'='1'::jsonb
 AND n.policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp()`, org)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for rows.Next() {
		var raw []byte
		var in ipsec.RuntimePolicyInput
		if err = rows.Scan(&raw, &in.CompiledAt); err != nil {
			rows.Close()
			return nil, err
		}
		var m ipsec.RuntimeManifest
		if json.Unmarshal(raw, &m) != nil {
			rows.Close()
			return nil, ipsec.ErrConnectionUnavailable
		}
		in.OrgID = org
		in.NodeID = m.NodeID
		in.SiteID = m.SiteID
		in.ConnectionID = m.ConnectionID
		in.DesktopTransitVersion = 1
		in.Config = ipsec.StaticConfig{ProfileID: m.ProfileID, LocalPrefixes: m.LocalPrefixes, RemotePrefixes: m.RemotePrefixes, BGP: m.BGP}
		for _, g := range compileIPsecDesktopGrants(snapshot, in) {
			if g.DeviceID == device.String() {
				seen[g.Destination] = true
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
