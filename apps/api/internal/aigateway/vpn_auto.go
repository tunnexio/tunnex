package aigateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
)

// ConfigureAutomaticVPNIngress enables only the deployment feature. It does
// not enable HTTP, organization AI, a user, or a model grant.
func (s *Policies) ConfigureAutomaticVPNIngress(enabled bool) { s.autoVPN = enabled }
func (s *Policies) AutomaticVPNEnabled() bool                 { return s != nil && s.autoVPN }

// readyVPNAddress accepts only a typed ready report for the exact organization
// gateway address. The caller checks report freshness using PostgreSQL's clock.
func readyVPNAddress(raw []byte, poolCIDR string) string {
	var caps struct {
		Ready   bool   `json:"ai_vpn_http_ready"`
		Address string `json:"ai_vpn_http_address"`
	}
	if json.Unmarshal(raw, &caps) != nil || !caps.Ready {
		return ""
	}
	ip, err := netip.ParseAddr(caps.Address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != caps.Address {
		return ""
	}
	gateway, err := ipalloc.GatewayCIDR(poolCIDR)
	if err != nil {
		return ""
	}
	prefix, err := netip.ParsePrefix(gateway)
	if err != nil || prefix.Addr() != ip {
		return ""
	}
	return ip.String()
}

// ResolveAutomaticVPNModel is only for the dedicated certificate-authenticated
// HTTP relay route, after its current saved HTTP policy check. Manual TLS keeps
// its independent explicitly provisioned gateway restriction.
func (s *Policies) ResolveAutomaticVPNModel(ctx context.Context, org, node uuid.UUID, source, key, model string, singleOrg bool) (Grant, error) {
	if !s.AutomaticVPNEnabled() || s.pool == nil {
		return Grant{}, policyDenied()
	}
	var caps []byte
	var cidr string
	err := s.pool.QueryRow(ctx, `SELECT n.capabilities,o.pool_cidr FROM nodes n
 JOIN organizations o ON o.id=n.org_id WHERE n.org_id=$1 AND n.id=$2
 AND n.status='active' AND n.revoked_at IS NULL AND o.deleted_at IS NULL AND o.ai_gateway_enabled
 AND n.policy_reported_at >= now()-interval '90 seconds' AND n.policy_reported_at <= now()`, org, node).Scan(&caps, &cidr)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, policyDenied()
	}
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	if readyVPNAddress(caps, cidr) == "" {
		return Grant{}, policyDenied()
	}
	return s.resolveVPNPeerModel(ctx, org, node, source, key, model, singleOrg)
}

// AutomaticVPNBaseURL discovers an endpoint on the requesting user's own live
// WireGuard device. It does not assert which device the user is currently using.
// HTTP permission is checked separately by the human handler and each inference.
func (s *Policies) AutomaticVPNBaseURL(ctx context.Context, org, user uuid.UUID) (string, error) {
	if !s.AutomaticVPNEnabled() || s.pool == nil {
		return "", nil
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT n.capabilities,o.pool_cidr FROM devices d
 JOIN nodes n ON n.org_id=d.org_id AND n.id=d.node_id
 JOIN organizations o ON o.id=d.org_id
 JOIN memberships m ON m.org_id=d.org_id AND m.user_id=d.user_id
 JOIN users u ON u.id=d.user_id
 WHERE d.org_id=$1 AND d.user_id=$2 AND d.transport='wireguard' AND d.kind='human'
 AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked
 AND n.status='active' AND n.revoked_at IS NULL AND o.deleted_at IS NULL AND o.ai_gateway_enabled
 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL
 AND u.email_verified_at IS NOT NULL AND NOT (u.must_change_password AND u.password_hash IS NOT NULL)
 AND n.policy_reported_at >= now()-interval '90 seconds' AND n.policy_reported_at <= now()`, org, user)
	if err != nil {
		return "", aiUnavailable()
	}
	defer rows.Close()
	address := ""
	for rows.Next() {
		var caps []byte
		var cidr string
		if rows.Scan(&caps, &cidr) != nil {
			return "", aiUnavailable()
		}
		if candidate := readyVPNAddress(caps, cidr); candidate != "" {
			address = candidate
		}
	}
	if rows.Err() != nil {
		return "", aiUnavailable()
	}
	if address == "" {
		return "", nil
	}
	var memberships int
	// lint:cross-org count only this already verified device owner's live memberships, exactly like the existing short-route authorization guard.
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN organizations o ON o.id=m.org_id WHERE m.user_id=$1 AND m.access_revoked_at IS NULL AND o.deleted_at IS NULL`, user).Scan(&memberships); err != nil {
		return "", aiUnavailable()
	}
	if memberships == 1 {
		return "http://" + address + ":8083/ai/v1", nil
	}
	return "http://" + address + ":8083/api/v1/organizations/" + org.String() + "/ai-gateway/inference/v1", nil
}
