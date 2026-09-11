package aigateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ResolveVPNModel is called only by the authenticated gateway mTLS channel.
// The gateway must have observed the source on its VPN-only ingress. Never call
// this with a public HTTP forwarding header or a NAT address.
func (s *Policies) ResolveVPNModel(ctx context.Context, org, node uuid.UUID, source, key, model string) (Grant, error) {
	if s == nil || s.vpnIngress == nil || s.vpnIngress.Node != node {
		return Grant{}, policyDenied()
	}
	ip, err := netip.ParseAddr(source)
	raw, keyErr := base64.StdEncoding.DecodeString(key)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || keyErr != nil || len(raw) != 32 || node == uuid.Nil {
		return Grant{}, policyDenied()
	}
	return s.resolveUserModel(ctx, org, uuid.Nil, model, func(tx pgx.Tx) (uuid.UUID, error) {
		var user uuid.UUID
		var roles []string
		// Org and gateway come from the authenticated node, never from the client.
		// An active human device with an exact current key/address must be homed here.
		err := tx.QueryRow(ctx, `SELECT d.user_id,m.roles FROM devices d JOIN memberships m ON m.org_id=d.org_id AND m.user_id=d.user_id
   WHERE d.org_id=$1 AND d.node_id=$2 AND d.public_key=$3
   AND d.assigned_ip=$4 AND d.transport='wireguard' AND d.kind='human'
   AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND m.access_revoked_at IS NULL
   FOR SHARE`, org, node, key, ip.String()).Scan(&user, &roles)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, policyDenied()
		}
		if err != nil {
			return uuid.Nil, aiUnavailable()
		}
		if !rbac.CanAny(roles, rbac.PermAIModelUse) {
			return uuid.Nil, policyDenied()
		}
		return user, nil
	})
}

// VPNIngress is an explicitly provisioned single-gateway ingress. Configuration
// does not enable organization AI or grant any model access.
type VPNIngress struct {
	Host    string
	Node    uuid.UUID
	Address netip.Addr
}

func (s *Policies) ConfigureVPNIngress(host, node, address string) error {
	if host == "" && node == "" && address == "" {
		return nil
	}
	id, err := uuid.Parse(node)
	ip, ipErr := netip.ParseAddr(address)
	host = strings.ToLower(strings.TrimSpace(host))
	if err != nil || id == uuid.Nil || ipErr != nil || !ip.Is4() || !ip.IsPrivate() || host == "" || strings.ContainsAny(host, "/:@ ") {
		return fmt.Errorf("invalid VPN AI ingress configuration")
	}
	s.vpnIngress = &VPNIngress{Host: host, Node: id, Address: ip}
	return nil
}

// VPNDeviceIngress only publishes split DNS to the active device's owner, for
// the explicitly provisioned gateway. Generic org reads cannot acquire it.
func (s *Policies) VPNDeviceIngress(ctx context.Context, org, device, user uuid.UUID) *VPNIngress {
	if s == nil || s.vpnIngress == nil || s.pool == nil {
		return nil
	}
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices d JOIN nodes n ON n.id=d.node_id AND n.org_id=d.org_id JOIN organizations o ON o.id=d.org_id
 WHERE d.org_id=$1 AND d.id=$2 AND d.user_id=$3 AND d.node_id=$4
 AND d.kind='human' AND d.transport='wireguard' AND d.status='active' AND NOT d.health_blocked AND d.deleted_at IS NULL
 AND n.status='active' AND o.ai_gateway_enabled AND o.deleted_at IS NULL)`, org, device, user, s.vpnIngress.Node).Scan(&ok)
	if err != nil || !ok {
		return nil
	}
	v := *s.vpnIngress
	return &v
}
