package sandboxes

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"net"
	"net/netip"
	"strconv"
)

// RemoteTerminalBinding is explicit operator metadata; no public request or
// saved-key selection can create a transport corridor or move a device.
type RemoteTerminalBinding struct {
	GatewayID                               uuid.UUID
	GatewayEndpoint, RuntimeGatewayEndpoint string
}

func validPrivateGatewayEndpoint(value string) bool {
	host, port, e := net.SplitHostPort(value)
	ip, ipErr := netip.ParseAddr(host)
	n, pErr := strconv.Atoi(port)
	return e == nil && ipErr == nil && ip.Is4() && ip.IsPrivate() && pErr == nil && n > 0 && n <= 65535
}
func (b BoundedRuntimeBinding) terminalGatewayID() uuid.UUID {
	if b.RemoteTerminal != nil {
		return b.RemoteTerminal.GatewayID
	}
	return b.GatewayID
}
func (b BoundedRuntimeBinding) validRemoteTerminal() bool {
	r := b.RemoteTerminal
	return r == nil || (b.Persistent() && r.GatewayID != uuid.Nil && r.GatewayID != b.GatewayID && validPrivateGatewayEndpoint(r.GatewayEndpoint) && validPrivateGatewayEndpoint(r.RuntimeGatewayEndpoint))
}
func (b BoundedRuntimeBinding) validateTerminalDevice(ctx context.Context, q reservationReader, actor, device uuid.UUID) error {
	if actor == uuid.Nil || device == uuid.Nil {
		return ErrForbidden
	}
	var admitted bool
	if err := q.QueryRow(ctx, `SELECT true FROM devices WHERE id=$1 AND org_id=$2 AND user_id=$3 AND node_id=$4 AND kind='human' AND status='active' AND deleted_at IS NULL AND NOT health_blocked
 AND (NOT $5 OR EXISTS(SELECT 1 FROM nodes n WHERE n.id=devices.node_id AND n.org_id=devices.org_id AND n.status='active' AND COALESCE(n.enrolled_kind,'gateway')='gateway' AND n.wg_public_key<>'')) FOR SHARE OF devices`, device, b.OrgID, actor, b.terminalGatewayID(), b.OrganizationScoped()).Scan(&admitted); err == pgx.ErrNoRows {
		return ErrForbidden
	} else if err != nil {
		return err
	}
	if !admitted {
		return ErrForbidden
	}
	return nil
}
func (b BoundedRuntimeBinding) validateRemoteTerminal(ctx context.Context, tx pgx.Tx, actor, device uuid.UUID) error {
	if b.RemoteTerminal == nil || !b.validRemoteTerminal() {
		return ErrForbidden
	}
	var global bool
	var address string
	// A runtime is dedicated to this corridor, not a site/HA carrier or a
	// gateway hosting existing human/agent subjects. Ordinary routing stays on
	// its existing carriers and cannot supply sandbox grants implicitly.
	err := tx.QueryRow(ctx, `SELECT o.cross_gateway_clients_enabled,COALESCE(d.assigned_ip,'') FROM devices d JOIN nodes terminal ON terminal.id=d.node_id AND terminal.org_id=d.org_id AND terminal.status='active' AND COALESCE(terminal.enrolled_kind,'gateway')='gateway' JOIN nodes runtime ON runtime.id=$5 AND runtime.org_id=d.org_id AND runtime.status='active' AND runtime.site_id IS NULL AND COALESCE(runtime.enrolled_kind,'gateway')='gateway' JOIN organizations o ON o.id=d.org_id WHERE d.id=$1 AND d.org_id=$2 AND d.user_id=$3 AND d.node_id=$4 AND d.kind='human' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND terminal.wg_public_key<>'' AND runtime.wg_public_key<>'' AND NOT EXISTS(SELECT 1 FROM devices existing WHERE existing.org_id=d.org_id AND existing.node_id=runtime.id AND existing.kind IN ('human','agent') AND existing.deleted_at IS NULL)`, device, b.OrgID, actor, b.RemoteTerminal.GatewayID, b.GatewayID).Scan(&global, &address)
	if err == pgx.ErrNoRows {
		return ErrForbidden
	}
	if err != nil {
		return err
	}
	if global {
		ordinary, err := gatewaymesh.Load(ctx, sqlc.New(tx), b.OrgID, true, true)
		if err != nil {
			return err
		}
		if ordinary == nil || ordinary.Owner(address) != b.RemoteTerminal.GatewayID || ordinary.Relay == b.GatewayID {
			return ErrForbidden
		}
	}
	return nil
}
func (b BoundedRuntimeBinding) persistRemoteTerminal(ctx context.Context, tx pgx.Tx, id, device uuid.UUID) error {
	if b.RemoteTerminal == nil {
		return nil
	}
	r := b.RemoteTerminal
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_remote_terminal_routes(sandbox_id,org_id,terminal_device_id,terminal_gateway_id,runtime_gateway_id,terminal_gateway_endpoint,runtime_gateway_endpoint) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, b.OrgID, device, r.GatewayID, b.GatewayID, r.GatewayEndpoint, r.RuntimeGatewayEndpoint)
	return err
}
