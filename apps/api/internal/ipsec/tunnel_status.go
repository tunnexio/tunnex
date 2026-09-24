package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

type RuntimeTunnelStatus struct {
	ID       uuid.UUID `json:"id"`
	Slot     int       `json:"slot"`
	Status   string    `json:"status"`
	Selected bool      `json:"selected"`
}
type RuntimeStatusReport struct {
	DeliveryID            uuid.UUID              `json:"delivery_id"`
	DesiredRevision       int64                  `json:"desired_revision"`
	ConfigurationRevision int64                  `json:"configuration_revision"`
	Tunnels               [2]RuntimeTunnelStatus `json:"tunnels"`
}
type ConnectionStatus struct {
	ObservedAt *time.Time            `json:"observed_at"`
	Tunnels    []RuntimeTunnelStatus `json:"tunnels"`
}

func (s *ConnectionStore) ReportStatus(ctx context.Context, p RuntimePrincipal, id uuid.UUID, r RuntimeStatusReport) error {
	if r.DeliveryID == uuid.Nil || r.DesiredRevision <= 0 || r.ConfigurationRevision != 1 {
		return ErrConnectionInvalid
	}
	for i, t := range r.Tunnels {
		if t.ID == uuid.Nil || t.Slot != i+1 || t.Selected != (i == 0) || (t.Status != "up" && t.Status != "down" && t.Status != "unknown") {
			return ErrConnectionInvalid
		}
	}
	if r.Tunnels[0].ID == r.Tunnels[1].ID {
		return ErrConnectionInvalid
	}
	tx, l, e := s.runtimeLock(ctx, p.OrgID, id, &p)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if l.connection.DesiredIntent != "enabled" || l.connection.DesiredRevision != r.DesiredRevision || l.state.cleanup != nil {
		return ErrConnectionConflict
	}
	if !l.enabled || !l.eligible {
		return ErrConnectionIneligible
	}
	var manifest []byte
	e = tx.QueryRow(ctx, `SELECT manifest FROM ipsec_runtime_deliveries WHERE id=$1 AND connection_id=$2 AND org_id=$3 AND node_id=$4 AND desired_revision=$5 AND configuration_revision=$6 AND certificate_serial=$7 AND kind='apply'`, r.DeliveryID, id, p.OrgID, p.NodeID, r.DesiredRevision, r.ConfigurationRevision, p.CertificateSerial).Scan(&manifest)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrConnectionConflict
	}
	if e != nil {
		return ErrConnectionUnavailable
	}
	var m RuntimeManifest
	if json.Unmarshal(manifest, &m) != nil {
		return ErrConnectionUnavailable
	}
	for i, t := range r.Tunnels {
		if t.ID != m.Tunnels[i].ID || t.Slot != m.Tunnels[i].Slot || t.Selected != m.Tunnels[i].Selected {
			return ErrConnectionInvalid
		}
	}
	raw, _ := json.Marshal(r.Tunnels)
	_, e = tx.Exec(ctx, `INSERT INTO ipsec_tunnel_status(connection_id,org_id,node_id,delivery_id,desired_revision,configuration_revision,certificate_serial,received_at,tunnels) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp(),$8) ON CONFLICT(connection_id) DO UPDATE SET node_id=excluded.node_id,delivery_id=excluded.delivery_id,desired_revision=excluded.desired_revision,configuration_revision=excluded.configuration_revision,certificate_serial=excluded.certificate_serial,received_at=excluded.received_at,tunnels=excluded.tunnels`, id, p.OrgID, p.NodeID, r.DeliveryID, r.DesiredRevision, r.ConfigurationRevision, p.CertificateSerial, raw)
	if e != nil {
		return ErrConnectionUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrConnectionUnavailable
	}
	return nil
}
func (s *ConnectionStore) ReadStatus(ctx context.Context, org, id uuid.UUID) (ConnectionStatus, error) {
	out := ConnectionStatus{Tunnels: []RuntimeTunnelStatus{}}
	if s == nil || s.pool == nil {
		return out, ErrConnectionUnavailable
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return out, ErrConnectionUnavailable
	}
	defer tx.Rollback(ctx)
	c, e := scanConnection(tx.QueryRow(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c JOIN organizations o ON o.id=c.org_id WHERE c.id=$1 AND c.org_id=$2 AND o.deleted_at IS NULL`, id, org))
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrConnectionNotFound
	}
	if e != nil {
		return out, ErrConnectionUnavailable
	}
	rows, e := tx.Query(ctx, `SELECT id,slot FROM ipsec_tunnels WHERE connection_id=$1 AND org_id=$2 ORDER BY slot`, id, org)
	if e != nil {
		return out, ErrConnectionUnavailable
	}
	for rows.Next() {
		var t RuntimeTunnelStatus
		if rows.Scan(&t.ID, &t.Slot) != nil {
			rows.Close()
			return out, ErrConnectionUnavailable
		}
		t.Selected = t.Slot == 1
		t.Status = "unknown"
		out.Tunnels = append(out.Tunnels, t)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, ErrConnectionUnavailable
	}
	var raw []byte
	var fresh bool
	var now time.Time
	e = tx.QueryRow(ctx, `SELECT clock_timestamp(),s.received_at,s.tunnels,COALESCE((s.desired_revision=$3 AND c.desired_intent='enabled' AND d.desired_revision=c.desired_revision AND d.kind='apply' AND d.configuration_revision=s.configuration_revision AND d.certificate_serial=s.certificate_serial AND n.cert_serial=s.certificate_serial AND n.status='active' AND n.revoked_at IS NULL AND n.site_id=c.site_id AND n.id=c.gateway_node_id AND n.capabilities->>'ipsec_config_version'='1' AND EXISTS(SELECT 1 FROM ipsec_org_settings o WHERE o.org_id=c.org_id AND o.enabled)),false) FROM ipsec_tunnel_status s JOIN ipsec_connections c ON c.id=s.connection_id JOIN ipsec_runtime_deliveries d ON d.id=s.delivery_id AND d.connection_id=c.id AND d.org_id=c.org_id JOIN nodes n ON n.id=s.node_id AND n.org_id=c.org_id WHERE s.connection_id=$1 AND s.org_id=$2`, id, org, c.DesiredRevision).Scan(&now, &out.ObservedAt, &raw, &fresh)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return out, ErrConnectionUnavailable
	}
	if fresh && tunnelStatusFresh(out.ObservedAt, now) && len(out.Tunnels) == 2 {
		var reported [2]RuntimeTunnelStatus
		if json.Unmarshal(raw, &reported) == nil {
			for i, t := range reported {
				if t.ID == out.Tunnels[i].ID && t.Slot == out.Tunnels[i].Slot && (t.Status == "up" || t.Status == "down" || t.Status == "unknown") {
					out.Tunnels[i].Status = t.Status
				}
			}
		}
	}
	if tx.Commit(ctx) != nil {
		return out, ErrConnectionUnavailable
	}
	return out, nil
}

func tunnelStatusFresh(received *time.Time, now time.Time) bool {
	return received != nil && !received.After(now) && !received.Before(now.Add(-90*time.Second))
}
