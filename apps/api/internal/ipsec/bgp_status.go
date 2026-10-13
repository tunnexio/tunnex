package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"reflect"
	"time"
)

func validBGPStatus(m RuntimeManifest, r RuntimeStatusReport) bool {
	b := r.BGP
	if r.TransportVersion != nil || r.TunnelCount != nil || !runtimeBGPCompatible(m, true) || b == nil || b.Version != 1 || b.Sequence == 0 || b.Sequence > 9007199254740991 || r.RecoveryVersion != nil || r.ActiveSlot != nil || r.SelectionSequence != nil || b.Routes == nil || len(b.Routes) > len(m.RemotePrefixes) {
		return false
	}
	allowed := map[string]bool{}
	for _, p := range m.RemotePrefixes {
		allowed[p] = true
	}
	installed := [2]int{}
	seen := map[string]bool{}
	for _, route := range b.Routes {
		if route.Slot < 1 || route.Slot > 2 || !allowed[route.Prefix] || seen[route.Prefix] {
			return false
		}
		if _, ok := canonicalIPv4Prefix(route.Prefix); !ok {
			return false
		}
		seen[route.Prefix] = true
		installed[route.Slot-1]++
	}
	for i, p := range b.Peers {
		switch p.State {
		case "unknown", "idle", "connect", "active", "opensent", "openconfirm", "established":
		default:
			return false
		}
		if p.Slot != i+1 || p.AcceptedPrefixes < 0 || p.AcceptedPrefixes > m.BGP.MaximumPrefixes || p.AcceptedPrefixes > len(allowed) || p.InstalledPrefixes != installed[i] || p.InstalledPrefixes > p.AcceptedPrefixes || (p.State != "established" && (p.AcceptedPrefixes != 0 || p.InstalledPrefixes != 0)) || p.RejectedPrefixes != nil && (*p.RejectedPrefixes < 0 || *p.RejectedPrefixes > 1000000000) {
			return false
		}
		t := r.Tunnels[i]
		if t.ID != m.Tunnels[i].ID || t.Slot != i+1 || t.Selected || (t.Status != "up" && t.Status != "down" && t.Status != "unknown") || (p.State == "established" && t.Status != "up") {
			return false
		}
	}
	return true
}
func (s *ConnectionStore) reportBGPStatus(ctx context.Context, p RuntimePrincipal, id uuid.UUID, r RuntimeStatusReport) error {
	if r.DeliveryID == uuid.Nil || r.DesiredRevision <= 0 || r.ConfigurationRevision != 1 {
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
	if !l.enabled || !l.bgpEligible {
		return ErrConnectionIneligible
	}
	// runtimeLock authenticates the current active enrollment certificate. Delivery
	// ownership remains immutable across renewal; reports bind its exact node identity.
	var manifestRaw []byte
	e = tx.QueryRow(ctx, `SELECT manifest FROM ipsec_runtime_deliveries WHERE id=$1 AND connection_id=$2 AND org_id=$3 AND node_id=$4 AND desired_revision=$5 AND configuration_revision=$6 AND kind='apply'`, r.DeliveryID, id, p.OrgID, p.NodeID, r.DesiredRevision, r.ConfigurationRevision).Scan(&manifestRaw)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrConnectionConflict
	}
	if e != nil {
		return ErrConnectionUnavailable
	}
	var m RuntimeManifest
	if json.Unmarshal(manifestRaw, &m) != nil {
		return ErrConnectionUnavailable
	}
	if m.ProfileID == GCPHAProfile && !l.gcpHAEligible {
		return ErrConnectionIneligible
	}
	if !validBGPStatus(m, r) {
		return ErrConnectionInvalid
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 16384 {
		return ErrConnectionInvalid
	}
	var oldRaw []byte
	var delivery uuid.UUID
	e = tx.QueryRow(ctx, `SELECT delivery_id,report FROM ipsec_bgp_status WHERE connection_id=$1 FOR UPDATE`, id).Scan(&delivery, &oldRaw)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return ErrConnectionUnavailable
	}
	if e == nil && delivery == r.DeliveryID {
		var old RuntimeStatusReport
		if json.Unmarshal(oldRaw, &old) != nil || old.BGP == nil {
			return ErrConnectionUnavailable
		}
		if r.BGP.Sequence < old.BGP.Sequence {
			return ErrConnectionConflict
		}
		if r.BGP.Sequence == old.BGP.Sequence {
			if !reflect.DeepEqual(old, r) {
				return ErrConnectionConflict
			}
			return tx.Commit(ctx)
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO ipsec_bgp_status(connection_id,org_id,node_id,delivery_id,desired_revision,configuration_revision,certificate_serial,received_at,report) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp(),$8) ON CONFLICT(connection_id) DO UPDATE SET node_id=excluded.node_id,delivery_id=excluded.delivery_id,desired_revision=excluded.desired_revision,configuration_revision=excluded.configuration_revision,certificate_serial=excluded.certificate_serial,received_at=excluded.received_at,report=excluded.report`, id, p.OrgID, p.NodeID, r.DeliveryID, r.DesiredRevision, r.ConfigurationRevision, p.CertificateSerial, raw)
	if e != nil {
		return ErrConnectionUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrConnectionUnavailable
	}
	return nil
}
func readBGPStatus(ctx context.Context, tx pgx.Tx, c Connection, out *ConnectionStatus) error {
	var now time.Time
	var raw, manifestRaw []byte
	var fresh bool
	e := tx.QueryRow(ctx, `SELECT clock_timestamp(),s.received_at,s.report,d.manifest,COALESCE((c.desired_intent='enabled' AND c.desired_revision=s.desired_revision AND d.kind='apply' AND d.desired_revision=c.desired_revision AND d.configuration_revision=s.configuration_revision AND d.node_id=s.node_id AND d.org_id=s.org_id AND n.cert_serial=s.certificate_serial AND n.status='active' AND n.revoked_at IS NULL AND n.site_id=c.site_id AND n.id=c.gateway_node_id AND n.capabilities->'ipsec_config_version'='1'::jsonb AND n.capabilities->'ipsec_bgp_version'='1'::jsonb AND (c.provider_profile<>'gcp-ha-bgp-ipv4-v1' OR n.capabilities->'ipsec_gcp_ha_version'='1'::jsonb) AND n.policy_reported_at BETWEEN clock_timestamp()-interval '90 seconds' AND clock_timestamp() AND EXISTS(SELECT 1 FROM ipsec_org_settings o WHERE o.org_id=c.org_id AND o.enabled) AND NOT EXISTS(SELECT 1 FROM ipsec_runtime_state r WHERE r.connection_id=c.id AND r.current_cleanup_id IS NOT NULL)),false) FROM (SELECT connection_id,org_id,node_id,delivery_id,desired_revision,configuration_revision,certificate_serial,received_at,report FROM ipsec_bgp_status UNION ALL SELECT connection_id,org_id,node_id,delivery_id,desired_revision,configuration_revision,certificate_serial,received_at,jsonb_build_object('tunnels',tunnels) AS report FROM ipsec_tunnel_status) s JOIN ipsec_connections c ON c.id=s.connection_id AND c.org_id=s.org_id JOIN ipsec_runtime_deliveries d ON d.id=s.delivery_id AND d.connection_id=c.id AND d.org_id=c.org_id JOIN nodes n ON n.id=s.node_id AND n.org_id=c.org_id WHERE s.connection_id=$1 AND s.org_id=$2 ORDER BY s.received_at DESC LIMIT 1`, c.ID, c.OrgID).Scan(&now, &out.ObservedAt, &raw, &manifestRaw, &fresh)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return ErrConnectionUnavailable
	}
	if !fresh || !tunnelStatusFresh(out.ObservedAt, now) || len(out.Tunnels) != 2 {
		return nil
	}
	var r RuntimeStatusReport
	var m RuntimeManifest
	if json.Unmarshal(raw, &r) != nil || json.Unmarshal(manifestRaw, &m) != nil || (r.BGP != nil && !validBGPStatus(m, r)) || (r.BGP == nil && !validMissingBGPStatus(m, r)) {
		return nil
	}
	for i, t := range r.Tunnels {
		if t.ID != out.Tunnels[i].ID || t.Slot != out.Tunnels[i].Slot {
			return nil
		}
	}
	out.BGP = r.BGP
	out.Tunnels = []RuntimeTunnelStatus{r.Tunnels[0], r.Tunnels[1]}
	return nil
}

// Fixed Go arrays otherwise silently discard extra JSON peer elements.
func (b *RuntimeBGPStatus) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Version  int                    `json:"version"`
		Sequence uint64                 `json:"sequence"`
		Peers    []RuntimeBGPPeerStatus `json:"peers"`
		Routes   []RuntimeBGPRoute      `json:"routes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if len(wire.Peers) != 2 {
		return ErrConnectionInvalid
	}
	*b = RuntimeBGPStatus{Version: wire.Version, Sequence: wire.Sequence, Peers: [2]RuntimeBGPPeerStatus{wire.Peers[0], wire.Peers[1]}, Routes: wire.Routes}
	return nil
}

// Required observation counts must be explicit; missing/null does not mean zero.
func (p *RuntimeBGPPeerStatus) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Slot              *int    `json:"slot"`
		State             *string `json:"state"`
		AcceptedPrefixes  *int    `json:"accepted_prefixes"`
		InstalledPrefixes *int    `json:"installed_prefixes"`
		RejectedPrefixes  *int    `json:"rejected_prefixes,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if wire.Slot == nil || wire.State == nil || wire.AcceptedPrefixes == nil || wire.InstalledPrefixes == nil {
		return ErrConnectionInvalid
	}
	*p = RuntimeBGPPeerStatus{Slot: *wire.Slot, State: *wire.State, AcceptedPrefixes: *wire.AcceptedPrefixes, InstalledPrefixes: *wire.InstalledPrefixes, RejectedPrefixes: wire.RejectedPrefixes}
	return nil
}

// Missing observation preserves unknown BGP counters, never fabricated zeroes.
func validMissingBGPStatus(m RuntimeManifest, r RuntimeStatusReport) bool {
	if !runtimeBGPCompatible(m, true) || r.BGP != nil || r.RecoveryVersion != nil || r.SelectionSequence != nil || r.ActiveSlot != nil {
		return false
	}
	for i, t := range r.Tunnels {
		if t.ID != m.Tunnels[i].ID || t.Slot != i+1 || t.Selected || (t.Status != "up" && t.Status != "down" && t.Status != "unknown") {
			return false
		}
	}
	return true
}
