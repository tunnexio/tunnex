package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

type Eligibility struct {
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason"`
}

// gatewayEligibilityReason is shared by advisory reads and locked creation.
func gatewayEligibilityReason(status, serial string, revoked, reported *time.Time, capabilities []byte, clock time.Time) string {
	if status != "active" || revoked != nil || strings.TrimSpace(serial) == "" {
		return "gateway_unavailable"
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(capabilities, &caps) != nil || string(caps["ipsec_config_version"]) != "1" {
		return "unsupported"
	}
	if reported == nil || reported.After(clock) || clock.Sub(*reported) > 90*time.Second {
		return "report_stale"
	}
	return "eligible"
}

// ReadEligibility never locks or writes. Creation must recheck under its locks.
func (s *ConnectionStore) ReadEligibility(ctx context.Context, org, site, gateway uuid.UUID) (Eligibility, error) {
	if org == uuid.Nil || site == uuid.Nil || gateway == uuid.Nil {
		return Eligibility{}, ErrConnectionInvalid
	}
	if s == nil || s.pool == nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	defer tx.Rollback(ctx)
	var live bool
	if err = tx.QueryRow(ctx, `SELECT true FROM organizations WHERE id=$1 AND deleted_at IS NULL`, org).Scan(&live); errors.Is(err, pgx.ErrNoRows) {
		return Eligibility{}, ErrConnectionNotFound
	} else if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT enabled FROM ipsec_org_settings WHERE org_id=$1`, org).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
		return Eligibility{Reason: "opt_in_required"}, nil
	}
	if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	var status, serial string
	var revoked, reported *time.Time
	var caps []byte
	err = tx.QueryRow(ctx, `SELECT n.status,n.cert_serial,n.revoked_at,n.policy_reported_at,n.capabilities FROM nodes n JOIN sites s ON s.id=n.site_id AND s.org_id=n.org_id WHERE n.org_id=$1 AND n.id=$2 AND n.site_id=$3`, org, gateway, site).Scan(&status, &serial, &revoked, &reported, &caps)
	if errors.Is(err, pgx.ErrNoRows) {
		return Eligibility{Reason: "gateway_unavailable"}, nil
	}
	if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	var clock time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&clock); err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	reason := gatewayEligibilityReason(status, serial, revoked, reported, caps, clock)
	return Eligibility{Eligible: reason == "eligible", Reason: reason}, nil
}
