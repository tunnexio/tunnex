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
	Eligible    bool         `json:"eligible"`
	Reason      string       `json:"reason"`
	GCPClassic  *Eligibility `json:"gcp_classic,omitempty"`
	AzureBGP    *Eligibility `json:"azure_bgp,omitempty"`
	AzureStatic *Eligibility `json:"azure_static,omitempty"`
	GCPHA       *Eligibility `json:"gcp_ha,omitempty"`
	BGP         *Eligibility `json:"bgp,omitempty"`
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

// gatewayBGPEligibilityReason describes reported capability, not rollout authority.
func gatewayBGPEligibilityReason(status, serial string, revoked, reported *time.Time, capabilities []byte, clock time.Time) string {
	reason := gatewayEligibilityReason(status, serial, revoked, reported, capabilities, clock)
	if reason != "eligible" {
		return reason
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(capabilities, &caps) != nil || string(caps["ipsec_bgp_version"]) != "1" {
		return "unsupported"
	}
	return "eligible"
}

// Advisory readiness follows actual reported capability; activation rechecks under locks.
func advisoryEligibility(reason, bgpReason string) Eligibility {
	return Eligibility{Eligible: reason == "eligible", Reason: reason, BGP: &Eligibility{Eligible: bgpReason == "eligible", Reason: bgpReason}}
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
		return advisoryEligibility("opt_in_required", "opt_in_required"), nil
	}
	if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	var status, serial string
	var revoked, reported *time.Time
	var caps []byte
	err = tx.QueryRow(ctx, `SELECT n.status,n.cert_serial,n.revoked_at,n.policy_reported_at,n.capabilities FROM nodes n JOIN sites s ON s.id=n.site_id AND s.org_id=n.org_id WHERE n.org_id=$1 AND n.id=$2 AND n.site_id=$3`, org, gateway, site).Scan(&status, &serial, &revoked, &reported, &caps)
	if errors.Is(err, pgx.ErrNoRows) {
		return advisoryEligibility("gateway_unavailable", "gateway_unavailable"), nil
	}
	if err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	var clock time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&clock); err != nil {
		return Eligibility{}, ErrConnectionUnavailable
	}
	reason := gatewayEligibilityReason(status, serial, revoked, reported, caps, clock)
	result := advisoryEligibility(reason, gatewayBGPEligibilityReason(status, serial, revoked, reported, caps, clock))
	gcpReason := result.BGP.Reason
	var cap map[string]json.RawMessage
	if gcpReason == "eligible" && (json.Unmarshal(caps, &cap) != nil || string(cap["ipsec_gcp_ha_version"]) != "1") {
		gcpReason = "unsupported"
	}
	result.GCPHA = &Eligibility{Eligible: gcpReason == "eligible", Reason: gcpReason}
	classicReason := reason
	if classicReason == "eligible" && (json.Unmarshal(caps, &cap) != nil || string(cap["ipsec_gcp_classic_version"]) != "1") {
		classicReason = "unsupported"
	}
	result.GCPClassic = &Eligibility{Eligible: classicReason == "eligible", Reason: classicReason}
	azureReason := reason
	if azureReason == "eligible" && string(cap["ipsec_azure_version"]) != "1" {
		azureReason = "unsupported"
	}
	result.AzureStatic = &Eligibility{Eligible: azureReason == "eligible", Reason: azureReason}
	azureBGPReason := azureReason
	if azureBGPReason == "eligible" && !result.BGP.Eligible {
		azureBGPReason = result.BGP.Reason
	}
	result.AzureBGP = &Eligibility{Eligible: azureBGPReason == "eligible", Reason: azureBGPReason}
	return result, nil
}
