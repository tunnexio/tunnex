package ipsec_test

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

// No authority is changed: report only CP receipt-clock facts on eligibility failure.
func logGatewayEligibility(t *testing.T, p *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var now time.Time
	var reported *time.Time
	var age *float64
	var status string
	var revoked bool
	var config *string
	err := p.QueryRow(ctx, `SELECT clock_timestamp(),policy_reported_at,extract(epoch FROM clock_timestamp()-policy_reported_at)::float8,status,revoked_at IS NOT NULL,capabilities->>'ipsec_config_version' FROM nodes WHERE id=$1`, id).Scan(&now, &reported, &age, &status, &revoked, &config)
	if err != nil {
		t.Logf("eligibility diagnostic unavailable: %v", err)
		return
	}
	ageValue := "unset"
	if age != nil {
		ageValue = fmt.Sprintf("%.9f", *age)
	}
	configValue := "unset"
	if config != nil {
		configValue = *config
	}
	t.Logf("eligibility CP clock=%s reported=%v age_seconds=%v status=%s revoked=%v config_version=%v", now.Format(time.RFC3339Nano), reported, ageValue, status, revoked, configValue)
}
