package appaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

func TestApplicationMFAAssurance(t *testing.T) {
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, source              string
		verified                  time.Time
		enrolled, required, setup bool
	}{
		{"fresh TOTP", "local_totp", now.Add(-time.Minute), false, false, false},
		{"fresh recovery", "local_recovery", now.Add(-time.Minute), false, false, false},
		{"fresh SSO without local enrollment", "sso_mfa", now.Add(-time.Minute), false, false, false},
		{"SSO method without assurance", "", time.Time{}, false, true, true},
		{"unknown assurance source", "sso", now.Add(-time.Minute), true, true, false},
		{"untrusted source", "claimed_mfa", now.Add(-time.Minute), false, true, true},
		{"missing timestamp", "local_totp", time.Time{}, true, true, false},
		{"future timestamp", "local_totp", now.Add(time.Nanosecond), true, true, false},
		{"exact expiry", "local_totp", now.Add(-900 * time.Second), true, true, false},
		{"expired SSO with factor", "sso_mfa", now.Add(-901 * time.Second), true, true, false},
		{"expired SSO without factor", "sso_mfa", now.Add(-901 * time.Second), false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := NewService(nil, Config{Now: func() time.Time { return now }}).WithMFAEnrollmentChecker(func(context.Context, uuid.UUID) (bool, error) { calls++; return tc.enrolled, nil })
			got, err := s.applicationMFAStatus(context.Background(), true, session.Session{MFAVerifiedAt: tc.verified, MFAAssuranceSource: tc.source})
			if err != nil || got.Required != tc.required || got.SetupRequired != tc.setup {
				t.Fatalf("status %#v: %v", got, err)
			}
			if !tc.required && (calls != 0 || !got.Deadline.Equal(tc.verified.Add(900*time.Second))) {
				t.Fatal("fresh assurance unexpectedly requires enrollment or wrong deadline")
			}
			if tc.required && (calls != 1 || !got.Deadline.IsZero()) {
				t.Fatal("stale assurance did not check factor availability")
			}
		})
	}
	s := NewService(nil, Config{})
	if got, err := s.applicationMFAStatus(context.Background(), false, session.Session{}); err != nil || got.Required {
		t.Fatal("policy off must not require factor storage", err)
	}
	if _, err := s.applicationMFAStatus(context.Background(), true, session.Session{}); err == nil {
		t.Fatal("missing enrollment authority must fail closed")
	}
	s.WithMFAEnrollmentChecker(func(context.Context, uuid.UUID) (bool, error) { return false, errors.New("unavailable") })
	if _, err := s.applicationMFAStatus(context.Background(), true, session.Session{}); err == nil {
		t.Fatal("enrollment storage failure must fail closed")
	}
}
