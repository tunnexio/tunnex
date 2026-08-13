// Package idpsyncspec holds the build-tag-neutral DTOs for the IdP-group-sync port (S7.5.2), so
// the open build's HTTP handlers can reference the port's inputs/outputs without importing the
// enterprise idpsync package (which is //go:build enterprise). Mirrors policyspec.
package idpsyncspec

import (
	"time"

	"github.com/google/uuid"
)

// ConfigInput is a provider-credential upsert (the client_secret is sealed before storage).
type ConfigInput struct {
	ClientID            string
	ClientSecret        string
	TenantID            string // Entra tenant; empty for google
	DelegatedAdminEmail string // Google Workspace DWD subject
	ServiceAccountJSON  string // Google service-account JSON; sealed at rest
	Enabled             bool
}

// ConfigView is a stored config for display — NEVER carries the secret, only its fingerprint.
type ConfigView struct {
	Provider            string
	ClientID            string
	SecretFingerprint   string // keyed 12-hex proof-of-secret (S4.5); never the secret itself
	TenantID            string
	DelegatedAdminEmail string
	Enabled             bool
	LastSyncAt          *time.Time
	LastSyncOk          bool
	LastSyncError       string
	SyncHealth          string // ok | degraded | escalated (derived, D2)
}

// HealthView is the two-tier sync-health snapshot.
type HealthView struct {
	Provider      string
	SyncHealth    string // ok | degraded | escalated
	LastSyncOk    bool
	LastSyncAt    *time.Time
	LastSyncError string
}

// MapInput maps a directory group to a Tunnex group. Exactly one of Name (create a new idp_sync
// group) or GroupID (bind an existing EMPTY manual group) is set; neither → name defaults to the
// idp group id.
type MapInput struct {
	IdpGroupID string
	Name       string
	GroupID    *uuid.UUID
}
