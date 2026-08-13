// Package idpsync (S7.5.2) syncs IdP directory groups into Tunnex user_groups so the S7.2
// compiler grants access to their members' devices. This file is the PROVIDER-AGNOSTIC seam:
// the reconciler (slice 3) talks ONLY to DirectoryProvider, so Google is a second implementation,
// not a refactor (the S8.1 transport-enum discipline). Every provider-specific detail — Graph
// pagination, app-credential token minting, the accountEnabled/suspended → status mapping — lives
// BEHIND an implementation (entra.go) and never leaks through these types.
package idpsync

import (
	"context"
	"errors"
)

// UserStatus is the provider-agnostic lifecycle of a directory user — the deprovision signal (D3).
type UserStatus int

const (
	StatusActive   UserStatus = iota // exists + enabled in the directory
	StatusDisabled                   // exists but disabled/blocked upstream (Entra accountEnabled=false)
	StatusGone                       // no longer in the directory (deleted upstream)
)

func (s UserStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDisabled:
		return "disabled"
	case StatusGone:
		return "gone"
	default:
		return "unknown"
	}
}

// DirectoryMember is one member of an IdP group, provider-agnostic. Email is the join key to
// Tunnex users (matched to users.email); ExternalID is the provider's stable user id (durable
// across email changes — used for logs/audit and the ResolveUserStatus lookup).
type DirectoryMember struct {
	ExternalID string
	Email      string
	Status     UserStatus // a group can list a DISABLED member; the reconciler routes it to deprovision
}

// ErrGroupGone means the mapped IdP group no longer exists upstream (deleted). The reconciler
// treats it as an empty membership (0 grants) + surfaces "source group gone" on sync health —
// distinct from a transient fetch error (which keeps the last-known membership, D2 fail-static).
var ErrGroupGone = errors.New("idp group not found (deleted upstream)")

// DirectoryProvider is the seam every IdP directory client implements. Provider-agnostic by
// construction: the two calls the reconciler needs, in provider-neutral terms.
type DirectoryProvider interface {
	// ListGroupMembers returns the current members of one IdP group (the implementation paginates
	// internally; the caller gets the full flat set). A disabled member IS returned (with
	// StatusDisabled) so the reconciler can deprovision it; a deleted user is simply absent.
	// A deleted GROUP returns ErrGroupGone.
	ListGroupMembers(ctx context.Context, groupID string) ([]DirectoryMember, error)

	// ResolveUserStatus reports whether a directory user (by external id) is active / disabled /
	// gone — used when a synced member drops out of all our groups, to tell "moved groups (still
	// active)" from "deprovisioned (disable/delete → the full DeactivateMember sweep)".
	ResolveUserStatus(ctx context.Context, externalID string) (UserStatus, error)
}
