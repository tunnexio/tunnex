package ipsec

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

const MaxPermitLease = 60 * time.Second

var ErrPermitLease = errors.New("IPsec permit authority unavailable")

// PermitLeaseIdentity binds ephemeral authority to one exact CP delivery and policy.
type PermitLeaseIdentity struct {
	PolicyHash string // Current canonical CP policy identity; never persisted as authority.
	Binding    Binding
	DeliveryID uuid.UUID
}
type PermitLeaseRequest struct {
	Identity PermitLeaseIdentity
	Nonce    string
}
type PermitLeaseResponse struct {
	PermitLeaseRequest
	TTLMillis int64
}

// PermitLeaseAuthority is process-local and must not be copied or persisted.
// Callers authenticate the response transport; this helper cannot authenticate a CP.
// It does not install permits, acknowledge cleanup or advertise capability.
type PermitLeaseAuthority struct {
	mu       sync.Mutex
	elapsed  func() time.Duration
	last     time.Duration
	pending  *PermitLeaseRequest
	started  time.Duration
	identity PermitLeaseIdentity
	deadline time.Duration
}

func NewPermitLeaseAuthority() *PermitLeaseAuthority {
	origin := time.Now()
	return &PermitLeaseAuthority{elapsed: func() time.Duration { return time.Since(origin) }}
}
func validPermitIdentity(i PermitLeaseIdentity) bool {
	b := i.Binding
	return i.DeliveryID != uuid.Nil && b.OrgID != uuid.Nil && b.GatewayID != uuid.Nil && b.ConnectionID != uuid.Nil && b.DesiredRevision > 0 && b.ConfigurationRevision > 0 && ((i.PolicyHash == "" && b.PolicyRevision > 0) || (validDigest(i.PolicyHash) && b.PolicyRevision == 0))
}
func (a *PermitLeaseAuthority) nowLocked() (time.Duration, bool) {
	if a.elapsed == nil {
		return 0, false
	}
	now := a.elapsed()
	if now < 0 || now < a.last {
		a.clearLocked()
		return 0, false
	}
	a.last = now
	return now, true
}
func (a *PermitLeaseAuthority) clearLocked() {
	a.pending = nil
	a.identity = PermitLeaseIdentity{}
	a.deadline = 0
}

// Begin supersedes any outstanding request. Different identities also revoke the
// previous in-memory lease. Begin must run immediately before sending the request.
func (a *PermitLeaseAuthority) Begin(identity PermitLeaseIdentity) (PermitLeaseRequest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending = nil
	if !validPermitIdentity(identity) {
		a.clearLocked()
		return PermitLeaseRequest{}, ErrPermitLease
	}
	now, ok := a.nowLocked()
	if !ok {
		return PermitLeaseRequest{}, ErrPermitLease
	}
	if a.identity != identity {
		a.identity = PermitLeaseIdentity{}
		a.deadline = 0
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PermitLeaseRequest{}, ErrPermitLease
	}
	request := PermitLeaseRequest{Identity: identity, Nonce: hex.EncodeToString(nonce[:])}
	a.pending = &request
	a.started = now
	return request, nil
}

// Accept consumes the outstanding attempt even on refusal. A failed same-identity
// renewal leaves only the previous lease's original deadline, never an extension.
func (a *PermitLeaseAuthority) Accept(response PermitLeaseResponse) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	request := a.pending
	a.pending = nil
	now, ok := a.nowLocked()
	if !ok || request == nil || response.PermitLeaseRequest != *request || response.TTLMillis <= 0 || response.TTLMillis > MaxPermitLease.Milliseconds() {
		return ErrPermitLease
	}
	ttl := time.Duration(response.TTLMillis) * time.Millisecond
	if a.started > time.Duration(1<<63-1)-ttl {
		return ErrPermitLease
	}
	deadline := a.started + ttl
	if now >= deadline {
		return ErrPermitLease
	}
	a.identity = request.Identity
	a.deadline = deadline
	return nil
}

// RemainingForApply returns a downward millisecond-rounded kernel timeout after
// reserving a strictly positive bounded apply budget. Recompute immediately before
// each install; never cache or persist the result. Check again after apply/readback.
// The renderer may round further downward, never up. This is not cleanup proof.
func (a *PermitLeaseAuthority) RemainingForApply(identity PermitLeaseIdentity, budget time.Duration) (time.Duration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now, ok := a.nowLocked()
	if !ok || !validPermitIdentity(identity) || identity != a.identity || budget <= 0 || budget >= MaxPermitLease || now >= a.deadline {
		return 0, ErrPermitLease
	}
	remaining := a.deadline - now
	if remaining <= budget {
		return 0, ErrPermitLease
	}
	remaining = (remaining - budget).Truncate(time.Millisecond)
	if remaining <= 0 {
		return 0, ErrPermitLease
	}
	return remaining, nil
}

// Invalidate rejects late replies and discards authority, without claiming that
// existing kernel objects have been removed. Permanent refusal must remain.
func (a *PermitLeaseAuthority) Invalidate() { a.mu.Lock(); defer a.mu.Unlock(); a.clearLocked() }
