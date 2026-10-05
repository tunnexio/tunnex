// Package sandboxes defines sandbox identity independently of AI Agents.
// Enrollment peers and provider instances are bindings, not product identities.
package sandboxes

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const PeerKind = "sandbox"

type State string

const (
	StateCreating State = "creating"
	StateStarting State = "starting"
	StateReady    State = "ready"
	StateStopping State = "stopping"
	StateStopped  State = "stopped"
	StateDeleting State = "deleting"
	StateDeleted  State = "deleted"
	StateError    State = "error"
)

// Identity is immutable after creation. CreatorID is a management association,
// never a device owner from which the policy compiler may inherit grants.
type Identity struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	CreatorID uuid.UUID
}

// Sandbox is desired/observed domain state. Ready requires an independently
// verified current-policy acknowledgement and private SSH check from the
// reconciler; a successful provider start alone must not select StateReady.
// Secrets, enrollment tokens and runtime credentials belong in separate stores.
type ConnectionInfo struct {
	Address            string
	Username           string
	Port               int
	HostPublicKey      string
	HostKeyFingerprint string
}
type Sandbox struct {
	Connection        *ConnectionInfo
	Identity          Identity
	TemplateVersionID uuid.UUID
	Name              string
	SelectedSkills    []SkillSelection
	SSHPublicKeys     []string
	RequestedScope    []Scope
	DesiredState      string
	PeerID            *uuid.UUID
	State             State
	Revision          int64
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

var ErrInvalidIdentity = errors.New("sandbox requires nonzero sandbox, organization and creator identities")
var ErrInvalidTransition = errors.New("invalid sandbox lifecycle transition")

func (i Identity) Validate() error {
	if i.ID == uuid.Nil || i.OrgID == uuid.Nil || i.CreatorID == uuid.Nil {
		return ErrInvalidIdentity
	}
	return nil
}

// CanManage is only the ownership predicate. Callers must ALSO verify current
// membership and sandbox permissions; matching IDs alone is not authorization.
func (i Identity) CanManage(orgID, userID uuid.UUID) bool {
	return i.Validate() == nil && i.OrgID == orgID && i.CreatorID == userID
}

// Transition validates observed lifecycle updates. Same-state retries are safe;
// revision CAS and durable operation idempotency belong to the future store.
func Transition(from, to State) error {
	if !validState(from) || !validState(to) {
		return ErrInvalidTransition
	}
	if from == to {
		return nil
	}
	if to == StateDeleting && from != StateDeleted {
		return nil
	}
	switch from {
	case StateCreating, StateStarting:
		if to == StateReady || to == StateError {
			return nil
		}
	case StateReady:
		if to == StateStopping || to == StateError {
			return nil
		}
	case StateStopping:
		if to == StateStopped || to == StateError {
			return nil
		}
	case StateStopped:
		if to == StateStarting {
			return nil
		}
	case StateDeleting:
		if to == StateDeleted {
			return nil
		}
	case StateError:
		// Failed instances require cleanup before a fresh start. Never retry creation
		// blindly and mint a second peer after an uncertain enrollment outcome.
		if to == StateStopping {
			return nil
		}
	}
	return ErrInvalidTransition
}

func validState(s State) bool {
	switch s {
	case StateCreating, StateStarting, StateReady, StateStopping, StateStopped, StateDeleting, StateDeleted, StateError:
		return true
	}
	return false
}
