package scopeapproval

import (
	"errors"
	"sort"

	"github.com/google/uuid"
)

var (
	ErrInvalidLiveInventory    = errors.New("invalid live exact-port inventory")
	ErrCurrentIdentityMismatch = errors.New("current exact-port identity does not match approved identity")
)

// ExpansionInput makes every enforcement gate explicit. Entitlement loss,
// organization opt-out, or an inactive scope yields no entitlement. An
// unavailable/stale inventory remains a typed error, never empty-success.
type ExpansionInput struct {
	Scope        Scope
	Feature      FeatureState
	ScopeActive  bool
	Inventory    InventoryState
	LiveChildren []ExactPortChild
}

// ExpandApproved returns exact child IDs that are approved and still match the
// current attributed Service UID, namespace, protocol, and port. It grants no
// namespace wildcard, sibling port, Pod, Node, endpoint, or provider access.
func ExpandApproved(in ExpansionInput, limits Limits) ([]uuid.UUID, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	// OFF states are authoritative zero-output states. They intentionally do
	// not depend on the retained scope or inventory being readable.
	if !in.Feature.EntitlementUnlocked || !in.Feature.OrganizationOptInEnabled || !in.ScopeActive {
		return nil, nil
	}
	if err := in.Inventory.requireCurrent(); err != nil {
		return nil, err
	}
	if err := validateScope(in.Scope, limits); err != nil {
		return nil, err
	}
	if len(in.LiveChildren) > limits.MaxCurrentCandidates {
		return nil, ErrCandidateLimitReached
	}

	byChildID := make(map[uuid.UUID]ExactPortChild, len(in.LiveChildren))
	exactIdentities := make(map[exactIdentityKey]struct{}, len(in.LiveChildren))
	for _, child := range in.LiveChildren {
		if err := validateEligibleChild(in.Scope.OrgID, in.Scope.ClusterID, child); err != nil {
			if errors.Is(err, ErrUIDAttributionNotCurrent) {
				return nil, err
			}
			return nil, ErrInvalidLiveInventory
		}
		if _, duplicate := byChildID[child.Identity.ChildID]; duplicate {
			return nil, ErrDuplicateChildID
		}
		key := identityKey(child.Identity)
		if _, duplicate := exactIdentities[key]; duplicate {
			return nil, ErrDuplicateExactIdentity
		}
		byChildID[child.Identity.ChildID] = child
		exactIdentities[key] = struct{}{}
	}

	approved := make([]ExactChildIdentity, 0, len(in.Scope.Memberships))
	for _, membership := range in.Scope.Memberships {
		if membership.Status != StatusApproved {
			continue
		}
		child, live := byChildID[membership.Identity.ChildID]
		if !live {
			continue
		}
		if child.Identity != membership.Identity {
			return nil, ErrCurrentIdentityMismatch
		}
		approved = append(approved, child.Identity)
	}
	sort.Slice(approved, func(i, j int) bool { return compareIdentity(approved[i], approved[j]) < 0 })
	out := make([]uuid.UUID, len(approved))
	for i, identity := range approved {
		out[i] = identity.ChildID
	}
	return out, nil
}
