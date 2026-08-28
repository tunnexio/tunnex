package scopeapproval

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func expandInput(scope Scope, live []ExactPortChild) ExpansionInput {
	return ExpansionInput{
		Scope: scope, Feature: testFeature, ScopeActive: true,
		Inventory: InventoryCurrent, LiveChildren: live,
	}
}

func TestExpandApprovedLowersOnlyApprovedCurrentExactChildren(t *testing.T) {
	tcp443 := child(testChildA, "uid-payments", ProtocolTCP, 443)
	udp443 := child(testChildB, "uid-payments", ProtocolUDP, 443)
	scope := createScope(t, []ExactPortChild{tcp443, udp443}, []uuid.UUID{testChildA})
	later := child(testChildC, "uid-payments", ProtocolTCP, 8443)
	pending, err := AddLaterExposure(scope, later, testLimits)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ExpandApproved(expandInput(pending, []ExactPortChild{later, udp443, tcp443}), testLimits)
	if err != nil || !reflect.DeepEqual(got, []uuid.UUID{testChildA}) {
		t.Fatalf("pending expansion = %v, %v", got, err)
	}
	approved, err := Decide(pending, later, StatusApproved, testFeature, testActor, testNow, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	got, err = ExpandApproved(expandInput(approved.Scope, []ExactPortChild{later, udp443, tcp443}), testLimits)
	if err != nil || !reflect.DeepEqual(got, []uuid.UUID{testChildA, testChildC}) {
		t.Fatalf("approved expansion = %v, %v", got, err)
	}
}

func TestExpandApprovedWithholdsDeletedAndRejectsConflictingCurrentIdentity(t *testing.T) {
	original := child(testChildA, "uid-old", ProtocolTCP, 443)
	scope := createScope(t, []ExactPortChild{original}, []uuid.UUID{testChildA})

	got, err := ExpandApproved(expandInput(scope, nil), testLimits)
	if err != nil || len(got) != 0 {
		t.Fatalf("deleted output = %v, error = %v", got, err)
	}
	for _, tc := range []struct {
		name string
		live ExactPortChild
	}{
		{"recreated UID", child(testChildA, "uid-new", ProtocolTCP, 443)},
		{"substituted protocol", child(testChildA, "uid-old", ProtocolUDP, 443)},
		{"substituted port", child(testChildA, "uid-old", ProtocolTCP, 8443)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandApproved(expandInput(scope, []ExactPortChild{tc.live}), testLimits)
			if !errors.Is(err, ErrCurrentIdentityMismatch) || got != nil {
				t.Fatalf("output = %v, error = %v", got, err)
			}
		})
	}
}

func TestExpandApprovedFeatureAndScopeOffYieldZeroWithoutReadingRetainedState(t *testing.T) {
	malformed := Scope{}
	cases := []ExpansionInput{
		{Scope: malformed, Feature: FeatureState{OrganizationOptInEnabled: true}, ScopeActive: true},
		{Scope: malformed, Feature: FeatureState{EntitlementUnlocked: true}, ScopeActive: true},
		{Scope: malformed, Feature: testFeature, ScopeActive: false},
	}
	for i, in := range cases {
		got, err := ExpandApproved(in, testLimits)
		if err != nil || got != nil {
			t.Fatalf("case %d: output=%v error=%v", i, got, err)
		}
	}
}

func TestExpandApprovedDistinguishesUnavailableAndStaleInventoryFromEmpty(t *testing.T) {
	scope := createScope(t, nil, nil)
	for state, want := range map[InventoryState]error{
		InventoryUnavailable: ErrInventoryUnavailable,
		InventoryStale:       ErrInventoryStale,
	} {
		in := expandInput(scope, nil)
		in.Inventory = state
		if got, err := ExpandApproved(in, testLimits); !errors.Is(err, want) || got != nil {
			t.Fatalf("state %q: output=%v error=%v", state, got, err)
		}
	}
	got, err := ExpandApproved(expandInput(scope, nil), testLimits)
	if err != nil || len(got) != 0 {
		t.Fatalf("authoritative empty inventory: output=%v error=%v", got, err)
	}
}

func TestExpandApprovedRejectsUnattributedMalformedDuplicateAndOverLimitInventory(t *testing.T) {
	approved := child(testChildA, "uid-a", ProtocolTCP, 443)
	scope := createScope(t, []ExactPortChild{approved}, []uuid.UUID{testChildA})
	unattributed := approved
	unattributed.UIDAttributionCurrent = false
	if got, err := ExpandApproved(expandInput(scope, []ExactPortChild{unattributed}), testLimits); !errors.Is(err, ErrUIDAttributionNotCurrent) || got != nil {
		t.Fatalf("unattributed: output=%v error=%v", got, err)
	}
	if got, err := ExpandApproved(expandInput(scope, []ExactPortChild{approved, approved}), testLimits); !errors.Is(err, ErrDuplicateChildID) || got != nil {
		t.Fatalf("duplicate: output=%v error=%v", got, err)
	}
	notLive := approved
	notLive.Live = false
	if got, err := ExpandApproved(expandInput(scope, []ExactPortChild{notLive}), testLimits); !errors.Is(err, ErrInvalidLiveInventory) || got != nil {
		t.Fatalf("not live: output=%v error=%v", got, err)
	}
	overLimit := Limits{MaxCurrentCandidates: 1, MaxInitialSelections: 1, MaxMemberships: 2}
	second := child(testChildB, "uid-b", ProtocolTCP, 80)
	if got, err := ExpandApproved(expandInput(scope, []ExactPortChild{approved, second}), overLimit); !errors.Is(err, ErrCandidateLimitReached) || got != nil {
		t.Fatalf("over limit: output=%v error=%v", got, err)
	}
}

func TestExpandApprovedIsDeterministicallyOrderedByExactIdentity(t *testing.T) {
	port8443 := child(testChildA, "uid-shared", ProtocolTCP, 8443)
	port443 := child(testChildB, "uid-shared", ProtocolTCP, 443)
	udp443 := child(testChildC, "uid-shared", ProtocolUDP, 443)
	scope := createScope(t, []ExactPortChild{port8443, udp443, port443}, []uuid.UUID{testChildA, testChildB, testChildC})
	want := []uuid.UUID{testChildB, testChildA, testChildC}
	got, err := ExpandApproved(expandInput(scope, []ExactPortChild{udp443, port8443, port443}), testLimits)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered output=%v error=%v want=%v", got, err, want)
	}
}
