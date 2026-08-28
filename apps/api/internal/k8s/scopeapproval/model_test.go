package scopeapproval

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testOrg     = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	testCluster = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	testRule    = uuid.MustParse("00000000-0000-4000-8000-000000000003")
	testActor   = uuid.MustParse("00000000-0000-4000-8000-000000000004")
	testChildA  = uuid.MustParse("00000000-0000-4000-8000-000000000101")
	testChildB  = uuid.MustParse("00000000-0000-4000-8000-000000000102")
	testChildC  = uuid.MustParse("00000000-0000-4000-8000-000000000103")
	testNow     = time.Date(2026, time.August, 28, 9, 0, 0, 0, time.FixedZone("IST", 5*60*60+30*60))
	testFeature = FeatureState{EntitlementUnlocked: true, OrganizationOptInEnabled: true}
	testLimits  = Limits{MaxCurrentCandidates: 8, MaxInitialSelections: 4, MaxMemberships: 8}
)

func child(id uuid.UUID, uid string, protocol Protocol, port int32) ExactPortChild {
	return ExactPortChild{
		Identity: ExactChildIdentity{
			ChildID: id, OrgID: testOrg, ClusterID: testCluster,
			Namespace: "payments", ServiceUID: uid, Protocol: protocol, ServicePort: port,
		},
		Live: true, UIDAttributionCurrent: true,
	}
}

func createScope(t *testing.T, current []ExactPortChild, selected []uuid.UUID) Scope {
	t.Helper()
	scope, err := Create(CreateInput{
		RuleID: testRule, OrgID: testOrg, ClusterID: testCluster,
		Feature: testFeature, Inventory: InventoryCurrent,
		CurrentChildren: current, InitialChildIDs: selected,
		ActorUserID: testActor, Now: testNow,
	}, testLimits)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return scope
}

func TestProductionLimitsAreLocked(t *testing.T) {
	if got := ProductionLimits(); got != (Limits{MaxCurrentCandidates: 500, MaxInitialSelections: 100, MaxMemberships: 500}) {
		t.Fatalf("production limits = %+v", got)
	}
	if err := (Limits{MaxCurrentCandidates: 501, MaxInitialSelections: 100, MaxMemberships: 500}).validate(); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("oversized limits error = %v", err)
	}
}

func TestCreateRetainsSelectedAndUnselectedInitialEvidence(t *testing.T) {
	tcp443 := child(testChildA, "uid-payments", ProtocolTCP, 443)
	udp53 := child(testChildB, "uid-payments", ProtocolUDP, 53)
	scope := createScope(t, []ExactPortChild{udp53, tcp443}, []uuid.UUID{testChildA})

	if len(scope.InitialEvidence) != 2 {
		t.Fatalf("initial evidence count = %d", len(scope.InitialEvidence))
	}
	if scope.InitialEvidence[0].Identity != tcp443.Identity || !scope.InitialEvidence[0].Selected {
		t.Fatalf("selected evidence = %+v", scope.InitialEvidence[0])
	}
	if scope.InitialEvidence[1].Identity != udp53.Identity || scope.InitialEvidence[1].Selected {
		t.Fatalf("unselected evidence = %+v", scope.InitialEvidence[1])
	}
	if len(scope.Memberships) != 1 || scope.Memberships[0].Identity != tcp443.Identity || scope.Memberships[0].Origin != OriginInitial || scope.Memberships[0].Status != StatusApproved {
		t.Fatalf("initial membership = %+v", scope.Memberships)
	}
	if scope.Memberships[0].DecidedByUserID == nil || *scope.Memberships[0].DecidedByUserID != testActor || scope.Memberships[0].DecidedAt == nil || !scope.Memberships[0].DecidedAt.Equal(testNow) || scope.Memberships[0].DecidedAt.Location() != time.UTC {
		t.Fatalf("server decision evidence = %+v", scope.Memberships[0])
	}
}

func TestCreateAllowsAuthoritativeEmptyInventoryAndZeroSelection(t *testing.T) {
	scope := createScope(t, nil, nil)
	if len(scope.InitialEvidence) != 0 || len(scope.Memberships) != 0 {
		t.Fatalf("empty scope = %+v", scope)
	}
}

func TestCreateFailsClosedOnFeatureInventoryAttributionAndLimits(t *testing.T) {
	valid := child(testChildA, "uid-a", ProtocolTCP, 443)
	cases := []struct {
		name      string
		feature   FeatureState
		inventory InventoryState
		children  []ExactPortChild
		selected  []uuid.UUID
		limits    Limits
		want      error
	}{
		{"entitlement locked", FeatureState{OrganizationOptInEnabled: true}, InventoryCurrent, []ExactPortChild{valid}, nil, testLimits, ErrEntitlementUnavailable},
		{"opt-in disabled", FeatureState{EntitlementUnlocked: true}, InventoryCurrent, []ExactPortChild{valid}, nil, testLimits, ErrOptInDisabled},
		{"inventory unavailable", testFeature, InventoryUnavailable, nil, nil, testLimits, ErrInventoryUnavailable},
		{"inventory stale", testFeature, InventoryStale, nil, nil, testLimits, ErrInventoryStale},
		{"UID unattributed", testFeature, InventoryCurrent, []ExactPortChild{{Identity: valid.Identity, Live: true}}, nil, testLimits, ErrUIDAttributionNotCurrent},
		{"candidate cap", testFeature, InventoryCurrent, []ExactPortChild{valid, child(testChildB, "uid-b", ProtocolTCP, 80)}, nil, Limits{MaxCurrentCandidates: 1, MaxInitialSelections: 1, MaxMemberships: 1}, ErrCandidateLimitReached},
		{"selection cap", testFeature, InventoryCurrent, []ExactPortChild{valid, child(testChildB, "uid-b", ProtocolTCP, 80)}, []uuid.UUID{testChildA, testChildB}, Limits{MaxCurrentCandidates: 2, MaxInitialSelections: 1, MaxMemberships: 2}, ErrSelectionLimitReached},
		{"membership cap", testFeature, InventoryCurrent, []ExactPortChild{valid, child(testChildB, "uid-b", ProtocolTCP, 80)}, []uuid.UUID{testChildA, testChildB}, Limits{MaxCurrentCandidates: 2, MaxInitialSelections: 2, MaxMemberships: 1}, ErrMembershipLimitReached},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Create(CreateInput{
				RuleID: testRule, OrgID: testOrg, ClusterID: testCluster,
				Feature: tc.feature, Inventory: tc.inventory,
				CurrentChildren: tc.children, InitialChildIDs: tc.selected,
				ActorUserID: testActor, Now: testNow,
			}, tc.limits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCreateRefusesMalformedExactChildrenAndSelection(t *testing.T) {
	valid := child(testChildA, "uid-a", ProtocolTCP, 443)
	cases := []struct {
		name     string
		children []ExactPortChild
		selected []uuid.UUID
		want     error
	}{
		{"duplicate child", []ExactPortChild{valid, valid}, nil, ErrDuplicateChildID},
		{"duplicate exact identity", []ExactPortChild{valid, child(testChildB, "uid-a", ProtocolTCP, 443)}, nil, ErrDuplicateExactIdentity},
		{"unknown selected child", []ExactPortChild{valid}, []uuid.UUID{testChildB}, ErrUnknownChildID},
		{"duplicate selected child", []ExactPortChild{valid}, []uuid.UUID{testChildA, testChildA}, ErrDuplicateChildID},
		{"wildcard protocol", []ExactPortChild{child(testChildA, "uid-a", Protocol("any"), 443)}, nil, ErrInvalidChildIdentity},
		{"zero port", []ExactPortChild{child(testChildA, "uid-a", ProtocolTCP, 0)}, nil, ErrInvalidChildIdentity},
		{"empty UID", []ExactPortChild{child(testChildA, "", ProtocolTCP, 443)}, nil, ErrInvalidChildIdentity},
		{"not live", []ExactPortChild{{Identity: valid.Identity, UIDAttributionCurrent: true}}, nil, ErrExposureNotLive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Create(CreateInput{
				RuleID: testRule, OrgID: testOrg, ClusterID: testCluster,
				Feature: testFeature, Inventory: InventoryCurrent,
				CurrentChildren: tc.children, InitialChildIDs: tc.selected,
				ActorUserID: testActor, Now: testNow,
			}, testLimits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLaterExposureStartsPendingAndInitialUnselectedCannotBeRelabeled(t *testing.T) {
	initialSelected := child(testChildA, "uid-a", ProtocolTCP, 443)
	initialUnselected := child(testChildB, "uid-b", ProtocolUDP, 53)
	scope := createScope(t, []ExactPortChild{initialSelected, initialUnselected}, []uuid.UUID{testChildA})

	if _, err := AddLaterExposure(scope, initialUnselected, testLimits); !errors.Is(err, ErrNotLaterExposure) {
		t.Fatalf("initial unselected relabel error = %v", err)
	}
	later := child(testChildC, "uid-c", ProtocolTCP, 8443)
	pending, err := AddLaterExposure(scope, later, testLimits)
	if err != nil {
		t.Fatalf("AddLaterExposure: %v", err)
	}
	if got := pending.Memberships[1]; got.Identity != later.Identity || got.Origin != OriginLater || got.Status != StatusPending || got.DecidedByUserID != nil || got.DecidedAt != nil {
		t.Fatalf("later membership = %+v", got)
	}
	if len(scope.Memberships) != 1 {
		t.Fatal("transition mutated input scope")
	}
}

func TestDecideIsOneWayIdempotentAndReportsAuditChange(t *testing.T) {
	initial := child(testChildA, "uid-a", ProtocolTCP, 443)
	later := child(testChildC, "uid-c", ProtocolTCP, 8443)
	scope := createScope(t, []ExactPortChild{initial}, []uuid.UUID{initial.Identity.ChildID})
	pending, err := AddLaterExposure(scope, later, testLimits)
	if err != nil {
		t.Fatal(err)
	}

	for _, decision := range []Status{StatusApproved, StatusRejected} {
		t.Run(string(decision), func(t *testing.T) {
			result, err := Decide(pending, later, decision, testFeature, testActor, testNow, testLimits)
			if err != nil || !result.Changed {
				t.Fatalf("first decision: result=%+v err=%v", result, err)
			}
			retry, err := Decide(result.Scope, later, decision, testFeature, testActor, testNow.Add(time.Hour), testLimits)
			if err != nil || retry.Changed || !reflect.DeepEqual(retry.Scope, result.Scope) {
				t.Fatalf("idempotent retry: result=%+v err=%v", retry, err)
			}
			opposite := StatusApproved
			if decision == StatusApproved {
				opposite = StatusRejected
			}
			if _, err := Decide(result.Scope, later, opposite, testFeature, testActor, testNow, testLimits); !errors.Is(err, ErrInvalidDecision) {
				t.Fatalf("opposing retry error = %v", err)
			}
		})
	}
}

func TestDecisionFailsClosedWhenFeatureUnavailableOrIdentityChanges(t *testing.T) {
	initial := child(testChildA, "uid-a", ProtocolTCP, 443)
	later := child(testChildC, "uid-c", ProtocolTCP, 8443)
	scope := createScope(t, []ExactPortChild{initial}, []uuid.UUID{testChildA})
	pending, err := AddLaterExposure(scope, later, testLimits)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decide(pending, later, StatusApproved, FeatureState{OrganizationOptInEnabled: true}, testActor, testNow, testLimits); !errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatalf("entitlement error = %v", err)
	}
	if _, err := Decide(pending, later, StatusApproved, FeatureState{EntitlementUnlocked: true}, testActor, testNow, testLimits); !errors.Is(err, ErrOptInDisabled) {
		t.Fatalf("opt-in error = %v", err)
	}
	changedPort := later
	changedPort.Identity.ServicePort = 9443
	if _, err := Decide(pending, changedPort, StatusApproved, testFeature, testActor, testNow, testLimits); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("port substitution error = %v", err)
	}
	changedUID := later
	changedUID.Identity.ServiceUID = "uid-recreated"
	if _, err := Decide(pending, changedUID, StatusApproved, testFeature, testActor, testNow, testLimits); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("UID substitution error = %v", err)
	}

	approved, err := Decide(pending, later, StatusApproved, testFeature, testActor, testNow, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	noLongerLive := later
	noLongerLive.Live = false
	noLongerLive.UIDAttributionCurrent = false
	retry, err := Decide(approved.Scope, noLongerLive, StatusApproved, testFeature, testActor, testNow.Add(time.Hour), testLimits)
	if err != nil || retry.Changed {
		t.Fatalf("stored idempotent retry: result=%+v err=%v", retry, err)
	}
}

func TestMalformedStoredScopeFailsClosed(t *testing.T) {
	selected := child(testChildA, "uid-a", ProtocolTCP, 443)
	scope := createScope(t, []ExactPortChild{selected}, []uuid.UUID{testChildA})
	scope.InitialEvidence[0].Selected = false
	if _, err := AddLaterExposure(scope, child(testChildB, "uid-b", ProtocolTCP, 80), testLimits); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("selected membership without selected evidence error = %v", err)
	}

	scope = createScope(t, []ExactPortChild{selected}, []uuid.UUID{testChildA})
	scope.Memberships[0].Origin = Origin("legacy-unknown")
	if _, err := AddLaterExposure(scope, child(testChildB, "uid-b", ProtocolTCP, 80), testLimits); !errors.Is(err, ErrUnknownOrigin) {
		t.Fatalf("unknown origin error = %v", err)
	}
}
