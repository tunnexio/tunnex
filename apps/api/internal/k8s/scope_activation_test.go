package k8s

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s/scopeapproval"
)

func TestRequireClusterScopeHumanFailsClosed(t *testing.T) {
	userID := uuid.New()
	cases := []struct {
		name  string
		actor *authctx.Principal
		code  string
	}{
		{name: "missing", code: "human_actor_required"},
		{name: "zero user", actor: &authctx.Principal{EmailVerified: true}, code: "human_actor_required"},
		{name: "unverified", actor: &authctx.Principal{UserID: userID}, code: "email_not_verified"},
		{name: "machine", actor: &authctx.Principal{UserID: userID, MachineID: uuid.New(), EmailVerified: true, AuthMethod: authctx.AuthMachine}, code: "human_actor_required"},
		{name: "agent", actor: &authctx.Principal{UserID: userID, NodeID: uuid.New(), EmailVerified: true, AuthMethod: authctx.AuthAgent}, code: "human_actor_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requireClusterScopeHuman(tc.actor)
			assertScopeAPIError(t, err, http.StatusForbidden, tc.code)
		})
	}

	got, err := requireClusterScopeHuman(&authctx.Principal{UserID: userID, EmailVerified: true, AuthMethod: authctx.AuthSSO})
	if err != nil {
		t.Fatalf("verified human: %v", err)
	}
	if got != userID {
		t.Fatalf("actor id = %s, want %s", got, userID)
	}
}

func TestClusterScopeExposureActorPreservesMachineAuditCompatibility(t *testing.T) {
	ownerID, machineID, orgID := uuid.New(), uuid.New(), uuid.New()
	machine := authctx.NewMachinePrincipal(ownerID, machineID, orgID, "gitops", "owner", "inventory-controller")
	actorID, actorSystem, memberID, cause, err := clusterScopeExposureActor(machine, "")
	if err != nil {
		t.Fatal(err)
	}
	if actorID != uuid.Nil || actorSystem != "operator:gitops" || memberID != ownerID || cause != "inventory-controller" {
		t.Fatalf("machine attribution = %s/%q/%s/%q", actorID, actorSystem, memberID, cause)
	}

	humanID := uuid.New()
	actorID, actorSystem, memberID, cause, err = clusterScopeExposureActor(&authctx.Principal{UserID: humanID}, "manual exposure")
	if err != nil {
		t.Fatal(err)
	}
	if actorID != humanID || actorSystem != "" || memberID != humanID || cause != "manual exposure" {
		t.Fatalf("human attribution = %s/%q/%s/%q", actorID, actorSystem, memberID, cause)
	}

	_, _, _, _, err = clusterScopeExposureActor(&authctx.Principal{UserID: humanID, NodeID: uuid.New(), AuthMethod: authctx.AuthAgent}, "")
	assertScopeAPIError(t, err, http.StatusForbidden, "actor_required")
	_, _, _, _, err = clusterScopeExposureActor(&authctx.Principal{MachineID: machineID, AuthMethod: authctx.AuthMachine}, "")
	assertScopeAPIError(t, err, http.StatusForbidden, "actor_required")
}

func TestValidateClusterScopeSource(t *testing.T) {
	for _, kind := range []string{"group", "user", "site", "agent"} {
		t.Run(kind, func(t *testing.T) {
			id := uuid.New()
			got, err := validateClusterScopeSource(ClusterScopeSource{Kind: kind, ID: id})
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != id || got.Kind != kind || got.CIDR != "" {
				t.Fatalf("unexpected source: %+v", got)
			}
		})
	}
	_, err := validateClusterScopeSource(ClusterScopeSource{Kind: "agent_group", ID: uuid.New()})
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_request")

	cidr, err := validateClusterScopeSource(ClusterScopeSource{Kind: "cidr", CIDR: "10.20.30.47/24"})
	if err != nil {
		t.Fatal(err)
	}
	if cidr.CIDR != "10.20.30.0/24" {
		t.Fatalf("masked CIDR = %q", cidr.CIDR)
	}

	invalid := []ClusterScopeSource{
		{},
		{Kind: "group"},
		{Kind: "group", ID: uuid.New(), CIDR: "10.0.0.0/8"},
		{Kind: "cidr", ID: uuid.New(), CIDR: "10.0.0.0/8"},
		{Kind: "cidr", CIDR: "not-a-cidr"},
	}
	for _, source := range invalid {
		_, err := validateClusterScopeSource(source)
		assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_request")
	}
}

func TestScopeInventoryCursorRoundTripAndRejectsInvalid(t *testing.T) {
	want := scopeInventoryCursor{
		ReportID: uuid.New(), Namespace: "payments", Service: "ledger", InventoryRef: uuid.New(),
	}
	encoded, err := encodeScopeInventoryCursor(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeScopeInventoryCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("cursor = %+v, want %+v", got, want)
	}

	for _, encoded := range []string{"%%%", "e30", "eyJyIjoiYmFkIn0"} {
		_, err := decodeScopeInventoryCursor(encoded)
		assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_inventory_cursor")
	}
	empty, err := decodeScopeInventoryCursor("")
	if err != nil || empty != (scopeInventoryCursor{}) {
		t.Fatalf("empty cursor = %+v, %v", empty, err)
	}
}

func TestScopeReadCursorsAreEndpointAndBoundaryBound(t *testing.T) {
	ruleID := uuid.New()
	want := scopeReadCursor{
		Kind: "memberships", BoundaryID: ruleID, Namespace: "payments", Service: "ledger",
		Protocol: "tcp", ServicePort: 443, ChildID: uuid.New(),
	}
	encoded, err := encodeScopeReadCursor(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeScopeReadCursor(encoded, "memberships", ruleID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("cursor = %+v, want %+v", got, want)
	}
	_, err = decodeScopeReadCursor(encoded, "candidates", ruleID)
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_scope_cursor")
	_, err = decodeScopeReadCursor(encoded, "memberships", uuid.New())
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_scope_cursor")

	review := scopeReadCursor{
		Kind: "review_queue", BoundaryID: uuid.New(), CreatedAt: time.Now().UTC(), RuleID: uuid.New(), ChildID: uuid.New(),
	}
	encoded, err = encodeScopeReadCursor(review)
	if err != nil {
		t.Fatal(err)
	}
	got, err = decodeScopeReadCursor(encoded, "review_queue", review.BoundaryID)
	if err != nil || got != review {
		t.Fatalf("review cursor = %+v, %v", got, err)
	}
	_, err = decodeScopeReadCursor("%%%", "review_queue", review.BoundaryID)
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_scope_cursor")
}

func TestScopeReadBoundsAndViewsDoNotExposeRawServiceUID(t *testing.T) {
	if got, err := clusterScopeReadLimit(0); err != nil || got != 100 {
		t.Fatalf("default read limit = %d, %v", got, err)
	}
	if got, err := clusterScopeReadLimit(37); err != nil || got != 37 {
		t.Fatalf("explicit read limit = %d, %v", got, err)
	}
	_, err := clusterScopeReadLimit(101)
	assertScopeAPIError(t, err, http.StatusBadRequest, "invalid_page_limit")

	for _, typ := range []reflect.Type{
		reflect.TypeOf(ClusterScopeCandidateView{}), reflect.TypeOf(ClusterScopeMembershipView{}),
	} {
		if _, exposed := typ.FieldByName("ServiceUID"); exposed {
			t.Fatalf("%s exposes raw Kubernetes Service UID", typ.Name())
		}
	}
}

func TestClusterScopeEffectProjectionIsFailClosedAndExplainsTheCompilerGuard(t *testing.T) {
	base := clusterScopeEffectInput{
		entitlementUnlocked: true, selected: true, status: "approved", scopeActive: true,
		orgEnabled: true, current: true,
	}
	if effective, reason := projectClusterScopeEffect(base); !effective || reason != "" {
		t.Fatalf("eligible membership = %v/%q, want true/empty", effective, reason)
	}
	cases := []struct {
		name   string
		mutate func(*clusterScopeEffectInput)
		reason string
	}{
		{name: "edition loss", mutate: func(in *clusterScopeEffectInput) { in.entitlementUnlocked = false }, reason: clusterScopeInactiveEditionLocked},
		{name: "not selected", mutate: func(in *clusterScopeEffectInput) { in.status = ""; in.selected = false }, reason: clusterScopeInactiveNotSelected},
		{name: "pending", mutate: func(in *clusterScopeEffectInput) { in.status = "pending" }, reason: clusterScopeInactivePending},
		{name: "rejected", mutate: func(in *clusterScopeEffectInput) { in.status = "rejected" }, reason: clusterScopeInactiveRejected},
		{name: "scope disabled", mutate: func(in *clusterScopeEffectInput) { in.scopeActive = false }, reason: clusterScopeInactiveScopeDisabled},
		{name: "organization disabled", mutate: func(in *clusterScopeEffectInput) { in.orgEnabled = false }, reason: clusterScopeInactiveOrganizationDisabled},
		{name: "rule disabled", mutate: func(in *clusterScopeEffectInput) { in.ruleDisabled = true }, reason: clusterScopeInactiveRuleDisabled},
		{name: "rule expired", mutate: func(in *clusterScopeEffectInput) { in.ruleExpired = true }, reason: clusterScopeInactiveRuleExpired},
		{name: "UID changed", mutate: func(in *clusterScopeEffectInput) {
			in.current = false
			in.currentReason = clusterScopeInactiveIdentityChanged
		}, reason: clusterScopeInactiveIdentityChanged},
		{name: "inventory stale", mutate: func(in *clusterScopeEffectInput) {
			in.current = false
			in.currentReason = clusterScopeInactiveInventoryStale
		}, reason: clusterScopeInactiveInventoryStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			if effective, reason := projectClusterScopeEffect(in); effective || reason != tc.reason {
				t.Fatalf("projection = %v/%q, want false/%q", effective, reason, tc.reason)
			}
		})
	}
}

func TestScopeActivationErrorMappingAndLockedLimits(t *testing.T) {
	if clusterScopeInventoryPageLimit != 100 || clusterScopeExposurePortLimit != 32 ||
		clusterScopePendingFanoutLimit != 500 || clusterScopeActiveLimit != 20 {
		t.Fatal("scope activation limits drifted from S20.4")
	}
	limits := scopeapproval.ProductionLimits()
	if limits.MaxCurrentCandidates != 500 || limits.MaxInitialSelections != 100 || limits.MaxMemberships != 500 {
		t.Fatalf("scope approval limits drifted: %+v", limits)
	}

	cases := []struct {
		err    error
		status int
		code   string
	}{
		{scopeapproval.ErrInventoryStale, http.StatusConflict, "k8s_inventory_stale"},
		{scopeapproval.ErrInventoryUnavailable, http.StatusConflict, "k8s_inventory_unavailable"},
		{scopeapproval.ErrEntitlementUnavailable, http.StatusForbidden, "edition_required"},
		{scopeapproval.ErrOptInDisabled, http.StatusConflict, "k8s_cluster_scope_opt_in_required"},
		{scopeapproval.ErrCandidateLimitReached, http.StatusConflict, "k8s_cluster_scope_limit_reached"},
		{scopeapproval.ErrSelectionLimitReached, http.StatusConflict, "k8s_cluster_scope_limit_reached"},
		{scopeapproval.ErrMembershipLimitReached, http.StatusConflict, "k8s_cluster_scope_limit_reached"},
		{scopeapproval.ErrInvalidDecision, http.StatusConflict, "k8s_scope_decision_conflict"},
		{scopeapproval.ErrCurrentIdentityMismatch, http.StatusConflict, "k8s_scope_decision_conflict"},
		{scopeapproval.ErrExposureNotLive, http.StatusConflict, "k8s_scope_membership_stale"},
		{scopeapproval.ErrUIDAttributionNotCurrent, http.StatusConflict, "k8s_scope_membership_stale"},
		{scopeapproval.ErrUnknownChildID, http.StatusBadRequest, "k8s_scope_unknown_child"},
	}
	for _, tc := range cases {
		assertScopeAPIError(t, scopeActivationError(tc.err), tc.status, tc.code)
	}

	sentinel := errors.New("sentinel")
	if got := scopeActivationError(sentinel); !errors.Is(got, sentinel) {
		t.Fatalf("unmapped error = %v", got)
	}
}

func assertScopeAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var got *apierr.Error
	if !errors.As(err, &got) {
		t.Fatalf("error = %v, want apierr %d/%s", err, status, code)
	}
	if got.Status != status || got.Code != code {
		t.Fatalf("apierr = %d/%s, want %d/%s", got.Status, got.Code, status, code)
	}
}
