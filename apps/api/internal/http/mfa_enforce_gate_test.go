package http

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

// gateMustPass / gateMustDeny are ABSOLUTE semantic pins: (method, path) -> whether a MFA-enrollment-
// gated user may reach it. Written as LITERALS, derived from NOTHING in the code under test — not from
// enrollmentGateAllow, not from operationId strings. This is the anti-tautology guard.
//
// The prior self-arming test compared gateAllows(req) against enrollmentGateAllow[op.OperationID] — the
// SAME map on both sides — so it could only detect a thing disagreeing with itself. A casing mismatch
// (enrollmentGateAllow used source-yaml camelCase; api.GetSwagger() carries oapi-codegen's exported
// PascalCase operationIds) cancelled perfectly: both lookups missed, both false, equal, GREEN — while
// the D8 grandfather path was fully bricked (every escape op denied). These pins assert absolute
// behavior instead, so they fail LOUDLY on the live defect. (S7.5.5 law: a guard's test must assert
// ABSOLUTE expected behavior, never derive its expectation from the same artifact under test.)
var gateMustPass = []struct{ method, path string }{
	{"GET", "/api/v1/auth/me"},                   // read own state (carries enrollment_required so the client can route)
	{"POST", "/api/v1/auth/mfa/enroll"},          // start enrollment
	{"POST", "/api/v1/auth/mfa/enroll/confirm"},  // confirm enrollment
	{"POST", "/api/v1/auth/verify-email"},        // email verify is UPSTREAM of enroll (finding #5)
	{"POST", "/api/v1/auth/verify-email/resend"}, // resend the verify mail
	{"POST", "/api/v1/auth/logout"},              // sign out
}

var gateMustDeny = []struct{ method, path string }{
	{"POST", "/api/v1/auth/login"},                   // a plain auth op
	{"DELETE", "/api/v1/auth/mfa"},                   // mfaDisenroll — excluded by design (nothing to disenroll; self-cycling)
	{"POST", "/api/v1/auth/cli/authorize"},           // cliAuthorize — excluded (must not birth a credential that outlives the gate)
	{"GET", "/api/v1/organizations/{orgId}/devices"}, // a plain resource op — the everything-else default
}

// TestEnrollmentGateSelfArming drives the gate's resolve+allowlist decision. It proves TWO properties
// SEPARATELY (founder condition d): (1) CORRECTNESS — the absolute semantic pins above pass/deny
// exactly as intended; (2) BREADTH — every operation in the spec RESOLVES (no legit route silently
// fails closed as a false-deny) and the gate allows EXACTLY the ops the must-pass pins cover (no leak
// outside the pinned escape set), proven against the pins, not against enrollmentGateAllow.
func TestEnrollmentGateSelfArming(t *testing.T) {
	swagger, err := api.GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger: %v", err)
	}
	swagger.Servers = nil // match paths as-is (we run behind nginx)
	oapiRouter, err := gorillamux.NewRouter(swagger)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	fill := func(p string) string {
		for _, param := range []string{"orgId", "userId", "nodeId", "deviceId", "credentialId", "groupId", "resourceId", "ruleId"} {
			p = strings.ReplaceAll(p, "{"+param+"}", uuid.NewString())
		}
		p = strings.ReplaceAll(p, "{provider}", "google")
		p = strings.ReplaceAll(p, "{checkKind}", "disk_encryption")
		return p
	}

	// (1) CORRECTNESS — absolute pins. These are the load-bearing assertions; they fail loudly on the
	// live defect (a bricked escape op / a leaked excluded op), unlike a self-referential comparison.
	for _, tc := range gateMustPass {
		if !gateAllows(oapiRouter, httptest.NewRequest(tc.method, fill(tc.path), nil)) {
			t.Errorf("MUST-PASS bricked: a gated user is DENIED on the escape op %s %s", tc.method, tc.path)
		}
	}
	for _, tc := range gateMustDeny {
		if gateAllows(oapiRouter, httptest.NewRequest(tc.method, fill(tc.path), nil)) {
			t.Errorf("MUST-DENY leaked: a gated user is ALLOWED on the excluded op %s %s", tc.method, tc.path)
		}
	}

	// (2) BREADTH — resolve the must-pass pins to their operationIds (independently of enrollmentGateAllow),
	// then sweep EVERY spec op: it must resolve, and gateAllows must equal "is this op one the pins cover".
	pinnedEscape := map[string]bool{}
	for _, tc := range gateMustPass {
		route, _, ferr := oapiRouter.FindRoute(httptest.NewRequest(tc.method, fill(tc.path), nil))
		if ferr != nil || route == nil || route.Operation == nil {
			t.Fatalf("must-pass pin %s %s does not resolve — pins/spec drift", tc.method, tc.path)
		}
		pinnedEscape[route.Operation.OperationID] = true
	}
	checked := 0
	for path, item := range swagger.Paths.Map() {
		for method, op := range item.Operations() {
			req := httptest.NewRequest(method, fill(path), nil)
			route, _, ferr := oapiRouter.FindRoute(req)
			if ferr != nil || route == nil || route.Operation == nil {
				t.Errorf("op %s %s (%q) does NOT resolve — a legit route fails closed as a false-deny", method, path, op.OperationID)
				continue
			}
			if got := gateAllows(oapiRouter, req); got != pinnedEscape[op.OperationID] {
				t.Errorf("breadth: %s %s (%q) allowed=%v, want=%v (allowed iff a must-pass pin covers it)", method, path, op.OperationID, got, pinnedEscape[op.OperationID])
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("walk covered only %d operations — spec load looks wrong", checked)
	}
}
