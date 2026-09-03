package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ⛔ THE PERMISSION GATE MUST PRECEDE THE EDITION GATE IN EVERY DOUBLE-GATED HANDLER.
//
// THE ONE-LINE REASON: **the edition answer leaks what a caller is not entitled to ask about.**
//
// `403 edition_required` names a capability and invites a purchase. Returned to a caller whose ROLE forbids the
// capability regardless of edition, it is a purchase prompt shown on the strength of the wrong gate — the
// S14.5 HALT running forward. `403 forbidden` is the honest answer, and it is also the one that discloses
// nothing about what the deployment does or does not have.
//
// WHY THIS TEST IS A SOURCE SCAN AND NOT A CALL-LEVEL TEST — stated because it is the unusual choice:
//
//   THERE IS NO SHARED SEAM. The pair
//       if _, err := authorize(ctx, req.OrgId, rbac.PermX); err != nil { return nil, err }
//       if s.port == nil { return nil, xPlanOrFeatureRequired() }
//   is hand-written at the handler boundary. The exact inventory below covers
//   both named-plan and named-feature gates, including the Scale JIT wrapper;
//   a new helper or handler cannot silently widen the protected surface.
//
// WHAT PROMPTED IT: the S14.11 web view-model had this order BACKWARDS, twice in one file, and a mutation that
// swapped the two lines SURVIVED — the ordering was untested on both sides of the wire. The server was already
// correct at all 41 sites; this test is what keeps it that way. See docs/laws.md → A MUTATION SURVIVOR IS NOT
// AUTOMATICALLY A MISSING TEST.
//
// PROVEN TO FIRE: swapping the two lines in ListGroups makes this test red, naming that handler.

// preSessionEditionGates are the handlers that legitimately have an edition gate and NO permission gate,
// enumerated by name with the reason, so "no permission gate" can never be a silent pass.
//
// SSO login begins BEFORE a session exists, so there is no principal to authorize and nothing to check first.
// The edition answer there discloses a DEPLOYMENT fact ("this deployment has no SSO") rather than a per-caller
// entitlement — and the caller must be told, or the login button leads nowhere.
var preSessionEditionGates = map[string]string{
	"StartSsoLogin": "pre-session: no principal exists yet; the caller must learn the login method is absent",
	"SsoCallback":   "pre-session: the IdP round-trip lands here before a session is minted",
}

// expectedNamedErrorHelpers is an exact source inventory. A new helper which
// emits one of the public entitlement errors must be deliberately classified;
// it cannot silently fall outside the authorization-order scan.
var expectedNamedErrorHelpers = map[string]string{
	"editionRequired":                 "named plan",
	"mfaEnforceEditionRequired":       "named plan",
	"agentAccessFeatureRequired":      "named feature: agent_jit_access",
	"requireSSOAdmin":                 "named feature: sso",
	"requireK8sClusterScopesEntitled": "named feature: k8s_cluster_scopes",
}

// expectedEntitlementHandlers is the current one-binary inventory. It includes
// the retained legacy named-plan handlers, post-historical named-plan handlers,
// and Scale feature gates that the old edition-only scanner missed.
var expectedEntitlementHandlers = map[string]string{
	"PutIdpSyncConfig": "named plan", "GetIdpSyncHealth": "named plan", "TriggerIdpSync": "named plan", "MapIdpGroup": "named plan", "UnmapIdpGroup": "named plan",
	"GetMfaEnforce": "named plan", "SetMfaEnforce": "named plan", "AdminResetMfa": "named plan",
	"StartSsoLogin": "named plan", "SsoCallback": "named plan", "SetSsoConfig": "named plan", "GetSsoConfig": "named plan",
	"ListAccessEvents": "named plan", "GetAccessLogHealth": "named plan",
	"GetAccessEventRetention": "named plan", "UpdateAccessEventRetention": "named plan", "RunAccessEventPrune": "named plan",
	"ListAgents":                  "named feature: agent_jit_access filter",
	"ListAgentAccessDestinations": "named feature: agent_jit_access", "GetOrganizationAgentJITAccessSetting": "named feature: agent_jit_access", "SetOrganizationAgentJITAccessEnabled": "named feature: agent_jit_access",
	"CreateAgentAccessRequest": "named feature: agent_jit_access", "ListAgentAccessRequests": "named feature: agent_jit_access", "GetAgentAccessRequest": "named feature: agent_jit_access",
	"ApproveAgentAccessRequest": "named feature: agent_jit_access", "RejectAgentAccessRequest": "named feature: agent_jit_access", "CancelAgentAccessRequest": "named feature: agent_jit_access", "RevokeAgentAccessRequest": "named feature: agent_jit_access",
	"CreateK8sClusterScope": "named feature: k8s_cluster_scopes", "DecideK8sClusterScopeMembership": "named feature: k8s_cluster_scopes",
}

type historicalEntitlementHandler struct {
	name, classification string
}

// historicalEntitlementHandlers is the measured 43-handler pre-one-binary
// inventory. It is deliberately a list, not a map: the test below rejects a
// duplicate name as well as a missing classification.
var historicalEntitlementHandlers = []historicalEntitlementHandler{
	{"PutIdpSyncConfig", "retained named-plan"}, {"GetIdpSyncHealth", "retained named-plan"}, {"TriggerIdpSync", "retained named-plan"}, {"MapIdpGroup", "retained named-plan"}, {"UnmapIdpGroup", "retained named-plan"},
	{"GetMfaEnforce", "retained named-plan"}, {"SetMfaEnforce", "retained named-plan"}, {"AdminResetMfa", "retained named-plan"},
	{"StartSsoLogin", "pre-session exception"}, {"SsoCallback", "pre-session exception"}, {"SetSsoConfig", "retained named-plan"}, {"GetSsoConfig", "retained named-plan"},
	{"ListAccessEvents", "retained named-plan"}, {"GetAccessLogHealth", "retained named-plan"},
	{"ListAgents", "reclassified named-feature"}, {"ListAgentAccessDestinations", "reclassified named-feature"}, {"GetOrganizationAgentJITAccessSetting", "reclassified named-feature"}, {"SetOrganizationAgentJITAccessEnabled", "reclassified named-feature"},
	{"CreateAgentAccessRequest", "reclassified named-feature"}, {"ListAgentAccessRequests", "reclassified named-feature"}, {"GetAgentAccessRequest", "reclassified named-feature"}, {"ApproveAgentAccessRequest", "reclassified named-feature"}, {"RejectAgentAccessRequest", "reclassified named-feature"}, {"CancelAgentAccessRequest", "reclassified named-feature"}, {"RevokeAgentAccessRequest", "reclassified named-feature"},
	{"ListPolicyRules", "Community-core"}, {"CreatePolicyRule", "Community-core"}, {"SetPolicyRuleEnabled", "Community-core"}, {"DeletePolicyRule", "Community-core"}, {"ExtendGrant", "Community-core"},
	{"ListGroups", "Community-core"}, {"CreateGroup", "Community-core"}, {"UpdateGroup", "Community-core"}, {"DeleteGroup", "Community-core"}, {"ListGroupMembers", "Community-core"}, {"AddGroupMember", "Community-core"}, {"RemoveGroupMember", "Community-core"},
	{"ListResources", "Community-core"}, {"CreateResource", "Community-core"}, {"UpdateResource", "Community-core"}, {"DeleteResource", "Community-core"}, {"GetZeroTrustMode", "Community-core"}, {"SetZeroTrustMode", "Community-core"},
}

// postHistoricalEntitlementHandlers records capabilities introduced after the
// measured 43-handler migration ledger; they must not be rewritten into that
// historical evidence merely to make a new feature pass the guard.
var postHistoricalEntitlementHandlers = map[string]string{
	"CreateK8sClusterScope":           "named feature: k8s_cluster_scopes",
	"DecideK8sClusterScopeMembership": "named feature: k8s_cluster_scopes",
	"GetAccessEventRetention":         "named plan",
	"UpdateAccessEventRetention":      "named plan",
	"RunAccessEventPrune":             "named plan",
}

var (
	reFunction = regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)\(`)
	reHandler  = regexp.MustCompile(`^func \(s apiServer\) (\w+)\(ctx context\.Context, req api\.`)
	reAuth     = regexp.MustCompile(`\b(authorize|requireVerifiedSessionUser|requireVerifiedUser)\(ctx`)
)

type entitlementSourceFunction struct {
	file, fn string
	lines    []string
	at       int
	handler  bool
}

func TestEditionGateNeverPrecedesPermissionGate(t *testing.T) {
	bodies := collectEntitlementSourceFunctions(t)

	// Find every function that emits a public entitlement refusal. This catches
	// newly introduced plan/feature helpers even if their name does not include
	// "edition" and makes the ledger, rather than a count, the guardrail.
	errorHelpers := map[string]bool{}
	for _, body := range bodies {
		if !body.handler && containsNamedEntitlementError(body.lines) {
			errorHelpers[body.fn] = true
		}
	}
	assertExactInventory(t, "named entitlement error helpers", errorHelpers, expectedNamedErrorHelpers)

	// Follow local wrappers to a fixed point: requireAgentAccessCapability is a
	// Scale feature wrapper, and every handler using it must remain in the scan.
	gateFunctions := make(map[string]bool, len(errorHelpers))
	for name := range errorHelpers {
		gateFunctions[name] = true
	}
	for changed := true; changed; {
		changed = false
		for _, body := range bodies {
			if body.handler {
				continue
			}
			if gateFunctions[body.fn] || callsAny(body.lines, gateFunctions) {
				if !gateFunctions[body.fn] {
					gateFunctions[body.fn] = true
					changed = true
				}
			}
		}
	}
	observed := map[string]bool{}
	permissionFirst := 0
	for _, body := range bodies {
		if !body.handler || !callsAny(body.lines, gateFunctions) {
			continue
		}
		observed[body.fn] = true
		authAt, gateAt := firstAuthorization(body.lines), firstGateCall(body.lines, gateFunctions)
		if authAt < 0 {
			if _, ok := preSessionEditionGates[body.fn]; !ok {
				t.Errorf("%s: %s has a named plan/feature gate and no permission gate; add authorization or classify a pre-session exception", body.file, body.fn)
			}
			continue
		}
		if gateAt < 0 {
			t.Errorf("%s: %s reached an entitlement helper but no direct gate call was found", body.file, body.fn)
			continue
		}
		if authAt > gateAt {
			t.Errorf("%s: %s checks a named plan/feature gate at line %d before authorization at line %d", body.file, body.fn, body.at+gateAt+1, body.at+authAt+1)
			continue
		}
		permissionFirst++
	}
	assertExactInventory(t, "named plan/feature handlers", observed, expectedEntitlementHandlers)
	for fn := range preSessionEditionGates {
		if !observed[fn] {
			t.Errorf("pre-session exception %s is no longer entitlement-gated; remove or reclassify it", fn)
		}
	}
	t.Logf("named plan/feature handlers: %d — permission-first: %d, pre-session: %d", len(observed), permissionFirst, len(observed)-permissionFirst)
}

func TestHistoricalEntitlementLedgerReconcilesToOneBinaryInventory(t *testing.T) {
	if len(historicalEntitlementHandlers) != 43 {
		t.Fatalf("historical entitlement ledger has %d entries; expected 43", len(historicalEntitlementHandlers))
	}
	seen := map[string]string{}
	for _, entry := range historicalEntitlementHandlers {
		if prior, duplicate := seen[entry.name]; duplicate {
			t.Fatalf("historical entitlement ledger duplicates %s: %q and %q", entry.name, prior, entry.classification)
		}
		switch entry.classification {
		case "retained named-plan", "reclassified named-feature", "Community-core", "operational-unavailable", "pre-session exception":
		default:
			t.Fatalf("historical entitlement ledger has invalid classification for %s: %q", entry.name, entry.classification)
		}
		seen[entry.name] = entry.classification
	}

	legacy, features := 0, 0
	for name, classification := range expectedEntitlementHandlers {
		historical, ok := seen[name]
		if !ok {
			postHistorical, addedLater := postHistoricalEntitlementHandlers[name]
			if !addedLater || postHistorical != classification {
				t.Fatalf("current scanned handler %s is missing from both the historical 43-handler ledger and post-historical inventory", name)
			}
			if strings.HasPrefix(classification, "named plan") {
				historical = "post-historical named-plan"
			} else {
				historical = "post-historical named-feature"
			}
		}
		switch {
		case strings.HasPrefix(classification, "named plan"):
			legacy++
			if historical != "retained named-plan" && historical != "pre-session exception" && historical != "post-historical named-plan" {
				t.Fatalf("current named-plan handler %s is classified %q", name, historical)
			}
		case strings.HasPrefix(classification, "named feature"):
			features++
			if historical != "reclassified named-feature" && historical != "post-historical named-feature" {
				t.Fatalf("current named-feature handler %s is classified %q", name, historical)
			}
		}
	}
	if legacy != 17 || features != 13 {
		t.Fatalf("entitlement reconciliation is %d named-plan + %d feature; expected 17 named-plan + 13 feature", legacy, features)
	}
	for name, classification := range seen {
		if classification == "Community-core" {
			if _, stillScanned := expectedEntitlementHandlers[name]; stillScanned {
				t.Fatalf("Community-core handler %s remains in the named entitlement scanner", name)
			}
		}
	}
}

func collectEntitlementSourceFunctions(t *testing.T) []entitlementSourceFunction {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bodies []entitlementSourceFunction
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		fn, start := "", 0
		isHandler := false
		for i, l := range lines {
			if m := reFunction.FindStringSubmatch(l); m != nil {
				if fn != "" {
					bodies = append(bodies, entitlementSourceFunction{file: f, fn: fn, lines: lines[start:i], at: start, handler: isHandler})
				}
				fn, start = m[1], i
				isHandler = reHandler.MatchString(l)
			}
		}
		if fn != "" {
			bodies = append(bodies, entitlementSourceFunction{file: f, fn: fn, lines: lines[start:], at: start, handler: isHandler})
		}
	}
	return bodies
}

func containsNamedEntitlementError(lines []string) bool {
	for _, line := range lines {
		if strings.Contains(line, "apierr.") && (strings.Contains(line, `"edition_required"`) || strings.Contains(line, `"feature_required"`) || strings.Contains(line, `"plan_required"`)) {
			return true
		}
	}
	return false
}

func callsAny(lines []string, names map[string]bool) bool {
	return firstGateCall(lines, names) >= 0
}

func firstAuthorization(lines []string) int {
	for i, line := range lines {
		if reAuth.MatchString(line) {
			return i
		}
	}
	return -1
}

func firstGateCall(lines []string, names map[string]bool) int {
	for i, line := range lines {
		for name := range names {
			if strings.Contains(line, name+"(") {
				return i
			}
		}
	}
	return -1
}

func assertExactInventory(t *testing.T, label string, observed map[string]bool, expected map[string]string) {
	t.Helper()
	var missing, unexpected []string
	for name := range expected {
		if !observed[name] {
			missing = append(missing, name)
		}
	}
	for name := range observed {
		if _, ok := expected[name]; !ok {
			unexpected = append(unexpected, name)
		}
	}
	if len(missing) == 0 && len(unexpected) == 0 {
		return
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	t.Fatalf("%s inventory changed without classification: missing=%v unexpected=%v", label, missing, unexpected)
}
