package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// RBAC-1 route matrix (docs/RBAC-1-roles.md, Validation). For each new role, EVERY state-changing route in the
// OpenAPI spec is called as a verified person holding only that role, and every route the role's grants do
// not cover must answer 403 forbidden. It is spec-driven like TestSessionlessRequestsAre401, so a route added
// later is covered without editing this file; it runs in both editions (go test with and without
// -tags enterprise).
//
// The walk has no database. A route the role IS allowed reaches its handler and fails on a missing
// dependency; nothing is asserted about it beyond the role holding the permission named for it here. A route
// the role is NOT allowed must be refused by the permission gate, which runs before any dependency, so:
//
//   - 403 with code "forbidden" is the only pass. edition_required would mean the edition gate ran first
//     (the edition-order law), email_not_verified or csrf that authorization never ran.
//   - a 400 validation_failed anywhere fails the walk: the validator answered before authorization, so
//     nothing was proven (walkBodies / walkPath supply valid shapes).

// rbac1WalkAllowed lists, per role, the state-changing routes its grants cover, each with the permission
// that covers it. Everything else must be 403 forbidden.
var rbac1WalkAllowed = map[string]map[string]rbac.Permission{
	rbac.RoleAuditor: {},
	rbac.RoleHelpdesk: {
		"AdminResetMfa":      rbac.PermMfaReset,
		"ApproveDevice":      rbac.PermDeviceApprove,
		"RejectDevice":       rbac.PermDeviceApprove,
		"RestoreNodeDevices": rbac.PermDeviceRestore,
	},
	rbac.RoleAgentsAdmin: {
		"AcceptAgentMCPToolDefinition":               rbac.PermAgentMCPToolPolicyManage,
		"AddAgentGroupMember":                        rbac.PermAgentTemplateManage,
		"ApplyAgentPolicyTemplate":                   rbac.PermAgentGrantAccess,
		"ApproveAgentAccessRequest":                  rbac.PermAgentAccessApprove,
		"ApproveAgentMCPToolApprovalRequest":         rbac.PermAgentMCPToolApprovalApprove,
		"ArchiveAgentGroup":                          rbac.PermAgentTemplateManage,
		"ArchiveAgentMCPProfile":                     rbac.PermAgentTemplateManage,
		"ArchiveAgentPolicyTemplate":                 rbac.PermAgentTemplateManage,
		"AssignAgentMCPProfile":                      rbac.PermAgentTemplateManage,
		"ConnectMCPServer":                           rbac.PermMCPManage,
		"CreateAgentAccessRequest":                   rbac.PermAgentAccessRequest,
		"CreateAgentGroup":                           rbac.PermAgentTemplateManage,
		"CreateAgentMCPProfile":                      rbac.PermAgentTemplateManage,
		"CreateAgentPolicyTemplateVersion":           rbac.PermAgentTemplateManage,
		"CreateAgentPolicyTemplate":                  rbac.PermAgentTemplateManage,
		"CreateAgentRulesFromOwnerAccess":            rbac.PermAgentGrantAccess,
		"DeletePolicyRule":                           rbac.PermAgentGrantAccess,
		"ExtendGrant":                                rbac.PermAgentGrantAccess,
		"SetPolicyRuleEnabled":                       rbac.PermAgentGrantAccess,
		"DenyAgentMCPToolApprovalRequest":            rbac.PermAgentMCPToolApprovalApprove,
		"DisconnectAgentMCPOAuthConnection":          rbac.PermAgentManage,
		"IssueAgentBootstrapToken":                   rbac.PermAgentEnroll,
		"PreviewAgentGroupMCPProfileImpact":          rbac.PermAgentTemplateManage,
		"PreviewAgentOwnerAccess":                    rbac.PermAgentGrantAccess,
		"PreviewAgentPolicyTemplate":                 rbac.PermAgentTemplateManage,
		"RejectAgentAccessRequest":                   rbac.PermAgentAccessApprove,
		"RemoveAgentGroupMember":                     rbac.PermAgentTemplateManage,
		"RemoveAgentMCPToolPolicyOverride":           rbac.PermAgentMCPToolPolicyManage,
		"RemoveAgentPolicyTemplateAssignment":        rbac.PermAgentGrantAccess,
		"ReplaceAgentGroupMCPProfile":                rbac.PermAgentTemplateManage,
		"ReplaceAgentGroupMCPToolPolicy":             rbac.PermAgentMCPToolPolicyManage,
		"ReplaceAgentMCPToolPolicy":                  rbac.PermAgentMCPToolPolicyManage,
		"RequestAgentCredentialRotation":             rbac.PermAgentCredentialRotate,
		"RevokeAgentAccessRequest":                   rbac.PermAgentAccessApprove,
		"RevokeAgentBootstrapToken":                  rbac.PermAgentEnroll,
		"SetOrganizationAgentJITAccessEnabled":       rbac.PermAgentAccessApprove,
		"SetOrganizationAgentPolicyTemplatesEnabled": rbac.PermAgentTemplateManage,
		"SetOrganizationAgentRuntimeEnabled":         rbac.PermAgentRuntimeManage,
		"SetOrganizationMCPEnabled":                  rbac.PermMCPManage,
		"StartAgentMCPOAuthConnection":               rbac.PermAgentManage,
		"StartMCPConnectionPreview":                  rbac.PermMCPManage,
		"UnassignAgentGroupMCPProfile":               rbac.PermAgentTemplateManage,
		"UpdateAgentGroup":                           rbac.PermAgentTemplateManage,
		"UpdateAgentPolicyTemplate":                  rbac.PermAgentTemplateManage,
		"UpdateAgentProfile":                         rbac.PermAgentManage,
	},
	rbac.RoleNetworkAdmin: {
		"AbortNodeLifecycleClaim":           rbac.PermK8sManage,
		"AcknowledgeNodeLifecycleClaim":     rbac.PermK8sManage,
		"AddSiteSubnet":                     rbac.PermSiteManage,
		"ApproveDevice":                     rbac.PermDeviceApprove,
		"ApproveSiteSubnet":                 rbac.PermSiteManage,
		"BeginNodeLifecycleInstall":         rbac.PermK8sManage,
		"BindSiteNode":                      rbac.PermSiteManage,
		"CancelNodeLifecycleInstall":        rbac.PermK8sManage,
		"CheckIPsecConfiguration":           rbac.PermIPsecManage,
		"CompleteNodeLifecycleInstall":      rbac.PermK8sManage,
		"ConfigureConnectivityProfile":      rbac.PermConnectivityManage,
		"ConfigureK8sConnectorPool":         rbac.PermK8sHAManage,
		"CreateFQDNResource":                rbac.PermFQDNResourceManage,
		"CreateIPsecProviderConnection":     rbac.PermIPsecManage,
		"CreateK8sClusterScope":             rbac.PermK8sScopeManage,
		"CreateK8sNamespaceRule":            rbac.PermK8sManage,
		"CreatePolicyRule":                  rbac.PermPolicyRuleManage,
		"CreateResource":                    rbac.PermResourceManage,
		"DecideK8sClusterScopeMembership":   rbac.PermK8sScopeApprove,
		"DeleteFQDNResolverContextConfig":   rbac.PermFQDNResourceManage,
		"DeleteFQDNResource":                rbac.PermFQDNResourceManage,
		"DeleteHealthCheck":                 rbac.PermDeviceHealthManage,
		"DeleteIPsecConnection":             rbac.PermIPsecManage,
		"DeleteK8sClusterScope":             rbac.PermK8sScopeManage,
		"DeleteK8sNamespaceRule":            rbac.PermK8sManage,
		"DeleteNode":                        rbac.PermGatewayManage,
		"DeletePolicyRule":                  rbac.PermPolicyRuleManage,
		"ExtendGrant":                       rbac.PermPolicyRuleManage,
		"SetPolicyRuleEnabled":              rbac.PermPolicyRuleManage,
		"DeleteResource":                    rbac.PermResourceManage,
		"DeleteSite":                        rbac.PermSiteManage,
		"DeregisterK8sCluster":              rbac.PermK8sManage,
		"ExposeK8sInventoryService":         rbac.PermK8sManage,
		"ExposeK8sService":                  rbac.PermK8sManage,
		"FinalizeNodeLifecycleInstallAbort": rbac.PermK8sManage,
		"HeartbeatNodeLifecycleInstall":     rbac.PermK8sManage,
		"IssueJoinToken":                    rbac.PermGatewayManage,
		"PreviewFQDNResourceImpact":         rbac.PermFQDNResourceManage,
		"PutHealthCheck":                    rbac.PermDeviceHealthManage,
		"RegisterK8sCluster":                rbac.PermK8sManage,
		"RegisterSite":                      rbac.PermSiteManage,
		"RejectDevice":                      rbac.PermDeviceApprove,
		"RemintNodeLifecycleClaim":          rbac.PermGatewayManage,
		"RemoveSiteDNSForward":              rbac.PermSiteManage,
		"RemoveSiteSubnet":                  rbac.PermSiteManage,
		"RequestNodeLifecycleInstallAbort":  rbac.PermK8sManage,
		"ResizePool":                        rbac.PermGatewayManage,
		"RestoreNodeDevices":                rbac.PermDeviceRestore,
		"RevokeNode":                        rbac.PermGatewayManage,
		"RotateIPsecPSKs":                   rbac.PermIPsecManage,
		"RouteLAN":                          rbac.PermSiteManage,
		"SetCrossGatewayClientsEnabled":     rbac.PermGatewayManage,
		"SetDeviceApproval":                 rbac.PermDeviceApprovalManage,
		"SetFQDNResolverContextConfig":      rbac.PermFQDNResourceManage,
		"SetFQDNResourceEnabled":            rbac.PermFQDNResourceManage,
		"SetHubPriority":                    rbac.PermSiteManage,
		"SetIPsecConnectionIntent":          rbac.PermIPsecManage,
		"SetIPsecSettings":                  rbac.PermIPsecManage,
		"SetK8sClusterApiAccess":            rbac.PermK8sAPIManage,
		"SetK8sClusterConnector":            rbac.PermK8sManage,
		"SetK8sClusterProviderMetadata":     rbac.PermK8sManage,
		"SetK8sClusterScopeActive":          rbac.PermK8sScopeManage,
		"SetK8sClusterScopeSettings":        rbac.PermK8sScopeManage,
		"SetK8sConnectorPoolHAMode":         rbac.PermK8sHAManage,
		"SetK8sHASettings":                  rbac.PermK8sHAManage,
		"SetOVPNEnabled":                    rbac.PermGatewayManage,
		"SetSiteDNSForward":                 rbac.PermSiteManage,
		"SetSiteLanEgress":                  rbac.PermSiteManage,
		"TransferNodeDevices":               rbac.PermDeviceTransfer,
		"UnbindSiteNode":                    rbac.PermSiteManage,
		"UnexposeK8sService":                rbac.PermK8sManage,
		"UpdateFQDNResource":                rbac.PermFQDNResourceManage,
		"UpdateK8sNamespaceRule":            rbac.PermK8sManage,
		"UpdateNode":                        rbac.PermGatewayManage,
		"UpdateResource":                    rbac.PermResourceManage,
	},
}

// rbac1SelfService are mutations every organization member may make on their OWN things (org:view plus a
// relational check in the handler: your device, your access request). RBAC-0 D5 reviewed each one; a
// role's grants do not change them, so the walk requires only that the role is treated exactly like a
// plain member there.
var rbac1SelfService = map[string]string{
	"CreateDevice":             "your own device (someone else's needs member:manage)",
	"ExportOVPNProfile":        "your own OpenVPN device (someone else's needs member:manage)",
	"UpdateDeviceMode":         "your own device (someone else's needs member:manage)",
	"RemoveDevice":             "your own device (someone else's needs member:manage or agent:revoke)",
	"RevokeDevice":             "your own device (someone else's needs member:manage or agent:revoke)",
	"ReportDeviceHealth":       "your own device's health facts",
	"CancelAgentAccessRequest": "your own access request",
}

type walkResult struct {
	status int
	code   string
}

// walkMutationsAs calls every state-changing, non-public operation as a verified person holding roles.
func walkMutationsAs(t *testing.T, roles []string) map[string]walkResult {
	t.Helper()
	return walkAs(t, roles, false)
}

// walkAs calls every non-public operation as a verified person holding roles: the state-changing ones, or
// (reads=true) the GETs.
func walkAs(t *testing.T, roles []string, reads bool) map[string]walkResult {
	t.Helper()
	swagger, err := api.GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger: %v", err)
	}
	org := uuid.New()
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Orgs: tenancy.NewService(nil), AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: roles[0]}, RoleSets: map[uuid.UUID][]string{org: roles}}
	}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	srv := httptest.NewTLSServer(router)
	defer srv.Close()
	out := map[string]walkResult{}
	for path, item := range swagger.Paths.Map() {
		for method, op := range item.Operations() {
			if (method == http.MethodGet) != reads || method == http.MethodHead || method == http.MethodOptions {
				continue
			}
			if op.Security != nil && len(*op.Security) == 0 {
				continue
			}
			reqPath := walkPath(path, org)
			var body io.Reader
			if b, ok := walkBodies[strings.ToLower(op.OperationID)]; ok {
				body = bytes.NewBufferString(b)
			}
			if q, ok := walkQueries[strings.ToLower(op.OperationID)]; ok {
				reqPath += q
			}
			req, err := http.NewRequest(method, srv.URL+reqPath, body)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("If-Match", `"1"`)
			req.Header.Set("Idempotency-Key", "rbac1-walk")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var envelope struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.Unmarshal(raw, &envelope)
			out[op.OperationID] = walkResult{status: resp.StatusCode, code: envelope.Error.Code}
		}
	}
	if len(out) == 0 {
		t.Fatal("no state-changing operations walked — walk is vacuous")
	}
	return out
}

func TestRBAC1RouteMatrixRefusesEveryUncoveredMutation(t *testing.T) {
	// A member of the organization with no permission at all: what answers anything but 403 for it is not
	// permission-gated (account self-service, the AI data plane, shelved routes) and is outside this matrix.
	none := walkMutationsAs(t, []string{"rbac1-walk-no-grants"})
	member := walkMutationsAs(t, []string{rbac.RoleMember})
	for op, why := range rbac1SelfService {
		r, ok := member[op]
		if !ok {
			t.Errorf("self-service %s is not a state-changing route (%s)", op, why)
		} else if r.status == http.StatusForbidden && r.code == "forbidden" {
			t.Errorf("self-service %s refuses a plain member, so it is not self-service (%s)", op, why)
		}
	}
	for role, allowed := range rbac1WalkAllowed {
		t.Run(role, func(t *testing.T) {
			for op, perm := range allowed {
				if !rbac.Can(role, perm) {
					t.Errorf("%s: allowed %s names %s, which %s does not hold", role, op, perm, role)
				}
				r, ok := none[op]
				if !ok {
					t.Errorf("%s: allowed %s is not a state-changing route", role, op)
				} else if r.status != http.StatusForbidden || r.code != "forbidden" {
					t.Errorf("%s: allowed %s is not permission-gated (no-grant caller got %d %s)", role, op, r.status, r.code)
				}
			}
			got := walkMutationsAs(t, []string{role})
			var leaks []string
			walked := 0
			for op, r := range got {
				if r.code == "validation_failed" {
					t.Errorf("%s %s: 400 validation_failed — the validator answered before authorization", role, op)
					continue
				}
				b := none[op]
				if b.status != http.StatusForbidden {
					continue // not permission-gated: account self-service, the AI data plane, shelved routes
				}
				if b.code != "forbidden" {
					// Refused by a gate that is not a role permission (deployment administrator, a browser
					// session, a human session). The role must change nothing about that answer.
					if r != b {
						t.Errorf("%s %s: answered %d %s, a caller with no grants got %d %s", role, op, r.status, r.code, b.status, b.code)
					}
					continue
				}
				if _, ok := rbac1SelfService[op]; ok {
					if m := member[op]; r != m {
						t.Errorf("%s %s: self-service answered %d %s, a member got %d %s", role, op, r.status, r.code, m.status, m.code)
					}
					continue
				}
				if _, ok := allowed[op]; ok {
					continue
				}
				walked++
				if r.status != http.StatusForbidden || r.code != "forbidden" {
					leaks = append(leaks, op+" → "+http.StatusText(r.status)+" "+r.code)
				}
			}
			sort.Strings(leaks)
			for _, l := range leaks {
				t.Errorf("%s reached a route its grants do not cover: %s", role, l)
			}
			if walked < 100 {
				t.Fatalf("%s: only %d uncovered mutations walked — walk is vacuous", role, walked)
			}
			t.Logf("%s: %d uncovered state-changing routes answer 403 forbidden", role, walked)
		})
	}
}

// The role walk with a COMBINATION where the role that grants the permission is not the primary one: the
// handlers read the whole role set, not the compatibility primary role.
func TestRBAC1SecondaryRoleGrantsAreHonoured(t *testing.T) {
	got := walkMutationsAs(t, []string{rbac.RoleNetworkAdmin, rbac.RoleAgentsAdmin})
	for _, op := range []string{"StartAgentMCPOAuthConnection", "UpdateAgentProfile", "DisconnectAgentMCPOAuthConnection", "SetOrganizationMCPEnabled"} {
		if r := got[op]; r.status == http.StatusForbidden && r.code == "forbidden" {
			t.Errorf("network-admin + agents-admin refused %s: the secondary role was ignored", op)
		}
	}
}

// rbac1AuditorReads are the admin lists the founder opened to the Auditor on 2026-11-28, each with the view
// permission that now gates it. The walk has no database, so "allowed" means the permission gate let the
// read through (any answer but 403); a caller with no grants and a plain member are still refused.
var rbac1AuditorReads = map[string]rbac.Permission{
	"ListPendingDevices":                 rbac.PermDeviceView,
	"GetDeviceApproval":                  rbac.PermDeviceView,
	"ListAgentGroups":                    rbac.PermAgentTemplateView,
	"ListAgentGroupMembers":              rbac.PermAgentTemplateView,
	"ListAgentMCPProfiles":               rbac.PermAgentTemplateView,
	"ListAgentMCPAssignments":            rbac.PermAgentTemplateView,
	"ListAgentPolicyTemplates":           rbac.PermAgentTemplateView,
	"ListAgentPolicyTemplateVersions":    rbac.PermAgentTemplateView,
	"ListAgentPolicyTemplateAssignments": rbac.PermAgentTemplateView,
	"GetAgentGroupMCPToolPolicy":         rbac.PermAgentTemplateView,
	"GetOrganizationAlertingSetting":     rbac.PermAlertingView,
	"ListAlertDestinations":              rbac.PermAlertingView,
	"ListAlertDestinationSubscriptions":  rbac.PermAlertingView,
	"ListAlertDeliveries":                rbac.PermAlertingView,
	"ListAlertOccurrences":               rbac.PermAlertingView,
	"GetMfaEnforce":                      rbac.PermMfaView,
	"ListHealthChecks":                   rbac.PermDeviceHealthView,
	"ListPendingSiteSubnets":             rbac.PermSiteView,
	"ListSiteDNSForwards":                rbac.PermSiteView,
	"GetSiteReferences":                  rbac.PermSiteView,
	"ListK8sClusterInventory":            rbac.PermK8sView,
	"ListInvitations":                    rbac.PermInvitationView,
	"ListAppAccessGrants":                rbac.PermAppAccessView,
	"ListAppAccessApplicationSessions":   rbac.PermAppAccessView,
}

func TestRBAC1AuditorReadsAdminListsAndWritesNothing(t *testing.T) {
	auditor := walkAs(t, []string{rbac.RoleAuditor}, true)
	member := walkAs(t, []string{rbac.RoleMember}, true)
	for op, perm := range rbac1AuditorReads {
		if !rbac.Can(rbac.RoleAuditor, perm) || rbac.Can(rbac.RoleMember, perm) {
			t.Errorf("%s: %s must be held by the auditor and not by a member", op, perm)
		}
		r, ok := auditor[op]
		if !ok {
			t.Errorf("%s is not a GET route", op)
			continue
		}
		if r.status == http.StatusForbidden && r.code == "forbidden" {
			t.Errorf("auditor refused %s", op)
		}
		if m := member[op]; m.status != http.StatusForbidden {
			t.Errorf("a member reached %s (%d %s)", op, m.status, m.code)
		}
	}
	// Secrets and approvals stay closed to the auditor.
	for _, op := range []string{"ListAgentBootstrapTokens", "GetAgentBootstrapTokenStatus", "ListOrganizationMCPToolApprovalRequests", "ListAgentMCPToolApprovalRequests", "GetServerAccessRecording"} {
		if r := auditor[op]; r.status != http.StatusForbidden {
			t.Errorf("auditor reached %s (%d %s)", op, r.status, r.code)
		}
	}
}

// Founder, 2026-11-28: whoever may create a rule may enable, disable and extend it. The GitOps operator still
// may not (RBAC-0 D4), and a plain member may not.
func TestRBAC1RuleLifecycleFollowsRuleAuthoring(t *testing.T) {
	org := uuid.New()
	rule := uuid.New()
	exp := time.Now().Add(time.Hour)
	call := func(ctx context.Context) (error, error) {
		_, a := (apiServer{}).SetPolicyRuleEnabled(ctx, api.SetPolicyRuleEnabledRequestObject{OrgId: org, RuleId: rule, Body: &api.SetPolicyRuleEnabledJSONRequestBody{Enabled: false}})
		_, b := (apiServer{}).ExtendGrant(ctx, api.ExtendGrantRequestObject{OrgId: org, RuleId: rule, Body: &api.ExtendGrantJSONRequestBody{ExpiresAt: exp}})
		return a, b
	}
	for _, roles := range [][]string{{rbac.RoleNetworkAdmin}, {rbac.RoleAgentsAdmin}, {rbac.RoleAdmin}} {
		a, b := call(rbac1Principal(org, roles...))
		if hasCode(a, 403, "forbidden") || hasCode(b, 403, "forbidden") {
			t.Errorf("%v refused at the permission gate: %v / %v", roles, a, b)
		}
	}
	for _, roles := range [][]string{{rbac.RoleMember}, {rbac.RoleAuditor}, {rbac.RoleHelpdesk}} {
		a, b := call(rbac1Principal(org, roles...))
		if !hasCode(a, 403, "forbidden") || !hasCode(b, 403, "forbidden") {
			t.Errorf("%v toggled or extended a rule: %v / %v", roles, a, b)
		}
	}
	operator := authctx.WithPrincipal(context.Background(), &authctx.Principal{MachineID: uuid.New(), MachineName: "gitops",
		AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOperator}})
	if a, b := call(operator); !hasCode(a, 403, "forbidden") || !hasCode(b, 403, "forbidden") {
		t.Errorf("the GitOps operator toggled or extended a rule: %v / %v", a, b)
	}
}
