package http

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// minimal valid bodies so a gated POST/PATCH passes spec validation and reaches
// the handler's authorization check (which is what we're asserting fails closed).
// keyed by lower(operationId) so a valid body accompanies gated POST/PATCH ops
// (otherwise the validator 400s on the missing body before auth is checked).
var walkBodies = map[string]string{
	// ⚠ A body is required so the 401 is about AUTHENTICATION, not about a missing field. Without one the
	// spec validator answers 400 first and the walk cannot tell "you are not signed in" from "your JSON is
	// wrong" — which is exactly the confusion the walk exists to rule out.
	"installlicense": `{"key":"tnxl_walk-probe"}`,
	// ⛔ The forced-password-change escape hatch. It is the ONE authenticated route not blocked by a
	// forced change — without a body the validator 400s first and the walk cannot prove it still 401s.
	"changepassword": `{"current_password":"walk-probe-current","new_password":"walk-probe-new-password"}`,
	// ⛔ THE CROSS-TENANT SURFACE (S12.11). The walk CAUGHT these: both routes answered 400 to a sessionless
	// caller, so an unauthenticated stranger was being told about request-body validation on the one surface
	// that edits privileges in organizations the caller is not in.
	"adminsetorgrole":          `{"role":"member"}`,
	"adminsetcpadmin":          `{"granted":true}`,
	"updategatewayendpoint":    `{"url":"https://agent.example.com:8443"}`,
	"createorganization":       `{"name":"Walk","slug":"walk-test"}`,
	"updateorganization":       `{"name":"Walk"}`,
	"setssoconfig":             `{"client_id":"x","client_secret":"y","enabled":true}`,
	"createinvitation":         `{"email":"walk@example.com","role":"member"}`,
	"changememberrole":         `{"role":"member"}`,
	"resizepool":               `{"cidr":"10.0.0.0/24"}`,
	"resendinvitation":         `{"email":"walk@example.com"}`,
	"revokeinvitation":         `{"email":"walk@example.com"}`,
	"issuejointoken":           `{"node_name":"walk-node"}`,
	"issueagentbootstraptoken": `{"name":"walk-agent","gateway_id":"00000000-0000-0000-0000-000000000000"}`,
	"updateagentprofile":       `{"environment":"walk"}`,
	"createdevice":             `{"name":"walk-device","node_id":"00000000-0000-0000-0000-000000000000"}`,
	"exportovpnprofile":        `{"name":"walk-ovpn","node_id":"00000000-0000-0000-0000-000000000000"}`,
	"setovpnenabled":           `{"enabled":true}`,
	// S13.1 Slice 7: the operator restore is device:restore-gated and still 401s sessionless.
	"restorenodedevices":  `{"target_node_id":"00000000-0000-0000-0000-000000000000"}`,
	"transfernodedevices": `{"target_node_id":"00000000-0000-0000-0000-000000000000"}`,
	"updatenode":          `{"name":"gw"}`,
	// S5.1 CLI-auth gated ops (cliToken/cliDeviceStart/cliDeviceToken are public).
	"cliauthorize":     `{"redirect_uri":"http://127.0.0.1:1/callback","code_challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"walk"}`,
	"clideviceapprove": `{"user_code":"WALK-CODE"}`,
	// S7.5.5 MFA: enroll/confirm is session-gated (mfaVerify is public; enroll-start/disenroll have no body).
	"mfaenrollconfirm": `{"code":"123456"}`,
	"setmfaenforce":    `{"enforce":false}`,
	// S7.5.1 access-event retention: inert, structurally valid requests keep
	// the spec walk focused on authentication rather than body validation.
	"updateaccesseventretention": `{"retention_days":30,"cleanup_interval_minutes":60,"expected_revision":0}`,
	"runaccesseventprune":        `{"idempotency_key":"walk-prune"}`,
	// S10.2 machine credentials (machine:manage-gated; a valid body so the POST reaches auth, not the validator).
	"mintmachinecredential": `{"name":"walk-op"}`,
	// S15.1 owner assignment (machine:manage-gated). ⛔ WITHOUT THIS THE WALK CAUGHT A REAL NO-ORACLE
	// DEFECT: the required body made the request validator answer 400 BEFORE auth ran, so a sessionless
	// caller learned the endpoint exists and what it expects. A valid body pushes the request past the
	// validator so the 401 is the AUTH layer's answer, which is the thing under test.
	"assignmachinecredentialowner": `{"user_id":"11111111-1111-1111-1111-111111111111"}`,
	// S7.1 Zero Trust policy gated ops (all enterprise; each still 401s sessionless).
	"creategroup":          `{"name":"Walk"}`,
	"updategroup":          `{"name":"Walk"}`,
	"addgroupmember":       `{"user_id":"00000000-0000-0000-0000-000000000000"}`,
	"createresource":       `{"name":"Walk","cidr":"10.0.0.0/24","protocol":"any"}`,
	"updateresource":       `{"name":"Walk","cidr":"10.0.0.0/24","protocol":"any"}`,
	"createpolicyrule":     `{"src_group_id":"00000000-0000-0000-0000-000000000000","dst_kind":"group","dst_group_id":"00000000-0000-0000-0000-000000000000"}`,
	"extendgrant":          `{"expires_at":"2099-01-01T00:00:00Z"}`,
	"setpolicyruleenabled": `{"enabled":false}`,
	// S8.1 site-to-site gated ops (site:manage; each still 401s sessionless. approveSiteSubnet + listPending have no body).
	"registersite":      `{"name":"Walk"}`,
	"routelan":          `{"node_id":"00000000-0000-0000-0000-000000000000","cidr":"10.20.0.0/24"}`,
	"sethubpriority":    `{"priority":1}`,
	"addsitesubnet":     `{"cidr":"10.20.0.0/24"}`,
	"setsitednsforward": `{"domain":"corp.local","resolver_ip":"10.20.0.53"}`,
	"bindsitenode":      `{"node_id":"00000000-0000-0000-0000-000000000000"}`,
	"setzerotrustmode":  `{"mode":"off"}`,
	// S21 resolver configuration is management-gated before endpoint validation.
	"setfqdnresolvercontextconfig": `{"endpoints":[{"address":"10.20.0.53","port":53,"transport":"udp"}]}`,
	// S10.3 Kubernetes gated ops (k8s:manage; each still 401s sessionless. deregister/unexpose have no body).
	"registerk8scluster":              `{"site_id":"00000000-0000-0000-0000-000000000000","name":"walk","vip_range":"100.64.0.0/16","service_cidr":"10.96.0.0/12","dns_zone":"k8s.example.com"}`,
	"setk8sclusterconnector":          `{"node_id":"00000000-0000-0000-0000-000000000000"}`,
	"exposek8sservice":                `{"name":"api","namespace":"prod"}`,
	"setk8sclusterprovidermetadata":   `{"provider":"aws","platform":"eks"}`,
	"setk8shasettings":                `{"enabled":false,"expected_revision":0}`,
	"setk8sconnectorpoolhamode":       `{"requested_mode":"legacy","expected_transition_revision":0}`,
	"setk8sclusterscopesettings":      `{"enabled":false,"expected_revision":0}`,
	"createk8sclusterscope":           `{"cluster_id":"00000000-0000-0000-0000-000000000000","source":{"kind":"group","id":"00000000-0000-0000-0000-000000000000"},"initial_service_child_ids":[]}`,
	"setk8sclusterscopeactive":        `{"active":false,"expected_revision":1}`,
	"decidek8sclusterscopemembership": `{"decision":"rejected"}`,
	"exposek8sinventoryservice":       `{"port_refs":["00000000-0000-0000-0000-000000000000"]}`,
	"setdeviceapproval":               `{"mode":"off"}`,
	// S7.5.2 IdP-group sync gated ops (enterprise; each still 401s sessionless).
	"putidpsyncconfig": `{"client_id":"x","client_secret":"y"}`,
	"mapidpgroup":      `{"idp_group_id":"grp-walk"}`,
	// S7.5.3 device health gated ops (enterprise; each still 401s sessionless).
	"puthealthcheck":     `{"mode":"warn"}`,
	"reportdevicehealth": `{"platform":"macos","os_version":"14.0","disk_encrypted":true}`,
	// F09 reusable agent policy templates. Valid inert bodies ensure the walk reaches authentication.
	"setorganizationagentpolicytemplatesenabled": `{"enabled":true}`,
	"createagentgroup":                           `{"name":"Walk"}`,
	"updateagentgroup":                           `{"name":"Walk"}`,
	"addagentgroupmember":                        `{"device_id":"00000000-0000-0000-0000-000000000000"}`,
	"createagentpolicytemplate":                  `{"name":"Walk"}`,
	"updateagentpolicytemplate":                  `{"name":"Walk"}`,
	"createagentpolicytemplateversion":           `{"items":[{"destination_kind":"resource","destination_id":"00000000-0000-0000-0000-000000000000"}]}`,
	"previewagentpolicytemplate":                 `{"group_id":"00000000-0000-0000-0000-000000000000","template_version_id":"00000000-0000-0000-0000-000000000000"}`,
	"applyagentpolicytemplate":                   `{"group_id":"00000000-0000-0000-0000-000000000000","template_version_id":"00000000-0000-0000-0000-000000000000","preview_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotency_key":"walk"}`,
	"createagentmcpprofile":                      `{"name":"Walk MCP","endpoint":"https://mcp.example.test/mcp"}`,
	"assignagentmcpprofile":                      `{"group_id":"00000000-0000-0000-0000-000000000000"}`,
	"replaceagentgroupmcpprofile":                `{"profile_id":"00000000-0000-0000-0000-000000000000"}`,
	"previewagentgroupmcpprofileimpact":          `{}`,
	// F10 JIT agent access. Keep these structurally valid so the spec-driven
	// walk measures authentication rather than request validation.
	"setorganizationagentjitaccessenabled": `{"enabled":true}`,
	"createagentaccessrequest":             `{"device_id":"00000000-0000-0000-0000-000000000000","destination_kind":"resource","destination_id":"00000000-0000-0000-0000-000000000000","duration_seconds":300,"reason":"walk","idempotency_key":"walk-create"}`,
	"approveagentaccessrequest":            `{"idempotency_key":"walk-approve"}`,
	"rejectagentaccessrequest":             `{"reason":"walk","idempotency_key":"walk-reject"}`,
	"cancelagentaccessrequest":             `{"idempotency_key":"walk-cancel"}`,
	"revokeagentaccessrequest":             `{"idempotency_key":"walk-revoke"}`,
}

// Required query tuples serve the same purpose as walkBodies: make the request
// structurally valid so this walk measures authentication rather than the
// generated parameter validator. Keep values inert and non-secret.
var walkQueries = map[string]string{
	"testagentaccess":                         "?destination=192.0.2.10&protocol=tcp&port=443",
	"getagentpolicytemplatedestinationimpact": "?destination_kind=resource&destination_id=00000000-0000-0000-0000-000000000000",
	"deletek8sclusterscope":                   "?expected_revision=1",
}

// TestSessionlessMutationsAre401 walks EVERY operation in the OpenAPI spec and
// asserts that operations requiring auth reject a sessionless request with 401.
// It is spec-driven, so any endpoint a future story adds is covered automatically
// — unless it opts out via `security: []` (the documented public allowlist).
func TestSessionlessRequestsAre401(t *testing.T) {
	swagger, err := api.GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger: %v", err)
	}
	// No AuthFn => no principal is ever attached => every gated op must 401.
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Orgs: tenancy.NewService(nil)})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	srv := httptest.NewServer(router) // real server: faithful body handling
	defer srv.Close()

	checked := 0
	for path, item := range swagger.Paths.Map() {
		for method, op := range item.Operations() {
			public := op.Security != nil && len(*op.Security) == 0
			if public {
				continue
			}
			reqPath := strings.ReplaceAll(path, "{orgId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{provider}", "google")
			reqPath = strings.ReplaceAll(reqPath, "{userId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{nodeId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{gatewayId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{deviceId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{credentialId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{groupId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{resourceId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{ruleId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{siteId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{subnetId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{clusterId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{serviceId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{poolId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{inventoryRef}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{serviceChildId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{checkKind}", "disk_encryption")
			reqPath = strings.ReplaceAll(reqPath, "{templateId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{profileId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{assignmentId}", uuid.NewString())
			reqPath = strings.ReplaceAll(reqPath, "{requestId}", uuid.NewString())

			var body io.Reader
			if b, ok := walkBodies[strings.ToLower(op.OperationID)]; ok {
				body = bytes.NewBufferString(b)
			}
			if query, ok := walkQueries[strings.ToLower(op.OperationID)]; ok {
				reqPath += query
			}
			req, err := http.NewRequest(method, srv.URL+reqPath, body)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			rb, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s (op %s): sessionless status = %d, want 401 — body: %s",
					method, path, op.OperationID, resp.StatusCode, string(rb))
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no gated operations checked — walk is vacuous")
	}
	t.Logf("verified %d gated operations reject sessionless requests with 401", checked)
}
