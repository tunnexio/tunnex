package http

import (
	"crypto/tls"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

func TestAppAccessAgentWireMatchesDeclaredSchemas(t *testing.T) {
	loader := openapi3.NewLoader()
	spec, err := loader.LoadFromFile("../../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"AppAccessAssignment": appAccessAssignmentWire{}, "AppAccessGatewayDesired": appAccessDesiredWire{}, "AppAccessGatewayResult": appAccessResultWire{}, "AppAccessGatewayApplied": appAccessAppliedWire{}, "AppAccessGatewayCapabilityInput": appAccessCapabilityWire{}, "AppProxyRouteBinding": appProxyBindingWire{}, "AppProxyRouteLookupInput": appProxyLookupWire{}, "AppProxyRequestMetadata": appProxyMetadataWire{}, "AppProxyAuthorizeInput": appProxyAuthorizeWire{}, "AppProxyLeaseInput": appProxyLeaseWire{}, "AppProxyChannelInput": appProxyChannelWire{}, "AppProxyRoute": appProxyRouteWire{}, "AppProxyStreamTerminatedInput": appProxyTerminatedWire{}, "AppProxyRedeemInput": appProxyRedeemWire{}, "AppProxyRedeemResult": appProxyRedeemResultWire{}, "AppProxyPendingLaunchInput": appProxyPendingWire{}, "AppProxyPendingLaunchResult": appProxyExpiryWire{}, "AppProxyAuthorityDecision": appProxyDecisionWire{}, "AppProxyReadinessClaimInput": appProxyReadinessClaimWire{}, "AppProxyReadinessClaimResult": appProxyReadinessClaimResultWire{}, "AppProxyReadinessWork": appProxyReadinessWorkWire{}, "AppProxyReadinessReportInput": appProxyReadinessReportWire{}, "AppProxyReadinessReportResult": appProxyReadinessReportResultWire{}, "AppProxyBrowserDesired": appAccessBrowserDesiredWire{}, "AppProxyBrowserAssignment": appAccessBrowserAssignmentWire{}} {
		t.Run(name, func(t *testing.T) {
			schema := spec.Components.Schemas[name].Value
			kind := reflect.TypeOf(value)
			fields := map[string]bool{}
			var collectFields func(reflect.Type)
			collectFields = func(kind reflect.Type) {
				for i := 0; i < kind.NumField(); i++ {
					f := kind.Field(i)
					tag := strings.Split(f.Tag.Get("json"), ",")[0]
					if f.Anonymous && tag == "" {
						collectFields(f.Type)
					} else {
						fields[tag] = true
					}
				}
			}
			collectFields(kind)
			properties := map[string]bool{}
			var collectSchema func(*openapi3.Schema)
			collectSchema = func(v *openapi3.Schema) {
				for name := range v.Properties {
					properties[name] = true
				}
				for _, part := range v.AllOf {
					collectSchema(part.Value)
				}
			}
			collectSchema(schema)
			if len(fields) != len(properties) {
				t.Fatalf("wire fields %v differ from schema properties %v", fields, schema.Properties)
			}
			for name := range properties {
				if !fields[name] {
					t.Fatalf("schema field %s missing in wire", name)
				}
			}
			for _, name := range schema.Required {
				if !fields[name] {
					t.Fatalf("required field %s missing", name)
				}
			}
		})
	}
	// The generated browser router must never mount the private agent surface.
	browser, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	for path := range browser.Paths.Map() {
		if strings.HasPrefix(path, "/agent/") || strings.HasPrefix(path, "/internal/app-access/") {
			t.Fatalf("private agent route mounted in browser contract: %s", path)
		}
	}
}
func TestAppAccessAgentStrictBoundedDecoder(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"valid", `{"protocol_version":1}`, 200},
		{"forged org", `{"protocol_version":1,"org_id":"foreign"}`, 400},
		{"second object", `{"protocol_version":1}{"protocol_version":1}`, 400},
		{"oversized", `{"protocol_version":1,"padding":"` + strings.Repeat("x", 8192) + `"}`, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/agent/app-access/capability", strings.NewReader(tc.body))
			response := httptest.NewRecorder()
			var wire appAccessCapabilityWire
			ok := decodeAppAccessAgent(response, request, &wire)
			if response.Code != tc.code || ok != (tc.code == 200) {
				t.Fatalf("decode status%d ok%v", response.Code, ok)
			}
		})
	}
}
func TestAppAccessAgentEndpointsRequireCertificateBeforeService(t *testing.T) {
	channel := &AgentChannel{}
	for _, route := range []struct{ method, path string }{
		{"GET", "/agent/app-access/desired-state"}, {"GET", "/agent/app-access/browser-desired-state"}, {"POST", "/agent/app-access/capability"}, {"POST", "/agent/app-access/report"}, {"POST", "/agent/app-access/checks/00000000-0000-4000-8000-000000000001/result"},
	} {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		channel.Handler().ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatalf("%s got%d", route.path, response.Code)
		}
	}
}
func TestAppAccessOriginPolicyPatchPresence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cidrs   *[]string
		ca      *string
		present bool
	}{
		{name: "omitted"}, {name: "explicit clear", cidrs: ptrStrings([]string{}), ca: ptrString(""), present: true},
		{name: "explicit private network", cidrs: ptrStrings([]string{"10.0.0.0/8"}), ca: ptrString("public CA fixture"), present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input appaccess.DraftInput
			appAccessOriginPolicy(&input, tc.cidrs, tc.ca)
			if input.AllowedDestinationCIDRsSet != tc.present || input.OriginCAPEMSet != tc.present {
				t.Fatalf("policy presence lost %#v", input)
			}
			if tc.cidrs != nil && !reflect.DeepEqual(input.AllowedDestinationCIDRs, *tc.cidrs) {
				t.Fatal("explicit policy lost")
			}
		})
	}
}
func ptrStrings(value []string) *[]string { return &value }
func ptrString(value string) *string      { return &value }

func TestAppAccessProbeResultKeepsStagesAndSafeFailureCodes(t *testing.T) {
	check := appaccess.Check{ID: uuid.New(), AppID: uuid.New(), Generation: uuid.New(), Revision: 4, Digest: strings.Repeat("a", 64), Purpose: "origin_check"}
	for _, tc := range []struct{ status, dns, connect, tls, code, wantDNS, wantConnect, wantTLS string }{
		{"ready", "ready", "ready", "ready", "", "passed", "passed", "passed"},
		{"ready", "ready", "ready", "not_required", "", "passed", "passed", "skipped"},
		{"http_failed", "ready", "ready", "ready", "http_failed", "passed", "passed", "passed"},
		{"dns_refused", "failed", "not_checked", "not_checked", "dns_failed", "failed", "pending", "pending"},
		{"dns_refused", "refused", "not_checked", "not_checked", "target_refused", "failed", "pending", "pending"},
		{"origin_refused", "ready", "not_checked", "not_checked", "target_refused", "passed", "pending", "pending"},
		{"timeout", "not_checked", "not_checked", "not_checked", "deadline_exceeded", "pending", "pending", "pending"},
	} {
		t.Run(tc.status+tc.tls, func(t *testing.T) {
			out := appAccessProbeResult(check, originpolicy.Result{Status: tc.status, DNS: tc.dns, Connect: tc.connect, TLS: tc.tls})
			if out.RequestID != check.ID || out.Generation != check.Generation || out.Digest != check.Digest || out.ErrorCode != tc.code || out.DNSStatus != tc.wantDNS || out.ConnectStatus != tc.wantConnect || out.TLSStatus != tc.wantTLS {
				t.Fatalf("wrong exact correlated diagnostic %#v", out)
			}
		})
	}
}

func TestAppAccessChannelRequiresTLS13BeforeAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  *tls.ConnectionState
		code int
	}{
		{"absent", nil, 401}, {"downgrade", &tls.ConnectionState{Version: tls.VersionTLS12}, 403}, {"TLS13 without certificate", &tls.ConnectionState{Version: tls.VersionTLS13}, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("CONNECT", "/agent/app-access/channel", nil)
			request.TLS = tc.tls
			response := httptest.NewRecorder()
			(&AgentChannel{}).Handler().ServeHTTP(response, request)
			if response.Code != tc.code {
				t.Fatalf("channel admission status%d want%d", response.Code, tc.code)
			}
		})
	}
}
