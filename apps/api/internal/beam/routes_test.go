package beam

import (
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestRoutesValidationAndDigestIncludesEveryBinding(t *testing.T) {
	root := Target{Protocol: "http", Address: "127.0.0.1", Port: 3000, Routes: []Route{{"/api", Target{Protocol: "https", Address: "::1", Port: 8443}}}}
	if e := ValidateTarget(root); e != nil {
		t.Fatal(e)
	}
	before := digest(root)
	root.Routes[0].Target.Port = 8444
	if before == digest(root) {
		t.Fatal("route target absent from binding digest")
	}
	for _, prefix := range []string{"/", "/api/", "//api", "/api/../admin", "/api%2fadmin", "http://localhost"} {
		root.Routes[0].PathPrefix = prefix
		if ValidateTarget(root) == nil {
			t.Fatalf("accepted%q", prefix)
		}
	}
}
func TestRoutedShareRefusesLegacyConnectorBeforeIssuance(t *testing.T) {
	f := newFixture(t)
	root := Target{Protocol: "http", Address: "127.0.0.1", Port: 3000, Routes: []Route{{"/api", Target{Protocol: "http", Address: "127.0.0.1", Port: 8080}}}}
	share, e := f.s.Create(f.ctx, f.org, f.a, CreateInput{Name: "Routed", Target: root, Duration: 120, Grants: []Grant{{"user", f.reviewer}}, IdempotencyKey: uuid.New()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.IssueConnector(f.ctx, f.org, share.ID, f.a, ConnectorInput{ExpectedVersion: share.Version, CSR: "invalid"}); e == nil || !strings.Contains(e.Error(), "path_routes_v1") {
		t.Fatalf("legacy connector should fail capability gate, got %v", e)
	}
	// Invalid CSR remains refused even with capability; capability never grants authority.
	if _, e := f.s.IssueConnector(f.ctx, f.org, share.ID, f.a, ConnectorInput{ExpectedVersion: share.Version, CSR: "invalid", Capabilities: []string{"path_routes_v1"}}); e == nil {
		t.Fatal("capability bypassed CSR verification")
	}
}
