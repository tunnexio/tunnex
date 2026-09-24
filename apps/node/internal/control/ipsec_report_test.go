package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type ipsecReportTransport func(*http.Request) (*http.Response, error)

func (f ipsecReportTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestReportInfoExplicitlyRefusesIPsecRuntime(t *testing.T) {
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/report" {
			t.Fatal("wrong report endpoint")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	if err := c.ReportInfo(context.Background(), "public-key", "", false, false, PolicyStatus{Version: 1, MaxSupportedVersion: 99, DNSResolveRPCVersion: 1}); err != nil {
		t.Fatal(err)
	}
	version, ok := got["ipsec_config_version"]
	if !ok || string(version) != "0" {
		t.Fatalf("runtime must explicitly report IPsec unsupported, got %s", version)
	}
	if _, exists := got["ipsec_reported_at"]; exists {
		t.Fatal("agent cannot choose capability receipt time")
	}
}
