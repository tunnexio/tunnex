package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The periodic report carries the running agent version so the dashboard does
// not keep showing the version from enrollment or the last certificate renewal.
func TestReportInfoCarriesRunningAgentVersion(t *testing.T) {
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		got = nil
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}); err != nil {
		t.Fatal(err)
	}
	if _, present := got["agent_version"]; present {
		t.Fatal("an unset version must be omitted, not reported as empty")
	}
	c.SetAgentVersion("v0.1.46")
	if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := json.Unmarshal(got["agent_version"], &version); err != nil || version != "v0.1.46" {
		t.Fatalf("agent_version = %q (%v)", version, err)
	}
}
