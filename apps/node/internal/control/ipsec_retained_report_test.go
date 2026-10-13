package control

import (
	"context"
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReportRetainedGuardCapabilityRequiresOpaqueController(t *testing.T) {
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	for _, controller := range []*ipsec.RuntimeController{nil, {}} {
		c.AttachIPsecController(controller)
		if c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}) != nil {
			t.Fatal("report")
		}
		if string(got["ipsec_retained_guard_version"]) != "0" {
			t.Fatal("absent/unqualified runtime advertised successor capability")
		}
	}
}
