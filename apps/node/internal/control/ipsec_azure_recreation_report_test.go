package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type azureRecreationQualifiedVersion int

func (v azureRecreationQualifiedVersion) AzureBGPRecreationCapability() int { return int(v) }

// Existing capability methods cannot opt an old implementation into the new protocol.
type azureRecreationOldRuntime struct{}

func (azureRecreationOldRuntime) AzureCapability() int         { return 1 }
func (azureRecreationOldRuntime) BGPCapability() int           { return 1 }
func (azureRecreationOldRuntime) RetainedGuardCapability() int { return 1 }
func (azureRecreationOldRuntime) GCPHACapability() int         { return 1 }

func TestAzureBGPRecreationVersionIsExplicitAndExact(t *testing.T) {
	for _, tc := range []struct {
		runtime any
		want    int
	}{
		{nil, 0}, {azureRecreationOldRuntime{}, 0},
		{azureRecreationQualifiedVersion(0), 0}, {azureRecreationQualifiedVersion(1), 1},
		{azureRecreationQualifiedVersion(2), 0}, {azureRecreationQualifiedVersion(-1), 0},
	} {
		if got := azureBGPRecreationVersion(tc.runtime); got != tc.want {
			t.Fatalf("version %d, want %d", got, tc.want)
		}
	}
}

func TestAzureBGPRecreationReportOmitsAbsentOrUnqualifiedRuntime(t *testing.T) {
	if (*Client)(nil).ipsecAzureBGPRecreationCapability() != 0 {
		t.Fatal("nil client advertised")
	}
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	for _, controller := range []*ipsec.RuntimeController{nil, {}} {
		c.AttachIPsecController(controller)
		if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := got["ipsec_azure_bgp_recreation_version"]; ok {
			t.Fatal("unqualified runtime opted into Azure BGP recreation")
		}
	}
}
