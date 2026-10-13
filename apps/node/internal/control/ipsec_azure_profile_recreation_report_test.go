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

type azureProfileRecreationQualifiedVersion int

func (v azureProfileRecreationQualifiedVersion) AzureProfileRecreationCapability() int { return int(v) }

// Existing capability methods cannot opt an old implementation into the new protocol.
type azureProfileRecreationOldRuntime struct{}

func (azureProfileRecreationOldRuntime) AzureCapability() int              { return 1 }
func (azureProfileRecreationOldRuntime) BGPCapability() int                { return 1 }
func (azureProfileRecreationOldRuntime) RetainedGuardCapability() int      { return 1 }
func (azureProfileRecreationOldRuntime) AzureBGPRecreationCapability() int { return 1 }
func (azureProfileRecreationOldRuntime) GCPHACapability() int              { return 1 }

func TestAzureProfileRecreationVersionIsExplicitAndExact(t *testing.T) {
	for _, tc := range []struct {
		runtime any
		want    int
	}{
		{nil, 0}, {azureProfileRecreationOldRuntime{}, 0},
		{azureProfileRecreationQualifiedVersion(0), 0}, {azureProfileRecreationQualifiedVersion(1), 1},
		{azureProfileRecreationQualifiedVersion(2), 0}, {azureProfileRecreationQualifiedVersion(-1), 0},
	} {
		if got := azureProfileRecreationVersion(tc.runtime); got != tc.want {
			t.Fatalf("version %d, want %d", got, tc.want)
		}
	}
}

func TestAzureProfileRecreationReportOmitsAbsentOrUnqualifiedRuntime(t *testing.T) {
	if (*Client)(nil).ipsecAzureProfileRecreationCapability() != 0 {
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
		if _, ok := got["ipsec_azure_profile_recreation_version"]; ok {
			t.Fatal("unqualified runtime opted into Azure profile recreation")
		}
	}
}
