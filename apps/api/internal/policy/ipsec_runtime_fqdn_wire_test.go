package policy

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

// The explicit private path connects the two independent Go modules without
// importing an internal node package or inventing the compiler's wire output.
func TestIPsecFQDNCompilerProducesNodeWire(t *testing.T) {
	path := os.Getenv("TUNNEX_FQDN_TEST_WIRE_PATH")
	if path == "" {
		t.Skip("run paired compiler-to-node qualification with a fresh private fixture path")
	}
	for _, version := range []int{1, 2} {
		file := path
		if version == 2 {
			file += ".v2"
		}
		snapshot, input := runtimeFQDNFixture(t)
		input.FQDNPolicyVersion = version
		snapshot.FQDNResources[0].Active.FreshUntil = time.Now().UTC().Add(time.Minute)
		p, err := compileIPsecRuntimePolicy(snapshot, input)
		if err != nil || len(p.FQDNGrants) != 1 {
			t.Fatal("compiler did not produce one scoped grant", err)
		}
		wire := struct {
			Policy                              ipsec.RuntimePolicy `json:"policy"`
			OrgID, NodeID, SiteID, ConnectionID uuid.UUID
			Local, Remote                       []string
		}{p, input.OrgID, input.NodeID, input.SiteID, input.ConnectionID, input.Config.LocalPrefixes, input.Config.RemotePrefixes}
		b, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(b); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}

	}
}
