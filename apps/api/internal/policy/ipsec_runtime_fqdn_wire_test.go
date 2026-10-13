package policy

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// Reuse the donor's private file bridge between the independent API/node modules.
// Both the committed generation and lowered grant come from the real compilers.
func TestIPsecFQDNCompilerProducesNodeWire(t *testing.T) {
	path := os.Getenv("TUNNEX_FQDN_TEST_WIRE_PATH")
	if path == "" {
		t.Skip("run paired compiler-to-node qualification")
	}
	snapshot, input := runtimeFQDNFixture(t)
	snapshot.FQDNResources[0].Active.ValidUntil = time.Now().UTC().Add(time.Minute)
	p, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(p.FQDNGrants) != 1 {
		t.Fatal("compiler did not produce one scoped grant", err)
	}
	compiled := Compile(snapshot)[input.NodeID]
	if len(compiled.FQDNGenerations) != 1 || len(compiled.FQDNGenerations[0].Answers) != 1 || compiled.FQDNGenerations[0].Answers[0] != p.FQDNGrants[0].Destination {
		t.Fatal("ordinary compiler and runtime lowering disagree on canonical host")
	}
	// Desired resolver profiles are a separate configured projection. Use its
	// existing API projection, without synthesizing or rewriting generation Answers.
	active := snapshot.FQDNResources[0].Active
	declared := dnsProfileFixture()
	declared.Profile.ContextConfigID = active.ResolverConfigID.String()
	declared.Profile.ContextConfigVersion = active.ResolverConfigVersion
	declared.Profile.ProfileID = active.ResolverProfileID.String()
	declared.Profile.ZoneSuffixes = []string{active.ResolverMatchSuffix}
	declared.Profile.IPsecPath = policyspec.DNSResolverIPsecPath{ConnectionID: input.ConnectionID.String(), ConfigurationRevision: input.ConfigurationRevision, SourceAddress: "10.84.2.254"}
	compiled.DNSResolverProfiles = []policyspec.DNSResolverProfile{DNSProfileForAllowedTraffic(declared, compiled.Allow)}
	wire := struct {
		Policy                              ipsec.RuntimePolicy `json:"policy"`
		Compiled                            policyspec.Compiled `json:"compiled"`
		CanonicalHash                       string              `json:"canonical_hash"`
		OrgID, NodeID, SiteID, ConnectionID uuid.UUID
		Local, Remote                       []string
	}{p, compiled, policyspec.CanonicalHash(compiled), input.OrgID, input.NodeID, input.SiteID, input.ConnectionID, input.Config.LocalPrefixes, input.Config.RemotePrefixes}
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
