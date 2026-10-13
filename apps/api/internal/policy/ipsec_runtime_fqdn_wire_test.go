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
		compiled := Compile(snapshot)[input.NodeID]
		if len(compiled.FQDNGenerations) != 1 || len(compiled.FQDNGenerations[0].Answers) != 1 || compiled.FQDNGenerations[0].Answers[0] != p.FQDNGrants[0].Destination {
			t.Fatal("ordinary compiler and runtime lowering disagree on canonical host")
		}
		// Resolver profiles are a separate configured projection. Use the existing
		// projection without synthesizing or rewriting the compiler's Answers.
		active := snapshot.FQDNResources[0].Active
		declared := dnsProfileFixture()
		declared.Profile.ContextConfigID = active.ResolverConfigID.String()
		declared.Profile.ContextConfigVersion = active.ResolverConfigVersion
		declared.Profile.ProfileID = active.ResolverProfileID.String()
		declared.Profile.ZoneSuffixes = []string{active.ResolverMatchSuffix}
		declared.Profile.IPsecPath = policyspec.DNSResolverIPsecPath{ConnectionID: input.ConnectionID.String(), ConfigurationRevision: input.ConfigurationRevision, SourceAddress: active.IPsecSourceAddress}
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
