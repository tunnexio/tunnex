package ownershiplease

import (
	"reflect"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestProjectorPreservesPrivateDNSIdentityAndSnapshots(t *testing.T) {
	base := projectorBase()
	base.DNSResolveRequest.ResolverIPsecPath = &fqdnrpc.IPsecPath{ConnectionID: "connection-a", ConfigurationRevision: 3, SourceAddress: "10.84.2.254"}
	base.Policy.DNSResolverProfiles = []nodepolicy.DNSResolverProfile{{ContextConfigID: "config-a", ContextConfigVersion: 4, ProfileID: "profile-a", ZoneSuffixes: []string{"s2s-qa.tunnex.test"}, Endpoints: []nodepolicy.DNSResolverEndpoint{{Address: "10.85.2.24", Port: 53, Transport: "udp"}}, IPsecPath: nodepolicy.DNSResolverIPsecPath{ConnectionID: "connection-a", ConfigurationRevision: 3, SourceAddress: "10.84.2.254"}, AllowedSources: []string{"10.99.0.2/32"}}}
	base.Policy.DNSResolverProfiles[0].LANListener = &nodepolicy.DNSLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1"}}
	want := cloneDesiredState(base)
	p := NewProjector()
	if err := p.UpdateBase(base); err != nil {
		t.Fatal(err)
	}
	base.DNSResolveRequest.ResolverIPsecPath.SourceAddress = "198.51.100.1"
	base.Policy.DNSResolverProfiles[0].ZoneSuffixes[0] = "public.test"
	base.Policy.DNSResolverProfiles[0].Endpoints[0].Address = "8.8.8.8"
	base.Policy.DNSResolverProfiles[0].AllowedSources[0] = "0.0.0.0/0"
	base.Policy.DNSResolverProfiles[0].LANListener.DefaultUpstreams[0] = "8.8.8.8"
	if err := p.SetOwnership(projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	got, found, err := p.Snapshot()
	if err != nil || !found || !reflect.DeepEqual(got.Policy.DNSResolverProfiles, want.Policy.DNSResolverProfiles) || !reflect.DeepEqual(got.DNSResolveRequest.ResolverIPsecPath, want.DNSResolveRequest.ResolverIPsecPath) {
		t.Fatal("private DNS source or identity mutated across ownership projection", err)
	}
	got.Policy.DNSResolverProfiles[0].AllowedSources[0] = "0.0.0.0/0"
	got.Policy.DNSResolverProfiles[0].LANListener.DefaultUpstreams[0] = "9.9.9.9"
	got.DNSResolveRequest.ResolverIPsecPath.ConfigurationRevision++
	again, _, err := p.Snapshot()
	if err != nil || !reflect.DeepEqual(again.Policy.DNSResolverProfiles, want.Policy.DNSResolverProfiles) || !reflect.DeepEqual(again.DNSResolveRequest.ResolverIPsecPath, want.DNSResolveRequest.ResolverIPsecPath) {
		t.Fatal("returned snapshot rewrote private DNS authority", err)
	}
}
