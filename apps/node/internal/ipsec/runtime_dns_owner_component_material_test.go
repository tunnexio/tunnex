package ipsec

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// Preparation only, no networking. Writes fresh disposable credentials to a new
// private directory, never stdout; the caller supplies the owned native peers.
func TestDNSOwnerViewGCPComponentPrepare(t *testing.T) {
	directory := os.Getenv("TUNNEX_GCP_DNS_OWNER_PREPARE_DIR")
	if directory == "" {
		t.Skip("explicit private fixture preparation only")
	}
	if !filepath.IsAbs(directory) {
		t.Fatal("absolute new private directory required")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("new private directory required", err)
	}
	value := func(name, fallback string) string {
		if text := os.Getenv(name); text != "" {
			return text
		}
		return fallback
	}
	local, err := netip.ParsePrefix(value("TUNNEX_GCP_DNS_OWNER_LOCAL_PREFIX", "10.86.0.0/24"))
	if err != nil || !local.Addr().Is4() || !local.Addr().IsPrivate() || local.Bits() != 24 || local != local.Masked() {
		t.Fatal("exact private IPv4 local /24 required")
	}
	remote, err := netip.ParsePrefix(value("TUNNEX_GCP_DNS_OWNER_REMOTE_PREFIX", "10.87.0.0/24"))
	if err != nil || !remote.Addr().Is4() || !remote.Addr().IsPrivate() || remote.Bits() != 24 || remote != remote.Masked() || local.Overlaps(remote) {
		t.Fatal("disjoint private IPv4 remote /24 required")
	}
	source, err := netip.ParseAddr(value("TUNNEX_GCP_DNS_OWNER_SOURCE", "10.86.0.1"))
	if err != nil || !local.Contains(source) || source == local.Addr() || source == netip.AddrFrom4([4]byte{local.Addr().As4()[0], local.Addr().As4()[1], local.Addr().As4()[2], 255}) {
		t.Fatal("assigned local host source required")
	}
	resolver, err := netip.ParseAddr(value("TUNNEX_GCP_DNS_OWNER_RESOLVER", "10.87.0.53"))
	if err != nil || !remote.Contains(resolver) || resolver == remote.Addr() || resolver == netip.AddrFrom4([4]byte{remote.Addr().As4()[0], remote.Addr().As4()[1], remote.Addr().As4()[2], 255}) {
		t.Fatal("owned remote host resolver required")
	}
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	outside := make([]netip.Addr, 3)
	for i, item := range []struct{ name, fallback string }{{"TUNNEX_GCP_DNS_OWNER_GATEWAY_OUTSIDE", "198.18.222.10"}, {"TUNNEX_GCP_DNS_OWNER_PEER_OUTSIDE_1", "198.18.222.20"}, {"TUNNEX_GCP_DNS_OWNER_PEER_OUTSIDE_2", "198.18.222.21"}} {
		address, err := netip.ParseAddr(value(item.name, item.fallback))
		if err != nil || !address.Is4() || !(address.IsPrivate() || benchmark.Contains(address)) || address.As4()[3] == 0 || address.As4()[3] == 255 {
			t.Fatal("private or benchmark component underlay host required")
		}
		outside[i] = address
		for j := 0; j < i; j++ {
			if address == outside[j] || netip.PrefixFrom(address, 24).Masked() != netip.PrefixFrom(outside[j], 24).Masked() {
				t.Fatal("distinct component hosts in one underlay /24 required")
			}
		}
		if local.Contains(address) || remote.Contains(address) {
			t.Fatal("underlay cannot overlap component LAN")
		}
	}
	for _, profile := range []string{GCPClassicStaticProfile, GCPHABGPProfile} {
		m := classicMaterialFixture()
		if profile == GCPHABGPProfile {
			m = gcpMaterialFixture()
		}
		count, err := runtimeMaterialTransportContract(m)
		if err != nil {
			t.Fatal(err)
		}
		m.Manifest.LocalPrefixes = []string{local.String()}
		m.Manifest.RemotePrefixes = []string{remote.String()}
		if m.Manifest.BGP != nil {
			m.Manifest.BGP.RouterID = source.String()
		}
		m.Manifest.CustomerOutsideAddress = outside[0].String()
		for i := 0; i < count; i++ {
			m.Manifest.Tunnels[i].OutsideAddress = outside[i+1].String()
			secret := make([]byte, 16)
			if _, err = rand.Read(secret); err != nil {
				t.Fatal("disposable entropy unavailable")
			}
			m.Secrets[i].PSK = "0-" + hex.EncodeToString(secret)
		}
		m.Policy.Grants = nil
		m.Policy.DNSResolverGrants = []RuntimeDNSResolverGrant{{ContextConfigID: uuid.New(), ContextConfigVersion: 1, ProfileID: uuid.New(), ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, SourceAddress: source.String(), ResolverAddress: resolver.String()}}
		runtimeReseal(&m)
		if _, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err != nil {
			t.Fatal("generated component material invalid", err)
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, profile+".json"), append(raw, '\n'), 0600); err != nil {
			t.Fatal("private material write refused", err)
		}
	}
}
