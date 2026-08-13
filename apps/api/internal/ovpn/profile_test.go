package ovpn

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/ovpnca"
)

// TestBuildProfileInlineAndServerPinned (S9.1 Slice 4b) locks the .ovpn shape: a standard client can
// import it (inline ca/cert/key), the gateway remote is set, and remote-cert-tls server pins the
// server-auth EKU so a client cert can't impersonate the gateway.
func TestBuildProfileInlineAndServerPinned(t *testing.T) {
	p := ovpnca.Profile{
		CertPEM:       "-----BEGIN CERTIFICATE-----\nCLIENTCERT\n-----END CERTIFICATE-----\n",
		PrivateKeyPEM: "-----BEGIN RSA PRIVATE KEY-----\nCLIENTKEY\n-----END RSA PRIVATE KEY-----\n",
	}
	out := BuildProfile("-----BEGIN CERTIFICATE-----\nCACERT\n-----END CERTIFICATE-----\n", p, []string{"gw.example.com"}, 1194)

	for _, want := range []string{
		"client\n", "remote gw.example.com 1194\n", "remote-cert-tls server\n",
		// WF-OVPN-walk-4: the minted profile MUST carry the low connect-timeout so a dead primary
		// is abandoned in seconds, not the 120s default (bounds client-side failover re-home).
		"connect-timeout 10\n",
		"<ca>\n", "CACERT", "</ca>\n",
		"<cert>\n", "CLIENTCERT", "</cert>\n",
		"<key>\n", "CLIENTKEY", "</key>\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("profile missing %q; got:\n%s", want, out)
		}
	}
	// the inline material must be the ACTUAL key/cert (the one-time-delivered secret), not a placeholder.
	if !strings.Contains(out, "CLIENTKEY") {
		t.Fatal("the client private key must be inlined (delivered once)")
	}
}

// TestBuildProfileMultiRemote is the WF-OVPN-9 Part-A red: a hub-set device's profile lists EVERY member as
// a `remote` in the given PRIORITY ORDER (OpenVPN's native client-side failover), each on the OVPN port.
func TestBuildProfileMultiRemote(t *testing.T) {
	p := ovpnca.Profile{CertPEM: "c", PrivateKeyPEM: "k"}
	out := BuildProfile("ca", p, []string{"hub1.example", "hub2.example", "hub3.example"}, 1194)
	// all three, in order, on the OVPN port.
	want := "remote hub1.example 1194\nremote hub2.example 1194\nremote hub3.example 1194\n"
	if !strings.Contains(out, want) {
		t.Fatalf("multi-remote profile must list every member in priority order:\n%s", out)
	}
}
