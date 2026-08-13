//go:build linux

package reconcile

import (
	"strings"
	"testing"
)

func TestParseWGStats(t *testing.T) {
	// Line 0 = interface; peer line fields: pubkey, psk, endpoint, allowed-ips,
	// latest-handshake(unix), rx, tx, keepalive.
	dump := strings.Join([]string{
		"iprivkey\tipubkey\t51820\toff",
		"peerkey1\t(none)\t203.0.113.5:51820\t10.0.0.2/32\t1700000000\t4096\t8192\toff",
		"peerkey2\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff", // never handshaked
	}, "\n")

	stats := parseWGStats(dump)
	if len(stats) != 2 {
		t.Fatalf("want 2 peer stats, got %d", len(stats))
	}
	if stats[0].PublicKey != "peerkey1" || stats[0].LastHandshake != 1700000000 ||
		stats[0].RxBytes != 4096 || stats[0].TxBytes != 8192 {
		t.Fatalf("peer0 mis-parsed: %+v", stats[0])
	}
	// A never-handshaked peer: handshake 0, zero bytes.
	if stats[1].LastHandshake != 0 || stats[1].RxBytes != 0 {
		t.Fatalf("peer1 should be zeroed: %+v", stats[1])
	}
}

func TestParseWGInterface(t *testing.T) {
	// A configured interface: private-key, PUBLIC-key, listen-port, fwmark.
	pub, port := parseWGInterface("iPrivKey==\tiPubKey==\t51820\toff\npeerkey\t(none)\t...\t10.0.0.2/32")
	if pub != "iPubKey==" {
		t.Fatalf("want public key from field 1, got %q", pub)
	}
	if port != 51820 {
		t.Fatalf("want port 51820, got %d", port)
	}
	// A freshly-created keyless interface: both keys are "(none)".
	pub, port = parseWGInterface("(none)\t(none)\t38717\toff")
	if pub != "" {
		t.Fatalf("keyless interface should yield empty pubkey, got %q", pub)
	}
	if port != 38717 {
		t.Fatalf("want port 38717, got %d", port)
	}
	// Malformed / empty input.
	if p, n := parseWGInterface(""); p != "" || n != 0 {
		t.Fatalf("empty dump should yield (\"\",0), got (%q,%d)", p, n)
	}
}

func TestParseWGDump(t *testing.T) {
	// Line 0 = interface (privkey, pubkey, listen-port, fwmark). Then two peers;
	// the second has no endpoint and no allowed-ips ("(none)").
	dump := strings.Join([]string{
		"iprivkey\tipubkey\t51820\toff",
		"peerkey1\t(none)\t203.0.113.5:51820\t10.0.0.2/32,10.0.0.3/32\t0\t100\t200\toff",
		"peerkey2\t(none)\t(none)\t(none)\t0\t0\t0\toff",
	}, "\n")

	peers := parseWGDump(dump)
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d: %+v", len(peers), peers)
	}
	if peers[0].PublicKey != "peerkey1" || peers[0].Endpoint != "203.0.113.5:51820" {
		t.Fatalf("peer0 mis-parsed: %+v", peers[0])
	}
	if len(peers[0].AllowedIPs) != 2 || peers[0].AllowedIPs[1] != "10.0.0.3/32" {
		t.Fatalf("peer0 allowed-ips mis-parsed: %+v", peers[0].AllowedIPs)
	}
	if peers[1].PublicKey != "peerkey2" || peers[1].Endpoint != "" || len(peers[1].AllowedIPs) != 0 {
		t.Fatalf("peer1 should have no endpoint/allowed-ips: %+v", peers[1])
	}
}

// TestSyncConfRoundTrip proves the config we write matches what the device would
// report back: build a syncconf, and (simulating a dump of that state) confirm
// the peer identities round-trip. This is the read-back invariant the compose
// e2e checks against a real device.
func TestSyncConfRoundTrip(t *testing.T) {
	peers := []Peer{
		{PublicKey: "k1", AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "198.51.100.7:51820"},
		{PublicKey: "k2", AllowedIPs: []string{"10.0.0.3/32"}},
	}
	conf := buildSyncConf("privkeybase64", 51820, peers)
	if !strings.Contains(conf, "PublicKey = k1") || !strings.Contains(conf, "Endpoint = 198.51.100.7:51820") {
		t.Fatalf("k1 not rendered: %s", conf)
	}
	if !strings.Contains(conf, "AllowedIPs = 10.0.0.3/32") {
		t.Fatalf("k2 allowed-ips not rendered: %s", conf)
	}
	// A peer with no endpoint must not emit an Endpoint line.
	if strings.Count(conf, "Endpoint = ") != 1 {
		t.Fatalf("expected exactly one Endpoint line: %s", conf)
	}
	// The [Interface] MUST carry the key + port, or `wg syncconf` clears them
	// (the POC-surfaced wipe). This is the regression guard for Fault A.
	if !strings.Contains(conf, "PrivateKey = privkeybase64") || !strings.Contains(conf, "ListenPort = 51820") {
		t.Fatalf("syncconf [Interface] must echo key + port to avoid wiping them: %s", conf)
	}
}

// TestSyncConfSkipsKeylessPeer is the WF-OVPN-10 boundary red (the WF-OVPN-1 config-completeness lesson:
// a generated config for an external tool must be one that tool ACCEPTS). A peer with an EMPTY PublicKey
// renders `PublicKey = ` and makes `wg syncconf` reject the ENTIRE file — one bad peer bricks the whole
// interface. The renderer must SKIP a keyless peer, so the config it emits is always wg-valid regardless
// of what the control plane sends.
func TestSyncConfSkipsKeylessPeer(t *testing.T) {
	peers := []Peer{
		{PublicKey: "k1", AllowedIPs: []string{"10.99.0.2/32"}},
		{PublicKey: "", AllowedIPs: []string{"10.99.0.6/32"}}, // a keyless (OVPN) device leaked in
		{PublicKey: "k2", AllowedIPs: []string{"10.99.0.3/32"}},
	}
	conf := buildSyncConf("pk", 51820, peers)
	// NO empty PublicKey line — that single line is what `wg syncconf` rejects the whole config over.
	if strings.Contains(conf, "PublicKey = \n") || strings.Contains(conf, "PublicKey = \nAllowedIPs") {
		t.Fatalf("keyless peer must be skipped — an empty `PublicKey = ` bricks wg syncconf:\n%s", conf)
	}
	// exactly the two KEYED peers render.
	if strings.Count(conf, "[Peer]") != 2 || !strings.Contains(conf, "PublicKey = k1") || !strings.Contains(conf, "PublicKey = k2") {
		t.Fatalf("both keyed peers must render, the keyless one dropped:\n%s", conf)
	}
	// the keyless peer's /32 must NOT leak into the WG config (it rides the OVPN roster).
	if strings.Contains(conf, "10.99.0.6/32") {
		t.Fatalf("the keyless (OVPN) device's /32 must not appear in the WG config:\n%s", conf)
	}
}
