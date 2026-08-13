//go:build darwin || windows

package helper

import (
	"strings"
	"testing"
)

// TestAllowedIPsUAPINoBounce (S8.5 Slice 2a) — the live-apply uapi carries NO private_key / replace_peers /
// endpoint (so the device + peer identity + the session/handshake SURVIVE — no bounce, by construction) and
// DOES carry update_only=true (an absent peer is never CREATED — a typo can't conjure a phantom peer) +
// replace_allowed_ips=true (full-sweep) + the allowed_ip lines. Lives in a darwin||windows-tagged file
// because allowedIPsUAPI (wgcommon.go) is only compiled on the real-backend platforms.
func TestAllowedIPsUAPINoBounce(t *testing.T) {
	const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	uapi, err := allowedIPsUAPI(zeroKey, []string{"10.0.0.0/16", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, must := range []string{"update_only=true", "replace_allowed_ips=true", "allowed_ip=10.0.0.0/16", "allowed_ip=192.168.1.0/24"} {
		if !strings.Contains(uapi, must) {
			t.Errorf("uapi missing %q:\n%s", must, uapi)
		}
	}
	for _, forbidden := range []string{"private_key=", "replace_peers=", "endpoint="} {
		if strings.Contains(uapi, forbidden) {
			t.Errorf("uapi MUST NOT contain %q (would reset the peer/session — a bounce):\n%s", forbidden, uapi)
		}
	}
}

// TestGatewayPeerSwapUAPI (WF-A) — the re-home uapi is a peer SWAP that PRESERVES the device identity: it
// ADDS the new peer (its key + endpoint + keepalive + the CURRENT allowed_ips) BEFORE it REMOVES the old
// (add-before-remove so the routing is never momentarily unowned), and carries NO private_key / replace_peers
// (the device's own key + the interface + the kill-switch are untouched — the session survives, no
// re-enrollment). The old peer's key appears with remove=true; the new peer inherits the allowed_ips.
func TestGatewayPeerSwapUAPI(t *testing.T) {
	const oldKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const newKey = "bBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	uapi, err := gatewayPeerSwapUAPI(oldKey, newKey, "gw-b.example:51820", 25, []string{"10.99.0.0/24", "192.168.5.0/24"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	oldHex, _ := b64ToHex(oldKey)
	newHex, _ := b64ToHex(newKey)
	for _, must := range []string{
		"public_key=" + newHex,             // the new active hub is added
		"endpoint=gw-b.example:51820",      // dialing the new hub
		"persistent_keepalive_interval=25", // keepalive preserved
		"replace_allowed_ips=true",         // new peer carries the full current set
		"allowed_ip=10.99.0.0/24",          // ... which is preserved from the old peer
		"allowed_ip=192.168.5.0/24",
		"public_key=" + oldHex, // the old hub is named ...
		"remove=true",          // ... and removed
	} {
		if !strings.Contains(uapi, must) {
			t.Errorf("swap uapi missing %q:\n%s", must, uapi)
		}
	}
	// Identity is UNTOUCHED — no device key, no whole-peer-table replace.
	for _, forbidden := range []string{"private_key=", "replace_peers="} {
		if strings.Contains(uapi, forbidden) {
			t.Errorf("swap uapi MUST NOT contain %q (would touch device identity / bounce):\n%s", forbidden, uapi)
		}
	}
	// ADD-BEFORE-REMOVE: the new peer's add must precede the old peer's removal, so crypto-routing for the
	// preserved allowed_ips is never momentarily unowned.
	if strings.Index(uapi, "public_key="+newHex) >= strings.Index(uapi, "public_key="+oldHex) {
		t.Errorf("new peer must be ADDED before the old is removed (no unowned-routing window):\n%s", uapi)
	}
}

// TestGatewayPeerSwapUAPISameKeyNoRemove (WF-A) — re-homing to the SAME key (or a first apply where old==new)
// must NOT emit remove=true, or it would delete the peer it just installed. A no-op-safe swap.
func TestGatewayPeerSwapUAPISameKeyNoRemove(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	uapi, err := gatewayPeerSwapUAPI(key, key, "gw-a.example:51820", 0, []string{"10.99.0.0/24"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if strings.Contains(uapi, "remove=true") {
		t.Errorf("same-key swap must NOT remove the peer it just added:\n%s", uapi)
	}
}
