package sandboxes

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestNetworkWirePublicContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../deploy/sandbox/network-plan-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan networkWirePlan
	if json.Unmarshal(raw, &plan) != nil {
		t.Fatal("invalid shared public fixture")
	}
	if got := networkPlanHash(plan); got != "c1a77370b36ecf3aa248faf6e43c6e4aa3789a98dd3210fd16cc6f33107ccf06" {
		t.Fatal("node/helper contract changed", got)
	}
}
func TestPrivateNetworkPlanRejectsUnsupportedAndConflictingConfig(t *testing.T) {
	raw, _ := os.ReadFile("../../../../deploy/sandbox/network-plan-contract.json")
	var fixture networkWirePlan
	_ = json.Unmarshal(raw, &fixture)
	key, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	b := fixture.Binding
	target := PrivateNetworkTarget{OperationID: b.OperationID, OrgID: b.OrgID, SandboxID: b.SandboxID, GatewayID: b.GatewayID, PeerID: b.PeerID, Generation: b.Generation, RuntimeID: b.RuntimeID, SpecHash: b.SpecHash, PublicKey: public, Address: netip.MustParseAddr("10.254.242.2")}
	config := "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\nAddress = 10.254.242.2/32\nMTU = 1420\n[Peer]\nPublicKey = " + fixture.GatewayPublicKey + "\nEndpoint = 192.0.2.1:51830\nAllowedIPs = 10.254.242.0/24\nPersistentKeepalive = 25\n"
	plan, private, err := privateNetworkPlan(target, []byte(config))
	if err != nil || private == "" || plan.PublicKey != public {
		t.Fatal("valid split profile failed", err)
	}
	bounded, _, err := privateNetworkPlan(target, []byte(strings.Replace(config, "MTU = 1420", "MTU = 1280", 1)))
	if err != nil || bounded.MTU != 1280 || networkPlanHash(bounded) == networkPlanHash(plan) {
		t.Fatal("explicit bounded MTU must parse and change plan hash", err)
	}
	mutations := []string{
		strings.Replace(config, "MTU = 1420", "DNS = 10.254.242.1", 1),
		strings.Replace(config, "10.254.242.0/24", "0.0.0.0/0", 1),
		strings.Replace(config, "10.254.242.0/24", "10.0.0.0/7", 1),
		strings.Replace(config, "10.254.242.2/32", "10.254.242.3/32", 1),
		strings.Replace(config, "192.0.2.1:51830", "example.invalid:51830", 1),
		config + "PostUp = arbitrary-command\n",
		config + "[Peer]\nPublicKey = " + fixture.GatewayPublicKey + "\n",
	}
	for i, input := range mutations {
		if _, _, err := privateNetworkPlan(target, []byte(input)); err == nil {
			t.Fatalf("unsupported config %d accepted", i)
		}
	}
}
