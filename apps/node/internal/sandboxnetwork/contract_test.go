package sandboxnetwork

import (
	"encoding/json"
	"os"
	"testing"
)

func TestWorkerHelperPublicContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../deploy/sandbox/network-plan-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan Plan
	if json.Unmarshal(raw, &plan) != nil {
		t.Fatal("invalid shared public fixture")
	}
	hash, err := Identity(plan)
	if err != nil || hash != "c1a77370b36ecf3aa248faf6e43c6e4aa3789a98dd3210fd16cc6f33107ccf06" {
		t.Fatal("worker/helper contract changed", hash, err)
	}
	if InterfaceName(plan) != "tx2a8e02f7b440" {
		t.Fatal("interface identity changed")
	}
}
