package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func orphanGuardFixture() (string, string) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"lease_test","type":"iface_index","flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":24,"timeout":30}}]}}`
	manifest, err := RenderGuard(guardFixture())
	if err != nil {
		panic(err)
	}
	expected := strings.Replace(manifest.ExpectedJSON, `{"chain":`, set+`,{"chain":`, 1)
	matches := `{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":24}},{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":{"set":[24,10]}}},{"counter":null}`
	counter, _ := json.Marshal(guardCounter())
	expected = strings.Replace(expected, string(counter), matches, 1)
	observed := strings.ReplaceAll(expected, `"right":24`, `"right":"24"`)
	observed = strings.ReplaceAll(observed, `"set":[24,10]`, `"set":["24","tx0"]`)
	observed = strings.ReplaceAll(observed, `"val":24`, `"val":"24"`)
	return expected, observed
}

func TestGuardWithdrawalOrphanedInterfaceNumericRendering(t *testing.T) {
	expected, observed := orphanGuardFixture()
	links := []GuardInterface{{Name: "tx0", Index: 10}}
	if err := VerifyGuardWithdrawal([]byte(expected), []byte(observed), links); err != nil {
		t.Fatalf("exact orphaned index blocks safe withdrawal: %v", err)
	}
	if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(observed), links) == nil {
		t.Fatal("orphaned rendering became a positive readback")
	}
	for _, value := range []string{"25", "024", "+24", " 24", "24 ", "0", "-24", "24.0", "2.4e1", "2147483648", "unknown"} {
		t.Run(value, func(t *testing.T) {
			bad := strings.ReplaceAll(observed, `"24"`, `"`+value+`"`)
			if VerifyGuardWithdrawal([]byte(expected), []byte(bad), links) == nil {
				t.Fatal("foreign or noncanonical index accepted")
			}
		})
	}
	collision := append(links, GuardInterface{Name: "24", Index: 7})
	if VerifyGuardWithdrawal([]byte(expected), []byte(observed), collision) == nil {
		t.Fatal("numeric interface name bypassed actual mapping")
	}
	for _, bad := range []string{
		strings.Replace(observed, `"drop":null`, `"accept":null`, 1),
		strings.Replace(observed, `"chain":"forward_guard"`, `"chain":"input_guard"`, 1),
		strings.Replace(observed, `"comment":"tunnex-ipsec:`, `"comment":"foreign-ipsec:`, 1),
	} {
		if bad == observed {
			t.Fatal("mutation fixture did not change")
		}
		if VerifyGuardWithdrawal([]byte(expected), []byte(bad), links) == nil {
			t.Fatal("foreign rule/owner mutation accepted")
		}
	}
}

func TestGuardConnectionPermitRefusesOrphanedScalarIndex(t *testing.T) {
	intent := zeroExpiryGuardIntent()
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	match := `{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":24}},{"counter":null}`
	counter, _ := json.Marshal(guardCounter())
	expected := strings.Replace(manifest.ExpectedJSON, string(counter), match, 1)
	id := intent.Connections[0].ID
	if err := verifyGuardConnectionReadback([]byte(expected), []byte(expected), nil, id); err != nil {
		t.Fatalf("baseline target permit invalid: %v", err)
	}
	observed := strings.Replace(expected, `"right":24`, `"right":"24"`, 1)
	if expected == manifest.ExpectedJSON || observed == expected {
		t.Fatal("scalar orphan fixture did not change")
	}
	if VerifyGuardWithdrawal([]byte(expected), []byte(observed), nil) != nil {
		t.Fatal("exact orphaned scalar withdrawal refused")
	}
	if verifyGuardConnectionReadback([]byte(expected), []byte(observed), nil, id) == nil {
		t.Fatal("orphaned scalar became a positive target permit")
	}
}
