package ipsec

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestXFRMInventoryNativeLastUsedMetadata(t *testing.T) {
	before, err := ParseXFRMInventory("net:[42]", []byte(xfrmStateFixture), []byte(xfrmPolicyFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, date := range []string{"2026-09-24 09:42:54", "2024-02-29 23:59:59", "2099-01-01 00:00:00"} {
		state := strings.Replace(xfrmStateFixture, " anti-replay", " lastused "+date+"\n anti-replay", 1)
		after, err := ParseXFRMInventory("net:[42]", []byte(state), []byte(xfrmPolicyFixture))
		if err != nil {
			t.Fatalf("native metadata refused: %v", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("observational lastused changed authority/identity projection")
		}
	}
}
func TestXFRMInventoryLastUsedRefusals(t *testing.T) {
	for _, line := range []string{"lastused", "lastused 2026-09-24", "lastused 2026-09-24 09:42:54 trailing", "lastused 2026-02-30 09:42:54", "lastused 2026-09-24 24:00:00", "lastused 2026-09-24 09:42:60", "lastused 2026-9-24 09:42:54", "lastused 2026-09-24T09:42:54Z", "lastused 2026-09-24 09:42:54\n lastused 2026-09-24 09:42:54", "unknown-metadata 2026-09-24 09:42:54"} {
		state := strings.Replace(xfrmStateFixture, " anti-replay", " "+line+"\n anti-replay", 1)
		if _, err := ParseXFRMInventory("net:[42]", []byte(state), []byte(xfrmPolicyFixture)); err != ErrXFRMInventoryInvalid {
			t.Fatalf("unbounded metadata accepted: %q", line)
		}
	}
	for _, state := range []string{xfrmStateFixture + " lastused 2026-09-24 09:42:54\n", strings.Replace(xfrmStateFixture, " enc cbc(aes)", " lastused 2026-09-24 09:42:54\n enc cbc(aes)", 1)} {
		if _, err := ParseXFRMInventory("net:[42]", []byte(state), []byte(xfrmPolicyFixture)); err != ErrXFRMInventoryInvalid {
			t.Fatal("metadata position widened")
		}
	}
}
func TestXFRMInventoryCapturedPostTrafficNoKeys(t *testing.T) {
	states, err := os.ReadFile("testdata/xfrm-posttraffic-state-nokeys.txt")
	if err != nil {
		t.Fatal(err)
	}
	policies, err := os.ReadFile("testdata/xfrm-posttraffic-policy-nosock.txt")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := ParseXFRMInventory("net:[42]", states, policies)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.States) != 4 || len(inventory.Policies) != 6 {
		t.Fatal("native metadata associations lost")
	}
	for _, s := range inventory.States {
		matched := false
		for _, p := range inventory.Policies {
			if s.ReqID == p.ReqID && s.IfID == p.IfID && s.Source == p.TemplateSource && s.Destination == p.TemplateDestination && (p.TemplateSPI == 0 || p.TemplateSPI == s.SPI) {
				matched = true
			}
		}
		if !matched {
			t.Fatal("native SA identity disconnected from templates")
		}
	}
}

func TestXFRMInventoryKernel617Direction(t *testing.T) {
	for _, direction := range []string{"in", "out"} {
		for _, lastUsed := range []bool{false, true} {
			state := xfrmStateFixture
			if lastUsed {
				state = strings.Replace(state, " anti-replay", " lastused 2026-09-24 09:42:54\n anti-replay", 1)
			}
			state += " dir " + direction + "\n"
			inventory, err := ParseXFRMInventory("net:[42]", []byte(state), nil)
			if err != nil {
				t.Fatalf("direction %s lastused=%v: %v", direction, lastUsed, err)
			}
			if len(inventory.States) != 1 || inventory.States[0].Direction != direction {
				t.Fatal("SA direction lost")
			}
		}
	}
	states, err := os.ReadFile("testdata/xfrm-kernel617-state-nokeys.txt")
	if err != nil {
		t.Fatal(err)
	}
	policies, err := os.ReadFile("testdata/xfrm-kernel617-policy-nosock.txt")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := ParseXFRMInventory("net:[42]", states, policies)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.States) != 4 || len(inventory.Policies) != 6 {
		t.Fatal("captured association counts changed")
	}
	for index, direction := range []string{"out", "in", "out", "in"} {
		if inventory.States[index].Direction != direction {
			t.Fatal("captured direction changed")
		}
	}
	legacy, err := ParseXFRMInventory("net:[42]", []byte(xfrmStateFixture), nil)
	if err != nil || len(legacy.States) != 1 || legacy.States[0].Direction != "" {
		t.Fatal("legacy direction absence changed")
	}
}

func TestXFRMInventoryStateDirectionRefusals(t *testing.T) {
	for _, state := range []string{
		xfrmStateFixture + " dir fwd\n", xfrmStateFixture + " dir unknown\n", xfrmStateFixture + " dir in trailing\n",
		xfrmStateFixture + " dir\n", xfrmStateFixture + " dir in\n dir out\n", xfrmStateFixture + " dir in\n dir in\n",
		strings.Replace(xfrmStateFixture, " if_id", " dir in\n if_id", 1),
		strings.Replace(xfrmStateFixture, " anti-replay", " dir out\n anti-replay", 1),
		xfrmStateFixture + " dir in\n lastused 2026-09-24 09:42:54\n",
	} {
		if _, err := ParseXFRMInventory("net:[42]", []byte(state), nil); err != ErrXFRMInventoryInvalid {
			t.Fatal("invalid state direction accepted")
		}
	}
}
