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
