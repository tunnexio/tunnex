package ipsec

import (
	"errors"
	"strings"
	"testing"
)

const xfrmStateFixture = `src 192.0.2.1 dst 192.0.2.2
 proto esp spi 0xc0000001 reqid 7 mode tunnel
 replay-window 32 flag af-unspec
 auth-trunc hmac(sha256) <<Keys hidden>> 128
 enc cbc(aes) <<Keys hidden>>
 anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
 if_id 0x29
`
const xfrmPolicyFixture = `src 10.1.0.0/24 dst 10.2.0.0/24
 dir out priority 375423 ptype main
 tmpl src 192.0.2.1 dst 192.0.2.2
  proto esp reqid 7 mode tunnel
 if_id 0x29
`

func TestXFRMInventoryNoKeys(t *testing.T) {
	got, err := ParseXFRMInventory("net:[42]", []byte(xfrmStateFixture), []byte(xfrmPolicyFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.States) != 1 || got.States[0].ReqID != 7 || got.States[0].IfID != 41 || got.States[0].SPI != 0xc0000001 || len(got.Policies) != 1 || got.Policies[0].Direction != "out" || got.Policies[0].TemplateSource.String() != "192.0.2.1" {
		t.Fatal("tuple lost")
	}
	empty, err := ParseXFRMInventory("net:[42]", nil, nil)
	if err != nil || len(empty.States) != 0 || len(empty.Policies) != 0 {
		t.Fatal("empty inventory")
	}
}
func TestXFRMInventoryRefusesAmbiguity(t *testing.T) {
	cases := map[string][2]string{
		"key material":       {strings.Replace(xfrmStateFixture, "<<Keys hidden>>", "0xFAKE_SECRET", 1), xfrmPolicyFixture},
		"missing reqid":      {strings.Replace(xfrmStateFixture, "reqid 7 ", "", 1), xfrmPolicyFixture},
		"overflow":           {strings.Replace(xfrmStateFixture, "reqid 7", "reqid 4294967296", 1), xfrmPolicyFixture},
		"duplicate ifid":     {xfrmStateFixture + " if_id 0x29\n", xfrmPolicyFixture},
		"duplicate state":    {xfrmStateFixture + xfrmStateFixture, xfrmPolicyFixture},
		"duplicate policy":   {xfrmStateFixture, xfrmPolicyFixture + xfrmPolicyFixture},
		"conflicting policy": {xfrmStateFixture, xfrmPolicyFixture + strings.Replace(xfrmPolicyFixture, "reqid 7", "reqid 8", 1)},
		"optional":           {xfrmStateFixture, xfrmPolicyFixture + " level use\n"},
		"block":              {xfrmStateFixture, strings.Replace(xfrmPolicyFixture, "dir out", "dir out action block", 1)},
		"offload":            {xfrmStateFixture + " crypto offload parameters: dev eth0 dir out mode packet\n", xfrmPolicyFixture},
		"mark":               {xfrmStateFixture + " mark 0x1/0xffffffff\n", xfrmPolicyFixture},
		"extra template":     {xfrmStateFixture, xfrmPolicyFixture + " tmpl src 192.0.2.1 dst 192.0.2.2\n proto esp reqid 7 mode tunnel\n"},
		"partial":            {strings.TrimSuffix(xfrmStateFixture, " if_id 0x29\n"), xfrmPolicyFixture},
		"mode":               {strings.Replace(xfrmStateFixture, "mode tunnel", "mode transport", 1), xfrmPolicyFixture},
		"nul":                {xfrmStateFixture + "\x00", xfrmPolicyFixture},
		"too large":          {strings.Repeat(" ", kernelDumpLimit+1), xfrmPolicyFixture},
	}
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParseXFRMInventory("net:[42]", []byte(inputs[0]), []byte(inputs[1]))
			if !errors.Is(err, ErrXFRMInventoryInvalid) || got.Namespace != "" {
				t.Fatal("accepted ambiguous inventory")
			}
			if strings.Contains(err.Error(), "FAKE_SECRET") {
				t.Fatal("reflected input")
			}
		})
	}
}

func TestXFRMInventoryNativePolicy(t *testing.T) {
	native := strings.Replace(xfrmPolicyFixture, " ptype main", "", 1)
	native = strings.Replace(native, "proto esp reqid", "proto esp spi 0xc0000001 reqid", 1)
	got, err := ParseXFRMInventory("net:[42]", []byte(xfrmStateFixture), []byte(native))
	if err != nil || len(got.Policies) != 1 {
		t.Fatal("native policy refused")
	}
	if got.Policies[0].TemplateSPI != 0xc0000001 {
		t.Fatal("template SPI lost")
	}
}
