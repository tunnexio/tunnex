package ipsec

import (
	"strings"
	"testing"
)

func TestGuardReadbackNamedTimeoutMembers(t *testing.T) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"lease_test","type":"iface_index","flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":10,"timeout":30}},{"elem":{"val":11,"timeout":30}}]}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, set+`,{"chain":`, 1)
	observed := strings.ReplaceAll(strings.ReplaceAll(expected, `"val":10`, `"val":"tnxi-a"`), `"val":11`, `"val":"tnxi-b"`)
	links := []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}}
	if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(observed), links) != nil {
		t.Fatal("mapped timeout members refused")
	}
	if VerifyGuardReadback([]byte(expected), []byte(observed)) == nil {
		t.Fatal("unmapped named members accepted")
	}
	for _, bad := range []string{strings.Replace(observed, `"tnxi-b"`, `"foreign"`, 1), strings.Replace(observed, `"tnxi-b"`, `"tnxi-a"`, 1), strings.Replace(observed, `"timeout":30`, `"timeout":31`, 1)} {
		if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(bad), links) == nil {
			t.Fatal("member drift accepted")
		}
	}
}

func TestGuardReadbackNamedInlineInterfaces(t *testing.T) {
	for _, key := range []string{"iif", "oif"} {
		t.Run(key, func(t *testing.T) {
			match := `{"match":{"op":"==","left":{"meta":{"key":"` + key + `"}},"right":{"set":[10,11]}}},{"counter":null}`
			expected := strings.Replace(guardExpectedFixture, `{"counter":null}`, match, 1)
			observed := strings.Replace(expected, `"set":[10,11]`, `"set":["tnxi-a","tnxi-b"]`, 1)
			links := []GuardInterface{{Name: "tnxi-a", Index: 10}, {Name: "tnxi-b", Index: 11}}
			if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(observed), links) != nil {
				t.Fatal("inline mapping refused")
			}
			for _, bad := range []string{strings.Replace(observed, `"tnxi-b"`, `"unknown"`, 1), strings.Replace(observed, `"tnxi-b"`, `"tnxi-a"`, 1), strings.Replace(observed, `"key":"`+key+`"`, `"key":"iifname"`, 1)} {
				if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(bad), links) == nil {
					t.Fatal("inline match drift accepted")
				}
			}
		})
	}
}
