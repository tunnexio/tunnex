package ipsec

import (
	"bytes"
	"strings"
	"testing"
)

const guardExpectedFixture = `{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}},{"chain":{"family":"inet","table":"tunnex_ipsec","name":"forward_guard","type":"filter","hook":"forward","prio":-10,"policy":"accept"}},{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"forward_guard","expr":[{"counter":null},{"drop":null}]}}]}`

func TestGuardReadbackExactSemantics(t *testing.T) {
	actual := strings.ReplaceAll(guardExpectedFixture, `"name":"tunnex_ipsec"`, `"name":"tunnex_ipsec","handle":12`)
	actual = strings.ReplaceAll(actual, `"counter":null`, `"counter":{"packets":123,"bytes":456}`)
	actual = strings.Replace(actual, `"nftables":[`, `"nftables":[{"metainfo":{"version":"1.1.1","release_name":"test","json_schema_version":1}},`, 1)
	if err := VerifyGuardReadback([]byte(guardExpectedFixture), []byte(actual)); err != nil {
		t.Fatal(err)
	}
}
func TestGuardReadbackRefusesDrift(t *testing.T) {
	for name, actual := range map[string]string{
		"verdict":         strings.ReplaceAll(guardExpectedFixture, `"drop":null`, `"accept":null`),
		"priority":        strings.ReplaceAll(guardExpectedFixture, `"prio":-10`, `"prio":10`),
		"policy":          strings.ReplaceAll(guardExpectedFixture, `"policy":"accept"`, `"policy":"drop"`),
		"foreign table":   strings.ReplaceAll(guardExpectedFixture, `tunnex_ipsec`, `foreign_table`),
		"extra field":     strings.ReplaceAll(guardExpectedFixture, `"drop":null`, `"drop":null,"accept":null`),
		"duplicate key":   strings.ReplaceAll(guardExpectedFixture, `"prio":-10`, `"prio":-10,"pr\u0069o":-10`),
		"bad counter":     strings.ReplaceAll(guardExpectedFixture, `"counter":null`, `"counter":{"name":"foreign-counter"}`),
		"counter payload": strings.ReplaceAll(guardExpectedFixture, `"counter":null`, `"counter":{"packets":0,"bytes":0,"other":1}`),
		"empty":           `{"nftables":[]}`,
		"null":            `null`,
		"trailing":        guardExpectedFixture + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyGuardReadback([]byte(guardExpectedFixture), []byte(actual)); err == nil {
				t.Fatal("accepted guard drift")
			}
		})
	}
}
func TestGuardReadbackRefusesEmptyExpected(t *testing.T) {
	for _, v := range []string{`{"nftables":[]}`, `null`, `{"nftables":[{"metainfo":{"version":"test"}}]}`} {
		if err := VerifyGuardReadback([]byte(v), []byte(v)); err == nil {
			t.Fatal("empty proof accepted")
		}
	}
}

func TestGuardReadbackGroupedDefinitionsPreserveRuleOrder(t *testing.T) {
	expected := []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}},{"chain":{"family":"inet","table":"tunnex_ipsec","name":"a"}},{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"a","expr":[{"drop":null}]}},{"chain":{"family":"inet","table":"tunnex_ipsec","name":"b"}},{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"a","expr":[{"accept":null}]}}]}`)
	observed := []byte(`{"nftables":[{"table":{"family":"inet","name":"tunnex_ipsec"}},{"chain":{"family":"inet","table":"tunnex_ipsec","name":"a"}},{"chain":{"family":"inet","table":"tunnex_ipsec","name":"b"}},{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"a","expr":[{"drop":null}]}},{"rule":{"family":"inet","table":"tunnex_ipsec","chain":"a","expr":[{"accept":null}]}}]}`)
	if VerifyGuardReadback(expected, observed) != nil {
		t.Fatal("kernel definition grouping rejected")
	}
	reversed := bytes.ReplaceAll(observed, []byte(`"drop":null`), []byte(`"TEMP":null`))
	reversed = bytes.ReplaceAll(reversed, []byte(`"accept":null`), []byte(`"drop":null`))
	reversed = bytes.ReplaceAll(reversed, []byte(`"TEMP":null`), []byte(`"accept":null`))
	if VerifyGuardReadback(expected, reversed) == nil {
		t.Fatal("changed rule order accepted")
	}
}

func TestGuardReadbackExpiringSetBound(t *testing.T) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"lease_test","type":"iface_index","flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":10,"timeout":30}}]}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, set+`,{"chain":`, 1)
	observed := strings.Replace(expected, `"val":10,"timeout":30`, `"val":10,"timeout":30,"expires":29`, 1)
	if VerifyGuardReadback([]byte(expected), []byte(observed)) != nil {
		t.Fatal("bounded live expiry rejected")
	}
	for _, bad := range []string{
		strings.Replace(observed, `"expires":29`, `"expires":31`, 1),
		strings.Replace(observed, `"expires":29`, `"expires":0`, 1),
		strings.Replace(observed, `"expires":29`, `"expires":-1`, 1),
		strings.Replace(observed, `"timeout":30`, `"timeout":60`, 1),
		strings.Replace(observed, `"val":10`, `"val":11`, 1),
		strings.Replace(observed, `"flags":["timeout"]`, `"flags":[]`, 1),
	} {
		if VerifyGuardReadback([]byte(expected), []byte(bad)) == nil {
			t.Fatal("unsafe timed set accepted")
		}
	}
}

func TestGuardReadbackIndependentInterfaceMapping(t *testing.T) {
	expected := strings.Replace(guardExpectedFixture, `{"counter":null}`, `{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":10}},{"counter":null}`, 1)
	observed := strings.Replace(expected, `"right":10`, `"right":"tnxi-a"`, 1)
	if VerifyGuardReadback([]byte(expected), []byte(observed)) == nil {
		t.Fatal("name accepted without observed mapping")
	}
	if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(observed), []GuardInterface{{Name: "tnxi-a", Index: 10}}) != nil {
		t.Fatal("exact independent mapping rejected")
	}
	for _, links := range [][]GuardInterface{{{Name: "tnxi-a", Index: 11}}, {{Name: "other", Index: 10}}, {{Name: "tnxi-a", Index: 10}, {Name: "alias", Index: 10}}, {{Name: "tnxi-a", Index: 10}, {Name: "tnxi-a", Index: 11}}} {
		if VerifyGuardReadbackWithInterfaces([]byte(expected), []byte(observed), links) == nil {
			t.Fatal("ambiguous or foreign mapping accepted")
		}
	}
}

func TestGuardReadbackRecreatedUnhookedOwnerPosition(t *testing.T) {
	owner := `{"chain":{"family":"inet","table":"tunnex_ipsec","name":"owner","comment":"exact-owner"}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, owner+`,{"chain":`, 1)
	observed := strings.Replace(guardExpectedFixture, `{"rule":`, owner+`,{"rule":`, 1)
	if VerifyGuardReadback([]byte(expected), []byte(observed)) != nil {
		t.Fatal("unhooked marker listing position changed equality")
	}
	changed := strings.Replace(observed, `"comment":"exact-owner"`, `"comment":"stale-owner"`, 1)
	if VerifyGuardReadback([]byte(expected), []byte(changed)) == nil {
		t.Fatal("stale marker accepted")
	}
}

func TestGuardReadbackIntegerLeaseSet(t *testing.T) {
	set := `{"set":{"family":"inet","table":"tunnex_ipsec","name":"sa_lease_test","type":{"typeof":{"ipsec":{"dir":"out","key":"reqid","spnum":0}}},"flags":["timeout"],"timeout":60,"elem":[{"elem":{"val":123,"timeout":30}}]}}`
	expected := strings.Replace(guardExpectedFixture, `{"chain":`, set+`,{"chain":`, 1)
	observed := strings.Replace(expected, `"val":123,"timeout":30`, `"val":123,"timeout":30,"expires":29`, 1)
	if VerifyGuardReadback([]byte(expected), []byte(observed)) != nil {
		t.Fatal("bounded reqid set rejected")
	}
	for _, bad := range []string{strings.Replace(observed, `"val":123`, `"val":124`, 1), strings.Replace(observed, `"expires":29`, `"expires":31`, 1), strings.Replace(observed, `"type":{"typeof":{"ipsec":{"dir":"out","key":"reqid","spnum":0}}}`, `"type":"iface_index"`, 1)} {
		if VerifyGuardReadback([]byte(expected), []byte(bad)) == nil {
			t.Fatal("altered reqid proof accepted")
		}
	}
}
