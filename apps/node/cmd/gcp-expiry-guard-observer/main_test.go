package main

import (
	"encoding/json"
	"testing"
)

func TestConservativeUnknownAndWrongProtocol(t *testing.T) {
	e := []any{map[string]any{"accept": nil}, map[string]any{"unknown": true}}
	if m, x := appRule(e, "udp", 9000); !m || x {
		t.Fatal("unknown accept must block denial without proving exact allow")
	}
	e = append(e, map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "right": json.Number("9000")}})
	if m, _ := appRule(e, "udp", 9000); m {
		t.Fatal("TCP rule must not match UDP")
	}
}
func TestLiveExpiryCannotUseZeroOrWrongSlot(t *testing.T) {
	for _, v := range []struct {
		index, expiry string
		want          bool
	}{{"8", "1", true}, {"8", "0", false}, {"9", "1", false}} {
		s := map[string]any{"timeout": json.Number("60"), "elem": []any{map[string]any{"elem": map[string]any{"val": json.Number(v.index), "expires": json.Number(v.expiry)}}}}
		if liveSet(s, nil, true) != v.want {
			t.Fatal(v)
		}
	}
}
func TestPinnedBindingRefusesBeforeReadback(t *testing.T) {
	if _, err := verify(capture{}, "deny", "udp"); err == nil {
		t.Fatal("missing live capture binding accepted")
	}
}
