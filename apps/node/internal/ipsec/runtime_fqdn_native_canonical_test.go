package ipsec

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestRuntimeFQDNNativeMarkCanonicalReadback(t *testing.T) {
	expected, err := os.ReadFile("testdata/fqdn-native-v3-expected.json")
	if err != nil {
		t.Fatal(err)
	}
	observed, err := os.ReadFile("testdata/fqdn-native-v3-observed.json")
	if err != nil {
		t.Fatal(err)
	}
	links := []GuardInterface{{Name: "lo", Index: 1}, {Name: "tngcpfnq1", Index: 2}, {Name: "tngcpfnq2", Index: 3}}
	// Actual diagnostic had a one-second lease rounded to zero remaining seconds.
	// Keep that real refusal; positive-life model isolates the native expression difference.
	canonical := bytes.ReplaceAll(expected, []byte("4043309055"), []byte("4060086271"))
	if VerifyGuardReadbackWithInterfaces(canonical, observed, links) == nil {
		t.Fatal("actual zero-life lease accepted")
	}
	positive := bytes.ReplaceAll(observed, []byte(`"expires": 0`), []byte(`"expires": 1`))
	if bytes.Equal(positive, observed) {
		t.Fatal("fixture expiry shape changed")
	}
	if VerifyGuardReadbackWithInterfaces(expected, positive, links) == nil {
		t.Fatal("pre-fix noncanonical mark unexpectedly matched")
	}
	if err := VerifyGuardReadbackWithInterfaces(canonical, positive, links); err != nil {
		t.Fatal("exact native canonical mask refused", err)
	}
	for _, replacement := range []string{"4043309055", "4060086270", "4294967295"} {
		bad := bytes.ReplaceAll(positive, []byte("4060086271"), []byte(replacement))
		if VerifyGuardReadbackWithInterfaces(canonical, bad, links) == nil {
			t.Fatal("wrong mark preservation mask accepted", replacement)
		}
	}
	var extra map[string]any
	if json.Unmarshal(positive, &extra) != nil {
		t.Fatal("native fixture decode")
	}
	for _, raw := range extra["nftables"].([]any) {
		if rule, ok := raw.(map[string]any)["rule"].(map[string]any); ok {
			rule["expr"] = append(rule["expr"].([]any), map[string]any{"accept": nil})
			break
		}
	}
	extraRaw, _ := json.Marshal(extra)
	if VerifyGuardReadbackWithInterfaces(canonical, extraRaw, links) == nil {
		t.Fatal("extra expression accepted")
	}
	bad := bytes.ReplaceAll(positive, []byte("16777216"), []byte("33554432"))
	if VerifyGuardReadbackWithInterfaces(canonical, bad, links) == nil {
		t.Fatal("foreign mark accepted")
	}
}

func TestRuntimeFQDNCanonicalMarkPreservesOtherBits(t *testing.T) {
	const mask uint32 = 0x0f000000
	const mark uint32 = 0x01000000
	values := []uint32{0, ^uint32(0), mask, mark, 0xdeadbeef, 0x12345678}
	for bit := uint(0); bit < 32; bit++ {
		values = append(values, 1<<bit, ^(uint32(1) << bit))
	}
	for _, v := range values {
		old := (v & ^mask) | mark
		canonical := (v & (^mask | mark)) | mark
		if old != canonical || canonical & ^mask != v & ^mask || canonical&mask != mark {
			t.Fatal("mark algebra changed", v)
		}
	}
}
