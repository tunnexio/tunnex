package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func legacyRuntimeCensusRows(raw []byte) ([]map[string]json.RawMessage, bool) {
	root, ok := runtimeJSONObject(raw)
	if !ok || len(root) != 1 {
		return nil, false
	}
	return kernelObjects(root["nftables"])
}
func censusScale(t testing.TB, count int) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NFT []json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("fixture")
	}
	intent := guardFixture()
	intent.Connections = nil
	for i := 0; i < count; i++ {
		intent.Connections = append(intent.Connections, GuardConnection{PrefixOnly: true, ID: uuid.MustParse(fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", i+1)), Local: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.100.%d.0/24", i))}, Remote: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.200.%d.0/24", i))}})
	}
	rendered, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	var owned struct {
		NFT []json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(rendered.ExpectedJSON), &owned) != nil {
		t.Fatal("renderer")
	}
	doc.NFT = append(doc.NFT, owned.NFT...)
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestCensusSingleWalkParity(t *testing.T) {
	valid := censusScale(t, 36)
	cases := [][]byte{valid, []byte(`{"nftables":[]}`), []byte(`{"nftables":null}`), []byte(`{"nftables":{}}`), []byte(`{"nftables":[null]}`), []byte(`{"nftables":[1]}`), []byte(`{"nftables":[[]]}`), []byte(`{"nftables":[{}]}`), []byte(`{"nftables":[{"x":1,"x":2}]}`), []byte(`{"nftables":[{"x":1,"\u0078":2}]}`), []byte(`{"nftables":[],"nftables":[]}`), []byte(`{"nftables":[],"extra":true}`), []byte(`{"nftables":[]} {}`), []byte(`{"nftables":[{"x":"<>&\u2028"}]}`), []byte(`{"nftables":[{"x":"\ud800"}]}`), []byte(`{"nftables":[{"x":9007199254740993}]}`), []byte(`{"nftables":[{"x":1e9999}]}`)}
	bad := []byte(`{"nftables":[{"x":"?"}]}`)
	bad[bytes.IndexByte(bad, '?')] = 0xff
	cases = append(cases, bad)
	for depth := 58; depth <= 68; depth++ {
		cases = append(cases, []byte(`{"nftables":[{"x":`+strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth)+`}]} `))
	}
	for _, n := range []int{4095, 4096, 4097} {
		cases = append(cases, []byte(`{"nftables":[`+strings.Repeat("{},", n-1)+`{}]}`))
	}
	for _, n := range []int{kernelOutputLimit - 1, kernelOutputLimit, kernelOutputLimit + 1} {
		base := []byte(`{"nftables":[]}`)
		cases = append(cases, append(base, bytes.Repeat([]byte(" "), n-len(base))...))
	}
	for i := 0; i < len(valid); i += max(1, len(valid)/128) {
		truncated := append([]byte(nil), valid[:i]...)
		cases = append(cases, truncated)
		mutated := append([]byte(nil), valid...)
		mutated[i] = '!'
		cases = append(cases, mutated)
	}
	for i, raw := range cases {
		old, oldOK := legacyRuntimeCensusRows(raw)
		got, ok := runtimeCensusRows(raw)
		if oldOK != ok || !reflect.DeepEqual(old, got) {
			t.Fatalf("parity case%d len%d", i, len(raw))
		}
	}
}
func TestCensusSingleWalkFullQualifiers(t *testing.T) {
	raw := censusScale(t, 36)
	listing, err := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if err != nil {
		t.Fatal(err)
	}
	protected := []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")}
	for _, data := range [][]byte{raw, bytes.Replace(raw, []byte(`"name":"nat"`), []byte(`"name":"foreign"`), 1), bytes.Replace(raw, []byte(`"prio":100`), []byte(`"prio":400`), 1)} {
		a, ao := legacyRuntimeCensusRows(data)
		b, bo := runtimeCensusRows(data)
		if ao != bo || runtimeHookCensusRows(a, protected) != runtimeHookCensusRows(b, protected) || runtimeDockerDNSCensusRows(a, listing, protected) != runtimeDockerDNSCensusRows(b, listing, protected) {
			t.Fatal("qualifier parity")
		}
	}
	run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) == 1 {
			return []byte("iptables-nft-save v1.8.7 (nf_tables)"), nil
		}
		return listing, nil
	}
	if !runtimeQualifiedHookCensusWithCommands(context.Background(), "/sbin/nft", raw, protected, run) {
		t.Fatal("genuine-shaped full qualification refused")
	}
}
func TestCensusSingleWalkRemovesRepeatedTraversalAllocations(t *testing.T) {
	raw := censusScale(t, 36)
	old := testing.AllocsPerRun(5, func() {
		if _, ok := legacyRuntimeCensusRows(raw); !ok {
			panic("old fixture")
		}
	})
	current := testing.AllocsPerRun(5, func() {
		if _, ok := runtimeCensusRows(raw); !ok {
			panic("current fixture")
		}
	})
	t.Logf("scale36 bytes=%d legacy_allocs=%.0f candidate_allocs=%.0f", len(raw), old, current)
	if current >= old {
		t.Fatal("duplicate strict traversal allocations remain")
	}
}
func BenchmarkCensusSingleWalk(b *testing.B) {
	for _, count := range []int{1, 36} {
		raw := censusScale(b, count)
		for _, name := range []string{"legacy", "candidate"} {
			b.Run(fmt.Sprintf("owners%d/%s", count, name), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for b.Loop() {
					var ok bool
					if name == "legacy" {
						_, ok = legacyRuntimeCensusRows(raw)
					} else {
						_, ok = runtimeCensusRows(raw)
					}
					if !ok {
						b.Fatal("fixture")
					}
				}
			})
		}
	}
}
