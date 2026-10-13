package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

type gcpExportEnvironment struct {
	env     RuntimeEnvironment
	err     error
	calls   int
	entry   RuntimeJournalEntry
	changed bool
	cancel  context.CancelFunc
}

func (f *gcpExportEnvironment) Observe(_ context.Context, a KernelAllocation, e [2]EngineTunnel) (RuntimeEnvironment, error) {
	f.calls++
	if f.cancel != nil {
		f.cancel()
	}
	if !reflect.DeepEqual(a, f.entry.Allocation) || !reflect.DeepEqual(e, f.entry.Engines) {
		return RuntimeEnvironment{}, ErrRuntimeEnvironment
	}
	if f.changed {
		return RuntimeEnvironment{Namespace: f.env.Namespace, LocalIngressIndices: []int{99}}, nil
	}
	return f.env, f.err
}
func (f *gcpExportEnvironment) ObserveLocalExports(ctx context.Context, a KernelAllocation, e [2]EngineTunnel) (RuntimeEnvironment, error) {
	return f.Observe(ctx, a, e)
}
func (*gcpExportEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }
func TestGCPBGPExactFreshLocalExportProof(t *testing.T) {
	m := gcpMaterialFixture()
	entry, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := runtimeBGPProcessConfig(entry)
	if err != nil {
		t.Fatal(err)
	}
	env := RuntimeEnvironment{Namespace: entry.Allocation.Namespace, LocalIngressIndices: []int{2}, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("10.70.0.2"), OuterMTU: 1460}, {InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("10.70.0.2"), OuterMTU: 1460}}}
	f := &gcpExportEnvironment{env: env, entry: entry}
	c := &RuntimeController{config: RuntimeControllerConfig{Environment: f}}
	proof, err := c.gcpBGPLocalExportProof(entry, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if proof(context.Background(), cfg.LocalPrefixes) != nil || f.calls != 1 {
		t.Fatal("fresh exact environment refused")
	}
	// Recheck each use; neither a stored proof nor an unchanged configured prefix
	// can adopt a changed route/source/interface/namespace observation.
	f.changed = true
	if proof(context.Background(), cfg.LocalPrefixes) == nil {
		t.Fatal("environment drift admitted")
	}
	f.changed = false
	f.err = ErrRuntimeEnvironment
	if proof(context.Background(), cfg.LocalPrefixes) == nil {
		t.Fatal("native refusal admitted")
	}
	f.err = nil
	before := f.calls
	if proof(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}) == nil || f.calls != before {
		t.Fatal("changed configured export admitted")
	}
	during, stopDuring := context.WithCancel(context.Background())
	f.cancel = stopDuring
	if proof(during, cfg.LocalPrefixes) == nil {
		t.Fatal("cancellation during inventory admitted")
	}
	f.cancel = nil
	before = f.calls
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proof(ctx, cfg.LocalPrefixes) == nil || f.calls != before {
		t.Fatal("cancelled export admitted")
	}
	bad := cfg
	bad.LocalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}
	if _, err := c.gcpBGPLocalExportProof(entry, bad, env); err == nil {
		t.Fatal("unbound config admitted")
	}
	wrongEnv := env
	wrongEnv.Namespace = "net:[1]"
	if _, err := c.gcpBGPLocalExportProof(entry, cfg, wrongEnv); err == nil {
		t.Fatal("unbound namespace admitted")
	}
	aws := entry
	aws.Allocation.ProfileID = ""
	if _, err := c.gcpBGPLocalExportProof(aws, cfg, env); err == nil {
		t.Fatal("AWS gained GCP override")
	}
	c.config.Environment = nil
	if _, err := c.gcpBGPLocalExportProof(entry, cfg, env); err == nil {
		t.Fatal("nil native inspector admitted")
	}
}

// Native observation parser and provider contract are real; command I/O uses
// captured key-free GCP /32 routes. This is source qualification, not live FRR.
func TestGCPBGPProofReusesExactRoutedEnvironment(t *testing.T) {
	raw, err := os.ReadFile("../bgp/testdata/gcp_routed_export.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured map[string]json.RawMessage
	if json.Unmarshal(raw, &captured) != nil {
		t.Fatal("capture")
	}
	m := gcpMaterialFixture()
	m.Manifest.LocalPrefixes = []string{"10.70.0.0/24"}
	m.Manifest.BGP.RouterID = "10.70.0.2"
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	routes := captured["main_routes"]
	inspector := &runtimeEnvironmentInspector{namespace: func() (string, error) { return e.Allocation.Namespace, nil }, nft: func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil }, ip: func(_ context.Context, args ...string) ([]byte, error) {
		switch q := strings.Join(args, " "); q {
		case "-j -d link show":
			return captured["links"], nil
		case "-j -4 address show":
			return captured["addresses"], nil
		case "-j -4 route show table main":
			return routes, nil
		case "-j -4 rule show":
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
		default:
			if strings.HasPrefix(q, "-j -4 route get ") {
				return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"ens4","prefsrc":"10.70.0.2"}]`), nil
			}
			return nil, ErrRuntimeEnvironment
		}
	}}
	env, err := inspector.Observe(context.Background(), e.Allocation, e.Engines)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := runtimeBGPProcessConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	c := &RuntimeController{config: RuntimeControllerConfig{Environment: inspector}}
	proof, err := c.gcpBGPLocalExportProof(e, cfg, env)
	if err != nil {
		t.Fatal(err)
	}
	if proof(context.Background(), cfg.LocalPrefixes) != nil {
		t.Fatal("exact native parser proof refused")
	}
	original := append([]byte(nil), routes...)
	for _, bad := range []string{
		strings.Replace(string(original), `"10.70.0.0/24"`, `"10.70.0.0/16"`, 1),
		strings.Replace(string(original), `"protocol": "242"`, `"protocol": "bgp"`, 1),
		strings.Replace(string(original), `"prefsrc": "10.70.0.2"`, `"prefsrc": "10.70.0.3"`, -1),
	} {
		routes = []byte(bad)
		if proof(context.Background(), cfg.LocalPrefixes) == nil {
			t.Fatal("changed native route admitted")
		}
	}
}

func TestGCPBGPExportProtocolGrammar(t *testing.T) {
	for _, raw := range []string{`"kernel"`, `"static"`, `"boot"`, `"242"`, `"2"`, `2`, `3`, `4`, `242`} {
		if !runtimeLocalExportProtocol(json.RawMessage(raw)) {
			t.Fatal("legitimate protocol refused", raw)
		}
	}
	for _, raw := range []string{"", `null`, `"bgp"`, `"bird"`, `"dhcp"`, `"unknown"`, `"+242"`, `"0242"`, `"242x"`, `42`, `186`, `0`, `-1`, `2.0`, `true`, `{}`, `[]`, `4294967296`} {
		if runtimeLocalExportProtocol(json.RawMessage(raw)) {
			t.Fatal("unproved export protocol admitted", raw)
		}
	}
}
