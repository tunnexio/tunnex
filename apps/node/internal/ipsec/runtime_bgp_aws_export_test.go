package ipsec

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestAWSBGPProofReusesExactConnectedEnvironment(t *testing.T) {
	m := bgpMaterialFixture()
	m.Manifest.LocalPrefixes = []string{"10.181.10.0/24"}
	m.Manifest.RemotePrefixes = []string{"10.182.0.0/16"}
	m.Manifest.BGP.RouterID = "10.181.10.10"
	runtimeReseal(&m)
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	const links = `[{"ifindex":2,"ifname":"ens5","link_type":"ether","mtu":9001,"flags":["UP","LOWER_UP"]},{"ifindex":3,"ifname":"docker0","link_type":"ether","mtu":1500,"flags":["NO-CARRIER","UP"],"operstate":"DOWN","linkinfo":{"info_kind":"bridge"}},{"ifindex":4,"ifname":"wg0","link_type":"none","mtu":1420,"flags":["UP"],"linkinfo":{"info_kind":"wireguard"}}]`
	const originalAddress = `[{"ifname":"ens5","addr_info":[{"local":"10.181.10.10","prefixlen":24}]},{"ifname":"docker0","addr_info":[{"local":"172.17.0.1","prefixlen":16}]},{"ifname":"wg0","addr_info":[{"local":"10.99.0.1","prefixlen":24}]}]`
	routes, addresses := awsConnectedGatewayRoutes, originalAddress
	const originalSelection = `[{"dst":"10.181.10.0","dev":"ens5","prefsrc":"10.181.10.10"}]`
	selected, secondSelection := originalSelection, ""
	selectionReads := 0
	underlaySource := "10.181.10.10"
	inspector := &runtimeEnvironmentInspector{
		namespace: func() (string, error) { return e.Allocation.Namespace, nil },
		nft:       func(context.Context, ...string) ([]byte, error) { return []byte(`{"nftables":[]}`), nil },
		ip: func(_ context.Context, args ...string) ([]byte, error) {
			switch q := strings.Join(args, " "); q {
			case "-j -d link show":
				return []byte(links), nil
			case "-j -4 address show":
				return []byte(addresses), nil
			case "-j -4 route show table main":
				return []byte(routes), nil
			case "-j -4 route get 10.181.10.0":
				selectionReads++
				if selectionReads == 2 && secondSelection != "" {
					return []byte(secondSelection), nil
				}
				return []byte(selected), nil
			case "-j -4 rule show":
				return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
			default:
				if strings.HasPrefix(q, "-j -4 route get ") {
					return []byte(`[{"dst":"` + args[len(args)-1] + `","dev":"ens5","prefsrc":"` + underlaySource + `"}]`), nil
				}
				return nil, ErrRuntimeEnvironment
			}
		},
	}
	env, err := inspector.ObserveLocalExports(context.Background(), e.Allocation, e.Engines)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := runtimeBGPProcessConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	c := &RuntimeController{config: RuntimeControllerConfig{Environment: inspector}}
	proof, err := c.bgpLocalExportProof(e, cfg, env)
	if err != nil {
		t.Fatal("AWS cannot use its independently qualified local export", err)
	}
	if proof(context.Background(), cfg.LocalPrefixes) != nil {
		t.Fatal("exact AWS fresh export proof refused")
	}
	for name, mutate := range map[string]func(){
		"address mask":              func() { addresses = strings.Replace(addresses, `"prefixlen":24`, `"prefixlen":32`, 1) },
		"missing address mask":      func() { addresses = strings.Replace(addresses, `,"prefixlen":24`, ``, 1) },
		"different assigned source": func() { addresses = strings.Replace(addresses, `10.181.10.10`, `10.181.10.11`, 1) },
		"GCP owned route protocol": func() {
			routes = strings.Replace(routes, `"dst":"10.181.10.0/24","dev":"ens5","protocol":"kernel"`, `"dst":"10.181.10.0/24","dev":"ens5","protocol":"242"`, 1)
		},
		"bridge protected overlap": func() { routes = strings.Replace(routes, `172.17.0.0/16`, `10.181.10.0/24`, 1) },
		"bridge unknown flag":      func() { routes = strings.Replace(routes, `"linkdown"`, `"unknown"`, 1) },
		"missing covering route":   func() { routes = strings.Replace(routes, `10.181.10.0/24`, `10.181.20.0/24`, 1) },
		"unverified next hop": func() {
			routes = strings.Replace(routes, `"dst":"10.181.10.0/24"`, `"dst":"10.181.10.0/24","gateway":"10.182.0.1"`, 1)
		},
		"selected other device":       func() { selected = strings.Replace(selected, `ens5`, `wg0`, 1) },
		"selected unexpected gateway": func() { selected = `[{"dev":"ens5","gateway":"10.181.10.1"}]` },
		"selected malformed gateway":  func() { selected = `[{"dev":"ens5","gateway":null}]` },
		"selected multipath":          func() { selected = `[{"dev":"ens5","multipath":[]}]` },
		"selected flagged":            func() { selected = `[{"dev":"ens5","flags":["linkdown"]}]` },
		"selected empty":              func() { selected = `[]` },
	} {
		t.Run(name, func(t *testing.T) {
			routes, addresses = awsConnectedGatewayRoutes, originalAddress
			selected = originalSelection
			mutate()
			if proof(context.Background(), cfg.LocalPrefixes) == nil {
				t.Fatal("unsafe AWS export accepted")
			}
		})
	}
	routes, addresses = awsConnectedGatewayRoutes, originalAddress
	selected = originalSelection
	selectionReads = 0
	secondSelection = strings.Replace(originalSelection, `10.181.10.10`, `10.181.10.11`, 1)
	if proof(context.Background(), cfg.LocalPrefixes) == nil {
		t.Fatal("changed selected-route snapshot accepted")
	}
	secondSelection = ""
	if proof(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.181.0.0/16")}) == nil {
		t.Fatal("changed export prefixes accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proof(ctx, cfg.LocalPrefixes) == nil {
		t.Fatal("canceled export proof accepted")
	}
	// Keep the existing AWS routed-LAN behavior: an exact static route through
	// an actually connected next hop is valid, without GCP's /32 route exception.
	routes = `[{"dst":"default","gateway":"192.0.2.1","dev":"ens5","flags":[]},{"dst":"192.0.2.0/24","dev":"ens5","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","flags":[]},{"dst":"10.181.10.0/24","gateway":"192.0.2.1","dev":"ens5","protocol":"static","prefsrc":"192.0.2.10","flags":[]}]`
	addresses = strings.Replace(originalAddress, `10.181.10.10`, `192.0.2.10`, 1)
	// A changed underlay cannot inherit the old proof, even with valid routes.
	if proof(context.Background(), cfg.LocalPrefixes) == nil {
		t.Fatal("changed underlay identity accepted")
	}
	underlaySource = "192.0.2.10"
	selected = `[{"dst":"10.181.10.0","gateway":"192.0.2.1","dev":"ens5","prefsrc":"192.0.2.10"}]`
	routedEnv, err := inspector.ObserveLocalExports(context.Background(), e.Allocation, e.Engines)
	if err != nil {
		t.Fatal("existing physical routed AWS export refused", err)
	}
	routedProof, err := c.bgpLocalExportProof(e, cfg, routedEnv)
	if err != nil || routedProof(context.Background(), cfg.LocalPrefixes) != nil {
		t.Fatal("fresh physical routed AWS proof refused", err)
	}
	routedRoutes, routedAddress, routedSelection := routes, addresses, selected
	for name, mutate := range map[string]func(){
		"routed unconnected next hop": func() {
			routes = strings.Replace(routes, `"gateway":"192.0.2.1"`, `"gateway":"192.0.3.1"`, -1)
			selected = strings.Replace(selected, `192.0.2.1"`, `192.0.3.1"`, 1)
		},
		"routed own address as gateway": func() {
			routes = strings.Replace(routes, `"gateway":"192.0.2.1"`, `"gateway":"192.0.2.10"`, -1)
			selected = strings.Replace(selected, `192.0.2.1"`, `192.0.2.10"`, 1)
		},
		"routed gateway outside assigned mask": func() { addresses = strings.Replace(addresses, `"prefixlen":24`, `"prefixlen":32`, 1) },
		"routed selected gateway mismatch":     func() { selected = strings.Replace(selected, `192.0.2.1"`, `192.0.2.2"`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			routes, addresses, selected = routedRoutes, routedAddress, routedSelection
			mutate()
			if routedProof(context.Background(), cfg.LocalPrefixes) == nil {
				t.Fatal("unsafe physical routed AWS proof accepted")
			}
		})
	}
}
