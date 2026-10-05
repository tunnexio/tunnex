package sandboxnetwork

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func mustUUID(value string) uuid.UUID { return uuid.MustParse(value) }

func fixturePlan(t *testing.T) (Plan, string) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Plan{Binding: Binding{mustUUID("00000000-0000-0000-0000-000000000001"), mustUUID("00000000-0000-0000-0000-000000000002"), mustUUID("00000000-0000-0000-0000-000000000003"), mustUUID("00000000-0000-0000-0000-000000000004"), mustUUID("00000000-0000-0000-0000-000000000005"), 1, strings.Repeat("a", 64), strings.Repeat("b", 64)}, PublicKey: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), GatewayPublicKey: base64.StdEncoding.EncodeToString(gateway.PublicKey().Bytes()), Address: netip.MustParsePrefix("10.254.242.2/32"), Endpoint: netip.MustParseAddrPort("172.30.242.2:51830"), Routes: []netip.Prefix{netip.MustParsePrefix("10.254.242.0/24")}, MTU: 1420, KeepaliveSeconds: 25}
	return p, base64.StdEncoding.EncodeToString(private.Bytes())
}

type driverFixture struct {
	p                              Plan
	snapshot                       Snapshot
	birth                          *Link
	creates, moves, commands       int
	uncertainCreate, uncertainMove bool
}

func newDriver(p Plan) *driverFixture {
	return &driverFixture{p: p, snapshot: Snapshot{Links: []Link{{Index: 1, Name: "lo"}}, DefaultRulesOnly: true}}
}
func (d *driverFixture) Snapshot(context.Context, *os.File, Plan) (Snapshot, error) {
	return d.snapshot, nil
}
func (d *driverFixture) BirthLink(context.Context, Plan) (Link, error) {
	if d.birth == nil {
		return Link{}, ErrMissing
	}
	return *d.birth, nil
}
func (d *driverFixture) CreateBirthLink(_ context.Context, p Plan) error {
	d.creates++
	d.birth = &Link{Index: 7, Name: InterfaceName(p), Alias: Alias(p), Kind: "wireguard", MTU: 1500}
	if d.uncertainCreate {
		d.uncertainCreate = false
		return ErrUnavailable
	}
	return nil
}
func (d *driverFixture) DeleteBirthLink(_ context.Context, p Plan, expected Link) error {
	if d.birth == nil || !ownedLink(p, *d.birth) || d.birth.Index != expected.Index {
		return ErrOwnership
	}
	d.birth = nil
	return nil
}
func (d *driverFixture) MoveLink(_ context.Context, l Link, _ *os.File) error {
	d.moves++
	d.snapshot.Links = append(d.snapshot.Links, l)
	d.birth = nil
	if d.uncertainMove {
		d.uncertainMove = false
		return ErrUnavailable
	}
	return nil
}
func (d *driverFixture) Command(_ context.Context, _ *os.File, stdin []byte, tool string, args ...string) error {
	d.commands++
	if tool == "wg" {
		if !strings.Contains(string(stdin), "PrivateKey = ") {
			return ErrInvalid
		}
		d.snapshot.PublicKey = d.p.PublicKey
		d.snapshot.Peers = []Peer{{d.p.GatewayPublicKey, d.p.Endpoint, d.p.Routes, d.p.KeepaliveSeconds}}
		return nil
	}
	if len(args) > 2 && args[0] == "address" {
		p, _ := netip.ParsePrefix(args[2])
		d.snapshot.Addresses = append(d.snapshot.Addresses, Address{args[4], p})
		return nil
	}
	if len(args) > 2 && args[0] == "route" {
		p, _ := netip.ParsePrefix(args[2])
		d.snapshot.Routes = append(d.snapshot.Routes, Route{Interface: args[4], Prefix: p})
		return nil
	}
	if len(args) > 2 && args[0] == "link" && args[1] == "delete" {
		d.snapshot.Links = d.snapshot.Links[:1]
		d.snapshot.Addresses = nil
		d.snapshot.Routes = nil
		d.snapshot.PublicKey = ""
		d.snapshot.Peers = nil
		return nil
	}
	if len(args) > 3 && args[0] == "link" && args[1] == "set" {
		for i := range d.snapshot.Links {
			if d.snapshot.Links[i].Name == args[3] {
				d.snapshot.Links[i].Up = true
				if len(args) > 5 {
					d.snapshot.Links[i].MTU, _ = strconv.Atoi(args[5])
				}
			}
		}
		return nil
	}
	return ErrInvalid
}

func TestApplyRecoversSameInterfaceAndInspectsActualState(t *testing.T) {
	for _, uncertain := range []string{"create", "move", "none"} {
		t.Run(uncertain, func(t *testing.T) {
			p, key := fixturePlan(t)
			driver := newDriver(p)
			driver.uncertainCreate = uncertain == "create"
			driver.uncertainMove = uncertain == "move"
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			fd, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close() // fake driver only; never Linux-admitted
			controller := Controller{FilesystemManifests{root}, driver}
			identity := NamespaceIdentity{11, 22, 1000}
			if uncertain != "none" {
				if _, err = controller.Apply(context.Background(), fd, identity, p, key); !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
			}
			receipt, err := controller.Apply(context.Background(), fd, identity, p, key)
			if err != nil || receipt.Manifest.Namespace != identity || receipt.Interface != InterfaceName(p) || driver.creates != 1 || driver.moves != 1 {
				t.Fatal("recovery replaced namespace/interface", err)
			}
			if _, err = controller.Apply(context.Background(), fd, identity, p, key); err != nil || driver.creates != 1 || driver.moves != 1 {
				t.Fatal("retry created another interface", err)
			}
			manifest, err := root.ReadFile(p.Binding.OperationID.String() + ".json")
			if err != nil || strings.Contains(string(manifest), key) {
				t.Fatal("manifest contains secret or is missing")
			}
			if err = controller.Remove(context.Background(), fd, identity, p); err != nil {
				t.Fatal(err)
			}
			if err = controller.Remove(context.Background(), fd, identity, p); err != nil {
				t.Fatal("withdrawal not idempotent", err)
			}
		})
	}
}

func TestRefusesForeignNamespaceTopologyAndChangedBinding(t *testing.T) {
	for _, scenario := range []string{"native-interface", "foreign-alias", "native-route", "extra-address", "policy-rule", "gateway-peer", "changed-namespace", "changed-plan"} {
		t.Run(scenario, func(t *testing.T) {
			p, key := fixturePlan(t)
			driver := newDriver(p)
			root, _ := os.OpenRoot(t.TempDir())
			defer root.Close()
			fd, _ := os.Open(os.DevNull)
			defer fd.Close()
			identity := NamespaceIdentity{11, 22, 1000}
			controller := Controller{FilesystemManifests{root}, driver}
			if _, err := controller.Apply(context.Background(), fd, identity, p, key); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "native-interface":
				driver.snapshot.Links = append(driver.snapshot.Links, Link{Index: 8, Name: "eth0"})
			case "foreign-alias":
				driver.snapshot.Links[1].Alias = "unrelated"
			case "native-route":
				driver.snapshot.Routes = append(driver.snapshot.Routes, Route{Interface: InterfaceName(p), Prefix: netip.MustParsePrefix("0.0.0.0/0")})
			case "extra-address":
				driver.snapshot.Addresses = append(driver.snapshot.Addresses, Address{InterfaceName(p), netip.MustParsePrefix("10.1.1.1/32")})
			case "policy-rule":
				driver.snapshot.DefaultRulesOnly = false
			case "gateway-peer":
				driver.snapshot.Peers[0].Endpoint = netip.MustParseAddrPort("127.0.0.1:1")
			case "changed-namespace":
				identity.Inode++
			case "changed-plan":
				p.Binding.Generation++
			}
			before := driver.commands
			if _, err := controller.Apply(context.Background(), fd, identity, p, key); err == nil || driver.commands != before {
				t.Fatal("foreign/changed state mutated or accepted", err)
			}
			if _, err := controller.Inspect(context.Background(), fd, identity, p); err == nil {
				t.Fatal("foreign/changed state reported ready")
			}
		})
	}
}

func TestPlanRejectsFullTunnelAndWrongPrivateIdentity(t *testing.T) {
	p, key := fixturePlan(t)
	other, otherKey := fixturePlan(t)
	if _, err := WireGuardConfig(p, otherKey); !errors.Is(err, ErrOwnership) || p.PublicKey == other.PublicKey {
		t.Fatal("wrong private identity accepted", err)
	}
	for _, route := range []string{"0.0.0.0/0", "169.254.0.0/16", "10.0.0.0/7", "10.1.1.1/24"} {
		p.Routes = []netip.Prefix{netip.MustParsePrefix(route)}
		if _, err := WireGuardConfig(p, key); err == nil {
			t.Fatal("unsupported route accepted", route)
		}
	}
	public, _ := json.Marshal(p)
	if strings.Contains(string(public), key) {
		t.Fatal("public plan contains private key")
	}
}

func TestCleanupRecoversOwnedCreateBeforeMove(t *testing.T) {
	p, key := fixturePlan(t)
	driver := newDriver(p)
	driver.uncertainCreate = true
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	controller := Controller{Store: FilesystemManifests{Root: root}, Driver: driver}
	ns, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	identity := NamespaceIdentity{1, 2, 1000}
	if _, err = controller.Apply(context.Background(), ns, identity, p, key); err == nil {
		t.Fatal("uncertain create not exercised")
	}
	if driver.birth == nil {
		t.Fatal("missing birth resource")
	}
	if err = controller.Remove(context.Background(), ns, identity, p); err != nil {
		t.Fatal(err)
	}
	if driver.birth != nil || len(driver.snapshot.Links) != 1 {
		t.Fatal("owned resource survived")
	}
	if err = controller.InspectRemoved(context.Background(), ns, identity, p); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedKernelMulticastDoesNotAdmitIPv6Transport(t *testing.T) {
	p, _ := fixturePlan(t)
	name := InterfaceName(p)
	for _, item := range []struct {
		name   string
		route  Route
		accept bool
	}{
		{"owned-local-kernel", Route{Interface: name, Prefix: netip.MustParsePrefix("ff00::/8"), Local: true}, true},
		{"foreign-interface", Route{Interface: "eth0", Prefix: netip.MustParsePrefix("ff00::/8"), Local: true}, false},
		{"forwarded-multicast", Route{Interface: name, Prefix: netip.MustParsePrefix("ff00::/8")}, false},
		{"ipv6-private", Route{Interface: name, Prefix: netip.MustParsePrefix("fd00::/8"), Local: true}, false},
		{"ipv6-default", Route{Interface: name, Prefix: netip.MustParsePrefix("::/0")}, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			snapshot := Snapshot{Links: []Link{{Index: 1, Name: "lo"}, {Index: 2, Name: name, Alias: Alias(p), Kind: "wireguard"}}, Routes: []Route{item.route}, DefaultRulesOnly: true}
			err := checkSnapshot(p, snapshot, false)
			if (err == nil) != item.accept {
				t.Fatalf("admission=%v err=%v", item.accept, err)
			}
		})
	}
}
