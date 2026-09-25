package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func daemonFixture() EngineTunnel {
	return EngineTunnel{Binding: Binding{OrgID: uuid.New(), GatewayID: uuid.New(), ConnectionID: uuid.New(), DesiredRevision: 1, ConfigurationRevision: 1, PolicyRevision: 1}, TunnelID: uuid.New(), SecretRevision: 1, XFRMID: 701, LocalAddress: netip.MustParseAddr("192.0.2.1"), RemoteAddress: netip.MustParseAddr("192.0.2.2"), LocalIdentity: netip.MustParseAddr("192.0.2.1"), RemoteIdentity: netip.MustParseAddr("192.0.2.2"), LocalPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}, RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}
}
func TestDaemonTypedStageHasNoAutomaticActivation(t *testing.T) {
	var calls []string
	var loaded viciMessage
	c := &DaemonClient{request: func(_ context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		calls = append(calls, cmd)
		if cmd == "get-conns" {
			return viciMessage{"conns": viciList()}, nil, nil
		}
		if cmd == "get-shared" {
			return viciMessage{"keys": viciList()}, nil, nil
		}
		if cmd == "load-conn" {
			loaded = m
		}
		return viciMessage{"success": viciText("yes")}, nil, nil
	}}
	cfg := daemonFixture()
	secret := []byte("Synthetic.PSK_123")
	if err := c.stageTunnel(context.Background(), cfg, secret); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "get-conns,get-shared,load-shared,load-conn" {
		t.Fatal("unexpected mutation sequence")
	}
	conn := loaded[engineName(cfg)].section
	child := conn["children"].section[engineName(cfg)].section
	if string(child["start_action"].scalar) != "none" || string(child["if_id_in"].scalar) != "701" || string(conn["version"].scalar) != "2" {
		t.Fatal("unsafe connection transform")
	}
	// IKEv2 must actively detect a silent peer; child dpd_action alone does not
	// schedule probes, and dpd_timeout is an IKEv1-only setting.
	if string(conn["dpd_delay"].scalar) != "10s" || string(child["dpd_action"].scalar) != "clear" || string(child["close_action"].scalar) != "none" {
		t.Fatal("missing bounded dead-peer probes or daemon bypasses controller recovery")
	}
	if _, present := conn["dpd_timeout"]; present {
		t.Fatal("IKEv1-only DPD timeout used for IKEv2")
	}
	if string(secret) != "Synthetic.PSK_123" {
		t.Fatal("mutated caller secret")
	}
}
func TestDaemonStageRefusesCollisionAndRedacts(t *testing.T) {
	cfg := daemonFixture()
	mutated := false
	c := &DaemonClient{request: func(_ context.Context, cmd, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		if cmd == "get-conns" {
			return viciMessage{"conns": viciList(engineName(cfg))}, nil, nil
		}
		mutated = true
		return nil, nil, errors.New("secret marker")
	}}
	if err := c.stageTunnel(context.Background(), cfg, []byte("Synthetic.PSK_123")); err != ErrDaemonProtocol || mutated {
		t.Fatal("collision mutation or error leak")
	}
}
func TestDaemonInvalidInputDoesNotDial(t *testing.T) {
	c := &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
		t.Fatal("invalid input reached daemon")
		return nil, nil, nil
	}}
	cfg := daemonFixture()
	cfg.LocalPrefixes = nil
	if c.stageTunnel(context.Background(), cfg, []byte("Synthetic.PSK_123")) != ErrDaemonProtocol {
		t.Fatal("invalid config accepted")
	}
}
func TestDaemonSocketRefusesUnsafeParentAndSymlinks(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vici-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "charon.vici")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	os.Chmod(path, 0600)
	os.Chmod(dir, 0755)
	if _, err := dialOwnedVICI(context.Background(), path); err != ErrDaemonProtocol {
		t.Fatal("unsafe directory accepted")
	}
	os.Chmod(dir, 0700)
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := dialOwnedVICI(context.Background(), alias); err != ErrDaemonProtocol {
		t.Fatal("symlink accepted")
	}
	conn, err := dialOwnedVICI(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
func TestDaemonChildObservations(t *testing.T) {
	event := viciMessage{"owned": viciSection(viciMessage{"uniqueid": viciText("1"), "version": viciText("2"), "state": viciText("ESTABLISHED"), "local-host": viciText("192.0.2.1"), "remote-host": viciText("192.0.2.2"), "child-sas": viciSection(viciMessage{"child-1": viciSection(viciMessage{"name": viciText("owned"), "uniqueid": viciText("3"), "reqid": viciText("7"), "state": viciText("INSTALLED"), "mode": viciText("TUNNEL"), "protocol": viciText("ESP"), "if-id-in": viciText("000002bd"), "if-id-out": viciText("000002bd"), "spi-in": viciText("12345678"), "spi-out": viciText("87654321"), "local-ts": viciList("10.10.0.0/24"), "remote-ts": viciList("10.20.0.0/24"), "encr-alg": viciText("AES_CBC"), "encr-keysize": viciText("256"), "integ-alg": viciText("HMAC_SHA2_256_128"), "bytes-in": viciText("12"), "bytes-out": viciText("13")})})})}
	sas, err := parseDaemonSAs([]viciMessage{event})
	if err != nil || len(sas) != 1 || !sas[0].Established || len(sas[0].Children) != 1 || sas[0].Children[0].IfIDIn != 701 {
		t.Fatalf("bad observation: %v", err)
	}
	event["owned"].section["child-sas"].section["child-1"].section["encr-keysize"] = viciText("128")
	if _, err := parseDaemonSAs([]viciMessage{event}); err != ErrDaemonProtocol {
		t.Fatal("unexpected negotiated transform accepted")
	}
	event["owned"].section["child-sas"].section["child-1"].section["encr-keysize"] = viciText("256")
	event["owned"].section["child-sas"].section["child-1"].section["uniqueid"] = viciText("0")
	if _, err := parseDaemonSAs([]viciMessage{event}); err != ErrDaemonProtocol {
		t.Fatal("zero SA identity accepted")
	}
}

func TestDaemonLinuxSmoke(t *testing.T) {
	if os.Getenv("TUNNEX_IPSEC_DAEMON_LAB") != "1" {
		t.Skip("isolated daemon qualification only")
	}
	client, err := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := client.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Version != "6.1.0" || len(inventory.Connections) != 0 || len(inventory.SharedKeys) != 0 || len(inventory.SAs) != 0 {
		t.Fatal("unexpected fresh daemon inventory")
	}
	t.Log("verified dedicated charon6.1.0 plugin inventory and empty typed connection/credential/SA observations")
}

func TestDaemonRequiresActualAlgorithms(t *testing.T) {
	m := viciMessage{}
	for class, name := range map[string]string{"encryption": "AES_CBC", "integrity": "HMAC_SHA2_256_128", "prf": "PRF_HMAC_SHA2_256", "ke": "MODP_2048"} {
		m[class] = viciSection(viciMessage{name: viciText("openssl")})
	}
	if !verifyEngineAlgorithms(m) {
		t.Fatal("supported transforms refused")
	}
	delete(m, "ke")
	if verifyEngineAlgorithms(m) {
		t.Fatal("missing group accepted")
	}
}

func TestDaemonRejectsInvalidSecretsBeforeIO(t *testing.T) {
	for _, secret := range []string{"", "short", "0abcdefgh", "abc defgh", "abcdefgh!", strings.Repeat("a", 65)} {
		c := &DaemonClient{request: func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error) {
			t.Fatal("invalid secret reached I/O")
			return nil, nil, nil
		}}
		if c.stageTunnel(context.Background(), daemonFixture(), []byte(secret)) != ErrDaemonProtocol {
			t.Fatal("invalid credential accepted")
		}
	}
}
func TestDaemonSecretTransportAndStaticFailure(t *testing.T) {
	calls := 0
	c := &DaemonClient{request: func(_ context.Context, command, event string, message viciMessage) (viciMessage, []viciMessage, error) {
		calls++
		switch command {
		case "get-conns":
			return viciMessage{"conns": viciList()}, nil, nil
		case "get-shared":
			return viciMessage{"keys": viciList()}, nil, nil
		case "load-shared":
			if string(message["data"].scalar) != "Synthetic.PSK_123" || message["owners"].kind != 4 || len(message["owners"].list) != 2 {
				t.Fatal("secret/owner transform mismatch")
			}
			return viciMessage{"success": viciText("no"), "errmsg": viciText("Synthetic.PSK_123")}, nil, nil
		default:
			t.Fatal("continued after secret load refusal")
			return nil, nil, nil
		}
	}}
	err := c.stageTunnel(context.Background(), daemonFixture(), []byte("Synthetic.PSK_123"))
	if err != ErrDaemonProtocol || strings.Contains(err.Error(), "Synthetic") || calls != 3 {
		t.Fatal("unsafe daemon failure handling")
	}
}

func daemonInventoryStub(events []viciMessage, terminal viciMessage, mutations *int) *DaemonClient {
	return &DaemonClient{request: func(_ context.Context, command, event string, m viciMessage) (viciMessage, []viciMessage, error) {
		switch command {
		case "version":
			return viciMessage{"daemon": viciText("charon"), "version": viciText("6.1.0")}, nil, nil
		case "stats":
			return viciMessage{"plugins": viciList("vici", "kernel-netlink", "socket-default", "openssl", "random", "nonce", "kdf")}, nil, nil
		case "get-algorithms":
			a := viciMessage{}
			for class, name := range map[string]string{"encryption": "AES_CBC", "integrity": "HMAC_SHA2_256_128", "prf": "PRF_HMAC_SHA2_256", "ke": "MODP_2048"} {
				a[class] = viciSection(viciMessage{name: viciText("openssl")})
			}
			return a, nil, nil
		case "get-conns":
			return viciMessage{"conns": viciList()}, nil, nil
		case "get-shared":
			return viciMessage{"keys": viciList()}, nil, nil
		case "list-sas":
			return terminal, events, nil
		default:
			*mutations++
			return viciMessage{"success": viciText("yes")}, nil, nil
		}
	}}
}
func TestDaemonRejectsFailedEnumeration(t *testing.T) {
	for _, terminal := range []viciMessage{{"success": viciText("no")}, {"unexpected": viciText("marker")}} {
		calls := 0
		c := daemonInventoryStub(nil, terminal, &calls)
		if _, err := c.Inspect(context.Background()); err != ErrDaemonProtocol {
			t.Fatal("failed enumeration accepted")
		}
	}
}
func TestDaemonCleanupRefusesForeignTupleBeforeMutation(t *testing.T) {
	for _, field := range []string{"remote-host", "if-id-in", "local-ts", "name"} {
		t.Run(field, func(t *testing.T) {
			cfg := daemonFixture()
			fixture := daemonSAFixture()
			ike := fixture["owned"].section
			child := ike["child-sas"].section["child-1"].section
			child["name"] = viciText(engineName(cfg))
			switch field {
			case "remote-host":
				ike[field] = viciText("192.0.2.99")
			case "if-id-in":
				child[field] = viciText("000002be")
			case "local-ts":
				child[field] = viciList("10.11.0.0/24")
			case "name":
				child[field] = viciText("foreign")
			}
			events := []viciMessage{{engineName(cfg): viciSection(ike)}}
			calls := 0
			c := daemonInventoryStub(events, viciMessage{}, &calls)
			if err := c.removeTunnel(context.Background(), cfg); err != ErrDaemonProtocol || calls != 0 {
				t.Fatal("foreign tuple mutated")
			}
		})
	}
}
func TestDaemonRefusesPeerTransportRoutingLoop(t *testing.T) {
	cfg := daemonFixture()
	cfg.RemoteAddress = netip.MustParseAddr("10.20.0.1")
	if validEngineTunnel(cfg) {
		t.Fatal("peer routing loop accepted")
	}
	cfg = daemonFixture()
	cfg.LocalAddress = netip.MustParseAddr("10.10.0.1")
	if !validEngineTunnel(cfg) {
		t.Fatal("valid local NAT interface refused")
	}
}

func daemonSAFixture() viciMessage {
	return viciMessage{"owned": viciSection(viciMessage{"uniqueid": viciText("1"), "version": viciText("2"), "state": viciText("ESTABLISHED"), "local-host": viciText("192.0.2.1"), "remote-host": viciText("192.0.2.2"), "child-sas": viciSection(viciMessage{"child-1": viciSection(viciMessage{"name": viciText("owned"), "uniqueid": viciText("3"), "reqid": viciText("7"), "state": viciText("INSTALLED"), "mode": viciText("TUNNEL"), "protocol": viciText("ESP"), "if-id-in": viciText("000002bd"), "if-id-out": viciText("000002bd"), "spi-in": viciText("12345678"), "spi-out": viciText("87654321"), "local-ts": viciList("10.10.0.0/24"), "remote-ts": viciList("10.20.0.0/24"), "encr-alg": viciText("AES_CBC"), "encr-keysize": viciText("256"), "integ-alg": viciText("HMAC_SHA2_256_128"), "bytes-in": viciText("12"), "bytes-out": viciText("13")})})})}
}

func TestDaemonCleanupAcceptsExactObservedOwnership(t *testing.T) {
	cfg := daemonFixture()
	event := daemonSAFixture()
	ike := event["owned"].section
	ike["child-sas"].section["child-1"].section["name"] = viciText(engineName(cfg))
	calls := 0
	reads := 0
	c := daemonInventoryStub(nil, viciMessage{}, &calls)
	base := c.request
	c.request = func(ctx context.Context, cmd, eventName string, m viciMessage) (viciMessage, []viciMessage, error) {
		if cmd == "list-sas" {
			reads++
			if reads == 1 {
				return viciMessage{}, []viciMessage{{engineName(cfg): viciSection(ike)}}, nil
			}
		}
		return base(ctx, cmd, eventName, m)
	}
	if err := c.removeTunnel(context.Background(), cfg); err != nil || calls != 1 || reads != 2 {
		t.Fatal("exact owned SA cleanup failed")
	}
}

func TestDaemonEngineConfigDoesNotInventPolicyRevision(t *testing.T) {
	cfg := daemonFixture()
	cfg.Binding.PolicyRevision = 0
	if !validEngineTunnel(cfg) {
		t.Fatal("nonsecret engine configuration must not require fake policy authority")
	}
	// Engine configuration is not a permit. Runtime leases separately bind the
	// current authoritative policy hash before a packet permit can be installed.
}
