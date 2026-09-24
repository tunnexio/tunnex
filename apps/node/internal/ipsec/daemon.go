package ipsec

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// DaemonClient controls only the dedicated, locally owned Unix VICI endpoint.
// Mutation methods remain package-private until the refusal controller calls them.
// A successful command never grants runtime capability or proves traffic delivery.
type DaemonClient struct {
	request func(context.Context, string, string, viciMessage) (viciMessage, []viciMessage, error)
}

func NewDaemonClient(socketPath string) (*DaemonClient, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, ErrDaemonProtocol
	}
	transport := viciTransport{dial: func(ctx context.Context) (net.Conn, error) { return dialOwnedVICI(ctx, socketPath) }}
	return &DaemonClient{request: transport.call}, nil
}
func dialOwnedVICI(ctx context.Context, path string) (net.Conn, error) {
	if ctx == nil || !filepath.IsAbs(path) {
		return nil, ErrDaemonProtocol
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, ErrDaemonProtocol
	}
	for _, entry := range []struct {
		path   string
		socket bool
	}{{parent, false}, {path, true}} {
		info, err := os.Lstat(entry.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return nil, ErrDaemonProtocol
		}
		if !ownedByCurrentUser(info) {
			return nil, ErrDaemonProtocol
		}
		if entry.socket {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, ErrDaemonProtocol
			}
		} else if !info.IsDir() {
			return nil, ErrDaemonProtocol
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrDaemonProtocol
	}
	return conn, nil
}

type DaemonInventory struct {
	Daemon, Version                  string
	Plugins, Connections, SharedKeys []string
	SAs                              []DaemonIKE
}
type DaemonIKE struct {
	Name                        string
	UniqueID                    uint64
	Established                 bool
	LocalAddress, RemoteAddress netip.Addr
	Children                    []DaemonChild
}
type DaemonChild struct {
	Name                                  string
	UniqueID                              uint64
	ReqID, IfIDIn, IfIDOut, SPIIn, SPIOut uint32
	Installed                             bool
	LocalPrefixes, RemotePrefixes         []netip.Prefix
	BytesIn, BytesOut                     uint64
}

func (c *DaemonClient) Inspect(ctx context.Context) (DaemonInventory, error) {
	invalid := func() (DaemonInventory, error) { return DaemonInventory{}, ErrDaemonProtocol }
	if c == nil || c.request == nil {
		return invalid()
	}
	version, _, err := c.request(ctx, "version", "", viciMessage{})
	if err != nil {
		return invalid()
	}
	daemon, ok := viciString(version, "daemon")
	if !ok || daemon != "charon" {
		return invalid()
	}
	release, ok := viciString(version, "version")
	if !ok || release != "6.1.0" {
		return invalid()
	}
	stats, _, err := c.request(ctx, "stats", "", viciMessage{})
	if err != nil {
		return invalid()
	}
	plugins, ok := viciStrings(stats, "plugins")
	if !ok {
		return invalid()
	}
	for _, required := range []string{"vici", "kernel-netlink", "socket-default", "openssl", "random", "nonce", "kdf"} {
		if !containsString(plugins, required) {
			return invalid()
		}
	}
	algorithms, _, err := c.request(ctx, "get-algorithms", "", viciMessage{})
	if err != nil || !verifyEngineAlgorithms(algorithms) {
		return invalid()
	}
	conns, err := c.identifiers(ctx, "get-conns", "conns")
	if err != nil {
		return invalid()
	}
	keys, err := c.identifiers(ctx, "get-shared", "keys")
	if err != nil {
		return invalid()
	}
	terminal, events, err := c.request(ctx, "list-sas", "list-sa", viciMessage{})
	if err != nil || len(terminal) != 0 {
		return invalid()
	}
	sas, err := parseDaemonSAs(events)
	if err != nil {
		return invalid()
	}
	return DaemonInventory{Daemon: daemon, Version: release, Plugins: plugins, Connections: conns, SharedKeys: keys, SAs: sas}, nil
}
func (c *DaemonClient) identifiers(ctx context.Context, command, key string) ([]string, error) {
	m, _, err := c.request(ctx, command, "", viciMessage{})
	if err != nil {
		return nil, ErrDaemonProtocol
	}
	values, ok := viciStrings(m, key)
	if !ok {
		return nil, ErrDaemonProtocol
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validVICIName(value) || seen[value] {
			return nil, ErrDaemonProtocol
		}
		seen[value] = true
	}
	return values, nil
}
func viciString(m viciMessage, key string) (string, bool) {
	v, ok := m[key]
	return string(v.scalar), ok && v.kind == 3
}
func viciStrings(m viciMessage, key string) ([]string, bool) {
	v, ok := m[key]
	if !ok || v.kind != 4 {
		return nil, false
	}
	out := make([]string, 0, len(v.list))
	for _, item := range v.list {
		out = append(out, string(item))
	}
	return out, true
}
func viciUint(m viciMessage, key string, bits int) (uint64, bool) {
	s, ok := viciString(m, key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, bits)
	return n, err == nil && strconv.FormatUint(n, 10) == s
}
func viciHex(m viciMessage, key string) (uint32, bool) {
	s, ok := viciString(m, key)
	if !ok {
		return 0, false
	}
	s = strings.TrimPrefix(s, "0x")
	if len(s) == 0 || len(s) > 8 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 16, 32)
	return uint32(n), err == nil
}
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func daemonPrefixes(m viciMessage, key string) ([]netip.Prefix, bool) {
	values, ok := viciStrings(m, key)
	if !ok || len(values) == 0 || len(values) > 64 {
		return nil, false
	}
	out := make([]netip.Prefix, 0, len(values))
	seen := map[netip.Prefix]bool{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, e := netip.ParseAddr(value)
			if e != nil || !addr.Is4() {
				return nil, false
			}
			prefix = netip.PrefixFrom(addr, 32)
		}
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || seen[prefix] {
			return nil, false
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	return out, true
}
func parseDaemonSAs(events []viciMessage) ([]DaemonIKE, error) {
	out := []DaemonIKE{}
	ikeIDs := map[uint64]bool{}
	childIDs := map[uint64]bool{}
	for _, event := range events {
		for name, value := range event {
			if value.kind != 1 || !validVICIName(name) {
				return nil, ErrDaemonProtocol
			}
			m := value.section
			id, ok := viciUint(m, "uniqueid", 64)
			if !ok || id == 0 || ikeIDs[id] {
				return nil, ErrDaemonProtocol
			}
			ikeIDs[id] = true
			version, ok := viciString(m, "version")
			if !ok || version != "2" {
				return nil, ErrDaemonProtocol
			}
			state, ok := viciString(m, "state")
			if !ok || !containsString([]string{"CREATED", "CONNECTING", "ESTABLISHED", "PASSIVE", "REKEYING", "REKEYED", "DELETING", "DESTROYING"}, state) {
				return nil, ErrDaemonProtocol
			}
			local, _ := viciString(m, "local-host")
			remote, _ := viciString(m, "remote-host")
			la, le := netip.ParseAddr(local)
			ra, re := netip.ParseAddr(remote)
			if le != nil || re != nil || !la.Is4() || !ra.Is4() {
				return nil, ErrDaemonProtocol
			}
			ike := DaemonIKE{Name: name, UniqueID: id, Established: state == "ESTABLISHED", LocalAddress: la, RemoteAddress: ra, Children: []DaemonChild{}}
			children, exists := m["child-sas"]
			if exists && children.kind != 1 {
				return nil, ErrDaemonProtocol
			}
			for _, value := range children.section {
				if value.kind != 1 {
					return nil, ErrDaemonProtocol
				}
				child, err := parseDaemonChild(value.section)
				if err != nil || childIDs[child.UniqueID] {
					return nil, ErrDaemonProtocol
				}
				childIDs[child.UniqueID] = true
				ike.Children = append(ike.Children, child)
			}
			out = append(out, ike)
		}
	}
	return out, nil
}
func parseDaemonChild(m viciMessage) (DaemonChild, error) {
	invalid := func() (DaemonChild, error) { return DaemonChild{}, ErrDaemonProtocol }
	name, ok := viciString(m, "name")
	if !ok || !validVICIName(name) {
		return invalid()
	}
	id, ok := viciUint(m, "uniqueid", 64)
	if !ok || id == 0 {
		return invalid()
	}
	req, ok := viciUint(m, "reqid", 32)
	if !ok || req == 0 {
		return invalid()
	}
	state, ok := viciString(m, "state")
	if !ok || !containsString([]string{"CREATED", "ROUTED", "INSTALLING", "INSTALLED", "UPDATING", "REKEYING", "REKEYED", "RETRYING", "DELETING", "DELETED", "DESTROYING"}, state) {
		return invalid()
	}
	mode, ok := viciString(m, "mode")
	if !ok || mode != "TUNNEL" {
		return invalid()
	}
	protocol, ok := viciString(m, "protocol")
	if !ok || protocol != "ESP" {
		return invalid()
	}
	for key, want := range map[string]string{"encr-alg": "AES_CBC", "encr-keysize": "256", "integ-alg": "HMAC_SHA2_256_128"} {
		if got, ok := viciString(m, key); !ok || got != want {
			return invalid()
		}
	}
	local, ok := daemonPrefixes(m, "local-ts")
	if !ok {
		return invalid()
	}
	remote, ok := daemonPrefixes(m, "remote-ts")
	if !ok {
		return invalid()
	}
	in, ok := viciHex(m, "if-id-in")
	if !ok || in == 0 {
		return invalid()
	}
	out, ok := viciHex(m, "if-id-out")
	if !ok || out == 0 {
		return invalid()
	}
	spiIn, ok := viciHex(m, "spi-in")
	if !ok || spiIn == 0 {
		return invalid()
	}
	spiOut, ok := viciHex(m, "spi-out")
	if !ok || spiOut == 0 {
		return invalid()
	}
	bytesIn, ok := viciUint(m, "bytes-in", 64)
	if !ok {
		return invalid()
	}
	bytesOut, ok := viciUint(m, "bytes-out", 64)
	if !ok {
		return invalid()
	}
	return DaemonChild{Name: name, UniqueID: id, ReqID: uint32(req), IfIDIn: in, IfIDOut: out, SPIIn: spiIn, SPIOut: spiOut, Installed: state == "INSTALLED", LocalPrefixes: local, RemotePrefixes: remote, BytesIn: bytesIn, BytesOut: bytesOut}, nil
}

// EngineTunnel contains only explicit facts supplied by the owning controller.
// LocalAddress is the actual local underlay address; LocalIdentity may be the
// separately configured public NAT identity. Neither is inferred from a name.
type EngineTunnel struct {
	Binding                                                    Binding
	TunnelID                                                   uuid.UUID
	SecretRevision                                             int64
	XFRMID                                                     uint32
	ReqID                                                      uint32
	LocalAddress, RemoteAddress, LocalIdentity, RemoteIdentity netip.Addr
	LocalPrefixes, RemotePrefixes                              []netip.Prefix
}

func engineName(t EngineTunnel) string {
	return "tnx-ipsec-" + t.TunnelID.String() + "-d" + strconv.FormatInt(t.Binding.DesiredRevision, 10) + "-c" + strconv.FormatInt(t.Binding.ConfigurationRevision, 10) + "-s" + strconv.FormatInt(t.SecretRevision, 10)
}

// Engine configuration is not traffic authority. A policy revision is not
// required here: production permits use the current CP policy hash separately.
func validEngineTunnel(t EngineTunnel) bool {
	if t.Binding.OrgID == uuid.Nil || t.Binding.GatewayID == uuid.Nil || t.Binding.ConnectionID == uuid.Nil || t.Binding.DesiredRevision <= 0 || t.Binding.ConfigurationRevision <= 0 || t.TunnelID == uuid.Nil || t.SecretRevision <= 0 || t.XFRMID == 0 {
		return false
	}
	for _, a := range []netip.Addr{t.LocalAddress, t.RemoteAddress, t.LocalIdentity, t.RemoteIdentity} {
		if !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return false
		}
	}
	if t.LocalAddress == t.RemoteAddress || t.LocalIdentity == t.RemoteIdentity {
		return false
	}
	for _, prefix := range t.RemotePrefixes {
		if prefix.Contains(t.RemoteAddress) {
			return false
		}
	}
	seen := []netip.Prefix{}
	for _, side := range [][]netip.Prefix{t.LocalPrefixes, t.RemotePrefixes} {
		if len(side) == 0 || len(side) > 64 {
			return false
		}
		for _, p := range side {
			if !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 || p != p.Masked() {
				return false
			}
			for _, old := range seen {
				if old.Overlaps(p) {
					return false
				}
			}
			seen = append(seen, p)
		}
	}
	return true
}
func enginePrefixes(prefixes []netip.Prefix) viciValue {
	values := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		values = append(values, p.String())
	}
	return viciList(values...)
}
func validEnginePSK(psk []byte) bool {
	if len(psk) < 8 || len(psk) > 64 || psk[0] == '0' {
		return false
	}
	for _, c := range psk {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// stageTunnel is private because loading a responder is itself a mutation that
// requires verified denial, even with start_action=none. No automatic retry or
// rollback is attempted: the controller retains the durable cleanup obligation.
func (c *DaemonClient) stageTunnel(ctx context.Context, t EngineTunnel, psk []byte) error {
	if c == nil || c.request == nil || !validEngineTunnel(t) || !validEnginePSK(psk) {
		return ErrDaemonProtocol
	}
	name := engineName(t)
	conns, err := c.identifiers(ctx, "get-conns", "conns")
	if err != nil || containsString(conns, name) {
		return ErrDaemonProtocol
	}
	keys, err := c.identifiers(ctx, "get-shared", "keys")
	if err != nil || containsString(keys, name) {
		return ErrDaemonProtocol
	}
	shared := viciMessage{"id": viciText(name), "type": viciText("IKE"), "data": viciScalar(psk), "owners": viciList(t.LocalIdentity.String(), t.RemoteIdentity.String())}
	if c.success(ctx, "load-shared", shared) != nil {
		return ErrDaemonProtocol
	}
	child := viciMessage{"mode": viciText("tunnel"), "local_ts": enginePrefixes(t.LocalPrefixes), "remote_ts": enginePrefixes(t.RemotePrefixes), "esp_proposals": viciList("aes256-sha256-modp2048"), "start_action": viciText("none"), "dpd_action": viciText("clear"), "close_action": viciText("none"), "if_id_in": viciText(strconv.FormatUint(uint64(t.XFRMID), 10)), "if_id_out": viciText(strconv.FormatUint(uint64(t.XFRMID), 10)), "life_time": viciText("3600s"), "rekey_time": viciText("3000s")}
	if t.ReqID != 0 {
		child["reqid"] = viciText(strconv.FormatUint(uint64(t.ReqID), 10))
	}
	conn := viciMessage{"version": viciText("2"), "local_addrs": viciList(t.LocalAddress.String()), "remote_addrs": viciList(t.RemoteAddress.String()), "proposals": viciList("aes256-sha256-modp2048"), "mobike": viciText("no"), "rekey_time": viciText("28800s"), "reauth_time": viciText("0s"), "local": viciSection(viciMessage{"auth": viciText("psk"), "id": viciText(t.LocalIdentity.String())}), "remote": viciSection(viciMessage{"auth": viciText("psk"), "id": viciText(t.RemoteIdentity.String())}), "children": viciSection(viciMessage{name: viciSection(child)})}
	return c.success(ctx, "load-conn", viciMessage{name: viciSection(conn)})
}
func (c *DaemonClient) success(ctx context.Context, command string, m viciMessage) error {
	out, _, err := c.request(ctx, command, "", m)
	success, ok := viciString(out, "success")
	if err != nil || !ok || success != "yes" {
		return ErrDaemonProtocol
	}
	return nil
}
func (c *DaemonClient) initiateTunnel(ctx context.Context, t EngineTunnel) error {
	if !validEngineTunnel(t) {
		return ErrDaemonProtocol
	}
	name := engineName(t)
	return c.success(ctx, "initiate", viciMessage{"ike": viciText(name), "child": viciText(name), "timeout": viciText("20000"), "loglevel": viciText("-1")})
}

// removeTunnel requires already-verified refusal and an exact owned intent from
// the durable controller. Never terminate by wildcard or clear all credentials.
func (c *DaemonClient) removeTunnel(ctx context.Context, t EngineTunnel) error {
	if !validEngineTunnel(t) {
		return ErrDaemonProtocol
	}
	name := engineName(t)
	inventory, err := c.Inspect(ctx)
	if err != nil {
		return ErrDaemonProtocol
	}
	// Check every matching observation before the first mutation. Names alone
	// cannot establish ownership of live SAs. Durable stage ownership is also
	// required for stored configurations, whose VICI listing omits XFRM IDs.
	for _, sa := range inventory.SAs {
		if sa.Name != name {
			continue
		}
		if sa.LocalAddress != t.LocalAddress || sa.RemoteAddress != t.RemoteAddress {
			return ErrDaemonProtocol
		}
		for _, child := range sa.Children {
			if child.Name != name || child.IfIDIn != t.XFRMID || child.IfIDOut != t.XFRMID || (t.ReqID != 0 && child.ReqID != t.ReqID) || !sameEnginePrefixes(child.LocalPrefixes, t.LocalPrefixes) || !sameEnginePrefixes(child.RemotePrefixes, t.RemotePrefixes) {
				return ErrDaemonProtocol
			}
		}
	}
	if containsString(inventory.Connections, name) {
		if c.success(ctx, "unload-conn", viciMessage{"name": viciText(name)}) != nil {
			return ErrDaemonProtocol
		}
	}
	for _, sa := range inventory.SAs {
		if sa.Name == name {
			if c.success(ctx, "terminate", viciMessage{"ike-id": viciText(strconv.FormatUint(sa.UniqueID, 10)), "timeout": viciText("5000"), "loglevel": viciText("-1")}) != nil {
				return ErrDaemonProtocol
			}
		}
	}
	if containsString(inventory.SharedKeys, name) {
		if c.success(ctx, "unload-shared", viciMessage{"id": viciText(name)}) != nil {
			return ErrDaemonProtocol
		}
	}
	after, err := c.Inspect(ctx)
	if err != nil || containsString(after.Connections, name) || containsString(after.SharedKeys, name) {
		return ErrDaemonProtocol
	}
	for _, sa := range after.SAs {
		if sa.Name == name {
			return ErrDaemonProtocol
		}
	}
	return nil
}

func verifyEngineAlgorithms(message viciMessage) bool {
	for class, name := range map[string]string{"encryption": "AES_CBC", "integrity": "HMAC_SHA2_256_128", "prf": "PRF_HMAC_SHA2_256", "ke": "MODP_2048"} {
		section, ok := message[class]
		if !ok || section.kind != 1 {
			return false
		}
		provider, ok := viciString(section.section, name)
		if !ok || provider != "openssl" {
			return false
		}
	}
	return true
}

func sameEnginePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range a {
		if seen[p] {
			return false
		}
		seen[p] = true
	}
	for _, p := range b {
		if !seen[p] {
			return false
		}
		delete(seen, p)
	}
	return len(seen) == 0
}
