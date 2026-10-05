//go:build linux

package sandboxnetwork

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Admission struct{ WorkerUID, SubUIDStart, SubUIDCount uint32 }

// AdmitNamespace verifies the inherited descriptor, not a reusable PID/path.
// Nested keep-id namespaces must have a bounded owner ancestry ending at the
// configured worker's rootless namespace. Host/initial user namespaces refuse.
func AdmitNamespace(file *os.File, a Admission) (NamespaceIdentity, error) {
	if file == nil || a.WorkerUID == 0 || a.SubUIDCount == 0 || uint64(a.SubUIDStart)+uint64(a.SubUIDCount) > 1<<32 {
		return NamespaceIdentity{}, ErrInvalid
	}
	fd := int(file.Fd())
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return NamespaceIdentity{}, ErrOwnership
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return NamespaceIdentity{}, ErrOwnership
	}
	var target unix.Stat_t
	if unix.Fstat(fd, &target) != nil {
		return NamespaceIdentity{}, ErrOwnership
	}
	// The host helper has no PrivateUsers/PrivateNetwork. Verify its initial
	// user mapping, then inspect its own namespace descriptors: reading PID 1
	// would unnecessarily require ptrace permission when its service GID differs.
	mapping, mappingErr := os.ReadFile("/proc/self/uid_map")
	if mappingErr != nil || strings.Join(strings.Fields(string(mapping)), " ") != "0 0 4294967295" {
		return NamespaceIdentity{}, ErrOwnership
	}
	host, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return NamespaceIdentity{}, ErrUnavailable
	}
	defer host.Close()
	var initialNet unix.Stat_t
	if unix.Fstat(int(host.Fd()), &initialNet) != nil || (target.Dev == initialNet.Dev && target.Ino == initialNet.Ino) {
		return NamespaceIdentity{}, ErrOwnership
	}
	initial, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return NamespaceIdentity{}, ErrUnavailable
	}
	defer initial.Close()
	var initialUser unix.Stat_t
	if unix.Fstat(int(initial.Fd()), &initialUser) != nil {
		return NamespaceIdentity{}, ErrUnavailable
	}
	userFD, err := unix.IoctlRetInt(fd, unix.NS_GET_USERNS)
	if err != nil {
		return NamespaceIdentity{}, ErrOwnership
	}
	fds := []int{userFD}
	defer func() {
		for _, opened := range fds {
			unix.Close(opened)
		}
	}()
	workerAncestor := false
	for range 8 {
		var st unix.Stat_t
		if unix.Fstat(userFD, &st) != nil {
			return NamespaceIdentity{}, ErrOwnership
		}
		if st.Dev == initialUser.Dev && st.Ino == initialUser.Ino {
			if !workerAncestor {
				return NamespaceIdentity{}, ErrOwnership
			}
			return NamespaceIdentity{uint64(target.Dev), target.Ino, a.WorkerUID}, nil
		}
		uid, err := unix.IoctlGetUint32(userFD, unix.NS_GET_OWNER_UID)
		if err != nil || (uid != a.WorkerUID && (uid < a.SubUIDStart || uint64(uid) >= uint64(a.SubUIDStart)+uint64(a.SubUIDCount))) {
			return NamespaceIdentity{}, ErrOwnership
		}
		workerAncestor = workerAncestor || uid == a.WorkerUID
		userFD, err = unix.IoctlRetInt(userFD, unix.NS_GET_PARENT)
		if err != nil {
			return NamespaceIdentity{}, ErrOwnership
		}
		fds = append(fds, userFD)
	}
	return NamespaceIdentity{}, ErrOwnership
}

// LinuxDriver uses fixed packaged tools and a pinned FD for every child. It
// never invokes a shell or emits raw command output/errors to API clients.
type LinuxDriver struct{}

var toolPaths = map[string]string{"ip": "/usr/sbin/ip", "wg": "/usr/bin/wg", "nsenter": "/usr/bin/nsenter"}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
func output(ctx context.Context, ns *os.File, stdin []byte, tool string, args ...string) ([]byte, error) {
	path, ok := toolPaths[tool]
	if !ok {
		return nil, ErrInvalid
	}
	for _, binary := range []string{path, toolPaths["nsenter"]} {
		st, err := os.Stat(binary)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
			return nil, ErrUnavailable
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if ns == nil {
		cmd = exec.CommandContext(ctx, path, args...)
	} else {
		argv := append([]string{"--net=/proc/self/fd/3", "--", path}, args...)
		cmd = exec.CommandContext(ctx, toolPaths["nsenter"], argv...)
		cmd.ExtraFiles = []*os.File{ns}
	}
	cmd.Stdin = bytes.NewReader(stdin)
	diagnostic := &boundedOutput{limit: 65536}
	cmd.Stderr = diagnostic
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LC_ALL=C"}
	buf := &boundedOutput{limit: 262144}
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && tool == "ip" && ns == nil && slices.Equal(args, []string{"-d", "-j", "link", "show", "dev", argsLast(args)}) {
			return nil, ErrMissing
		}
		code := "command-failed"
		for _, phrase := range []struct{ Text, Code string }{{"Permission denied", "permission-denied"}, {"Operation not permitted", "operation-not-permitted"}, {"Invalid argument", "invalid-argument"}, {"No such file or directory", "missing-path"}, {"Configuration parsing error", "configuration-parse"}} {
			if bytes.Contains(diagnostic.Bytes(), []byte(phrase.Text)) {
				code = phrase.Code
				break
			}
		}
		fmt.Fprintf(os.Stderr, "sandbox network tool rejected tool=%s code=%s\n", tool, code)
		// This exact inspection can only contain public interface/key metadata;
		// configuration commands and all stdin remain excluded from raw logs.
		if tool == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "public-key" {
			fmt.Fprintf(os.Stderr, "sandbox public interface inspection failed detail=%q\n", diagnostic.String())
		}

		return nil, ErrUnavailable
	}
	return buf.Bytes(), nil
}
func argsLast(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}
func (LinuxDriver) Command(ctx context.Context, ns *os.File, stdin []byte, tool string, args ...string) error {
	_, err := output(ctx, ns, stdin, tool, args...)
	return err
}

type linkJSON struct {
	Index int      `json:"ifindex"`
	Name  string   `json:"ifname"`
	Alias string   `json:"ifalias"`
	MTU   int      `json:"mtu"`
	Flags []string `json:"flags"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func parseLinks(raw []byte) ([]Link, error) {
	var rows []linkJSON
	if json.Unmarshal(raw, &rows) != nil {
		return nil, ErrUnavailable
	}
	out := make([]Link, len(rows))
	for i, r := range rows {
		out[i] = Link{r.Index, r.Name, r.Alias, r.Info.Kind, r.MTU, slices.Contains(r.Flags, "UP")}
	}
	return out, nil
}
func (LinuxDriver) BirthLink(ctx context.Context, p Plan) (Link, error) {
	raw, err := output(ctx, nil, nil, "ip", "-d", "-j", "link", "show", "dev", InterfaceName(p))
	if err != nil {
		return Link{}, err
	}
	links, err := parseLinks(raw)
	if err != nil || len(links) != 1 {
		return Link{}, ErrUnavailable
	}
	if !ownedLink(p, links[0]) {
		return Link{}, ErrOwnership
	}
	return links[0], nil
}
func (LinuxDriver) CreateBirthLink(ctx context.Context, p Plan) error {
	if _, err := Normalize(p); err != nil {
		return err
	}
	a := netlink.NewAttributeEncoder()
	a.String(unix.IFLA_IFNAME, InterfaceName(p))
	a.String(unix.IFLA_IFALIAS, Alias(p))
	a.Nested(unix.IFLA_LINKINFO, func(n *netlink.AttributeEncoder) error { n.String(unix.IFLA_INFO_KIND, "wireguard"); return nil })
	attrs, err := a.Encode()
	if err != nil {
		return ErrInvalid
	}
	if err = mutateLink(ctx, 0, attrs, true); err != nil {
		return err
	}
	// This kernel's WireGuard newlink path omits IFLA_IFALIAS on create.
	// Complete metadata only for the link this successful exclusive create
	// just produced; retries still refuse unaliased ambient birth links.
	raw, err := output(ctx, nil, nil, "ip", "-d", "-j", "link", "show", "dev", InterfaceName(p))
	if err != nil {
		return err
	}
	links, err := parseLinks(raw)
	if err != nil || len(links) != 1 || links[0].Index < 1 || links[0].Name != InterfaceName(p) || links[0].Kind != "wireguard" || (links[0].Alias != "" && links[0].Alias != Alias(p)) {
		return ErrOwnership
	}
	if links[0].Alias == "" {
		alias := netlink.NewAttributeEncoder()
		alias.String(unix.IFLA_IFALIAS, Alias(p))
		metadata, e := alias.Encode()
		if e != nil {
			return ErrInvalid
		}
		if e = mutateLink(ctx, links[0].Index, metadata, false); e != nil {
			return e
		}
	}
	_, err = (LinuxDriver{}).BirthLink(ctx, p)
	return err
}

// DeleteBirthLink recovers only an exact owned create-before-move resource.
func (d LinuxDriver) DeleteBirthLink(ctx context.Context, p Plan, expected Link) error {
	current, err := d.BirthLink(ctx, p)
	if err != nil {
		return err
	}
	if !ownedLink(p, current) || current.Index != expected.Index || current.Name != expected.Name || current.Alias != expected.Alias {
		return ErrOwnership
	}
	return d.Command(ctx, nil, nil, "ip", "link", "delete", "dev", current.Name)
}
func (LinuxDriver) MoveLink(ctx context.Context, link Link, ns *os.File) error {
	if ns == nil || link.Index < 1 {
		return ErrInvalid
	}
	a := netlink.NewAttributeEncoder()
	a.Uint32(unix.IFLA_NET_NS_FD, uint32(ns.Fd()))
	attrs, err := a.Encode()
	if err != nil {
		return ErrInvalid
	}
	return mutateLink(ctx, link.Index, attrs, false)
}
func mutateLink(ctx context.Context, index int, attrs []byte, create bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if conn.SetDeadline(deadline) != nil {
		return ErrUnavailable
	}
	info := make([]byte, unix.SizeofIfInfomsg)
	info[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(info[4:8], uint32(index))
	flags := netlink.Request | netlink.Acknowledge
	if create {
		flags |= netlink.Create | netlink.Excl
	}
	if _, err = conn.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: flags}, Data: append(info, attrs...)}); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (LinuxDriver) Snapshot(ctx context.Context, ns *os.File, p Plan) (Snapshot, error) {
	if ns == nil {
		return Snapshot{}, ErrInvalid
	}
	var out Snapshot
	raw, err := output(ctx, ns, nil, "ip", "-d", "-j", "link", "show")
	if err != nil {
		return out, err
	}
	out.Links, err = parseLinks(raw)
	if err != nil || len(out.Links) > 4 {
		return Snapshot{}, ErrOwnership
	}
	raw, err = output(ctx, ns, nil, "ip", "-j", "address", "show")
	if err != nil {
		return out, err
	}
	var addresses []struct {
		Name string `json:"ifname"`
		Info []struct {
			Local string `json:"local"`
			Bits  int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(raw, &addresses) != nil {
		return out, ErrUnavailable
	}
	for _, iface := range addresses {
		for _, a := range iface.Info {
			addr, err := netip.ParseAddr(a.Local)
			if err != nil {
				return out, ErrOwnership
			}
			prefix := netip.PrefixFrom(addr, a.Bits)
			if !prefix.IsValid() {
				return out, ErrOwnership
			}
			out.Addresses = append(out.Addresses, Address{iface.Name, prefix})
		}
	}
	for _, family := range []string{"-4", "-6"} {
		raw, err = output(ctx, ns, nil, "ip", family, "-j", "route", "show", "table", "all")
		if err != nil {
			return out, err
		}
		routes, err := parseRoutes(raw)
		if err != nil {
			return out, err
		}
		out.Routes = append(out.Routes, routes...)
		raw, err = output(ctx, ns, nil, "ip", family, "-j", "rule", "show")
		if err != nil {
			return out, err
		}
		if !defaultRules(raw, family) {
			return out, ErrOwnership
		}
	}
	out.DefaultRulesOnly = true
	name := InterfaceName(p)
	if !hasInterface(out, name) {
		return out, nil
	}
	raw, err = output(ctx, ns, nil, "wg", "show", name, "public-key")
	if err != nil {
		return out, err
	}
	out.PublicKey = strings.TrimSpace(string(raw))
	if out.PublicKey == "(none)" {
		out.PublicKey = ""
	}
	raw, err = output(ctx, ns, nil, "wg", "show", name, "peers")
	if err != nil {
		return out, err
	}
	peers := strings.Fields(string(raw))
	if len(peers) == 0 {
		return out, nil
	}
	if len(peers) != 1 {
		return out, ErrOwnership
	}
	peer := Peer{PublicKey: peers[0]}
	raw, err = output(ctx, ns, nil, "wg", "show", name, "endpoints")
	if err != nil {
		return out, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[0] != peer.PublicKey {
		return out, ErrOwnership
	}
	peer.Endpoint, err = netip.ParseAddrPort(fields[1])
	if err != nil {
		return out, ErrOwnership
	}
	raw, err = output(ctx, ns, nil, "wg", "show", name, "allowed-ips")
	if err != nil {
		return out, err
	}
	fields = strings.Fields(string(raw))
	if len(fields) < 2 || fields[0] != peer.PublicKey {
		return out, ErrOwnership
	}
	for _, v := range fields[1:] {
		route, err := netip.ParsePrefix(v)
		if err != nil {
			return out, ErrOwnership
		}
		peer.Routes = append(peer.Routes, route)
	}
	raw, err = output(ctx, ns, nil, "wg", "show", name, "persistent-keepalive")
	if err != nil {
		return out, err
	}
	fields = strings.Fields(string(raw))
	if len(fields) != 2 || fields[0] != peer.PublicKey {
		return out, ErrOwnership
	}
	peer.KeepaliveSeconds, err = strconv.Atoi(fields[1])
	if err != nil {
		return out, ErrOwnership
	}
	out.Peers = []Peer{peer}
	return out, nil
}

func parseRoutes(raw []byte) ([]Route, error) {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) > 128 {
		return nil, ErrOwnership
	}
	allowed := map[string]bool{"dst": true, "dev": true, "protocol": true, "scope": true, "prefsrc": true, "flags": true, "table": true, "type": true, "metric": true, "gateway": true, "pref": true}
	out := make([]Route, 0, len(rows))
	for _, r := range rows {
		for field := range r {
			if !allowed[field] {
				return nil, ErrOwnership
			}
		}
		var dst, dev, kind, gateway string
		if json.Unmarshal(r["dst"], &dst) != nil || json.Unmarshal(r["dev"], &dev) != nil {
			return nil, ErrOwnership
		}
		if value, ok := r["type"]; ok && json.Unmarshal(value, &kind) != nil {
			return nil, ErrOwnership
		}
		if kind != "" && kind != "unicast" && kind != "local" && kind != "broadcast" && kind != "multicast" {
			return nil, ErrOwnership
		}
		if value, ok := r["gateway"]; ok && json.Unmarshal(value, &gateway) != nil {
			return nil, ErrOwnership
		}
		if value, ok := r["table"]; ok && !slices.Contains([]string{`"main"`, `"local"`, `254`, `255`}, string(value)) {
			return nil, ErrOwnership
		}
		if kind == "multicast" {
			var protocol string
			if dst != "ff00::/8" || gateway != "" || string(r["table"]) != `"local"` || json.Unmarshal(r["protocol"], &protocol) != nil || protocol != "kernel" {
				return nil, ErrOwnership
			}
		}
		prefix, err := netip.ParsePrefix(dst)
		if err != nil {
			addr, e := netip.ParseAddr(dst)
			if e != nil {
				return nil, ErrOwnership
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		out = append(out, Route{dev, prefix, gateway, kind == "local" || kind == "broadcast" || kind == "multicast"})
	}
	return out, nil
}
func defaultRules(raw []byte, family string) bool {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || (len(rows) != 3 && !(family == "-6" && len(rows) == 2)) {
		return false
	}
	expected := map[int]string{0: "local", 32766: "main", 32767: "default"}
	if len(rows) == 2 {
		delete(expected, 32767)
	}
	for _, r := range rows {
		for field := range r {
			if field != "priority" && field != "src" && field != "table" && field != "protocol" {
				return false
			}
		}
		var priority int
		var src, table string
		if json.Unmarshal(r["priority"], &priority) != nil || json.Unmarshal(r["src"], &src) != nil || src != "all" || json.Unmarshal(r["table"], &table) != nil || expected[priority] != table {
			return false
		}
		delete(expected, priority)
	}
	return len(expected) == 0
}
