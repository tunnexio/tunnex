//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The manager's reader of the `cilium` section, on the captured Cilium 1.20.5
// node (cilium_live_test.go says what the captures are).

// capturedCiliumNode answers the reader's four reads from captured files and
// records what was asked.
type capturedCiliumNode struct {
	t         *testing.T
	links     []string
	status    []byte
	statusErr error
	pins      []string
	pinErr    error
	dump      string
	dumpErr   error
	ran       []string
}

func newCapturedCiliumNode(t *testing.T, prefix string) *capturedCiliumNode {
	t.Helper()
	n := &capturedCiliumNode{t: t, status: ciliumLiveRead(t, prefix+"healthz.json"), pins: strings.Fields(string(ciliumLiveRead(t, prefix+"pinned-maps.txt")))}
	for _, name := range strings.Fields(string(ciliumLiveRead(t, prefix+"links.txt"))) {
		// `ip -o link` prints a peer suffix; the kernel's device list does not.
		name, _, _ = strings.Cut(name, "@")
		n.links = append(n.links, name)
	}
	if dump, err := os.ReadFile(prefix + "ipmasq-v4.bpftool.json"); err == nil {
		n.dump = string(dump)
		if strings.HasPrefix(strings.TrimSpace(n.dump), "{") {
			// bpftool printed its error object and exited 255.
			n.dumpErr = errors.New("bpftool inspection: exit status 255: ")
		}
	} else {
		n.dump, n.dumpErr = `{"error":"bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory"}`, errors.New("bpftool inspection: exit status 255: ")
	}
	return n
}

func (n *capturedCiliumNode) reader() *CiliumFactsReader {
	r := NewCiliumFactsReader(
		func() ([]string, error) { n.ran = append(n.ran, "links"); return n.links, nil },
		func(context.Context) ([]byte, error) {
			n.ran = append(n.ran, "GET /v1/healthz")
			return n.status, n.statusErr
		},
		func(context.Context) ([]string, error) { n.ran = append(n.ran, "list pins"); return n.pins, n.pinErr },
		func(_ context.Context, args ...string) (string, error) {
			n.ran = append(n.ran, "bpftool "+strings.Join(args, " "))
			return n.dump, n.dumpErr
		},
	)
	// No file of the test host is consulted for the socket.
	r.socket = filepath.Join(n.t.TempDir(), "absent.sock")
	return r
}

const ciliumDumpCommand = "bpftool --json map dump pinned /sys/fs/bpf/tc/globals/cilium_ipmasq_v4"

func TestCiliumReaderBuildsTheSectionOfTheCapturedNodes(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix string
		want   *CiliumFacts
		dumps  int
	}{
		"A": {prefix: ciliumLiveA, want: ciliumFactsA(t)},
		"B": {prefix: ciliumLiveB, want: ciliumFactsB(t), dumps: 1},
		"C": {prefix: ciliumLiveC, want: ciliumFactsC(t)},
	} {
		node := newCapturedCiliumNode(t, tc.prefix)
		got := node.reader().Read(t.Context())
		if got == nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: facts = %+v, want %+v", name, got, tc.want)
		}
		// The map is dumped only when the status says the ip-masq-agent is on,
		// and the status is asked for once.
		if count(node.ran, ciliumDumpCommand) != tc.dumps || count(node.ran, "GET /v1/healthz") != 1 || len(node.ran) != 3+tc.dumps {
			t.Errorf("%s: ran %v", name, node.ran)
		}
	}
	// The receipt carries a few hundred bytes of the status, not all 11 KiB.
	if facts := ciliumFactsB(t); len(facts.Status.Text) > 400 || facts.PinnedMaps.Total != 47 || facts.IPMasqMap.Text != `[{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}]` {
		t.Errorf("B facts = %+v", facts)
	}
}

func TestCiliumReaderPublishesNothingOnANodeWithoutCilium(t *testing.T) {
	node := &capturedCiliumNode{t: t, links: []string{"lo", "eth0", "flannel.1", "cni0", "wg0", "mycilium_0"}, pinErr: fs.ErrNotExist}
	if facts := node.reader().Read(t.Context()); facts != nil {
		t.Fatalf("facts = %+v", facts)
	}
	if !reflect.DeepEqual(node.ran, []string{"links", "list pins"}) {
		t.Fatalf("ran %v", node.ran)
	}
	// Maps pinned by something else do not make it a Cilium node either.
	node = &capturedCiliumNode{t: t, links: []string{"lo"}, pins: []string{"calico_failsafe", "xdp_stats"}}
	if facts := node.reader().Read(t.Context()); facts != nil {
		t.Fatalf("facts = %+v", facts)
	}
}

// Each trace alone makes the node a Cilium node: a device, a pinned map, or
// the agent's socket.
func TestCiliumReaderDetectsEachTraceAlone(t *testing.T) {
	a := newCapturedCiliumNode(t, ciliumLiveA)
	for name, node := range map[string]*capturedCiliumNode{
		"device": {t: t, links: []string{"lo", "cilium_host"}, status: a.status, pinErr: fs.ErrNotExist},
		"map":    {t: t, links: []string{"lo"}, status: a.status, pins: []string{"cilium_lxc"}},
	} {
		if facts := node.reader().Read(t.Context()); facts == nil || facts.Status.State != FactsRead {
			t.Errorf("%s: facts = %+v", name, facts)
		}
	}
	node := &capturedCiliumNode{t: t, links: []string{"lo"}, status: a.status, pinErr: fs.ErrNotExist}
	reader := node.reader()
	if err := os.WriteFile(reader.socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	facts := reader.Read(t.Context())
	if facts == nil || facts.Status.State != FactsRead || facts.PinnedMaps.State != FactsUnreadable || !strings.Contains(facts.PinnedMaps.Reason, "set cilium.enabled=true on the tunnex-host-posture chart") {
		t.Fatalf("socket alone: facts = %+v", facts)
	}
}

func TestCiliumReaderStatesWhatItCouldNotRead(t *testing.T) {
	type want struct{ status, pins, ipmasq string }
	for name, tc := range map[string]struct {
		prefix string
		mutate func(*capturedCiliumNode)
		want   want
	}{
		"socket not there": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				n.statusErr = &net.OpError{Op: "dial", Net: "unix", Err: fs.ErrNotExist}
			},
			want: want{status: "unreadable: no agent socket at ", ipmasq: "unreadable: the agent status was not read"},
		},
		"agent does not answer": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				n.statusErr = errors.New(`Get "http://localhost/v1/healthz": dial unix /var/run/cilium/cilium.sock: connect: connection refused`)
			},
			want: want{status: `unreadable: GET /v1/healthz on the agent socket: Get "http://localhost/v1/healthz": dial unix /var/run/cilium/cilium.sock: connect: connection refused`, ipmasq: "unreadable: the agent status was not read"},
		},
		"status that is not JSON": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) { n.status = []byte("<html>") },
			want:   want{status: "unreadable: Cilium status is not a JSON object", ipmasq: "unreadable: the agent status was not read"},
		},
		"status over the bound": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) { n.status = make([]byte, maxCiliumStatusBytes+1) },
			want:   want{status: "unreadable: Cilium status exceeds bound", ipmasq: "unreadable: the agent status was not read"},
		},
		// The status is carried as it is; the gateway refuses it by name.
		"masquerading report with an unknown field": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				n.status = []byte(`{"masquerading":{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","ip-masq-agent":true,"snat-exclusion-cidr-v4":"10.244.0.0/16","new-field":1}}`)
			},
			want: want{status: "read", ipmasq: "unreadable: the agent status is not understood"},
		},
		"pin directory not there": {
			prefix: ciliumLiveA,
			mutate: func(n *capturedCiliumNode) { n.pins, n.pinErr = nil, fs.ErrNotExist },
			want:   want{status: "read", pins: "unreadable: no pinned maps at /sys/fs/bpf/tc/globals; set cilium.enabled=true on the tunnex-host-posture chart", ipmasq: "not_needed: the agent reports that its ip-masq-agent is off"},
		},
		"pin directory not listable": {
			prefix: ciliumLiveA,
			mutate: func(n *capturedCiliumNode) {
				n.pins, n.pinErr = nil, errors.New("open /sys/fs/bpf/tc/globals: permission denied")
			},
			want: want{status: "read", pins: "unreadable: list pinned maps: open /sys/fs/bpf/tc/globals: permission denied", ipmasq: "not_needed: the agent reports that its ip-masq-agent is off"},
		},
		"egress-gateway map with a strange name": {
			prefix: ciliumLiveA,
			mutate: func(n *capturedCiliumNode) { n.pins = append(n.pins, "cilium_egress_gw_policy_v4 x") },
			want:   want{status: "read", pins: "unreadable: an egress-gateway map has a name that is not understood", ipmasq: "not_needed: the agent reports that its ip-masq-agent is off"},
		},
		// Seen live: the agent says ip-masq-agent is on, the pin is not there.
		// bpftool prints an error object and exits 255. That is not an empty map.
		"map not pinned": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				n.dump, n.dumpErr = string(ciliumLiveRead(t, ciliumLiveA+"ipmasq-v4.bpftool.json")), errors.New("bpftool inspection: exit status 255: ")
			},
			want: want{status: "read", ipmasq: "unreadable: bpftool: bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory"},
		},
		"error object with exit status 0": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) { n.dump = `{"error":"something else"}` },
			want:   want{status: "read", ipmasq: "unreadable: bpftool: something else"},
		},
		"bpftool not in the image": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				n.dump, n.dumpErr = "", errors.New(`bpftool inspection: exec: "bpftool": executable file not found in $PATH: `)
			},
			want: want{status: "read", ipmasq: `unreadable: bpftool inspection: exec: "bpftool": executable file not found in $PATH:`},
		},
		"bpftool failed after printing a map": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) { n.dumpErr = errors.New("bpftool inspection: signal: killed: ") },
			want:   want{status: "read", ipmasq: "unreadable: bpftool inspection: signal: killed:"},
		},
		"bpftool printed nothing": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) { n.dump = "\n" },
			want:   want{status: "read", ipmasq: "unreadable: bpftool did not print a map"},
		},
		// A map that does not fit is never cut to the part that does.
		"map over the bound": {
			prefix: ciliumLiveB,
			mutate: func(n *capturedCiliumNode) {
				entry := `{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}`
				n.dump = "[" + strings.Repeat(entry+",", MaxCiliumMapFactBytes/len(entry)) + entry + "]"
			},
			want: want{status: "read", ipmasq: fmt.Sprintf("unreadable: the ip-masq-agent map dump exceeds %d bytes", MaxCiliumMapFactBytes)},
		},
	} {
		node := newCapturedCiliumNode(t, tc.prefix)
		tc.mutate(node)
		facts := node.reader().Read(t.Context())
		if facts == nil {
			t.Errorf("%s: no facts", name)
			continue
		}
		if err := facts.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		state := func(s, reason string) string {
			if reason == "" {
				return s
			}
			return s + ": " + reason
		}
		got := want{state(facts.Status.State, facts.Status.Reason), state(facts.PinnedMaps.State, facts.PinnedMaps.Reason), state(facts.IPMasqMap.State, facts.IPMasqMap.Reason)}
		if tc.want.pins == "" {
			tc.want.pins = "read"
		}
		if !strings.HasPrefix(got.status, tc.want.status) || got.pins != tc.want.pins || got.ipmasq != tc.want.ipmasq {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
		if facts.Status.State != FactsRead && facts.Status.Text != "" || facts.IPMasqMap.State != FactsRead && facts.IPMasqMap.Text != "" {
			t.Errorf("%s: an unread fact carries text", name)
		}
		// Whatever could not be read, the gateway refuses the node.
		if tc.prefix == ciliumLiveB {
			if _, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/24")); !errors.Is(err, errCiliumNotVerified) {
				t.Errorf("%s: decision = %v", name, err)
			}
		}
	}
}

func TestCiliumReaderEgressGatewayPinsAreCarriedByName(t *testing.T) {
	node := newCapturedCiliumNode(t, ciliumLiveB)
	node.pins = append(node.pins, "cilium_egress_gw_policy_v4_v2", "cilium_egress_gw_policy_v4")
	facts := node.reader().Read(t.Context())
	if facts == nil || !reflect.DeepEqual(facts.PinnedMaps.EgressGateway, []string{"cilium_egress_gw_policy_v4", "cilium_egress_gw_policy_v4_v2"}) || facts.PinnedMaps.Total != 49 {
		t.Fatalf("facts = %+v", facts)
	}
	if _, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/24")); !errors.Is(err, errCiliumEgressGateway) {
		t.Fatalf("decision = %v", err)
	}
	// cilium_egresscall_policy, pinned on every node, is not one of them.
	if facts := newCapturedCiliumNode(t, ciliumLiveB).reader().Read(t.Context()); len(facts.PinnedMaps.EgressGateway) != 0 {
		t.Fatalf("facts = %+v", facts)
	}
}

func TestCiliumReaderGivesUpWithinItsBudget(t *testing.T) {
	node := newCapturedCiliumNode(t, ciliumLiveB)
	reader := node.reader()
	reader.getStatus = func(ctx context.Context) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	started := time.Now()
	facts := reader.Read(t.Context())
	if elapsed := time.Since(started); elapsed > CiliumFactsReadBudget+time.Second {
		t.Fatalf("read took %s", elapsed)
	}
	if facts == nil || facts.Status.State != FactsUnreadable || !strings.Contains(facts.Status.Reason, "deadline exceeded") || facts.Validate() != nil {
		t.Fatalf("facts = %+v", facts)
	}
}

// The real status runner against a real unix socket: one GET /v1/healthz, no
// other request, a bounded body, and no redirect followed.
func TestRealCiliumStatusRunnerSendsExactlyOneRequest(t *testing.T) {
	// A unix socket path is limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "cil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "cilium.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	respond := func(w http.ResponseWriter) { _, _ = w.Write(ciliumLiveRead(t, ciliumLiveB+"healthz.json")) }
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		handler := respond
		mu.Unlock()
		handler(w)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	pinDir := filepath.Join(dir, "globals")
	if err := os.Mkdir(pinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cilium_lxc", "cilium_ipmasq_v4", "cilium_egresscall_policy"} {
		if err := os.WriteFile(filepath.Join(pinDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var dumped []string
	reader := NewCiliumFactsReader(func() ([]string, error) { return []string{"lo"}, nil }, nil, nil, func(_ context.Context, args ...string) (string, error) {
		dumped = append(dumped, strings.Join(args, " "))
		return string(ciliumLiveRead(t, ciliumLiveB+"ipmasq-v4.bpftool.json")), nil
	})
	reader.socket, reader.pinDir = socket, pinDir

	facts := reader.Read(t.Context())
	want := ciliumFactsB(t)
	want.PinnedMaps.Total = 3
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("facts = %+v, want %+v", facts, want)
	}
	if !reflect.DeepEqual(seen, []string{"GET /v1/healthz"}) {
		t.Fatalf("requests = %v", seen)
	}
	// The dump names the pin by its path under the directory that was listed.
	if !reflect.DeepEqual(dumped, []string{"--json map dump pinned " + filepath.Join(pinDir, "cilium_ipmasq_v4")}) {
		t.Fatalf("dumped = %v", dumped)
	}

	for name, tc := range map[string]struct {
		respond func(http.ResponseWriter)
		want    string
	}{
		"error status": {respond: func(w http.ResponseWriter) { http.Error(w, "no", http.StatusServiceUnavailable) }, want: "the agent answered HTTP 503"},
		"redirect": {respond: func(w http.ResponseWriter) {
			w.Header().Set("Location", "/v1/config")
			w.WriteHeader(http.StatusFound)
		}, want: "the agent answered HTTP 302"},
		"oversized body": {respond: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"masquerading":"` + strings.Repeat("x", maxCiliumStatusBytes) + `"}`))
		}, want: "Cilium status exceeds bound"},
	} {
		mu.Lock()
		respond, seen = tc.respond, nil
		mu.Unlock()
		facts := reader.Read(t.Context())
		if facts == nil || facts.Status.State != FactsUnreadable || !strings.Contains(facts.Status.Reason, tc.want) {
			t.Errorf("%s: facts = %+v", name, facts)
		}
		mu.Lock()
		if !reflect.DeepEqual(seen, []string{"GET /v1/healthz"}) {
			t.Errorf("%s: requests = %v", name, seen)
		}
		mu.Unlock()
	}

	// With the agent gone the socket file can remain; the node is still a
	// Cilium node and the status is stated as unreadable.
	_ = server.Close()
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if facts := reader.Read(t.Context()); facts == nil || facts.Status.State != FactsUnreadable || !strings.HasPrefix(facts.Status.Reason, "GET /v1/healthz on the agent socket: ") {
		t.Fatalf("dead socket: facts = %+v", facts)
	}
	// With the socket and the maps gone there is no trace left.
	if err := os.RemoveAll(pinDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	if facts := reader.Read(t.Context()); facts != nil {
		t.Fatalf("no trace: facts = %+v", facts)
	}
}

func TestRealCiliumPinListerListsNamesOnly(t *testing.T) {
	reader := NewCiliumFactsReader(nil, nil, nil, nil)
	reader.pinDir = t.TempDir()
	if names, err := reader.realPins(t.Context()); err != nil || len(names) != 0 {
		t.Fatalf("empty directory: %v %v", names, err)
	}
	for i := 0; i < 2500; i++ {
		if err := os.WriteFile(filepath.Join(reader.pinDir, fmt.Sprintf("cilium_calls_%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := reader.realPins(t.Context()); err != nil || len(names) != 2500 {
		t.Fatalf("listing: %d %v", len(names), err)
	}
	reader.pinDir = filepath.Join(reader.pinDir, "absent")
	if _, err := reader.realPins(t.Context()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("absent directory: %v", err)
	}
}

// The real runners are closed: bpftool can be asked for the one dump only, and
// the status runner takes no argument at all.
func TestClosedCiliumRunnersRefuseEverythingElse(t *testing.T) {
	reader := NewCiliumFactsReader(nil, nil, nil, nil)
	if reader.socket != "/var/run/cilium/cilium.sock" || reader.pinDir != "/sys/fs/bpf/tc/globals" {
		t.Fatalf("paths = %q %q", reader.socket, reader.pinDir)
	}
	for _, args := range [][]string{
		nil,
		{"--json", "map", "dump", "pinned", "/sys/fs/bpf/tc/globals/cilium_lxc"},
		{"--json", "map", "dump", "pinned", "/sys/fs/bpf/tc/globals/cilium_ipmasq_v4", "extra"},
		{"--json", "map", "dump", "pinned", "/sys/fs/bpf/tc/globals/../globals/cilium_ipmasq_v4"},
		{"--json", "map", "dump", "name", "cilium_ipmasq_v4"},
		{"--json", "map", "update", "pinned", "/sys/fs/bpf/tc/globals/cilium_ipmasq_v4"},
		{"--json", "map", "delete", "pinned", "/sys/fs/bpf/tc/globals/cilium_ipmasq_v4"},
		{"map", "dump", "pinned", "/sys/fs/bpf/tc/globals/cilium_ipmasq_v4"},
		{"--json", "prog", "show"},
		{"--json", "net", "detach", "xdp", "dev", "eth0"},
	} {
		if out, err := reader.realBPFTool(t.Context(), args...); err == nil || err.Error() != "unsupported bpftool inspection" || out != "" {
			t.Errorf("%v: %q %v", args, out, err)
		}
	}
}
