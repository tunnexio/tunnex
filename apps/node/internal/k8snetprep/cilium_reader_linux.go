//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// K8N-2, the privileged side. The host-posture manager reads, on a node that
// shows Cilium, what the gateway cannot reach:
//
//   - the agent's status, with exactly `GET /v1/healthz` on its local socket;
//   - the names of the maps pinned under /sys/fs/bpf/tc/globals;
//   - the ip-masq-agent map, with exactly
//     `bpftool --json map dump pinned /sys/fs/bpf/tc/globals/cilium_ipmasq_v4`,
//     and only when the status says the ip-masq-agent is on.
//
// It reads only. The socket also accepts writes, so the status runner can
// issue no other request; the bpftool runner accepts no other argument vector.
// The two host paths are mounted read-only, and only where the chart value
// cilium.enabled is set (the installer sets it when it sees Cilium).

const (
	// CiliumAgentSocket is where the agent serves its local API.
	CiliumAgentSocket = "/var/run/cilium/cilium.sock"
	// CiliumPinnedMapsDir is where the agent pins its maps.
	CiliumPinnedMapsDir = "/sys/fs/bpf/tc/globals"
	// CiliumIPMasqMapName is the pinned ip-masq-agent map.
	CiliumIPMasqMapName = "cilium_ipmasq_v4"
	// CiliumFactsReadBudget bounds one whole read.
	CiliumFactsReadBudget = 2 * time.Second

	// maxCiliumPinnedMaps bounds the directory listing. Cilium pins a few
	// maps per endpoint, so a full node stays far below it.
	maxCiliumPinnedMaps = 16384
	// ciliumMountHint is added where a path is simply not there.
	ciliumMountHint = "set cilium.enabled=true on the tunnex-host-posture chart"
)

// LinkLister lists the names of the node's network devices.
type LinkLister func() ([]string, error)

// CiliumStatusRunner performs exactly GET /v1/healthz on the agent socket and
// returns the body of a 200 response.
type CiliumStatusRunner func(context.Context) ([]byte, error)

// CiliumPinLister lists the names pinned under the agent's map directory.
type CiliumPinLister func(context.Context) ([]string, error)

// BPFToolRunner runs one closed bpftool argument vector. It returns what
// bpftool printed on standard output even when bpftool failed: bpftool states
// its error there, as a JSON object.
type BPFToolRunner func(context.Context, ...string) (string, error)

// CiliumFactsReader is the manager's reader of the `cilium` section.
type CiliumFactsReader struct {
	listLinks  LinkLister
	getStatus  CiliumStatusRunner
	listPins   CiliumPinLister
	runBPFTool BPFToolRunner
	socket     string
	pinDir     string
}

// NewCiliumFactsReader returns a reader over the given runners; a nil runner
// is replaced by the real, closed one.
func NewCiliumFactsReader(links LinkLister, status CiliumStatusRunner, pins CiliumPinLister, bpftool BPFToolRunner) *CiliumFactsReader {
	r := &CiliumFactsReader{listLinks: links, getStatus: status, listPins: pins, runBPFTool: bpftool, socket: CiliumAgentSocket, pinDir: CiliumPinnedMapsDir}
	if r.listLinks == nil {
		r.listLinks = realLinkNames
	}
	if r.getStatus == nil {
		r.getStatus = r.realStatus
	}
	if r.listPins == nil {
		r.listPins = r.realPins
	}
	if r.runBPFTool == nil {
		r.runBPFTool = r.realBPFTool
	}
	return r
}

// realStatus issues the one request this reader may send. Nothing of it can
// be chosen by a caller: not the method, not the path, not the socket.
func (r *CiliumFactsReader) realStatus(ctx context.Context) ([]byte, error) {
	socket := r.socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/healthz", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the agent answered HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCiliumStatusBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCiliumStatusBytes {
		return nil, errors.New("Cilium status exceeds bound")
	}
	return body, nil
}

// realPins lists the directory. It opens nothing inside it.
func (r *CiliumFactsReader) realPins(context.Context) ([]string, error) {
	dir, err := os.Open(r.pinDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var names []string
	for {
		batch, err := dir.Readdirnames(1024)
		names = append(names, batch...)
		if len(names) > maxCiliumPinnedMaps {
			return nil, fmt.Errorf("more than %d maps are pinned", maxCiliumPinnedMaps)
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// realBPFTool dumps the one pinned map. bpftool opens a pinned map it only
// dumps read-only.
func (r *CiliumFactsReader) realBPFTool(ctx context.Context, args ...string) (string, error) {
	if len(args) != 5 || strings.Join(args[:4], " ") != "--json map dump pinned" || args[4] != filepath.Join(r.pinDir, CiliumIPMasqMapName) {
		return "", errors.New("unsupported bpftool inspection")
	}
	stdout := &boundedBuffer{limit: maxCiliumMapDumpBytes}
	stderr := &boundedBuffer{limit: 512}
	cmd := exec.CommandContext(ctx, "bpftool", args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.exceeded {
		return "", errors.New("bpftool inspection exceeds bound")
	}
	if err != nil {
		return stdout.Buffer.String(), fmt.Errorf("bpftool inspection: %w: %s", err, bounded(stderr.Buffer.String(), 120))
	}
	return stdout.Buffer.String(), nil
}

// Read performs one bounded read. It returns nil when the node shows no trace
// of Cilium: no cilium_ network device, no cilium_ pinned map and no agent
// socket. Otherwise it never fails: what could not be read is stated in the
// facts, with its reason, so the gateway can report it.
func (r *CiliumFactsReader) Read(ctx context.Context) *CiliumFacts {
	ctx, cancel := context.WithTimeout(ctx, CiliumFactsReadBudget)
	defer cancel()
	links, _ := r.listLinks()
	pins, pinErr := r.listPins(ctx)
	_, socketErr := os.Lstat(r.socket)
	if !ciliumPresent(links, nil, pins) && socketErr != nil {
		return nil
	}
	facts := &CiliumFacts{PinnedMaps: readCiliumPinFacts(pins, pinErr, r.pinDir)}
	var masq ciliumMasquerade
	understood := false
	switch raw, err := r.getStatus(ctx); {
	case errors.Is(err, fs.ErrNotExist):
		facts.Status = unreadableCiliumText(r.noSocketReason())
	case err != nil:
		facts.Status = unreadableCiliumText("GET /v1/healthz on the agent socket: " + bounded(err.Error(), 120))
	default:
		reduced, err := reduceCiliumStatus(raw)
		if err != nil {
			facts.Status = unreadableCiliumText(err.Error())
			break
		}
		facts.Status = CiliumTextFact{State: FactsRead, Text: reduced}
		masq, err = parseCiliumStatus([]byte(reduced))
		understood = err == nil
	}
	switch {
	case facts.Status.State != FactsRead:
		facts.IPMasqMap = unreadableCiliumText("the agent status was not read")
	case !understood:
		facts.IPMasqMap = unreadableCiliumText("the agent status is not understood")
	case !masq.IPMasqAgent:
		facts.IPMasqMap = CiliumTextFact{State: FactsNotNeeded, Reason: "the agent reports that its ip-masq-agent is off"}
	default:
		facts.IPMasqMap = r.readIPMasqMap(ctx)
	}
	if err := ctx.Err(); err != nil {
		return UnreadableCiliumFacts("read Cilium facts: " + err.Error())
	}
	if err := facts.Validate(); err != nil {
		return UnreadableCiliumFacts(err.Error())
	}
	return facts
}

// noSocketReason tells a manager that was not given the agent's directory from
// an agent that is not running: with the mount the directory is there even
// while the agent restarts and its socket is gone for a few seconds.
func (r *CiliumFactsReader) noSocketReason() string {
	dir := filepath.Dir(r.socket)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return fmt.Sprintf("%s is not mounted in the host-posture manager; %s", dir, ciliumMountHint)
	}
	return fmt.Sprintf("no agent socket at %s; the Cilium agent is not running or is restarting", r.socket)
}

func unreadableCiliumText(reason string) CiliumTextFact {
	return CiliumTextFact{State: FactsUnreadable, Reason: bounded(reason, maxReasonBytes)}
}

func readCiliumPinFacts(pins []string, err error, dir string) CiliumPinFacts {
	unreadable := func(reason string) CiliumPinFacts {
		return CiliumPinFacts{State: FactsUnreadable, Reason: bounded(reason, maxReasonBytes)}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return unreadable(fmt.Sprintf("no pinned maps at %s; %s", dir, ciliumMountHint))
	case err != nil:
		return unreadable("list pinned maps: " + bounded(err.Error(), 120))
	}
	facts := CiliumPinFacts{State: FactsRead, Total: len(pins)}
	for _, name := range pins {
		if !strings.HasPrefix(name, ciliumEgressGatewayPinPrefix) {
			continue
		}
		if !ciliumPinNameRE.MatchString(name) {
			return unreadable("an egress-gateway map has a name that is not understood")
		}
		facts.EgressGateway = append(facts.EgressGateway, name)
	}
	if len(facts.EgressGateway) > maxCiliumEgressPins {
		return unreadable(fmt.Sprintf("more than %d egress-gateway maps are pinned", maxCiliumEgressPins))
	}
	sort.Strings(facts.EgressGateway)
	return facts
}

// readIPMasqMap dumps the map. bpftool's exit status and its output are read
// together: a failed dump, an error object, or anything that is not a JSON
// array is a read error, never an empty map.
func (r *CiliumFactsReader) readIPMasqMap(ctx context.Context) CiliumTextFact {
	pin := filepath.Join(r.pinDir, CiliumIPMasqMapName)
	out, err := r.runBPFTool(ctx, "--json", "map", "dump", "pinned", pin)
	text := strings.TrimSpace(out)
	var stated struct {
		Error string `json:"error"`
	}
	if strings.HasPrefix(text, "{") && len(text) <= 4096 && json.Unmarshal([]byte(text), &stated) == nil && stated.Error != "" {
		return unreadableCiliumText("bpftool: " + bounded(stated.Error, 160))
	}
	switch {
	case err != nil:
		return unreadableCiliumText(bounded(err.Error(), 160))
	case !strings.HasPrefix(text, "["):
		return unreadableCiliumText("bpftool did not print a map")
	case len(text) > MaxCiliumMapFactBytes:
		return unreadableCiliumText(fmt.Sprintf("the ip-masq-agent map dump exceeds %d bytes", MaxCiliumMapFactBytes))
	}
	return CiliumTextFact{State: FactsRead, Text: text}
}

// UseCiliumFacts makes the Cilium proof take the manager's `cilium` section
// from source. It is set once, before the first Reconcile. Without a source a
// node that shows Cilium is refused.
func (r *Reconciler) UseCiliumFacts(source CiliumFactsSource) { r.ciliumFacts = source }
