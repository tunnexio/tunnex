//go:build linux

package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// S10.3 WF-K5 — endpoint DNAT. The box-walk proved a VIP->ClusterIP DNAT can NOT be completed by kube-proxy
// (netfilter applies at most ONE dst-NAT per prerouting pass, so kube-proxy's ClusterIP->pod DNAT is a
// silent no-op after ours). The gateway must DNAT VIP -> a READY pod endpoint directly, which needs the pod
// IPs — read from the K8s API (ruling A amended: target resolution moves from CoreDNS-ClusterIP to a
// read-only EndpointSlice+Service watch; the DNS answer half is unchanged). We do NOT pull in client-go: it
// drags the whole K8s API machinery onto every VM/bare-metal gateway (the minority-serves-the-majority
// refusal). This is a thin hand-rolled LIST+WATCH of exactly two read-only resource types.
//
// FAIL-CLOSED is the security property (WF-K5 condition 1): the cache is populated ONLY from a SUCCESSFUL
// API read. A list failure, watch error, 410 Gone, connection drop, or parse failure CLEARS the affected
// view (Targets returns ok=false) so the render programs NO DNAT — never a stale pod IP (a recycled pod IP
// reassigned to another workload is the reassignment trap at the datapath tier). Watch death triggers an
// immediate relist; only a FAILED relist clears.

// k8sTarget is one ready DNAT destination: a pod IP and the resolved container port (0 = address-only DNAT,
// preserving the client's destination port — the PortLow==0 "any" exposure edge).
type k8sTarget struct {
	ip   string
	port int
}

// endpointSource is the render's view of ready endpoints (WF-K5). ok=false means the source has NO
// successful view for this Service (fault / not-yet-listed / unknown) => the classifier fails closed. A
// non-cluster gateway has a nil source; it also has no VIPMappings, so ResolveK8sVIPs never calls this.
type endpointSource interface {
	// Targets returns the ready podIP:port backing (namespace, service) for the exposed servicePort.
	Targets(namespace, service string, servicePort int) (targets []k8sTarget, ok bool)
}

// ── in-cluster watcher ────────────────────────────────────────────────────────────────────────────────

const (
	epSlicePath   = "/apis/discovery.k8s.io/v1/endpointslices"
	servicePath   = "/api/v1/services"
	saTokenPath   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath      = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	watchIdleWait = 2 * time.Second // backoff after a FAILED list before retrying (never with a stale view — the list clears first)
	// H2 (dead-while-green): a watch must be BOUNDED. timeoutSeconds asks the API server to close the stream
	// (server-side), and watchMaxDuration is the CLIENT backstop for a SILENT partition (no FIN/RST) where the
	// server never closes — without it sc.Scan() blocks for the TCP-keepalive window (minutes) while the 30s
	// egress ticker keeps re-applying the frozen (stale) endpoint view. watchMaxDuration > watchServerTimeout
	// so a healthy server closes first (a clean relist), and the client timeout only fires on a real partition.
	watchServerTimeoutSec = 270
	watchMaxDuration      = 6 * time.Minute
)

// svcPorts maps a Service's exposed port NUMBER -> its port NAME. The name is what correlates a service
// port to an EndpointSlice port (which carries the RESOLVED container port number). We need the Service
// only for this number->name map; the EndpointSlice carries the ready addresses AND the resolved ports.
type svcPorts map[int]string

// epGroup is the union of a Service's EndpointSlices: ready addresses + the resolved (name->port) map. A
// Service may have >1 EndpointSlice, so entries are keyed by slice name and merged at read time.
type epGroup struct {
	ready []string       // ready pod IPs (conditions.ready == true)
	ports map[string]int // endpoint port NAME -> resolved container port number
}

type K8sWatcher struct {
	base   string // https://host:port
	token  string
	client *http.Client
	log    *slog.Logger
	kick   func() // signal the egress reconcile that the endpoint view changed (watch-driven, not polled)

	mu       sync.RWMutex
	services map[string]svcPorts           // ns/name -> port->name
	slices   map[string]map[string]epGroup // ns/service -> (sliceName -> group)
	// *Synced (L12): has a full LIST of this resource SUCCEEDED and not since been cleared by a fault? This
	// distinguishes "the API view is not live" (fail-closed, ok=false → drives k8s_endpoints_unavailable) from
	// "the API view is live but this Service has no endpoints" (ok=true, zero targets → a per-Service refuse,
	// NOT an API-down signal). Without it, a Service that simply has no EndpointSlice looked identical to an
	// unreachable API.
	servicesSynced bool
	slicesSynced   bool
}

// NewInClusterWatcher returns a watcher wired to the pod's ServiceAccount, or (nil,nil) when NOT running in
// a cluster (no KUBERNETES_SERVICE_HOST) — a VM/bare-metal gateway, which has no VIPMappings anyway. Any
// mis-wire (token/CA unreadable while in-cluster) is returned as an error the caller logs; the agent still
// runs (fail-closed: no endpoint source => no VIP DNAT, never a wrong one).
func NewInClusterWatcher(log *slog.Logger, kick func()) (*K8sWatcher, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, nil // not in a cluster
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read SA token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read SA CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("SA CA bundle contained no certificates")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		// No client Timeout: a watch is a long-lived stream. Per-request bounding is via ctx on list.
	}
	return &K8sWatcher{
		base:     "https://" + host + ":" + port,
		token:    strings.TrimSpace(string(token)),
		client:   client,
		log:      log,
		kick:     kick,
		services: map[string]svcPorts{},
		slices:   map[string]map[string]epGroup{},
	}, nil
}

// Targets implements endpointSource — a PURE read of the last-successful cache (no I/O in the render path).
func (w *K8sWatcher) Targets(namespace, service string, servicePort int) ([]k8sTarget, bool) {
	key := namespace + "/" + service
	w.mu.RLock()
	defer w.mu.RUnlock()
	// L12: ok=false means the API view is NOT live (no successful LIST yet, or a fault cleared it) — the
	// fail-closed API-down signal. Once BOTH resources have synced, ok=true and the per-Service lookup yields
	// whatever endpoints exist (possibly zero — a Service with no ready pods is a per-Service refuse upstream,
	// not an API-down signal).
	if !w.servicesSynced || !w.slicesSynced {
		return nil, false
	}
	ports := w.services[key]
	groups := w.slices[key]
	// The EndpointSlice port NAME that backs the exposed servicePort. servicePort==0 is refused upstream
	// (classify: all_ports_unsupported), so matchByName is effectively always true here; the guard stays for
	// defense-in-depth.
	wantName, matchByName := "", servicePort != 0
	if matchByName {
		n, ok := ports[servicePort]
		if !ok {
			return nil, true // API live, but this Service doesn't expose that port => zero targets (refuse)
		}
		wantName = n
	}
	var out []k8sTarget
	seen := map[string]struct{}{}
	for _, g := range groups {
		podPort := 0
		if matchByName {
			p, ok := g.ports[wantName]
			if !ok {
				continue // this slice has no port with the wanted name
			}
			podPort = p
		}
		for _, ip := range g.ready {
			k := ip + ":" + strconv.Itoa(podPort)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k8sTarget{ip: ip, port: podPort})
		}
	}
	return out, true
}

// Run drives two independent list+watch loops (Services and EndpointSlices have independent
// resourceVersions). Blocks until ctx is cancelled.
func (w *K8sWatcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w.loop(ctx, servicePath, w.listServices, w.applyServiceEvent, w.clearServices)
	}()
	go func() {
		defer wg.Done()
		w.loop(ctx, epSlicePath, w.listSlices, w.applySliceEvent, w.clearSlices)
	}()
	wg.Wait()
}

// loop is the relist-then-watch cycle for one resource. On a list failure it CLEARS the resource's view
// (fail-closed) and retries. On a clean watch close or a 410 Gone it relists (the canonical resync). Every
// state change kicks the egress reconcile.
func (w *K8sWatcher) loop(
	ctx context.Context,
	path string,
	list func(context.Context) (string, error),
	onEvent func(evType string, obj json.RawMessage),
	clear func(),
) {
	for ctx.Err() == nil {
		rv, err := list(ctx)
		if err != nil {
			w.logf("k8s_watch_list_failed", "path", path, "err", err.Error())
			clear() // fail-closed: a failed read must not leave a stale view backing a DNAT
			w.kick()
			sleepCtx(ctx, watchIdleWait)
			continue
		}
		w.kick() // fresh full view applied
		gone, err := w.watch(ctx, path, rv, onEvent)
		switch {
		case ctx.Err() != nil:
			return
		case gone:
			w.logf("k8s_watch_410_relist", "path", path) // resourceVersion expired — full relist (condition 2)
		case err != nil:
			w.logf("k8s_watch_stream_err", "path", path, "err", err.Error())
		}
		// H3: relist IMMEDIATELY on any watch termination (410 / stream error / server close / partition
		// timeout). We do NOT sleep here with a live cache — that would serve stale endpoints for the backoff
		// window. The relist's list() CLEARS the view if it fails (fail-closed) and is the ONLY place that
		// backs off (watchIdleWait), so a persistently-failing API never hot-loops yet a transient blip
		// re-syncs at once. loop → relist.
	}
}

// watch streams events from resourceVersion rv. Returns gone=true on a 410 Gone (relist), or an error on a
// stream/decode fault (the caller relists after a backoff). A clean EOF returns (false, nil) → relist.
func (w *K8sWatcher) watch(ctx context.Context, path, rv string, onEvent func(string, json.RawMessage)) (bool, error) {
	// H2: bound the watch. timeoutSeconds asks the server to close the stream (clean relist); watchMaxDuration
	// is the client backstop for a SILENT partition where the server never closes — sc.Scan() would otherwise
	// block for the TCP-keepalive window while the egress ticker re-applies a frozen (stale) view. On this
	// ctx expiry the request is cancelled → watch returns an error → loop relists.
	wctx, cancel := context.WithTimeout(ctx, watchMaxDuration)
	defer cancel()
	u := fmt.Sprintf("%s%s?watch=1&allowWatchBookmarks=true&timeoutSeconds=%d&resourceVersion=%s",
		w.base, path, watchServerTimeoutSec, rv)
	req, err := http.NewRequestWithContext(wctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone { // 410 at the request itself
		return true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("watch %s: status %d", path, resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // EndpointSlice objects can be large
	for sc.Scan() {
		var ev struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return false, fmt.Errorf("decode watch event: %w", err) // parse failure → relist (fail-closed)
		}
		if ev.Type == "ERROR" {
			// A Status object; a 410 here means the resourceVersion is too old → relist.
			var st struct {
				Code int `json:"code"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return true, nil
			}
			return false, fmt.Errorf("watch %s: error event code %d", path, st.Code)
		}
		if ev.Type == "BOOKMARK" {
			continue
		}
		onEvent(ev.Type, ev.Object)
		w.kick()
	}
	return false, sc.Err()
}

// ── list + event application ──────────────────────────────────────────────────────────────────────────

// getList GETs a collection and returns its items + the list resourceVersion (the watch start point).
func (w *K8sWatcher) getList(ctx context.Context, path string) ([]json.RawMessage, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.base+path, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("list %s: status %d", path, resp.StatusCode)
	}
	var out struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, "", fmt.Errorf("decode list %s: %w", path, err)
	}
	return out.Items, out.Metadata.ResourceVersion, nil
}

func (w *K8sWatcher) listServices(ctx context.Context) (string, error) {
	items, rv, err := w.getList(ctx, servicePath)
	if err != nil {
		return "", err
	}
	next := map[string]svcPorts{}
	for _, it := range items {
		if key, ports, ok := parseService(it); ok {
			next[key] = ports
		}
	}
	w.mu.Lock()
	w.services = next
	w.servicesSynced = true // a full LIST succeeded — the Services view is now live (L12)
	w.mu.Unlock()
	return rv, nil
}

func (w *K8sWatcher) listSlices(ctx context.Context) (string, error) {
	items, rv, err := w.getList(ctx, epSlicePath)
	if err != nil {
		return "", err
	}
	next := map[string]map[string]epGroup{}
	for _, it := range items {
		if svcKey, sliceName, g, ok := parseSlice(it); ok {
			if next[svcKey] == nil {
				next[svcKey] = map[string]epGroup{}
			}
			next[svcKey][sliceName] = g
		}
	}
	w.mu.Lock()
	w.slices = next
	w.slicesSynced = true // a full LIST succeeded — the EndpointSlices view is now live (L12)
	w.mu.Unlock()
	return rv, nil
}

func (w *K8sWatcher) applyServiceEvent(evType string, obj json.RawMessage) {
	key, ports, ok := parseService(obj)
	if !ok {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if evType == "DELETED" {
		delete(w.services, key)
		return
	}
	w.services[key] = ports
}

func (w *K8sWatcher) applySliceEvent(evType string, obj json.RawMessage) {
	svcKey, sliceName, g, ok := parseSlice(obj)
	if !ok {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if evType == "DELETED" {
		if m := w.slices[svcKey]; m != nil {
			delete(m, sliceName)
			if len(m) == 0 {
				delete(w.slices, svcKey)
			}
		}
		return
	}
	if w.slices[svcKey] == nil {
		w.slices[svcKey] = map[string]epGroup{}
	}
	w.slices[svcKey][sliceName] = g
}

// clear* mark the view NOT-live (fail-closed): a failed LIST drops the resource's map AND its synced flag, so
// Targets returns ok=false (API-down) until a fresh LIST succeeds — never serving a stale entry.
func (w *K8sWatcher) clearServices() {
	w.mu.Lock()
	w.services = map[string]svcPorts{}
	w.servicesSynced = false
	w.mu.Unlock()
}
func (w *K8sWatcher) clearSlices() {
	w.mu.Lock()
	w.slices = map[string]map[string]epGroup{}
	w.slicesSynced = false
	w.mu.Unlock()
}

// ── JSON shapes (minimal — only the fields we read) ─────────────────────────────────────────────────────

func parseService(raw json.RawMessage) (key string, ports svcPorts, ok bool) {
	var s struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Ports []struct {
				Name string `json:"name"`
				Port int    `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Metadata.Name == "" || s.Metadata.Namespace == "" {
		return "", nil, false
	}
	ports = svcPorts{}
	for _, p := range s.Spec.Ports {
		ports[p.Port] = p.Name
	}
	return s.Metadata.Namespace + "/" + s.Metadata.Name, ports, true
}

func parseSlice(raw json.RawMessage) (svcKey, sliceName string, g epGroup, ok bool) {
	var s struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Endpoints []struct {
			Addresses  []string `json:"addresses"`
			Conditions struct {
				Ready *bool `json:"ready"`
			} `json:"conditions"`
		} `json:"endpoints"`
		Ports []struct {
			Name string `json:"name"`
			Port *int   `json:"port"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", "", epGroup{}, false
	}
	svc := s.Metadata.Labels["kubernetes.io/service-name"]
	if svc == "" || s.Metadata.Namespace == "" || s.Metadata.Name == "" {
		return "", "", epGroup{}, false // an orphan slice (no owning Service) is not ours to map
	}
	g = epGroup{ports: map[string]int{}}
	for _, p := range s.Ports {
		if p.Port != nil {
			g.ports[p.Name] = *p.Port
		}
	}
	for _, e := range s.Endpoints {
		// FAIL-CLOSED: a nil ready condition is NOT ready (never assume readiness). Only ready addresses
		// become DNAT targets.
		if e.Conditions.Ready == nil || !*e.Conditions.Ready {
			continue
		}
		g.ready = append(g.ready, e.Addresses...)
	}
	return s.Metadata.Namespace + "/" + svc, s.Metadata.Name, g, true
}

func (w *K8sWatcher) logf(msg string, args ...any) {
	if w.log != nil {
		w.log.Info(msg, args...)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
