// Package k8sendpoint discovers the public WireGuard endpoint from the named
// Kubernetes LoadBalancer Service. It uses only the pod's projected read-only
// credential and never calls a cloud-provider API.
package k8sendpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	maxResponseBytes        = 1 << 20
	maxTokenBytes           = 64 << 10
	maxReasonBytes          = 200
)

// State is the finite endpoint discovery state used by readiness and logs.
type State string

const (
	StatePending   State = "pending"
	StateReady     State = "ready"
	StateAmbiguous State = "ambiguous"
	StateBlocked   State = "blocked"
)

// Config identifies one exact UDP LoadBalancer Service port.
type Config struct {
	Namespace string
	Service   string
	Port      int
}

// Snapshot is a bounded, non-secret observation. Generation changes whenever
// endpoint truth changes, allowing the reporter to reject a stale success.
type Snapshot struct {
	State      State
	Endpoint   string
	Reason     string
	Generation uint64
}

// Reportable is true only after one valid LoadBalancer Service read.
func (s Snapshot) Reportable() bool { return s.State == StateReady && s.Endpoint != "" }

type serviceResponse struct {
	Spec struct {
		Type  string `json:"type"`
		Ports []struct {
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

// Discoverer periodically refreshes one exact Service. A failed refresh clears
// reportability, so readiness never claims a stale, unobservable endpoint.
type Discoverer struct {
	config    Config
	base      string
	tokenPath string
	client    *http.Client
	onChange  func(Snapshot)

	mu       sync.RWMutex
	snapshot Snapshot
}

// NewInCluster builds a discoverer from Kubernetes' injected API coordinates
// and projected ServiceAccount material.
func NewInCluster(config Config, onChange func(Snapshot)) (*Discoverer, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	host := strings.Trim(strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")), "[]")
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, fmt.Errorf("Kubernetes API coordinates are unavailable")
	}
	if _, err := readToken(serviceAccountTokenPath); err != nil {
		return nil, fmt.Errorf("read projected ServiceAccount token: %w", err)
	}
	caPEM, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("read projected ServiceAccount CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("projected ServiceAccount CA contains no certificate")
	}
	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: refuseK8sAPIRedirect,
	}
	return newDiscoverer(config, "https://"+net.JoinHostPort(host, port), serviceAccountTokenPath, client, onChange)
}

func refuseK8sAPIRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func newDiscoverer(config Config, base, tokenPath string, client *http.Client, onChange func(Snapshot)) (*Discoverer, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if client == nil || strings.TrimSpace(base) == "" || strings.TrimSpace(tokenPath) == "" {
		return nil, fmt.Errorf("Kubernetes API client configuration is incomplete")
	}
	return &Discoverer{
		config:    config,
		base:      strings.TrimRight(base, "/"),
		tokenPath: tokenPath,
		client:    client,
		onChange:  onChange,
		snapshot:  Snapshot{State: StatePending, Reason: "not_observed"},
	}, nil
}

func validateConfig(config Config) error {
	if !validKubernetesName(config.Namespace) {
		return fmt.Errorf("invalid endpoint Service namespace")
	}
	if !validKubernetesName(config.Service) {
		return fmt.Errorf("invalid endpoint Service name")
	}
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("endpoint Service port must be between 1 and 65535")
	}
	return nil
}

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

func validKubernetesName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dnsLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// Run refreshes immediately, then periodically until cancellation.
func (d *Discoverer) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	refresh := func() {
		refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if ctx.Err() == nil {
			d.Refresh(refreshCtx)
		}
	}
	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

// Snapshot returns the latest complete observation.
func (d *Discoverer) Snapshot() Snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.snapshot
}

// Refresh performs one bounded authenticated Service read.
func (d *Discoverer) Refresh(ctx context.Context) Snapshot {
	path := "/api/v1/namespaces/" + url.PathEscape(d.config.Namespace) + "/services/" + url.PathEscape(d.config.Service)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return d.publish(StateBlocked, "", "request_build_failed")
	}
	token, err := readToken(d.tokenPath)
	if err != nil {
		return d.publish(StateBlocked, "", "service_account_token_unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return d.Snapshot()
		}
		return d.publish(StateBlocked, "", "kubernetes_api_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return d.publish(StatePending, "", "service_not_found")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return d.publish(StateBlocked, "", "kubernetes_api_status_"+strconv.Itoa(resp.StatusCode))
	}
	var service serviceResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := decoder.Decode(&service); err != nil {
		return d.publish(StateBlocked, "", "service_response_invalid")
	}
	if service.Spec.Type != "LoadBalancer" {
		return d.publish(StateBlocked, "", "service_is_not_load_balancer")
	}
	portFound := false
	for _, port := range service.Spec.Ports {
		if port.Port == d.config.Port && strings.EqualFold(port.Protocol, "UDP") {
			portFound = true
			break
		}
	}
	if !portFound {
		return d.publish(StateBlocked, "", "udp_service_port_not_found")
	}

	seenCandidate := false
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		for _, candidate := range []string{ingress.IP, ingress.Hostname} {
			if strings.TrimSpace(candidate) == "" {
				continue
			}
			seenCandidate = true
			host, ok := canonicalHost(candidate)
			if !ok {
				continue
			}
			// Kubernetes API order is authoritative and stable for one object read.
			// Within an ingress IP precedes hostname, matching the documented
			// status fields without sorting or guessing among legitimate addresses.
			return d.publish(StateReady, net.JoinHostPort(host, strconv.Itoa(d.config.Port)), "")
		}
	}
	if seenCandidate {
		return d.publish(StateBlocked, "", "load_balancer_ingress_invalid")
	}
	return d.publish(StatePending, "", "load_balancer_ingress_pending")
}

func (d *Discoverer) publish(state State, endpoint, reason string) Snapshot {
	reason = bounded(reason, maxReasonBytes)
	d.mu.Lock()
	previous := d.snapshot
	if previous.State == state && previous.Endpoint == endpoint && previous.Reason == reason {
		current := previous
		d.mu.Unlock()
		return current
	}
	current := Snapshot{State: state, Endpoint: endpoint, Reason: reason, Generation: previous.Generation + 1}
	d.snapshot = current
	d.mu.Unlock()
	if d.onChange != nil {
		d.onChange(current)
	}
	return current
}

func canonicalHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), true
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if !validKubernetesName(value) {
		return "", false
	}
	return value, true
}

func readToken(path string) (string, error) {
	token, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(token) > maxTokenBytes {
		return "", fmt.Errorf("projected token exceeds limit")
	}
	value := strings.TrimSpace(string(token))
	if value == "" {
		return "", fmt.Errorf("projected token is empty")
	}
	return value, nil
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
