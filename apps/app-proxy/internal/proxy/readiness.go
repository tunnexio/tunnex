package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

const PublicReadinessPath = "/__tunnex_app/readiness-public"

type ReadinessAuthority interface {
	ClaimReadiness(context.Context, authoritywire.AppProxyReadinessClaimInput) (authoritywire.AppProxyReadinessClaimResult, error)
	ReportReadiness(context.Context, authoritywire.AppProxyReadinessReportInput) (authoritywire.AppProxyReadinessReportResult, error)
}

func (c *Client) ClaimReadiness(ctx context.Context, input authoritywire.AppProxyReadinessClaimInput) (authoritywire.AppProxyReadinessClaimResult, error) {
	var out authoritywire.AppProxyReadinessClaimResult
	err := c.call(ctx, "publication-readiness/claim", input, &out)
	return out, err
}
func (c *Client) ReportReadiness(ctx context.Context, input authoritywire.AppProxyReadinessReportInput) (authoritywire.AppProxyReadinessReportResult, error) {
	var out authoritywire.AppProxyReadinessReportResult
	err := c.call(ctx, "publication-readiness/report", input, &out)
	return out, err
}

type readinessChallenge struct {
	work    authoritywire.AppProxyReadinessWork
	expires time.Time
}
type ReadinessWorker struct {
	authority                    ReadinessAuthority
	broker                       *apptransport.Broker
	base, instance, instanceHash string
	mu                           sync.Mutex
	challenges                   map[string]readinessChallenge
	// PublicProbe is an explicit test-fixture seam. Shipping construction always
	// installs StrictPublicProbe; no environment/configuration bypass exists.
	lastClaimSuccess time.Time
	PublicProbe      func(context.Context, string, string, string, string) (string, string, string)
}

func NewReadinessWorker(base string, a ReadinessAuthority, b *apptransport.Broker) (*ReadinessWorker, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	instance := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(instance))
	return &ReadinessWorker{authority: a, broker: b, base: base, instance: instance, instanceHash: hex.EncodeToString(hash[:]), challenges: map[string]readinessChallenge{}, PublicProbe: StrictPublicProbe}, nil
}
func challengeToken(instance, id string) string {
	sum := sha256.Sum256([]byte("app-readiness\x00" + instance + "\x00" + id))
	return hex.EncodeToString(sum[:])
}
func (w *ReadinessWorker) Challenge(response http.ResponseWriter, r *http.Request, host string) {
	if r.Method != "GET" || r.URL.Path != PublicReadinessPath || r.URL.RawPath != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("Upgrade")) != 0 {
		deny(response)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	ids := query["request_id"]
	if err != nil || len(query) != 1 || len(ids) != 1 {
		deny(response)
		return
	}
	w.mu.Lock()
	entry, ok := w.challenges[ids[0]]
	w.mu.Unlock()
	if !ok || entry.work.Route.Binding.Hostname != host || !entry.expires.After(time.Now()) {
		deny(response)
		return
	}
	redirectHeaders(response)
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(struct {
		RequestID      string `json:"request_id"`
		ChallengeToken string `json:"challenge_token"`
		InstanceHash   string `json:"instance_hash"`
	}{ids[0], entry.work.ChallengeToken, w.instanceHash})
}
func (w *ReadinessWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		claimCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		claimed, err := w.authority.ClaimReadiness(claimCtx, authoritywire.AppProxyReadinessClaimInput{InstanceToken: w.instance})
		ended := claimCtx.Err()
		cancel()
		if err == nil && ended == nil && len(claimed.Items) <= 8 {
			w.mu.Lock()
			w.lastClaimSuccess = time.Now()
			w.mu.Unlock()
			var wait sync.WaitGroup
			seen := map[string]bool{}
			for _, work := range claimed.Items {
				idBinding := Binding(work.Route.Binding)
				idBinding.AppID = work.OperationID
				idBinding.Generation = work.ReadinessRequestID
				if !idBinding.Valid() || seen[work.ReadinessRequestID] || !Binding(work.Route.Binding).Valid() || work.ChallengeToken != challengeToken(w.instance, work.ReadinessRequestID) || !work.Deadline.After(time.Now()) || work.Deadline.After(time.Now().Add(60*time.Second)) || work.Version < 1 {
					continue
				}
				if host, err := authorityHost(work.Route.Binding.Hostname, w.base, w.authority); err != nil || host != work.Route.Binding.Hostname {
					continue
				}
				seen[work.ReadinessRequestID] = true
				wait.Add(1)
				go func() { defer wait.Done(); w.round(ctx, work) }()
			}
			wait.Wait()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *ReadinessWorker) round(parent context.Context, work authoritywire.AppProxyReadinessWork) {
	// The same monotonic ten-second budget covers queue-free parallel probes and
	// report receipt. Failed reports are never retried with cached evidence.
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	ctx, stop := context.WithDeadline(ctx, work.Deadline)
	defer stop()
	probeCtx, probeCancel := context.WithTimeout(ctx, 8*time.Second)
	defer probeCancel()
	expiry := time.Now().Add(8 * time.Second)
	if work.Deadline.Before(expiry) {
		expiry = work.Deadline
	}
	w.mu.Lock()
	if len(w.challenges) >= 8 {
		w.mu.Unlock()
		return
	}
	w.challenges[work.ReadinessRequestID] = readinessChallenge{work, expiry}
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.challenges, work.ReadinessRequestID); w.mu.Unlock() }()
	var publicDNS, publicTLS, publicCode string
	var origin originpolicy.Result
	var serial string
	var originErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		publicDNS, publicTLS, publicCode = w.PublicProbe(probeCtx, work.Route.Binding.Hostname, work.ReadinessRequestID, work.ChallengeToken, w.instanceHash)
	}()
	go func() { defer wait.Done(); origin, serial, originErr = w.originProbe(probeCtx, work) }()
	wait.Wait()
	if ctx.Err() != nil || serial == "" {
		return
	}
	dns, connect, tlsStatus, code := readinessStages(origin)
	if originErr != nil {
		code = "connector_failed"
	}
	if publicCode != "" {
		code = publicCode
	}
	report := authoritywire.AppProxyReadinessReportInput{OperationID: work.OperationID, ExpectedOperationVersion: work.Version, ReadinessRequestID: work.ReadinessRequestID, Binding: work.Route.Binding, InstanceToken: w.instance, ChallengeToken: work.ChallengeToken, CertificateSerial: serial, PublicDNSStatus: authoritywire.AppProxyReadinessReportInputPublicDnsStatus(publicDNS), PublicTLSStatus: authoritywire.AppProxyReadinessReportInputPublicTlsStatus(publicTLS), DNSStatus: authoritywire.AppProxyReadinessReportInputDnsStatus(dns), ConnectStatus: authoritywire.AppProxyReadinessReportInputConnectStatus(connect), TLSStatus: authoritywire.AppProxyReadinessReportInputTlsStatus(tlsStatus), ErrorCode: code}
	reportCtx, reportCancel := context.WithTimeout(ctx, 2*time.Second)
	defer reportCancel()
	_, _ = w.authority.ReportReadiness(reportCtx, report)
}
func (w *ReadinessWorker) originProbe(ctx context.Context, work authoritywire.AppProxyReadinessWork) (originpolicy.Result, string, error) {
	b := Binding(work.Route.Binding).Transport()
	conn, serial, err := w.broker.DialAuthenticated(ctx, b)
	if err != nil {
		return originpolicy.Result{}, serial, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 4 << 10, DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}
	defer tr.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://app-connector.internal"+apptransport.BrowserReadinessPath, nil)
	request.Host = b.Hostname
	apptransport.BindingHeaders(request.Header, b)
	request.Header.Set("X-App-Operation-ID", work.OperationID)
	request.Header.Set("X-App-Readiness-ID", work.ReadinessRequestID)
	response, err := tr.RoundTrip(request)
	if err != nil {
		return originpolicy.Result{}, serial, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return originpolicy.Result{}, serial, ErrDenied
	}
	var result originpolicy.Result
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if readErr != nil || len(payload) > 4096 {
		return result, serial, ErrDenied
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, serial, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return result, serial, ErrDenied
	}
	return result, serial, nil
}
func readinessStages(r originpolicy.Result) (string, string, string, string) {
	stage := func(v string) string {
		switch v {
		case "ready":
			return "passed"
		case "failed", "refused":
			return "failed"
		default:
			return "pending"
		}
	}
	dns, connect, tlsStatus := stage(r.DNS), stage(r.Connect), stage(r.TLS)
	if r.TLS == "not_required" {
		tlsStatus = "skipped"
	}
	code := "connector_failed"
	switch r.Status {
	case "ready":
		if dns == "passed" && connect == "passed" && (tlsStatus == "passed" || tlsStatus == "skipped") && r.HTTPStatus >= 100 && r.HTTPStatus <= 599 {
			code = ""
		}
	case "dns_refused":
		code = "dns_failed"
		if r.DNS == "refused" {
			code = "target_refused"
		}
	case "origin_refused":
		code = "target_refused"
	case "http_failed":
		code = "http_failed"
	case "tls_refused":
		code = "tls_failed"
	case "unreachable":
		code = "connect_failed"
	case "timeout":
		code = "deadline_exceeded"
	case "cancelled":
		code = "assignment_changed"
	}
	return dns, connect, tlsStatus, code
}

// StrictPublicProbe trusts only system roots and validates all DNS answers before
// any literal dial. No redirect, cookie jar, environment proxy or private CA.
func StrictPublicProbe(parent context.Context, host, id, challenge, instanceHash string) (string, string, string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 || len(ips) > 64 {
		return "failed", "pending", "public_dns_failed"
	}
	policy, _ := originpolicy.Normalize(nil, "")
	for _, ip := range ips {
		if policy.Validate(ip, nil) != nil {
			return "failed", "pending", "public_dns_failed"
		}
	}
	return probePublicAddresses(ctx, host, id, challenge, instanceHash, ips, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host}, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
}
func probePublicAddresses(ctx context.Context, host, id, challenge, instanceHash string, ips []netip.Addr, config *tls.Config, dial func(context.Context, string, string) (net.Conn, error)) (string, string, string) {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 4 << 10, TLSClientConfig: config, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var err error
		for _, ip := range ips {
			var conn net.Conn
			conn, err = dial(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}}
	defer tr.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+PublicReadinessPath+"?"+url.Values{"request_id": {id}}.Encode(), nil)
	response, err := tr.RoundTrip(request)
	if err != nil {
		return "passed", "failed", "public_tls_failed"
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "passed", "passed", "public_challenge_failed"
	}
	var out struct {
		RequestID      string `json:"request_id"`
		ChallengeToken string `json:"challenge_token"`
		InstanceHash   string `json:"instance_hash"`
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(payload) > 4096 {
		return "passed", "passed", "public_challenge_failed"
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || out.RequestID != id || out.ChallengeToken != challenge || out.InstanceHash != instanceHash {
		return "passed", "passed", "public_challenge_failed"
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "passed", "passed", "public_challenge_failed"
	}
	return "passed", "passed", ""
}
