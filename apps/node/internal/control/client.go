// Package control is the tunnex-node agent's client for the control plane:
// enrollment (plain HTTP, join-token) and the mTLS reconcile channel.
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/flowlog"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

// GenerateKeyAndCSR creates an agent private key and a CSR for commonName.
func GenerateKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return keyPEM, csrPEM, nil
}

// EnrollResult holds the credentials returned by enrollment.
type EnrollResult struct {
	NodeID  string
	CertPEM string
	CAPEM   string
}

// Enroll exchanges a join token + CSR for a signed certificate over plain HTTP.
func Enroll(ctx context.Context, apiURL, joinToken string, csrPEM []byte, nodeName, agentVersion string, protocolVersion int) (EnrollResult, error) {
	body, _ := json.Marshal(map[string]any{
		"join_token": joinToken, "csr": string(csrPEM), "node_name": nodeName,
		"agent_version": agentVersion, "protocol_version": protocolVersion,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/v1/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return EnrollResult{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return EnrollResult{}, fmt.Errorf("enroll failed (%d): %s", resp.StatusCode, string(data))
	}
	var r struct {
		NodeID      string `json:"node_id"`
		Certificate string `json:"certificate"`
		CACert      string `json:"ca_certificate"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{NodeID: r.NodeID, CertPEM: r.Certificate, CAPEM: r.CACert}, nil
}

// Client is the mTLS reconcile-channel client (implements reconcile.ControlClient).
// The client certificate is served via GetClientCertificate reading an atomic
// holder, so Renew can hot-swap it mid-flight without rebuilding the client.
type Client struct {
	base     string
	nodeName string
	cert     atomic.Pointer[tls.Certificate]
	http     *http.Client
}

// NewClient builds an mTLS client presenting certPEM/keyPEM and trusting caPEM.
// serverName is the control-channel server cert's name (dialing host may differ,
// e.g. the compose service name).
func NewClient(agentURL, serverName, nodeName string, certPEM, keyPEM, caPEM []byte) (*Client, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bad CA PEM")
	}
	c := &Client{base: agentURL, nodeName: nodeName}
	c.cert.Store(&cert)
	c.http = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return c.cert.Load(), nil
			},
			RootCAs:    pool,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}},
	}
	return c, nil
}

// Renew rotates the agent's certificate over the mTLS channel: it generates a
// FRESH key + CSR, posts it (authenticated by the CURRENT cert), hot-swaps the
// new cert in, and returns the new cert+key PEM for the caller to persist.
// Renewing at half-life keeps the agent from ever reaching cert expiry.
func (c *Client) Renew(ctx context.Context, agentVersion string) (newCertPEM, newKeyPEM []byte, err error) {
	keyPEM, csrPEM, err := GenerateKeyAndCSR(c.nodeName)
	if err != nil {
		return nil, nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/renew", bytes.NewReader(csrPEM))
	req.Header.Set("X-Agent-Version", agentVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("renew status %d: %s", resp.StatusCode, string(body))
	}
	newCert, err := tls.X509KeyPair(body, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	c.cert.Store(&newCert) // hot-swap: subsequent requests use the fresh cert
	// Drop pooled TLS connections so the next request re-handshakes with the new
	// cert (an existing keep-alive connection would keep presenting the old one).
	c.http.CloseIdleConnections()
	return body, keyPEM, nil
}

// AdoptCredentials installs a credential set this client did NOT fetch — the one proof-of-possession recovery
// produced — and drops pooled connections so the next request re-handshakes with it.
//
// It exists so a recovery can land IN A RUNNING PROCESS. Re-key is not an mTLS call (that is the whole point: the
// certificate it replaces has expired), so its result arrives outside this client and had nowhere to go. Without
// this seam the only way to apply a recovery was to restart the agent, which is precisely what made the recovery
// path unreachable at runtime (WF-S13-6).
func (c *Client) AdoptCredentials(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	c.cert.Store(&pair)
	c.http.CloseIdleConnections()
	return nil
}

// PolicyStatus is the APPLIED Zero Trust policy status (S7.2 staleness reporting):
// the version + CANONICAL hash of the policy actually in force on the gateway's
// forward chain (last successful nft apply), plus the last apply error if any. The
// control plane compares this against what it pushed — applied != pushed means the
// gateway is running STALE policy, which must be visible, never silent.
type PolicyStatus struct {
	Version int
	Hash    string
	Error   string
	// FailingSince (RFC3339, empty when healthy) is the mismatch onset — the control
	// plane's stale alarm measures elapsed time from here, not the applied-hash age.
	FailingSince string
	// RefusedVersion (S8.1 D1) is the compiled-artifact Version the agent REFUSED as
	// unsupported (> MaxSupportedVersion), or 0 when none. The control plane surfaces this
	// as `unsupported_policy_version` (remedy: upgrade the agent) — distinct from staleness.
	RefusedVersion int
	// SiteLinkStale (S8.2 H5) — a site-link peer (hub/spoke) has a stale/absent WG handshake:
	// site-to-site traffic on that link is dead. Surfaced as site_link_down.
	SiteLinkStale bool
	// SiteSubnetUnreachable (S8.2c D3) — the CP advertised local site subnets but NO host address is inside
	// any: the gateway fronts a subnet it isn't on (bridge-trapped wg0 / misconfig). Surfaced as
	// site_subnet_unreachable so the reassuring-green shape (link fresh, LAN unreachable) is never silent.
	SiteSubnetUnreachable bool
	// ConntrackFlushUnavailable (S8.7 Slice 2) — the agent's expired-grant conntrack flush is failing (no
	// CAP_NET_ADMIN / netlink fault): revoked grants' established flows may linger. Surfaced as
	// conntrack_flush_unavailable so the degradation lives on the health plane, never just a log line.
	ConntrackFlushUnavailable bool
	// K8sEndpointsUnavailable (S10.3 WF-K5) — this gateway fronts exposed Services but has NO successful
	// endpoint view from the K8s API (unreachable / RBAC-denied / watch not synced), so no VIP can be
	// DNAT-programmed (fail-closed). Surfaced as k8s_endpoints_unavailable so the operator sees WHY. (Renamed
	// from the CoreDNS-era k8s_cluster_dns_unreachable — WF-K5 moved target resolution from CoreDNS to the API
	// watch; endpoint DNAT needs pod IPs, which CoreDNS can't give.)
	K8sEndpointsUnavailable bool
	// MaxSupportedVersion (S8.3 CW) is the highest compiled-artifact Version this agent can APPLY
	// (nodepolicy.MaxSupportedVersion). Observability — a reported fact, OUTSIDE the compile hash, no
	// version bump. The control plane uses it to warn, BEFORE an org goes multi-site, which gateways
	// are below the ceiling and would deny-all on the version bump.
	MaxSupportedVersion int
	// OVPNHealth (S9.1 4d) is the OpenVPN server's refuse-loudly kind ("" healthy, ovpn_certs_absent,
	// ovpn_binary_absent). A DIFFERENT axis from policy health — surfaced on the gateway so an operator
	// who enabled OpenVPN on a gateway missing its material sees WHY (the conntrack_flush_unavailable
	// precedent). Reported every tick; resolves on its own when the material/binary appears.
	OVPNHealth string
	// DNSResolveRPCVersion is this agent's highest supported brokered
	// selected-gateway DNS RPC version. Zero/missing means an older agent and is
	// a compatibility refusal for FQDN enforcement, never a public-DNS fallback.
	DNSResolveRPCVersion int
}

// ReportInfo reports the node's locally-generated WireGuard public key, its public
// endpoint (host:port that peer configs dial), its egress capabilities (whether
// the gateway can source-NAT IPv4/IPv6 full-tunnel traffic — S3.7/S15),
// and the applied Zero Trust policy status (S7.2 staleness).
func (c *Client) ReportInfo(ctx context.Context, publicKey, endpoint string, egressNAT, egressIPv6 bool, ps PolicyStatus) error {
	body, _ := json.Marshal(map[string]any{
		"public_key": publicKey, "endpoint": endpoint, "egress_nat": egressNAT, "egress_ipv6": egressIPv6,
		"policy_version": ps.Version, "policy_hash": ps.Hash, "policy_error": ps.Error,
		"policy_failing_since": ps.FailingSince, "policy_refused_version": ps.RefusedVersion,
		"site_link_stale": ps.SiteLinkStale, "site_subnet_unreachable": ps.SiteSubnetUnreachable,
		"conntrack_flush_unavailable": ps.ConntrackFlushUnavailable, "k8s_endpoints_unavailable": ps.K8sEndpointsUnavailable, "max_policy_version": ps.MaxSupportedVersion,
		"ovpn_health":             ps.OVPNHealth,
		"dns_resolve_rpc_version": ps.DNSResolveRPCVersion,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("report status %d", resp.StatusCode)
	}
	return nil
}

// ReportDNSResolution posts one response to a request carried in desired state.
// The endpoint is served on the existing mTLS node channel; its server-side
// handler authenticates the gateway certificate and validates the echoed
// request binding before accepting any answer. A transport error intentionally
// leaves the response unacknowledged: the next desired-state fetch replays the
// same request id and the responder returns its cached observation.
func (c *Client) ReportDNSResolution(ctx context.Context, response fqdnrpc.Response) error {
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/dns-resolution", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("dns-resolution status %d", resp.StatusCode)
	}
	return nil
}

// ReportFlows ships a drained batch of flow-observation events (+ the count DROPPED since
// the last drain) over the SAME mTLS channel (node identity = the client cert). Best-effort
// observability: a failed report just loses a batch (the CP writes a gap on the next drop),
// never affects enforcement. Skips the round-trip when there is nothing to send.
func (c *Client) ReportFlows(ctx context.Context, events []flowlog.Event, dropped int64) error {
	if len(events) == 0 && dropped == 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"events": events, "dropped": dropped})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/flow-events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("flow report status %d", resp.StatusCode)
	}
	return nil
}

// ReportStatus posts per-peer live telemetry (handshake/bytes/endpoint) over the
// mTLS channel. Fire-and-forget from the caller's view: a failed report just
// means a momentarily stale status view, not a data-plane problem.
func (c *Client) ReportStatus(ctx context.Context, stats []reconcile.PeerStat) error {
	body, _ := json.Marshal(map[string]any{"peers": stats})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status report status %d", resp.StatusCode)
	}
	return nil
}

// FetchDesired GETs the desired state over mTLS.
func (c *Client) FetchDesired(ctx context.Context) (reconcile.DesiredState, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/desired-state", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return reconcile.DesiredState{}, fmt.Errorf("desired-state status %d", resp.StatusCode)
	}
	var ds reconcile.DesiredState
	if err := json.NewDecoder(resp.Body).Decode(&ds); err != nil {
		return reconcile.DesiredState{}, err
	}
	return ds, nil
}

// AcknowledgeKubernetesOwnershipBaseAuthority posts only the exact durable
// applied receipt. It runs outside the data-plane command lane; a transport
// failure leaves the local pending ACK intact for exact replay.
func (c *Client) AcknowledgeKubernetesOwnershipBaseAuthority(ctx context.Context, ack reconcile.KubernetesOwnershipBaseAuthorityAck) error {
	body, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/kubernetes-ownership-base-authority/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Kubernetes ownership base-authority acknowledgement status %d", resp.StatusCode)
	}
	return nil
}

// Watch long-polls the control plane; it returns when the server responds
// (change or timeout), prompting a re-fetch. since is the version from the last
// fetch — the server returns immediately if its version has advanced past it.
func (c *Client) Watch(ctx context.Context, since uint64) error {
	url := c.base + "/agent/watch?v=" + strconv.FormatUint(since, 10)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch status %d", resp.StatusCode)
	}
	return nil
}
