package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// AI-KEYS-1. The internal AI endpoint has its own agent-channel document (D9) and certificate route
// (D8). Both ride the node mTLS channel: the control plane takes the organization and the node from the
// client certificate. Neither call follows a redirect, and an error never carries the response body.

const (
	aiInternalDesiredPath     = "/agent/ai-internal/desired-state"
	aiInternalCertificatePath = "/agent/ai-internal/certificate"
	aiInternalResponseLimit   = 64 << 10
)

// ErrAIInternalOff means the control plane answered and the listener must stop at once: the route is
// absent (an older control plane answers 404), the node is refused (401/403), or the answer is not a
// readable 200 document. Any other error is transient (no answer, a timeout, a 5xx).
var ErrAIInternalOff = errors.New("internal AI endpoint is not served")

// AIInternalEndpoint is the configured endpoint of this gateway, as delivered. The gateway validates
// every field again before it listens (aiinternal.ParseDesired).
type AIInternalEndpoint struct {
	ID              string   `json:"id"`
	Revision        int64    `json:"revision"`
	ListenAddresses []string `json:"listen_addresses"`
	Port            int      `json:"port"`
	DNSName         string   `json:"dns_name"`
	SourceCIDRs     []string `json:"source_cidrs"`
	TLSMode         string   `json:"tls_mode"`
}

// AIInternalDesired is `GET /agent/ai-internal/desired-state`. A null endpoint means no listener.
type AIInternalDesired struct {
	Version  int                 `json:"version"`
	Endpoint *AIInternalEndpoint `json:"endpoint"`
}

// AIInternalCertificate is the answer to a certificate request: the leaf, the organization's internal
// AI CA it chains to, and the leaf's expiry.
type AIInternalCertificate struct {
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
	NotAfter       string `json:"not_after"`
}

// aiInternalChannel refuses anything but the authenticated HTTPS control channel, so a plain-HTTP or
// misconfigured agent never runs the listener.
func (c *Client) aiInternalChannel() error {
	if _, _, err := c.AIVPNTransport(); err != nil {
		return ErrAIInternalOff
	}
	return nil
}

// AIInternalDesiredState fetches the listener configuration. It returns ErrAIInternalOff (wrapped) when
// the listener must stop at once, and another error when the control plane could not be reached.
func (c *Client) AIInternalDesiredState(ctx context.Context) (AIInternalDesired, error) {
	if err := c.aiInternalChannel(); err != nil {
		return AIInternalDesired{}, err
	}
	resp, err := c.mcpDo(ctx, http.MethodGet, aiInternalDesiredPath, nil, nil)
	if err != nil {
		return AIInternalDesired{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, aiInternalResponseLimit))
		return AIInternalDesired{}, fmt.Errorf("internal AI desired state status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, aiInternalResponseLimit))
		return AIInternalDesired{}, fmt.Errorf("%w: status %d", ErrAIInternalOff, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, aiInternalResponseLimit+1))
	if err != nil {
		return AIInternalDesired{}, err
	}
	var out AIInternalDesired
	if len(raw) > aiInternalResponseLimit || json.Unmarshal(raw, &out) != nil {
		return AIInternalDesired{}, fmt.Errorf("%w: unreadable document", ErrAIInternalOff)
	}
	return out, nil
}

// AIInternalSign sends a CSR for the endpoint's leaf. The private key stays with the caller.
func (c *Client) AIInternalSign(ctx context.Context, csrPEM string) (AIInternalCertificate, error) {
	if err := c.aiInternalChannel(); err != nil {
		return AIInternalCertificate{}, err
	}
	resp, err := c.mcpDo(ctx, http.MethodPost, aiInternalCertificatePath, map[string]string{"csr_pem": csrPEM}, nil)
	if err != nil {
		return AIInternalCertificate{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, aiInternalResponseLimit))
		return AIInternalCertificate{}, fmt.Errorf("internal AI certificate status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, aiInternalResponseLimit+1))
	if err != nil {
		return AIInternalCertificate{}, err
	}
	var out AIInternalCertificate
	if len(raw) > aiInternalResponseLimit || json.Unmarshal(raw, &out) != nil {
		return AIInternalCertificate{}, errors.New("internal AI certificate response is invalid")
	}
	return out, nil
}

// AIInternalTransport is the relay's upstream: the control origin and the AI VPN transport (a fresh
// mTLS handshake with the current node certificate per request, 16 connections, 30 s to headers).
func (c *Client) AIInternalTransport() (*url.URL, http.RoundTripper, error) {
	return c.AIVPNTransport()
}
