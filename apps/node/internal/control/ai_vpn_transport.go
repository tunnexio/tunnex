package control

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AIVPNTransport reuses the agent's CA and atomic GetClientCertificate callback.
// Every inference request performs a new mTLS handshake, so a certificate renewed
// or recovered after startup is used without retaining an initial certificate.
func (c *Client) AIVPNTransport() (*url.URL, http.RoundTripper, error) {
	target, err := url.Parse(c.base)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return nil, nil, fmt.Errorf("VPN AI requires the authenticated HTTPS control channel")
	}
	base, ok := c.http.Transport.(*http.Transport)
	if !ok || base.TLSClientConfig == nil || base.TLSClientConfig.InsecureSkipVerify || base.TLSClientConfig.GetClientCertificate == nil {
		return nil, nil, fmt.Errorf("VPN AI requires the rotating node identity")
	}
	tr := base.Clone()
	tr.DisableKeepAlives = true
	tr.MaxConnsPerHost = 16
	tr.ResponseHeaderTimeout = 30 * time.Second
	tr.TLSHandshakeTimeout = 10 * time.Second
	return target, tr, nil
}
