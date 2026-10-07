package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
)

type Binding authoritywire.AppProxyRouteBinding

func (b Binding) Transport() apptransport.Binding {
	return apptransport.Binding{OrgID: b.OrgID, AppID: b.AppID, GatewayID: b.GatewayID, Generation: b.Generation, Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Digest: b.Digest, Hostname: b.Hostname, Purpose: string(b.Purpose)}
}

type Route = authoritywire.AppProxyRoute
type Request = authoritywire.AppProxyRequestMetadata
type Decision = authoritywire.AppProxyAuthorityDecision
type PendingInput = authoritywire.AppProxyPendingLaunchInput
type PendingResult = authoritywire.AppProxyPendingLaunchResult
type RedeemInput = authoritywire.AppProxyRedeemInput
type RedeemResult = authoritywire.AppProxyRedeemResult
type Authority interface {
	Pending(context.Context, PendingInput) (PendingResult, error)
	Redeem(context.Context, RedeemInput) (RedeemResult, error)
	Lookup(context.Context, string) (Route, error)
	Authorize(context.Context, Binding, string, Request) (Decision, error)
	Renew(context.Context, Binding, string) (Decision, error)
	Channel(context.Context, Binding, string) (time.Time, error)
}

var ErrDenied = errors.New("application unavailable")
var ErrAppSession = errors.New("app session invalid")

type Client struct {
	base       string
	credential string
	http       *http.Client
	beam       bool
}

func NewClient(endpoint, credential string, config *tls.Config) (*Client, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || config == nil || config.InsecureSkipVerify || config.ServerName == "" || config.RootCAs == nil || !strings.HasPrefix(credential, "tnxap_") {
		return nil, ErrDenied
	}
	tlsConfig := config.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"http/1.1"}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, MaxConnsPerHost: 128, MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	return &Client{base: strings.TrimSuffix(endpoint, "/"), credential: credential, http: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}}, nil
}

// NewBeamClient uses the same bounded authenticated authority transport, with a
// separate CP namespace. The caller cannot select a namespace per request.
func NewBeamClient(endpoint, credential string, config *tls.Config) (*Client, error) {
	c, err := NewClient(endpoint, credential, config)
	if err == nil {
		c.beam = true
	}
	return c, err
}
func (c *Client) call(ctx context.Context, path string, input, output any) error {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(false)
	e := encoder.Encode(input)
	if e != nil || payload.Len() > 64<<10 {
		return ErrDenied
	}
	namespace := "/internal/app-access/"
	if c.beam {
		namespace = "/internal/beam/"
		switch path {
		case "route-lookup":
			path = "resolve"
		case "channel-authorize":
			path = "connector"
		case "leases/renew":
			path = "renew"
		case "pending-launch":
			path = "pending"
		case "stream-terminated":
			path = "terminated"
			output = new(struct{})
		}
	}
	request, e := http.NewRequestWithContext(ctx, "POST", c.base+namespace+path, bytes.NewReader(payload.Bytes()))
	if e != nil {
		return ErrDenied
	}
	request.Header.Set("Authorization", "AppProxy "+c.credential)
	request.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(request)
	if e != nil {
		return ErrDenied
	}
	defer response.Body.Close()
	if path == "stream-terminated" && response.StatusCode == http.StatusNoContent {
		return nil
	}
	if response.StatusCode != 200 {
		if path == "authorize" && response.StatusCode == 403 {
			payload, e := io.ReadAll(io.LimitReader(response.Body, 4097))
			if e == nil && len(payload) <= 4096 {
				var failure authoritywire.AppProxyError
				if json.Unmarshal(payload, &failure) == nil && (failure.Error.Code == "app_session_invalid" || (c.beam && failure.Error.Code == "beam_session_invalid")) {
					return ErrAppSession
				}
			}
		}
		return ErrDenied
	}
	responseLimit := 64 << 10
	if path == "publication-readiness/claim" {
		responseLimit = 512 << 10
	}
	responsePayload, e := io.ReadAll(io.LimitReader(response.Body, int64(responseLimit)+1))
	if e != nil || len(responsePayload) > responseLimit {
		return ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(responsePayload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return ErrDenied
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func (c *Client) Lookup(ctx context.Context, host string) (Route, error) {
	var out Route
	e := c.call(ctx, "route-lookup", authoritywire.AppProxyRouteLookupInput{Hostname: host}, &out)
	return out, e
}
func (c *Client) Authorize(ctx context.Context, b Binding, token string, r Request) (Decision, error) {
	var out Decision
	e := c.call(ctx, "authorize", authoritywire.AppProxyAuthorizeInput{Binding: authoritywire.AppProxyRouteBinding(b), AppSessionToken: token, Request: r}, &out)
	return out, e
}
func (c *Client) Renew(ctx context.Context, b Binding, id string) (Decision, error) {
	var out Decision
	e := c.call(ctx, "leases/renew", authoritywire.AppProxyLeaseInput{Binding: authoritywire.AppProxyRouteBinding(b), StreamID: id}, &out)
	return out, e
}
func (c *Client) Channel(ctx context.Context, b Binding, serial string) (time.Time, error) {
	var out authoritywire.AppProxyAuthorityLease
	e := c.call(ctx, "channel-authorize", authoritywire.AppProxyChannelInput{Binding: authoritywire.AppProxyRouteBinding(b), CertificateSerial: serial}, &out)
	return out.ExpiresAt, e
}

func (b Binding) Valid() bool {
	return b.validPurpose("browser_proxy")
}
func (b Binding) validPurpose(purpose string) bool {
	for _, id := range []string{b.OrgID, b.AppID, b.GatewayID, b.Generation} {
		if len(id) != 36 || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
		for i, c := range id {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false
				}
			} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	if len(b.Digest) != 64 {
		return false
	}
	for _, c := range b.Digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return string(b.Purpose) == purpose && b.Revision > 0 && b.AuthorityVersion > 0 && b.Hostname != ""
}

func (c *Client) Redeem(ctx context.Context, input RedeemInput) (RedeemResult, error) {
	var out RedeemResult
	e := c.call(ctx, "redeem", input, &out)
	return out, e
}

func (c *Client) Pending(ctx context.Context, input PendingInput) (PendingResult, error) {
	var out PendingResult
	err := c.call(ctx, "pending-launch", input, &out)
	return out, err
}

func (c *Client) Terminated(ctx context.Context, input authoritywire.AppProxyStreamTerminatedInput) error {
	return c.call(ctx, "stream-terminated", input, nil)
}
