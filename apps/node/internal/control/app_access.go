package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// AppAccessTLSConfig clones trust while retaining the live atomic credential
// callback. The operator's app-control override is independent of WG control.
func (c *Client) AppAccessTLSConfig(override string) (*url.URL, *tls.Config, error) {
	target, err := url.Parse(c.base)
	if override != "" {
		target, err = url.Parse(override)
	}
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return nil, nil, fmt.Errorf("invalid app control endpoint")
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.GetClientCertificate == nil {
		return nil, nil, fmt.Errorf("rotating identity required")
	}
	config := tr.TLSClientConfig.Clone()
	config.MinVersion = tls.VersionTLS13
	config.NextProtos = []string{"http/1.1"}
	if override != "" {
		config.ServerName = target.Hostname()
	}
	return target, config, nil
}

type AppAssignment struct {
	Generation              string   `json:"generation"`
	OrgID                   string   `json:"org_id"`
	GatewayID               string   `json:"gateway_id"`
	AppID                   string   `json:"app_id"`
	Revision                int64    `json:"revision"`
	Digest                  string   `json:"digest"`
	Purpose                 string   `json:"purpose"`
	OriginURL               string   `json:"origin_url"`
	AllowedDestinationCIDRs []string `json:"allowed_destination_cidrs"`
	OriginCAPEM             string   `json:"origin_ca_pem"`
	OriginCADigest          string   `json:"origin_ca_digest"`
}
type AppCheck struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	GatewayID  string    `json:"gateway_id"`
	AppID      string    `json:"app_id"`
	Generation string    `json:"generation"`
	Revision   int64     `json:"revision"`
	Digest     string    `json:"digest"`
	Purpose    string    `json:"purpose"`
	Status     string    `json:"status"`
	Deadline   time.Time `json:"deadline"`
}
type AppDesired struct {
	ProtocolVersion int             `json:"protocol_version"`
	Purpose         string          `json:"purpose"`
	Withdrawn       bool            `json:"withdrawn"`
	Reason          string          `json:"reason"`
	Assignments     []AppAssignment `json:"assignments"`
	Checks          []AppCheck      `json:"checks"`
}
type AppApplied struct {
	Generation string `json:"generation"`
	AppID      string `json:"app_id"`
	Revision   int64  `json:"revision"`
	Digest     string `json:"digest"`
	Purpose    string `json:"purpose"`
	Status     string `json:"status"`
	ErrorCode  string `json:"error_code"`
}
type AppCheckResult struct {
	RequestID     string `json:"request_id"`
	Generation    string `json:"generation"`
	AppID         string `json:"app_id"`
	Revision      int64  `json:"revision"`
	Digest        string `json:"digest"`
	Purpose       string `json:"purpose"`
	DNSStatus     string `json:"dns_status"`
	ConnectStatus string `json:"connect_status"`
	TLSStatus     string `json:"tls_status"`
	ErrorCode     string `json:"error_code"`
}
type AppAccessClient struct {
	base         string
	http         *http.Client
	ControlHosts []string
}

func (c *Client) NewAppAccessClient(override string) (*AppAccessClient, error) {
	target, config, e := c.AppAccessTLSConfig(override)
	if e != nil {
		return nil, e
	}
	native, e := url.Parse(c.base)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: config, Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 12, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	return &AppAccessClient{base: target.String(), http: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ControlHosts: []string{native.Hostname(), target.Hostname()}}, nil
}
func (a *AppAccessClient) rpc(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := a.http.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 204 {
		return fmt.Errorf("app control refusal: %d", response.StatusCode)
	}
	if output != nil {
		raw, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
		if e != nil {
			return e
		}
		if len(raw) > 4<<20 {
			return fmt.Errorf("app control response exceeds bound")
		}
		return json.Unmarshal(raw, output)
	}
	_, e = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return e
}
func (a *AppAccessClient) Capability(ctx context.Context) error {
	return a.rpc(ctx, "POST", "/agent/app-access/capability", map[string]int{"protocol_version": 1}, nil)
}
func (a *AppAccessClient) Desired(ctx context.Context) (AppDesired, error) {
	var out AppDesired
	e := a.rpc(ctx, "GET", "/agent/app-access/desired-state", nil, &out)
	if e == nil && (len(out.Assignments) > 64 || len(out.Checks) > 8) {
		e = fmt.Errorf("app desired state exceeds bound")
	}
	return out, e
}
func (a *AppAccessClient) Applied(ctx context.Context, r AppApplied) error {
	return a.rpc(ctx, "POST", "/agent/app-access/report", r, nil)
}
func (a *AppAccessClient) Result(ctx context.Context, r AppCheckResult) error {
	return a.rpc(ctx, "POST", "/agent/app-access/checks/"+url.PathEscape(r.RequestID)+"/result", r, nil)
}

func (a *AppAccessClient) ChannelConfig() (*url.URL, *tls.Config) {
	target, _ := url.Parse(a.base)
	return target, a.http.Transport.(*http.Transport).TLSClientConfig.Clone()
}
