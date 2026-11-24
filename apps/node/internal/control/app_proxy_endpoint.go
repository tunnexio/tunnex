package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ErrProxyEndpointUnsupported is an older control plane (404): the caller keeps
// its current state. Upgrade the control plane before gateways (AA-EN-1 E5).
var ErrProxyEndpointUnsupported = errors.New("control plane does not deliver the App Access proxy endpoint")

// AppProxyEndpoint is the control plane's answer for this gateway. Host empty
// means "dial the host of the agent channel".
type AppProxyEndpoint struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Host    string `json:"host"`
}

// AppProxyEndpoint asks GET /agent/app-access/proxy-endpoint over the mTLS
// agent channel.
func (c *Client) AppProxyEndpoint(ctx context.Context) (AppProxyEndpoint, error) {
	var out AppProxyEndpoint
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/agent/app-access/proxy-endpoint", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return out, ErrProxyEndpointUnsupported
	default:
		return out, fmt.Errorf("app proxy endpoint refused (%d)", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return AppProxyEndpoint{}, err
	}
	return out, nil
}

// AgentHost is the host this client dials for its agent channel; a delivered
// endpoint without a host override uses it.
func (c *Client) AgentHost() string {
	u, err := url.Parse(c.base)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
