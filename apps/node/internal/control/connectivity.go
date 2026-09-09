package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ErrConnectivityDenied is an authoritative refusal, not a transient outage.
var ErrConnectivityDenied = errors.New("connectivity authorization refused")

// ConnectivitySession mirrors CP's bounded mailbox; application authorization
// remains WireGuard/policy. ICE consumers must validate the snapshot schema.
type ConnectivitySession struct {
	DevicePublicKey  string                   `json:"device_public_key"`
	GatewayPublicKey string                   `json:"gateway_public_key"`
	Relay            *ConnectivityRelayAccess `json:"relay,omitempty"`
	SessionID        string                   `json:"session_id"`
	DeviceID         string                   `json:"device_id"`
	GatewayID        string                   `json:"gateway_id"`
	Generation       int64                    `json:"generation"`
	ExpiresAt        time.Time                `json:"expires_at"`
	DeviceSequence   int64                    `json:"device_sequence"`
	GatewaySequence  int64                    `json:"gateway_sequence"`
	DevicePayload    string                   `json:"device_payload"`
	GatewayPayload   string                   `json:"gateway_payload"`
}

type ConnectivityRelayAccess struct {
	URL       string    `json:"url"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ConnectivityPage struct {
	Items      []ConnectivitySession `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

func (c *Client) ConnectivityPending(ctx context.Context, after string) (ConnectivityPage, error) {
	var page ConnectivityPage
	err := c.connectivityRPC(ctx, http.MethodGet, "/agent/connectivity-sessions?after="+url.QueryEscape(after), nil, &page)
	if err == nil && len(page.Items) > 64 {
		return ConnectivityPage{}, fmt.Errorf("connectivity page exceeds limit")
	}
	return page, err
}

func (c *Client) ConnectivityRead(ctx context.Context, s ConnectivitySession) (ConnectivitySession, error) {
	var out ConnectivitySession
	err := c.connectivityRPC(ctx, http.MethodGet, connectivityPath(s), nil, &out)
	return out, err
}

func (c *Client) ConnectivityPublish(ctx context.Context, s ConnectivitySession, sequence int64, payload string) (ConnectivitySession, error) {
	if sequence < 1 || sequence > 64 || len(payload) > 16384 {
		return ConnectivitySession{}, fmt.Errorf("invalid connectivity snapshot")
	}
	var out ConnectivitySession
	body := struct {
		Sequence int64  `json:"sequence"`
		Payload  string `json:"payload"`
	}{sequence, payload}
	err := c.connectivityRPC(ctx, http.MethodPut, connectivityPath(s), body, &out)
	return out, err
}

func (c *Client) ConnectivityClose(ctx context.Context, s ConnectivitySession) error {
	return c.connectivityRPC(ctx, http.MethodDelete, connectivityPath(s), nil, nil)
}

func connectivityPath(s ConnectivitySession) string {
	return "/agent/connectivity-sessions/" + url.PathEscape(s.DeviceID) + "/" + url.PathEscape(s.SessionID) + "?generation=" + strconv.FormatInt(s.Generation, 10)
}

func (c *Client) connectivityRPC(ctx context.Context, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("invalid connectivity request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid connectivity endpoint")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connectivity control channel unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return ErrConnectivityDenied
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("connectivity control refused (%d)", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	const maxResponse = 8 << 20 // 64 bounded escaped JSON snapshots plus metadata.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return fmt.Errorf("invalid connectivity response")
	}
	if json.Unmarshal(raw, out) != nil {
		return fmt.Errorf("invalid connectivity response")
	}
	return nil
}
