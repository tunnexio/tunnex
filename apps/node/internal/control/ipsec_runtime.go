package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var ErrIPsecControl = errors.New("IPsec control request unavailable")

// The private channel uses the existing mTLS transport, but never copies a
// remote body or transport error into diagnostics. Redirects cannot move PSKs.
func (c *Client) ipsecRequest(ctx context.Context, method, path string, input, output any) error {
	if c == nil || c.http == nil {
		return ErrIPsecControl
	}
	base, e := url.Parse(c.base)
	if e != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return ErrIPsecControl
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return ErrIPsecControl
		}
		defer clear(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return ErrIPsecControl
	}
	req.Header.Set("Content-Type", "application/json")
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return ErrIPsecControl
	}
	defer resp.Body.Close()
	expectedStatus := http.StatusOK
	if output == nil {
		expectedStatus = http.StatusNoContent
	}
	if resp.StatusCode != expectedStatus {
		return ErrIPsecControl
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	defer clear(raw)
	if err != nil || len(raw) > 1<<20 {
		return ErrIPsecControl
	}
	if output == nil {
		if len(bytes.TrimSpace(raw)) != 0 {
			return ErrIPsecControl
		}
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(output) != nil {
		return ErrIPsecControl
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrIPsecControl
	}
	return nil
}
func (c *Client) IPsecPending(ctx context.Context, after *uuid.UUID, limit int) (ipsec.RuntimePendingPage, error) {
	var out ipsec.RuntimePendingPage
	if limit < 1 || limit > 100 || after != nil && *after == uuid.Nil {
		return out, ErrIPsecControl
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if after != nil {
		q.Set("after", after.String())
	}
	err := c.ipsecRequest(ctx, "GET", "/agent/ipsec/pending?"+q.Encode(), nil, &out)
	if err == nil && (out.OrgID == uuid.Nil || out.NodeID == uuid.Nil || len(out.Items) > limit) {
		return ipsec.RuntimePendingPage{}, ErrIPsecControl
	}
	return out, err
}
func ipsecRuntimePath(id uuid.UUID, suffix string) string {
	return "/agent/ipsec/connections/" + id.String() + suffix
}
func (c *Client) IPsecMaterial(ctx context.Context, id uuid.UUID, revision int64) (ipsec.RuntimeMaterial, error) {
	var out ipsec.RuntimeMaterial
	if id == uuid.Nil || revision <= 0 {
		return out, ErrIPsecControl
	}
	err := c.ipsecRequest(ctx, "POST", ipsecRuntimePath(id, "/material"), struct {
		Revision int64 `json:"desired_revision"`
	}{revision}, &out)
	if err != nil {
		return ipsec.RuntimeMaterial{}, err
	}
	return out, nil
}
func (c *Client) IPsecCleanup(ctx context.Context, id uuid.UUID, revision int64) (ipsec.RuntimeCleanup, error) {
	var out ipsec.RuntimeCleanup
	if id == uuid.Nil || revision <= 0 {
		return out, ErrIPsecControl
	}
	err := c.ipsecRequest(ctx, "GET", ipsecRuntimePath(id, "/cleanup?desired_revision="+strconv.FormatInt(revision, 10)), nil, &out)
	return out, err
}
func (c *Client) IPsecAcknowledge(ctx context.Context, id uuid.UUID, ack ipsec.RuntimeAcknowledgement) error {
	if id == uuid.Nil {
		return ErrIPsecControl
	}
	return c.ipsecRequest(ctx, "POST", ipsecRuntimePath(id, "/acknowledgements"), ack, nil)
}
func (c *Client) RenewIPsecLease(ctx context.Context, id uuid.UUID, request ipsec.RuntimeLeaseRequest) (ipsec.RuntimeLease, error) {
	var out ipsec.RuntimeLease
	if id == uuid.Nil {
		return out, ErrIPsecControl
	}
	err := c.ipsecRequest(ctx, "POST", ipsecRuntimePath(id, "/permit-lease"), request, &out)
	return out, err
}

func (c *Client) IPsecReportStatus(ctx context.Context, id uuid.UUID, report ipsec.RuntimeStatusReport) error {
	if id == uuid.Nil || report.DeliveryID == uuid.Nil || report.DesiredRevision <= 0 || report.ConfigurationRevision <= 0 {
		return ErrIPsecControl
	}
	for i, t := range report.Tunnels {
		if t.ID == uuid.Nil || t.Slot != i+1 || t.Selected != (i == 0) || (t.Status != "up" && t.Status != "down" && t.Status != "unknown") {
			return ErrIPsecControl
		}
	}
	if report.Tunnels[0].ID == report.Tunnels[1].ID {
		return ErrIPsecControl
	}
	return c.ipsecRequest(ctx, "POST", ipsecRuntimePath(id, "/status"), report, nil)
}
