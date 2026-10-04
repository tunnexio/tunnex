package apptransport

import (
	"context"
	"encoding/json"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

func (b *Broker) Probe(ctx context.Context, binding Binding, requestID string) (originpolicy.Result, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var serial atomic.Value
	serial.Store("")
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 8 << 10, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, s, e := b.DialAuthenticated(ctx, binding)
		if e == nil {
			serial.Store(s)
		}
		return conn, e
	}}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://logical.app/__app_access/check", nil)
	BindingHeaders(req.Header, binding)
	req.Header.Set("X-App-Check-ID", requestID)
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return originpolicy.Result{}, serial.Load().(string), e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return originpolicy.Result{}, serial.Load().(string), ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (8<<10)+1))
	if e != nil || len(raw) > 8<<10 {
		return originpolicy.Result{}, serial.Load().(string), ErrUnavailable
	}
	var out originpolicy.Result
	e = json.Unmarshal(raw, &out)
	return out, serial.Load().(string), e
}
