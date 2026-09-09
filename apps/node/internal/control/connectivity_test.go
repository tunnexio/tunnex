package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectivityRPC(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("generation") != "1" || r.Method != http.MethodPut {
			t.Error("bad method/generation")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"s","device_id":"d","generation":1,"gateway_sequence":1}`))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	out, err := c.ConnectivityPublish(context.Background(), ConnectivitySession{DeviceID: "d", SessionID: "s", Generation: 1}, 1, `{}`)
	if err != nil || out.GatewaySequence != 1 || calls != 1 {
		t.Fatal("publish failed", err)
	}
	if _, err := c.ConnectivityPublish(context.Background(), ConnectivitySession{}, 65, `{}`); err == nil || calls != 1 {
		t.Fatal("invalid sequence reached server")
	}
}

func TestConnectivityRPCRefusalDoesNotLeakBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("private candidate secret"))
	}))
	defer srv.Close()
	c := &Client{base: srv.URL, http: srv.Client()}
	_, err := c.ConnectivityPending(context.Background(), "")
	if !errors.Is(err, ErrConnectivityDenied) || strings.Contains(err.Error(), "private") {
		t.Fatal("missing refusal or body leaked")
	}
}
