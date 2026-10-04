package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserDesiredWithdrawalOnly(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"protocol_version":1,"purpose":"browser_proxy","withdrawn":true,"assignments":[]}`, true},
		{`{"protocol_version":2,"purpose":"browser_proxy","withdrawn":true,"assignments":[]}`, false},
		{`{"protocol_version":1,"purpose":"origin_check","withdrawn":true,"assignments":[]}`, false},
		{`{"protocol_version":1,"purpose":"browser_proxy","withdrawn":false,"assignments":[]}`, false},
		{`{"protocol_version":1,"purpose":"browser_proxy","withdrawn":true,"assignments":[{}]}`, false},
		{`{"protocol_version":1,"purpose":"browser_proxy","withdrawn":true,"assignments":null}`, false},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/agent/app-access/browser-desired-state" {
				t.Error("wrong private route")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(tc.body))
		}))
		client := &AppAccessClient{base: server.URL, http: server.Client()}
		e := client.BrowserWithdrawn(context.Background())
		server.Close()
		if (e == nil) != tc.ok {
			t.Fatal(tc.body, e)
		}
	}
}
