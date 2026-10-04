package proxy

import (
	"context"
	"encoding/json"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthorityMaximumMetadataWithoutHTMLEscaping(t *testing.T) {
	target := "/?" + strings.Repeat("&", 8190)
	prefix := "https://app.apps.example.net/?"
	referer := prefix + strings.Repeat("&", 8192-len(prefix))
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, e := io.ReadAll(io.LimitReader(r.Body, 65537))
		if e != nil || len(payload) > 65536 || strings.Contains(string(payload), `\u0026`) {
			t.Error("metadata expansion exceeded bound")
		}
		var input authoritywire.AppProxyAuthorizeInput
		if json.Unmarshal(payload, &input) != nil || input.Request.RelativePath != target || input.Request.Referer != referer {
			t.Error("maximum generated metadata changed")
		}
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"code":"browser_authority_unavailable","message":"unavailable"}}`))
	}))
	client, e := NewClient(server.URL, testProxyCredential(), config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Authorize(context.Background(), launchBinding(), "opaque", Request{Method: "GET", RelativePath: target, Referer: referer}); e != ErrDenied {
		t.Fatal(e)
	}
}
func TestAuthoritySessionErrorClassificationAndTypedRedeem(t *testing.T) {
	for _, tc := range []struct {
		status  int
		code    string
		session bool
	}{{403, "app_session_invalid", true}, {401, "proxy_unauthenticated", false}, {403, "browser_authority_unavailable", false}, {403, "parent_revoked", false}} {
		server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/internal/app-access/redeem" {
				var input authoritywire.AppProxyRedeemInput
				if json.NewDecoder(r.Body).Decode(&input) != nil || input.Hostname != "app.apps.example.net" || input.Code != "code" || input.Nonce != "nonce" || r.Header.Get("Cookie") != "" {
					t.Error("redeem payload drift")
				}
			}
			w.WriteHeader(tc.status)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": tc.code, "message": "private detail must not escape"}})
		}))
		client, e := NewClient(server.URL, testProxyCredential(), config)
		if e != nil {
			t.Fatal(e)
		}
		_, e = client.Authorize(context.Background(), launchBinding(), "opaque", Request{})
		if (e == ErrAppSession) != tc.session {
			t.Fatal(tc, e)
		}
		_, e = client.Redeem(context.Background(), RedeemInput{Code: "code", Nonce: "nonce", Hostname: "app.apps.example.net"})
		if e != ErrDenied {
			t.Fatal("redeem reauthentication misclassified", e)
		}
	}
}

func TestAuthorityTypedPendingRegistration(t *testing.T) {
	expected := PendingInput{Binding: authoritywire.AppProxyRouteBinding(launchBinding()), NonceHash: strings.Repeat("a", 64), RelativeTarget: "/forms?x=1"}
	expiry := time.Now().Add(10 * time.Minute).UTC()
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input PendingInput
		if r.URL.Path != "/internal/app-access/pending-launch" || json.NewDecoder(r.Body).Decode(&input) != nil || input != expected || r.Header.Get("Cookie") != "" {
			t.Error("pending registration wire drift")
		}
		json.NewEncoder(w).Encode(PendingResult{ExpiresAt: expiry})
	}))
	client, e := NewClient(server.URL, testProxyCredential(), config)
	if e != nil {
		t.Fatal(e)
	}
	result, e := client.Pending(context.Background(), expected)
	if e != nil || !result.ExpiresAt.Equal(expiry) {
		t.Fatal(result, e)
	}
}

func TestReadinessClaimBoundCoversEightMaximumCAPayloads(t *testing.T) {
	server, config := authorityFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/app-access/publication-readiness/claim" {
			t.Error("wrong claim path")
		}
		items := make([]authoritywire.AppProxyReadinessWork, 8)
		for i := range items {
			items[i] = authoritywire.AppProxyReadinessWork{Route: Route{OriginCAPEM: strings.Repeat("x", 32<<10)}}
		}
		json.NewEncoder(w).Encode(authoritywire.AppProxyReadinessClaimResult{Items: items})
	}))
	client, err := NewClient(server.URL, testProxyCredential(), config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ClaimReadiness(context.Background(), authoritywire.AppProxyReadinessClaimInput{InstanceToken: "instance"})
	if err != nil || len(result.Items) != 8 {
		t.Fatal("bounded valid multi-operation CA payload refused", err)
	}
}
