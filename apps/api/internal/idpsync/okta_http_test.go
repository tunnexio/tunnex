package idpsync

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type oktaTestDoer func(*http.Request) (*http.Response, error)

func (f oktaTestDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }
func oktaResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestOktaSignedAssertionAndCompletePagination(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(jose.JSONWebKey{Key: key, KeyID: "test-key", Algorithm: "RS256", Use: "sig"})
	now := time.Now().Truncate(time.Second)
	tokens, pages := 0, 0
	doer := oktaTestDoer(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oauth2/v1/token" {
			tokens++
			if r.Method != "POST" {
				t.Fatal("token method")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("scope") != "okta.users.read okta.groups.read" || r.Form.Get("grant_type") != "client_credentials" {
				t.Fatal("wrong OAuth scope or grant")
			}
			signed, err := jwt.ParseSigned(r.Form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				t.Fatal(err)
			}
			var claims jwt.Claims
			if err = signed.Claims(&key.PublicKey, &claims); err != nil {
				t.Fatal(err)
			}
			if err = claims.Validate(jwt.Expected{Issuer: "service-app", Subject: "service-app", AnyAudience: jwt.Audience{"https://company.okta.com/oauth2/v1/token"}, Time: now}); err != nil {
				t.Fatal(err)
			}
			if claims.ID == "" || signed.Headers[0].KeyID != "test-key" || claims.Expiry.Time().Sub(now) != 5*time.Minute {
				t.Fatal("assertion identity or expiry")
			}
			return oktaResponse(200, `{"access_token":"test-only","token_type":"Bearer","expires_in":3600}`), nil
		}
		if r.Header.Get("Authorization") != "Bearer test-only" || r.URL.Host != "company.okta.com" || r.URL.Path != "/api/v1/groups/team/users" {
			t.Fatal("wrong directory request")
		}
		pages++
		if r.URL.Query().Get("after") == "" {
			resp := oktaResponse(200, `[{"id":"user1","status":"ACTIVE","profile":{"email":"ONE@example.com"}}]`)
			resp.Header.Set("Link", `<https://company.okta.com/api/v1/groups/team/users?after=user1>; rel="next"`)
			return resp, nil
		}
		return oktaResponse(200, `[{"id":"user2","status":"SUSPENDED","profile":{"email":"two@example.com"}}]`), nil
	})
	p, err := NewOktaProvider("https://company.okta.com", "service-app", string(raw), doer)
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return now }
	members, err := p.ListGroupMembers(context.Background(), "team")
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 1 || pages != 2 || len(members) != 2 || members[0].Email != "one@example.com" || members[1].Status != StatusDisabled {
		t.Fatal("incomplete members or token not cached")
	}
}

func TestOktaFailedContinuationNeverReturnsPartialMembership(t *testing.T) {
	for _, code := range []int{401, 403, 404, 429, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			pages := 0
			p := &OktaProvider{origin: "https://company.okta.com", token: "test-only", expiry: time.Now().Add(time.Hour), now: time.Now}
			p.http = oktaTestDoer(func(r *http.Request) (*http.Response, error) {
				pages++
				if pages == 1 {
					resp := oktaResponse(200, `[{"id":"user1","status":"ACTIVE","profile":{"email":"one@example.com"}}]`)
					resp.Header.Set("Link", `<https://company.okta.com/api/v1/groups/team/users?after=user1>; rel=next`)
					return resp, nil
				}
				return oktaResponse(code, "sensitive upstream details"), nil
			})
			members, err := p.ListGroupMembers(context.Background(), "team")
			if err == nil || err == ErrGroupGone || members != nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("failed continuation exposed partial state or response")
			}
		})
	}
}
