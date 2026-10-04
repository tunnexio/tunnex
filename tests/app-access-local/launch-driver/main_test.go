package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPrivateArtifactPathsRemainInOwnedRuntime(t *testing.T) {
	for _, path := range []string{owned + "/.runtime/aa8-session.json", owned + "/.runtime/synthetic-account.env"} {
		if err := privatePath(path); err != nil {
			t.Fatal("owned private artifact refused")
		}
	}
	for _, path := range []string{"relative.json", "/private/tmp/session.json", owned + "/.runtime/../session.json", owned + "/.runtime/nested/session.json", owned + "/.runtime/nested/../session.json"} {
		if privatePath(path) == nil {
			t.Fatal("outside artifact accepted")
		}
	}
}

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestOwnedClientRefusesExternalDialAndKeepsSecureAppCookieOffCP(t *testing.T) {
	c, e := client()
	if e != nil {
		t.Fatal("retained owned CA required for helper qualification")
	}
	for _, target := range []string{"https://unrelated.example.test/", "http://127.0.0.1:18083/", "https://" + appHost + ":8443/"} {
		if _, e := c.Get(target); e == nil {
			t.Fatal("unapproved endpoint reached")
		}
	}
	app, _ := url.Parse(appBase)
	cp, _ := url.Parse(cpBase)
	c.Jar.SetCookies(app, []*http.Cookie{{Name: "__Host-tunnex_app_session", Value: "private-test-cookie", Path: "/", Secure: true, HttpOnly: true}})
	for _, cookie := range c.Jar.Cookies(cp) {
		if cookie.Value == "private-test-cookie" {
			t.Fatal("app cookie leaked to CP")
		}
	}
	calls := 0
	c.Transport = fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 303, Header: http.Header{"Location": []string{"https://unrelated.example.test/secret"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	status, _, _, e := request(c, "GET", appBase+"/__tunnex_app/start", nil, nil)
	if e != nil || status != 303 || calls != 1 {
		t.Fatal("redirect auto-follow boundary failed")
	}
}
