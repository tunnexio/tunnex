package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFixtureReviewerSecureCookie(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := seed.TLS.Certificates[0]
	seed.Close()
	viewer := newFixtureViewer(certificate, "synthetic-review-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
			t.Error("reviewer request must use TLS 1.3")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer viewer.Close()
	if !strings.HasPrefix(viewer.URL, "https://127.0.0.1:") {
		t.Fatalf("viewer must stay on loopback HTTPS: %s", viewer.URL)
	}
	client := viewer.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(viewer.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthenticated viewer status: %d", response.StatusCode)
	}
	response, err = client.Get(viewer.URL + "/_beam/fixture-signin")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	cookies := response.Cookies()
	if response.StatusCode != http.StatusSeeOther || len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("sign-in must issue a Secure, HttpOnly, SameSite=Strict cookie")
	}
	secure, _ := url.Parse("https://beam.example")
	plain, _ := url.Parse("http://beam.example")
	jar.SetCookies(secure, cookies)
	if len(jar.Cookies(plain)) != 0 {
		t.Fatal("review cookie must never be sent over plaintext HTTP")
	}
	// Loopback cookie jars may treat HTTP as secure; the actual viewer must
	// still reject plaintext traffic, regardless of that localhost exception.
	response, err = client.Get(strings.Replace(viewer.URL, "https://", "http://", 1))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext viewer must be refused: %d", response.StatusCode)
	}
	response, err = client.Get(viewer.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("authenticated reviewer status: %d", response.StatusCode)
	}
}
