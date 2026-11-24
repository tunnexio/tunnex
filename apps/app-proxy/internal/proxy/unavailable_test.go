package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The deny page is uniform: an unknown host, an unpublished app and a missing
// grant must render byte-identical pages. It may only be worded so a member
// knows what to do next; it must never say which of those it was.
func TestDenyPageIsUniformAndActionable(t *testing.T) {
	render := func() (int, string) {
		w := httptest.NewRecorder()
		deny(w)
		return w.Code, w.Body.String()
	}
	code, body := render()
	if code != http.StatusForbidden {
		t.Fatalf("status = %d", code)
	}
	if _, again := render(); again != body {
		t.Fatal("deny page is not uniform")
	}
	for _, want := range []string{"<title>Can&#39;t open this application · Tunnex</title>", "<h1>You can&#39;t open this application</h1>", "Reopen it from My Applications. If you need access, ask your administrator."} {
		if !strings.Contains(body, want) {
			t.Fatalf("deny page missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"Application unavailable", "grant", "unpublished", "authority"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("deny page reveals or alarms with %q", forbidden)
		}
	}
}

func TestBeamDenyPageKeepsItsOwnWording(t *testing.T) {
	w := httptest.NewRecorder()
	denyPage(w, true)
	if !strings.Contains(w.Body.String(), "This shared app is unavailable. Reopen the original Beam link.") {
		t.Fatal("beam deny wording changed")
	}
}
