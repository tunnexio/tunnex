package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
	for _, want := range []string{"<title>Can&#39;t open this application · Tunnex</title>", "<h1>You can&#39;t open this application</h1>", "Reopen it from My Applications. If it still won&#39;t open, ask your administrator."} {
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

// LS-UX-1: the Local Sharing refusal names the product, not its code name, says
// what to do next without saying why, and links to the console identically.
func TestBeamDenyPageKeepsItsOwnWording(t *testing.T) {
	w := httptest.NewRecorder()
	denyPage(w, true)
	body := w.Body.String()
	for _, want := range []string{"TUNNEX LOCAL SHARING", "Open Shared with me in Tunnex Local Sharing, or ask the person who shared the link."} {
		if !strings.Contains(body, want) {
			t.Fatalf("Local Sharing deny page missing %q", want)
		}
	}
	if strings.Contains(body, "Beam") || strings.Contains(body, "My Applications") {
		t.Fatal("Local Sharing deny page uses a code name or App Access wording")
	}
	h := NewBeamHandler("share.example.net", nil, nil)
	render := func() string { w := httptest.NewRecorder(); h.deny(w); return w.Body.String() }
	if strings.Contains(render(), "Open Local Sharing") {
		t.Fatal("console link shown before the console is known")
	}
	console, _ := url.Parse("https://console.example.com")
	h.Console = console
	body = render()
	if !strings.Contains(body, `<a href="https://console.example.com/beam/shared-with-me">Open Local Sharing</a>`) || render() != body {
		t.Fatalf("Local Sharing refusal link missing or not uniform:\n%s", body)
	}
}

// SA-UX-2 A14: once the console is known, every refusal links to My Applications, identically for every host and
// cause, and a refusal never asks the authority for it.
func TestDenyPageLinksMyApplicationsUniformly(t *testing.T) {
	h := NewHandler("apps.example.com", nil, nil)
	render := func() string {
		w := httptest.NewRecorder()
		h.deny(w)
		return w.Body.String()
	}
	if strings.Contains(render(), "Open My Applications") {
		t.Fatal("link shown before the console is known")
	}
	console, err := url.Parse("https://console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	h.rememberConsole(console)
	body := render()
	if !strings.Contains(body, `<a href="https://console.example.com/app-access/my-applications">Open My Applications</a>`) {
		t.Fatalf("missing My Applications link:\n%s", body)
	}
	if render() != body {
		t.Fatal("refusal page with link is not uniform")
	}
	for _, forbidden := range []string{"grant", "unpublished", "authority"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("refusal page reveals %q", forbidden)
		}
	}
	static := NewHandler("apps.example.com", nil, nil)
	static.Console = console
	w := httptest.NewRecorder()
	static.deny(w)
	if !strings.Contains(w.Body.String(), "Open My Applications") {
		t.Fatal("static console not linked")
	}
	beam := NewBeamHandler("apps.example.com", nil, nil)
	beam.rememberConsole(console)
	w = httptest.NewRecorder()
	beam.deny(w)
	if strings.Contains(w.Body.String(), "My Applications") {
		t.Fatal("Beam refusal must keep its own wording")
	}
}

func TestMyAppsLinkIsEscaped(t *testing.T) {
	if got := consoleLink(`https://x.example/"><script>`, false); strings.Contains(got, "<script>") {
		t.Fatalf("unescaped: %s", got)
	}
}
