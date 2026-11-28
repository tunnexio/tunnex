package aiinternal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = "tnx_sk_" + strings.Repeat("A1b2C3d4E5", 4) + "xyz" + "Q9w8E7"

type seenRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   string
}

type fakeControl struct {
	mu      sync.Mutex
	seen    []seenRequest
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeControl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (f *fakeControl) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

func newRelay(t *testing.T, upstream *fakeControl) http.Handler {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Handler(target, srv.Client().Transport, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
}

func call(h http.Handler, method, target, remote string, header http.Header, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = remote
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func bearer() http.Header {
	return http.Header{"Authorization": {"Bearer " + testKey}, "Content-Type": {"application/json"}}
}

func TestValidStaticKeyShape(t *testing.T) {
	if len(testKey) != 56 || !validStaticKey(testKey) {
		t.Fatalf("the test key is not a static key: %d", len(testKey))
	}
	for _, bad := range []string{"", testKey[:55], testKey + "A", "tnx_wai_" + testKey[8:], "tnx_SK_" + testKey[7:],
		testKey[:55] + "-", testKey[:55] + "_", testKey[:55] + "=", testKey[:30] + " " + testKey[31:]} {
		if validStaticKey(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRelayForwardsOnlyTheFixedHeadersAndSetsThePeerFromTCP(t *testing.T) {
	up := &fakeControl{}
	h := newRelay(t, up)
	header := bearer()
	header["Accept"] = []string{"text/event-stream"}
	header["X-Forwarded-For"] = []string{"10.20.9.9"}
	header["X-Real-Ip"] = []string{"10.20.9.9"}
	header["Forwarded"] = []string{"for=10.20.9.9"}
	header["X-Tunnex-Peer-Ip"] = []string{"10.20.9.9"}
	header["X-Tunnex-Vpn-Ip"] = []string{"10.20.9.9"}
	header["Cookie"] = []string{"session=human"}
	header["Openai-Organization"] = []string{"org"}
	w := call(h, http.MethodPost, "/v1/chat/completions", "10.20.3.4:51000", header, `{"model":"m"}`)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	seen := up.requests()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests", len(seen))
	}
	got := seen[0]
	if got.method != http.MethodPost || got.path != "/agent/ai-key/v1/chat/completions" || got.query != "" || got.body != `{"model":"m"}` {
		t.Fatalf("upstream request: %+v", got)
	}
	want := map[string]string{"Authorization": "Bearer " + testKey, "Content-Type": "application/json",
		"Accept": "text/event-stream", "X-Tunnex-Peer-Ip": "10.20.3.4"}
	for name, value := range want {
		if v := got.header.Values(name); len(v) != 1 || v[0] != value {
			t.Fatalf("%s=%v, want %q", name, v, value)
		}
	}
	// Only transport-level headers the Go client adds itself may appear beside the fixed set.
	for name := range got.header {
		if _, ok := want[name]; !ok && name != "Content-Length" && name != "Accept-Encoding" {
			t.Fatalf("upstream received the caller header %s=%v", name, got.header[name])
		}
	}
}

func TestRelayMapsEveryAllowedRouteAndRefusesTheRest(t *testing.T) {
	up := &fakeControl{}
	h := newRelay(t, up)
	for path, method := range routes {
		header := bearer()
		body := `{}`
		if method == http.MethodGet {
			delete(header, "Content-Type")
			body = ""
		}
		w := call(h, method, path, "10.20.3.4:5000", header, body)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d", method, path, w.Code)
		}
	}
	paths := map[string]bool{}
	for _, r := range up.requests() {
		paths[r.method+" "+r.path] = true
		if r.method == http.MethodGet && (r.header.Get("Content-Type") != "" || r.body != "") {
			t.Fatalf("GET carried a body or a content type: %+v", r)
		}
	}
	for path, method := range routes {
		if !paths[method+" /agent/ai-key"+path] {
			t.Fatalf("missing upstream %s /agent/ai-key%s in %v", method, path, paths)
		}
	}
	count := len(up.requests())
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/v1/videos"},
		{http.MethodPost, "/v1/videos/generations"},
		{http.MethodPost, "/ai/v1/chat/completions"},
		{http.MethodPost, "/v1/chat/completions/"},
		{http.MethodPost, "/v1/Chat/completions"},
		{http.MethodPost, "/agent/ai-key/v1/chat/completions"},
		{http.MethodPost, "/"},
		{http.MethodGet, "/v1/chat/completions"},
		{http.MethodPut, "/v1/embeddings"},
		{http.MethodPost, "/v1/models"},
		{http.MethodDelete, "/v1/models"},
	} {
		if w := call(h, tc.method, tc.target, "10.20.3.4:5000", bearer(), `{}`); w.Code != http.StatusNotFound {
			t.Fatalf("%s %s: %d", tc.method, tc.target, w.Code)
		}
	}
	for _, target := range []string{"/v1/chat/completions?x=1", "/v1/chat/completions?", "/v1/models?limit=1", "/v1/chat%2Fcompletions"} {
		if w := call(h, http.MethodPost, target, "10.20.3.4:5000", bearer(), `{}`); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", target, w.Code)
		}
	}
	if len(up.requests()) != count {
		t.Fatal("a refused request reached the control plane")
	}
}

func TestRelayForwardsOnlyOneStaticKeyCredential(t *testing.T) {
	up := &fakeControl{}
	h := newRelay(t, up)
	refused := map[string]http.Header{
		"no credential":                  {"Content-Type": {"application/json"}},
		"workload token":                 {"Authorization": {"Bearer tnx_wai_" + strings.Repeat("a", 48)}},
		"human token":                    {"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"}},
		"lower-case scheme":              {"Authorization": {"bearer " + testKey}},
		"basic scheme":                   {"Authorization": {"Basic " + testKey}},
		"bare key":                       {"Authorization": {testKey}},
		"short key":                      {"Authorization": {"Bearer " + testKey[:55]}},
		"two authorization headers":      {"Authorization": {"Bearer " + testKey, "Bearer " + testKey}},
		"authorization and api key":      {"Authorization": {"Bearer " + testKey}, "X-Api-Key": {testKey}},
		"api key off the messages route": {"X-Api-Key": {testKey}},
		"empty authorization":            {"Authorization": {""}},
	}
	for name, header := range refused {
		if w := call(h, http.MethodPost, "/v1/chat/completions", "10.20.3.4:5000", header, `{}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}
	messages := map[string]http.Header{
		"api key twice":         {"X-Api-Key": {testKey, testKey}},
		"api key and bearer":    {"X-Api-Key": {testKey}, "Authorization": {"Bearer " + testKey}},
		"api key workload":      {"X-Api-Key": {"tnx_wai_" + strings.Repeat("a", 48)}},
		"api key provider-like": {"X-Api-Key": {"sk-ant-" + strings.Repeat("a", 40)}},
	}
	for name, header := range messages {
		if w := call(h, http.MethodPost, messagesPath, "10.20.3.4:5000", header, `{}`); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("%d refused credentials reached the control plane", n)
	}
	w := call(h, http.MethodPost, messagesPath, "10.20.3.4:5000", http.Header{"X-Api-Key": {testKey}, "Content-Type": {"application/json"}}, `{}`)
	if w.Code != 200 {
		t.Fatalf("x-api-key on the messages route: %d", w.Code)
	}
	got := up.requests()[0].header
	if got.Get("X-Api-Key") != testKey || got.Get("Authorization") != "" {
		t.Fatalf("messages credential forwarded as %v", got)
	}
	w = call(h, http.MethodPost, messagesPath, "10.20.3.4:5000", bearer(), `{}`)
	if w.Code != 200 || up.requests()[1].header.Get("Authorization") != "Bearer "+testKey || up.requests()[1].header.Get("X-Api-Key") != "" {
		t.Fatalf("bearer on the messages route: %d %v", w.Code, up.requests()[1].header)
	}
}

func TestRelayChecksTheTCPPeerAgainInTheHandler(t *testing.T) {
	up := &fakeControl{}
	h := newRelay(t, up)
	for _, remote := range []string{"10.21.0.1:5000", "192.168.1.9:5000", "[fd00::1]:5000", "garbage"} {
		header := bearer()
		header["X-Forwarded-For"] = []string{"10.20.3.4"}
		header["X-Tunnex-Peer-Ip"] = []string{"10.20.3.4"}
		if w := call(h, http.MethodPost, "/v1/chat/completions", remote, header, `{}`); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", remote, w.Code)
		}
	}
	if w := call(h, http.MethodPost, "/v1/chat/completions", "[::ffff:10.20.3.4]:5000", bearer(), `{}`); w.Code != 200 {
		t.Fatalf("a mapped in-range peer: %d", w.Code)
	}
	if got := up.requests(); len(got) != 1 || got[0].header.Get("X-Tunnex-Peer-Ip") != "10.20.3.4" {
		t.Fatalf("upstream: %+v", got)
	}
}

// chunked hides the length, so the cap must hold without Content-Length.
type chunked struct{ r io.Reader }

func (c chunked) Read(p []byte) (int, error) { return c.r.Read(p) }

func TestRelayBodyCapsNeverLetAnOversizedBodyLeave(t *testing.T) {
	up := &fakeControl{}
	h := newRelay(t, up)
	send := func(path string, size int, declared bool) int {
		r := httptest.NewRequest(http.MethodPost, path, chunked{strings.NewReader(strings.Repeat("a", size))})
		if declared {
			r.ContentLength = int64(size)
		} else {
			r.ContentLength = -1
		}
		r.RemoteAddr = "10.20.3.4:5000"
		r.Header = bearer()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, declared := range []bool{true, false} {
		if code := send("/v1/chat/completions", bodyLimit+1, declared); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared=%v: %d", declared, code)
		}
		if code := send(transcriptionsPath, transcriptionCap+1, declared); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("transcription declared=%v: %d", declared, code)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("%d oversized bodies reached the control plane", n)
	}
	if code := send("/v1/chat/completions", bodyLimit, false); code != 200 {
		t.Fatalf("a body at the cap: %d", code)
	}
	if code := send(transcriptionsPath, bodyLimit+1, true); code != 200 {
		t.Fatalf("a transcription above the chat cap: %d", code)
	}
	if code := send(transcriptionsPath, transcriptionCap, false); code != 200 {
		t.Fatalf("a transcription at its cap: %d", code)
	}
	if got := up.requests(); len(got) != 3 || len(got[0].body) != bodyLimit || got[0].header.Get("Content-Length") == "" {
		t.Fatalf("forwarded bodies: %d", len(got))
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/models", strings.NewReader("x"))
	r.RemoteAddr, r.Header = "10.20.3.4:5000", bearer()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("GET with a body: %d", w.Code)
	}
}

func TestRelayHasSixteenSlots(t *testing.T) {
	up := &fakeControl{block: make(chan struct{}), entered: make(chan struct{}, maxConcurrent)}
	h := newRelay(t, up)
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			call(h, http.MethodPost, "/v1/embeddings", "10.20.3.4:5000", bearer(), `{}`)
		}()
	}
	for i := 0; i < maxConcurrent; i++ {
		select {
		case <-up.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the slots did not fill")
		}
	}
	if w := call(h, http.MethodPost, "/v1/embeddings", "10.20.3.4:5000", bearer(), `{}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the 17th request: %d", w.Code)
	}
	close(up.block)
	wg.Wait()
	up.block = nil
	if w := call(h, http.MethodPost, "/v1/embeddings", "10.20.3.4:5000", bearer(), `{}`); w.Code != 200 {
		t.Fatalf("after the slots drained: %d", w.Code)
	}
}

func TestRelayUpstreamFailureIsAFixedMessage(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	h := Handler(target, http.DefaultTransport, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	w := call(h, http.MethodPost, "/v1/chat/completions", "10.20.3.4:5000", bearer(), `{}`)
	if w.Code != http.StatusBadGateway || strings.TrimSpace(w.Body.String()) != "gateway unavailable" {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestRelayPassesTheControlPlaneAnswerThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"message":"AI access is not available under the current policy"}}`)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	h := Handler(target, srv.Client().Transport, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	w := call(h, http.MethodPost, "/v1/chat/completions", "10.20.3.4:5000", bearer(), `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "current policy") {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}
