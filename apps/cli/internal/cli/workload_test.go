package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

type workloadAuthorityFixture struct {
	t                 *testing.T
	server            *httptest.Server
	mu                sync.Mutex
	calls             map[string]int
	failed            map[string]int
	failedStatus      int
	denied            map[string]int
	proofs            map[string]bool
	receipt           api.AIWorkloadReceipt
	public, previous  ed25519.PublicKey
	request, rotation uuid.UUID
	ttl               int
	statePath         string
	inference         func(http.ResponseWriter, *http.Request)
}

func newWorkloadAuthority(t *testing.T) *workloadAuthorityFixture {
	f := &workloadAuthorityFixture{t: t, calls: map[string]int{}, failed: map[string]int{}, denied: map[string]int{}, proofs: map[string]bool{}, ttl: 300, receipt: api.AIWorkloadReceipt{InstanceId: uuid.New(), OrganizationId: uuid.New(), WorkloadId: uuid.New(), KeyGeneration: 1}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	f.receipt.TokenEndpoint = f.server.URL + "/api/v1/workload/token"
	f.receipt.GatewayBase = f.server.URL + "/ai/v1"
	t.Cleanup(f.server.Close)
	return f
}
func (f *workloadAuthorityFixture) verify(raw string, public ed25519.PublicKey, endpoint, subject string) map[string]any {
	f.t.Helper()
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	claims := map[string]any{}
	if err != nil || parsed.Claims(public, &claims) != nil {
		f.t.Error("invalid signed workload proof")
		return claims
	}
	aud, ok := claims["aud"].(string)
	if !ok {
		if values, ok := claims["aud"].([]any); ok && len(values) == 1 {
			aud, _ = values[0].(string)
		}
	}
	if aud != f.server.URL+endpoint || claims["iss"] != subject || claims["sub"] != subject {
		f.t.Error("workload proof authority mismatch")
	}
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || !iatOK || exp-iat != 60 {
		f.t.Error("wrong proof lifetime")
	}
	id, ok := claims["jti"].(string)
	if !ok || f.proofs[id] {
		f.t.Error("client repeated assertion JTI")
	}
	f.proofs[id] = true
	return claims
}
func (f *workloadAuthorityFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls[r.URL.Path]++
	var output any
	status := 200
	switch r.URL.Path {
	case "/api/v1/workload/enroll":
		var in api.AIWorkloadEnrollInput
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			f.t.Error("bad enrollment JSON")
		}
		public, _ := base64.RawURLEncoding.DecodeString(in.PublicKey)
		claims := f.verify(in.Proof, public, r.URL.Path, "enrollment")
		digest := sha256.Sum256([]byte(in.EnrollmentKey))
		if claims["request_id"] != in.RequestId.String() || claims["enrollment_hash"] != hex.EncodeToString(digest[:]) {
			f.t.Error("unbound enrollment proof")
		}
		if f.request == uuid.Nil {
			f.request = in.RequestId
			f.public = public
		} else if f.request != in.RequestId || !bytes.Equal(f.public, public) {
			f.t.Error("retry changed enrollment identity")
		}
		if f.statePath != "" {
			b, err := os.ReadFile(f.statePath)
			var saved workloadState
			if err != nil || json.Unmarshal(b, &saved) != nil || saved.RequestID != in.RequestId || !bytes.Equal(ed25519.PrivateKey(saved.PrivateKey).Public().(ed25519.PublicKey), public) {
				f.t.Error("identity was not durable before enrollment")
			}
		}
		output = f.receipt
	case "/api/v1/workload/token":
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_assertion_type") != workloadAssertionType || r.Form.Get("client_id") != f.receipt.InstanceId.String() || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			f.t.Error("incorrect OAuth token request")
		}
		f.verify(r.Form.Get("client_assertion"), f.public, r.URL.Path, f.receipt.InstanceId.String())
		output = api.AIWorkloadToken{AccessToken: "remote-workload-token", TokenType: "Bearer", Scope: "tunnex-ai", ExpiresIn: f.ttl}
	case "/api/v1/workload/rotate":
		var in api.AIWorkloadRotationInput
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			f.t.Error("bad rotation JSON")
		}
		public, _ := base64.RawURLEncoding.DecodeString(in.PublicKey)
		old := f.public
		if f.rotation == in.RequestId {
			old = f.previous
		}
		a := f.verify(in.OldProof, old, r.URL.Path, f.receipt.InstanceId.String())
		b := f.verify(in.NewProof, public, r.URL.Path, f.receipt.InstanceId.String())
		if a["next_key"] != in.PublicKey || b["next_key"] != in.PublicKey || a["request_id"] != in.RequestId.String() || b["request_id"] != in.RequestId.String() {
			f.t.Error("unbound rotation proof")
		}
		if f.rotation == uuid.Nil {
			f.rotation = in.RequestId
			f.previous = f.public
			f.public = public
			f.receipt.KeyGeneration++
		} else if f.rotation != in.RequestId || !bytes.Equal(f.public, public) {
			f.t.Error("rotation retry changed candidate")
		}
		output = f.receipt
	case "/ai/v1/models":
		if r.Header.Get("Authorization") != "Bearer remote-workload-token" {
			f.t.Error("models used an incorrect remote credential")
		}
		output = map[string]any{"object": "list", "data": []map[string]string{{"id": "openai/model", "object": "model", "owned_by": "workload", "mode": "chat"}}}
	case "/api/v1/workload/retire":
		if r.Header.Get("Authorization") != "Bearer remote-workload-token" {
			f.t.Error("retirement missing scoped bearer")
		}
		status = 204
	default:
		inference := f.inference
		f.mu.Unlock()
		if inference == nil {
			http.NotFound(w, r)
		} else {
			inference(w, r)
		}
		return
	}
	if f.failed[r.URL.Path] > 0 {
		f.failed[r.URL.Path]--
		status = 503
		if f.failedStatus != 0 {
			status = f.failedStatus
		}
	}
	if f.denied[r.URL.Path] != 0 {
		status = f.denied[r.URL.Path]
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == 200 {
		_ = json.NewEncoder(w).Encode(output)
	}
}
func (f *workloadAuthorityFixture) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}
func (f *workloadAuthorityFixture) fail(path string, n int) {
	f.mu.Lock()
	f.failed[path] = n
	f.mu.Unlock()
}

func workloadTestConfig(t *testing.T, server string) (path string, config workloadConfig) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config = workloadConfig{Server: server, EnrollmentKeyFile: filepath.Join(dir, "enrollment-key"), StateDirectory: filepath.Join(dir, "state")}
	b, _ := json.Marshal(config)
	path = filepath.Join(dir, "workload.json")
	if os.WriteFile(path, b, 0o600) != nil || os.WriteFile(config.EnrollmentKeyFile, []byte("private-enrollment-key"), 0o600) != nil {
		t.Fatal("write private fixture")
	}
	return
}
func workloadTestSession(t *testing.T, f *workloadAuthorityFixture) (*workloadSession, string) {
	t.Helper()
	path, config := workloadTestConfig(t, f.server.URL)
	f.statePath = filepath.Join(config.StateDirectory, "instance.json")
	s, err := openWorkloadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	s.retryDelay = time.Millisecond
	t.Cleanup(s.close)
	return s, path
}

func TestWorkloadEnrollmentAndRotationRecovery(t *testing.T) {
	f := newWorkloadAuthority(t)
	s, configPath := workloadTestSession(t, f)
	f.fail("/api/v1/workload/enroll", 3)
	if err := s.enroll(context.Background()); err == nil || strings.Contains(err.Error(), "private-enrollment-key") {
		t.Fatal("lost reply was not safely surfaced", err)
	}
	request := s.state.RequestID
	private := bytes.Clone(s.state.PrivateKey)
	s.close()
	if err := os.WriteFile(s.config.EnrollmentKeyFile, []byte("replacement-enrollment-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := openWorkloadSession(configPath)
	if err != nil {
		t.Fatal(err)
	}
	reopened.retryDelay = time.Millisecond
	if reopened.enroll(context.Background()) == nil || f.count("/api/v1/workload/enroll") != 3 {
		t.Fatal("pending receipt silently switched enrollment keys")
	}
	if err := os.WriteFile(s.config.EnrollmentKeyFile, []byte("private-enrollment-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = reopened.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reopened.state.RequestID != request || !bytes.Equal(reopened.state.PrivateKey, private) {
		t.Fatal("retry replaced persistent identity")
	}
	if err = os.Remove(s.config.EnrollmentKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.issueToken(context.Background()); err != nil {
		t.Fatal("enrolled instance required bootstrap", err)
	}
	f.fail("/api/v1/workload/rotate", 3)
	if reopened.rotate(context.Background()) == nil || reopened.state.PendingRotation == nil || !bytes.Equal(reopened.state.PrivateKey, private) {
		t.Fatal("failed rotation destroyed last key")
	}
	candidate := bytes.Clone(reopened.state.PendingRotation.PrivateKey)
	rotation := reopened.state.PendingRotation.RequestID
	reopened.close()
	final, err := openWorkloadSession(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer final.close()
	final.retryDelay = time.Millisecond
	if final.state.PendingRotation.RequestID != rotation {
		t.Fatal("lost pending rotation request")
	}
	if err = final.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if final.state.PendingRotation != nil || !bytes.Equal(final.state.PrivateKey, candidate) || final.state.Receipt.KeyGeneration != 2 {
		t.Fatal("rotation receipt did not promote exact candidate")
	}
	b, err := os.ReadFile(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("remote-workload-token")) || bytes.Contains(b, []byte("private-enrollment-key")) {
		t.Fatal("bearer persisted in instance state")
	}
}

func TestWorkloadPrivateStorageAndLock(t *testing.T) {
	f := newWorkloadAuthority(t)
	path, config := workloadTestConfig(t, f.server.URL)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if s, err := openWorkloadSession(path); err == nil {
		s.close()
		t.Fatal("public config accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openWorkloadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openWorkloadSession(path); err == nil {
		second.close()
		t.Fatal("simultaneous instance lock accepted")
	}
	if err := os.Chmod(config.StateDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if s.saveState() == nil {
		t.Fatal("state write accepted a widened private directory")
	}
	if err := os.Chmod(config.StateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	s.close()
	if err := os.Chmod(config.StateDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if second, err := openWorkloadSession(path); err == nil {
		second.close()
		t.Fatal("public state directory accepted")
	}
	if err := os.Chmod(config.StateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyCopy := config.EnrollmentKeyFile + ".original"
	if os.Rename(config.EnrollmentKeyFile, keyCopy) != nil || os.Symlink(keyCopy, config.EnrollmentKeyFile) != nil {
		t.Fatal("symlink fixture")
	}
	s, err = openWorkloadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.enroll(context.Background()) == nil || f.count("/api/v1/workload/enroll") != 0 {
		t.Fatal("symlink secret reached server")
	}
	stateInfo, _ := os.Stat(filepath.Join(config.StateDirectory, "instance.json"))
	lockInfo, _ := os.Stat(filepath.Join(config.StateDirectory, "instance.lock"))
	if stateInfo.Mode().Perm() != 0o600 || lockInfo.Mode().Perm() != 0o600 {
		t.Fatal("state or lock permissions")
	}
}

func TestWorkloadLockReleasedAfterProcessExit(t *testing.T) {
	path, _ := workloadTestConfig(t, "http://127.0.0.1:1")
	child := exec.Command(os.Args[0], "-test.run=^TestWorkloadLockHelper$")
	child.Env = append(os.Environ(), "TUNNEX_WORKLOAD_LOCK_HELPER="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "locked\n" {
			t.Fatal("helper failed to lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not start")
	}
	if s, err := openWorkloadSession(path); err == nil {
		s.close()
		t.Fatal("cross-process lock did not exclude second owner")
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	s, err := openWorkloadSession(path)
	if err != nil {
		t.Fatal("OS did not release exited process lock", err)
	}
	s.close()
}
func TestWorkloadLockHelper(t *testing.T) {
	path := os.Getenv("TUNNEX_WORKLOAD_LOCK_HELPER")
	if path == "" {
		return
	}
	s, err := openWorkloadSession(path)
	if err != nil {
		os.Exit(2)
	}
	defer s.close()
	_, _ = io.WriteString(os.Stdout, "locked\n")
	time.Sleep(time.Minute)
}

func TestWorkloadIdleRenewalAndSingleFlight(t *testing.T) {
	f := newWorkloadAuthority(t)
	f.ttl = 1
	s, _ := workloadTestSession(t, f)
	if err := s.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens := newWorkloadTokens(s)
	tokens.timing = workloadTokenTiming{lead: 500 * time.Millisecond, tick: 10 * time.Millisecond, retry: 10 * time.Millisecond, jitter: func() time.Duration { return 0 }}
	if _, err := tokens.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	initialExpiry := tokens.expires
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fatal := make(chan error, 1)
	go func() { defer close(done); tokens.renew(ctx, fatal) }()
	deadline := time.After(2 * time.Second)
	for {
		tokens.mu.Lock()
		refreshed := tokens.expires.After(initialExpiry)
		tokens.mu.Unlock()
		if refreshed {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("idle instance did not renew")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
	before := f.count("/api/v1/workload/token")
	tokens.mu.Lock()
	tokens.refresh = time.Now().Add(-time.Second)
	tokens.mu.Unlock()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tokens.get(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.count("/api/v1/workload/token") != before+1 {
		t.Fatal("concurrent requests issued duplicate renewals")
	}
	f.fail("/api/v1/workload/token", 6)
	tokens.mu.Lock()
	tokens.refresh = time.Now().Add(-time.Second)
	expires := tokens.expires
	tokens.mu.Unlock()
	if value, err := tokens.get(context.Background()); err != nil || value == "" {
		t.Fatal("transient failure discarded unexpired token")
	}
	tokens.mu.Lock()
	if !tokens.expires.Equal(expires) {
		t.Fatal("local renewal extended expiry")
	}
	tokens.expires = time.Now().Add(-time.Second)
	tokens.nextTry = time.Time{}
	tokens.mu.Unlock()
	if _, err := tokens.get(context.Background()); err == nil {
		t.Fatal("expired token authorized during outage")
	}
}

func TestWorkloadTransientTokenRecovery(t *testing.T) {
	for _, status := range []int{429, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newWorkloadAuthority(t)
			f.failedStatus = status
			s, _ := workloadTestSession(t, f)
			if err := s.enroll(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.fail("/api/v1/workload/token", 2)
			tokens := newWorkloadTokens(s)
			tokens.timing.retry = time.Hour
			value, err := tokens.get(context.Background())
			if err != nil || value == "" || f.count("/api/v1/workload/token") != 3 {
				t.Fatal("temporary HTTP failure did not recover within bounded retries", err)
			}
			f.mu.Lock()
			f.denied["/api/v1/workload/token"] = status
			f.mu.Unlock()
			tokens.refresh = time.Now().Add(-time.Second)
			expires := tokens.expires
			for range 2 {
				got, err := tokens.get(context.Background())
				if err != nil || got != value || !tokens.expires.Equal(expires) || tokens.terminal != nil {
					t.Fatal("temporary failure discarded or extended the existing token", err)
				}
			}
			if f.count("/api/v1/workload/token") != 6 {
				t.Fatal("temporary failure ignored the retry bound or backoff")
			}
			tokens.expires = time.Now().Add(-time.Second)
			tokens.nextTry = time.Time{}
			if got, err := tokens.get(context.Background()); err == nil || got != "" || tokens.terminal != nil || f.count("/api/v1/workload/token") != 9 {
				t.Fatal("expired token survived an outage or temporary outage became terminal", err)
			}
			f.mu.Lock()
			delete(f.denied, "/api/v1/workload/token")
			f.mu.Unlock()
			tokens.nextTry = time.Time{}
			if got, err := tokens.get(context.Background()); err != nil || got == "" || f.count("/api/v1/workload/token") != 10 {
				t.Fatal("authentication did not recover after the outage", err)
			}
			if f.count("/api/v1/workload/enroll") != 1 || s.state.Retired {
				t.Fatal("temporary token failure changed instance identity")
			}
		})
	}
}

func TestWorkloadOnlyCredentialRefusalTerminatesRenewal(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newWorkloadAuthority(t)
			s, _ := workloadTestSession(t, f)
			if err := s.enroll(context.Background()); err != nil {
				t.Fatal(err)
			}
			tokens := newWorkloadTokens(s)
			if _, err := tokens.get(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.denied["/api/v1/workload/token"] = status
			f.mu.Unlock()
			tokens.refresh = time.Now().Add(-time.Second)
			got, err := tokens.get(context.Background())
			if status == 401 || status == 403 {
				if err == nil || got != "" || tokens.value != "" || tokens.terminal == nil {
					t.Fatal("confirmed credential refusal retained authority", err)
				}
				if _, err = tokens.get(context.Background()); err == nil {
					t.Fatal("confirmed refusal was retried")
				}
			} else if err != nil || got == "" || tokens.terminal != nil {
				t.Fatal("non-authentication HTTP failure became credential refusal", err)
			}
			if f.count("/api/v1/workload/token") != 2 || f.count("/api/v1/workload/enroll") != 1 || s.state.Retired {
				t.Fatal("HTTP failure caused extra attempts or changed instance state")
			}
		})
	}
}

func TestWorkloadProxyBoundariesAndStreaming(t *testing.T) {
	f := newWorkloadAuthority(t)
	s, _ := workloadTestSession(t, f)
	if err := s.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens := newWorkloadTokens(s)
	if _, err := tokens.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := make(chan *http.Request, 10)
	bodies := make(chan []byte, 10)
	release := make(chan struct{})
	f.inference = func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-release
			_, _ = io.WriteString(w, "data: last\n\n")
			return
		}
		if r.URL.Path == "/ai/v1/rerank" {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/ai/v1/completions" {
			w.Header().Set("Location", "https://example.invalid/leak")
			w.WriteHeader(307)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Set-Cookie", "upstream-secret=hidden")
		_, _ = w.Write(body)
	}
	proxy := httptest.NewUnstartedServer(nil)
	proxy.Config.Handler = workloadProxy(tokens, proxy.Listener.Addr().String(), "local-secret")
	proxy.Start()
	defer proxy.Close()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, path := range []string{"/v1/chat/completions", "/v1/audio/transcriptions", "/v1/audio/speech", "/v1/messages"} {
		body := []byte{0, 1, 2, 255}
		req, _ := http.NewRequest("POST", proxy.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer local-secret")
		req.Header.Set("Cookie", "session=human-secret")
		req.Header.Set("X-Tunnex-Organization", "forged-org")
		req.Header.Set("X-Bf-Vk", "forged-native-key")
		req.Header.Set("Forwarded", "host=attacker")
		req.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		returned, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != 200 || !bytes.Equal(returned, body) || res.Header.Get("Set-Cookie") != "" {
			t.Fatal("binary payload or response boundary changed")
		}
		upstream := <-seen
		received := <-bodies
		if upstream.Header.Get("Authorization") != "Bearer remote-workload-token" || upstream.Header.Get("Cookie") != "" || upstream.Header.Get("X-Tunnex-Organization") != "" || upstream.Header.Get("X-Bf-Vk") != "" || upstream.Header.Get("Forwarded") != "" || upstream.Header.Get("X-Forwarded-For") != "" || !bytes.Equal(received, body) {
			t.Fatal("upstream credential/header/payload boundary")
		}
		if path == "/v1/messages" && upstream.URL.Path != "/ai/anthropic/v1/messages" {
			t.Fatal("wrong Anthropic route")
		}
	}
	for _, tc := range []struct {
		path, host, origin, auth string
		want                     int
	}{{"/v1/models", "attacker.invalid", "", "local-secret", 400}, {"/v1/models", "", "https://attacker.invalid", "local-secret", 400}, {"/v1/models?target=evil", "", "", "local-secret", 400}, {"/v1/models", "", "", "wrong", 401}, {"/admin", "", "", "local-secret", 404}} {
		req, _ := http.NewRequest("GET", proxy.URL+tc.path, nil)
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		req.Header.Set("Authorization", "Bearer "+tc.auth)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != tc.want {
			t.Fatalf("boundary status=%d want=%d", res.StatusCode, tc.want)
		}
	}
	for _, tc := range []struct {
		path   string
		status int
	}{{"/v1/rerank", 503}, {"/v1/completions", 502}} {
		req, _ := http.NewRequest("POST", proxy.URL+tc.path, strings.NewReader(`{}`))
		req.Header.Set("X-Api-Key", "local-secret")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != tc.status || res.Header.Get("Location") != "" {
			t.Fatal("paid failure or redirect not preserved safely")
		}
		<-seen
		<-bodies
		if f.count("/ai"+tc.path) != 1 {
			t.Fatal("paid inference retried")
		}
	}
	req, _ := http.NewRequest("POST", proxy.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer local-secret")
	req.Header.Set("Accept", "text/event-stream")
	res, err := client.Do(req)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	close(release)
	_ = res.Body.Close()
	if err != nil || line != "data: first\n" {
		t.Fatal("SSE was buffered until completion")
	}
	<-seen
	<-bodies
}

func TestWorkloadRedirectRefusalAndNoHumanState(t *testing.T) {
	var targetCalls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++; w.WriteHeader(500) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	}))
	defer redirect.Close()
	path, _ := workloadTestConfig(t, redirect.URL)
	human := t.TempDir()
	t.Setenv("TUNNEX_STATE_DIR", human)
	t.Setenv("HTTP_PROXY", target.URL)
	t.Setenv("HTTPS_PROXY", target.URL)
	var out bytes.Buffer
	err := Workload(context.Background(), []string{"enroll", "--config", path}, &out)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || strings.Contains(err.Error(), "private-enrollment-key") || out.Len() != 0 || targetCalls != 0 {
		t.Fatal("redirect or secret error boundary failed", err)
	}
	entries, _ := os.ReadDir(human)
	if len(entries) != 0 {
		t.Fatal("workload command touched human login state")
	}
	if workloadTransport().Proxy != nil {
		t.Fatal("transport honors ambient proxy configuration")
	}
}

func TestWorkloadRunPreservesInstanceForRestart(t *testing.T) {
	for _, childResult := range []string{"success", "crash"} {
		t.Run(childResult, func(t *testing.T) {
			f := newWorkloadAuthority(t)
			configPath, config := workloadTestConfig(t, f.server.URL)
			t.Setenv("TUNNEX_WORKLOAD_RUN_HELPER", childResult)
			t.Setenv("OPENAI_API_KEY", "unrelated-provider-secret")
			t.Setenv("ANTHROPIC_AUTH_TOKEN", "unrelated-auth-secret")
			t.Setenv("HTTP_PROXY", "http://untrusted-proxy.invalid")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var out bytes.Buffer
			err := Workload(ctx, []string{"run", "--config", configPath, "--", os.Args[0], "-test.run=^TestWorkloadRunHelper$"}, &out)
			if (err == nil) != (childResult == "success") {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "local application connected") || strings.Contains(out.String(), "remote-workload-token") || strings.Contains(out.String(), "private-enrollment-key") {
				t.Fatal("run output or secret hygiene")
			}
			if f.count("/api/v1/workload/retire") != 0 || f.count("/ai/v1/models") != 2 {
				t.Fatal("process exit retired the instance or skipped startup health")
			}
			b, _ := os.ReadFile(filepath.Join(config.StateDirectory, "instance.json"))
			var state workloadState
			_ = json.Unmarshal(b, &state)
			if state.Retired || state.Receipt == nil {
				t.Fatal("process exit did not preserve active instance state")
			}
			if err := os.Remove(config.EnrollmentKeyFile); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TUNNEX_WORKLOAD_RUN_HELPER", "success")
			out.Reset()
			if err := Workload(ctx, []string{"run", "--config", configPath, "--", os.Args[0], "-test.run=^TestWorkloadRunHelper$"}, &out); err != nil {
				t.Fatal("supervisor restart failed without the enrollment secret", err)
			}
			after, err := os.ReadFile(filepath.Join(config.StateDirectory, "instance.json"))
			if err != nil || !bytes.Equal(b, after) || f.count("/api/v1/workload/enroll") != 1 || f.count("/ai/v1/models") != 4 || f.count("/api/v1/workload/retire") != 0 {
				t.Fatal("supervisor restart changed the instance identity or skipped the application")
			}
		})
	}
}

func TestWorkloadExplicitRetirement(t *testing.T) {
	f := newWorkloadAuthority(t)
	configPath, config := workloadTestConfig(t, f.server.URL)
	var out bytes.Buffer
	if err := Workload(context.Background(), []string{"retire", "--config", configPath}, &out); err == nil || f.count("/api/v1/workload/enroll") != 0 || f.count("/api/v1/workload/token") != 0 || f.count("/api/v1/workload/retire") != 0 {
		t.Fatal("retirement enrolled a previously unknown instance")
	}
	if err := Workload(context.Background(), []string{"enroll", "--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.EnrollmentKeyFile); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	f.fail("/api/v1/workload/retire", 3)
	if err := Workload(context.Background(), []string{"retire", "--config", configPath}, &out); err == nil || !strings.Contains(err.Error(), "remote retirement could not be confirmed") {
		t.Fatal("lost retirement response was reported as confirmed", err)
	}
	b, err := os.ReadFile(filepath.Join(config.StateDirectory, "instance.json"))
	var state workloadState
	if err != nil || json.Unmarshal(b, &state) != nil || !state.Retired {
		t.Fatal("explicit retirement intent was not durable")
	}
	if err := Workload(context.Background(), []string{"retire", "--config", configPath}, &out); err != nil || out.Len() != 0 || f.count("/api/v1/workload/retire") != 4 || f.count("/api/v1/workload/enroll") != 1 || f.count("/api/v1/workload/token") != 2 {
		t.Fatal("explicit retirement could not be retried with proof of the existing identity", err)
	}
	for _, command := range []string{"enroll", "token", "rotate", "run"} {
		args := []string{command, "--config", configPath}
		if command == "run" {
			args = append(args, "--", "unused")
		}
		if err := Workload(context.Background(), args, &out); err == nil || !strings.Contains(err.Error(), "retired") || f.count("/api/v1/workload/token") != 2 || f.count("/api/v1/workload/enroll") != 1 {
			t.Fatal("explicitly retired instance silently restarted or reenrolled", command, err)
		}
	}
}

func TestWorkloadRetirementRequiresAuthentication(t *testing.T) {
	f := newWorkloadAuthority(t)
	configPath, _ := workloadTestConfig(t, f.server.URL)
	var out bytes.Buffer
	if err := Workload(context.Background(), []string{"enroll", "--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.denied["/api/v1/workload/token"] = 401
	f.mu.Unlock()
	out.Reset()
	if err := Workload(context.Background(), []string{"retire", "--config", configPath}, &out); err == nil || out.Len() != 0 || f.count("/api/v1/workload/retire") != 0 || f.count("/api/v1/workload/token") != 1 || f.count("/api/v1/workload/enroll") != 1 {
		t.Fatal("retirement proceeded without authenticated instance proof", err)
	}
}
func TestWorkloadDeniedTokenPreservesEnrollment(t *testing.T) {
	f := newWorkloadAuthority(t)
	configPath, config := workloadTestConfig(t, f.server.URL)
	var out bytes.Buffer
	if err := Workload(context.Background(), []string{"enroll", "--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	var receipt api.AIWorkloadReceipt
	if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.InstanceId == uuid.Nil || strings.Contains(out.String(), "private-enrollment-key") {
		t.Fatal("enroll did not print only its public receipt")
	}
	f.mu.Lock()
	f.denied["/api/v1/workload/token"] = 401
	f.mu.Unlock()
	out.Reset()
	err := Workload(context.Background(), []string{"token", "--config", configPath}, &out)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || out.Len() != 0 || f.count("/api/v1/workload/enroll") != 1 || f.count("/api/v1/workload/token") != 1 {
		t.Fatal("denied token retried or replaced the instance", err)
	}
	f.mu.Lock()
	delete(f.denied, "/api/v1/workload/token")
	f.mu.Unlock()
	if err := os.Remove(config.EnrollmentKeyFile); err != nil {
		t.Fatal(err)
	}
	if err := Workload(context.Background(), []string{"token", "--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	var token api.AIWorkloadToken
	if json.Unmarshal(out.Bytes(), &token) != nil || token.AccessToken != "remote-workload-token" || f.count("/api/v1/workload/enroll") != 1 {
		t.Fatal("explicit token command lost the enrolled identity")
	}
}

type workloadReadyWriter struct{ ready chan string }

func (w workloadReadyWriter) Write(p []byte) (int, error) {
	if strings.HasPrefix(string(p), "http://127.0.0.1:") {
		select {
		case w.ready <- strings.TrimSpace(string(p)):
		default:
		}
	}
	return len(p), nil
}

func TestWorkloadRunCancellationStopsChildAndGateway(t *testing.T) {
	f := newWorkloadAuthority(t)
	configPath, config := workloadTestConfig(t, f.server.URL)
	t.Setenv("TUNNEX_WORKLOAD_RUN_HELPER", "wait")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Workload(ctx, []string{"run", "--config", configPath, "--", os.Args[0], "-test.run=^TestWorkloadRunHelper$"}, workloadReadyWriter{ready: ready})
	}()
	var base string
	select {
	case base = <-ready:
	case err := <-done:
		t.Fatal("child did not start", err)
	case <-time.After(5 * time.Second):
		t.Fatal("child startup timeout")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation did not reach run")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child or gateway did not stop")
	}
	if f.count("/api/v1/workload/retire") != 0 {
		t.Fatal("cancelled process retired the instance")
	}
	if err := os.Remove(config.EnrollmentKeyFile); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Workload(context.Background(), []string{"token", "--config", configPath}, &out); err != nil || f.count("/api/v1/workload/enroll") != 1 {
		t.Fatal("cancelled process did not preserve reusable instance state", err)
	}
	client := &http.Client{Timeout: time.Second}
	if res, err := client.Get(base + "/models"); err == nil {
		_ = res.Body.Close()
		t.Fatal("local gateway still accepts connections")
	}
}

func TestWorkloadRunHelper(t *testing.T) {
	if os.Getenv("TUNNEX_WORKLOAD_RUN_HELPER") == "" {
		return
	}
	base, credential := os.Getenv("OPENAI_BASE_URL"), os.Getenv("OPENAI_API_KEY")
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/v1") || credential == "" || credential == "remote-workload-token" || credential == "unrelated-provider-secret" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" || os.Getenv("HTTP_PROXY") != "" {
		os.Exit(2)
	}
	req, _ := http.NewRequest("GET", base+"/models", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		os.Exit(3)
	}
	_ = res.Body.Close()
	if os.Getenv("TUNNEX_WORKLOAD_RUN_HELPER") == "wait" {
		_, _ = io.WriteString(os.Stdout, base+"\n")
		time.Sleep(time.Minute)
		return
	}
	_, _ = io.WriteString(os.Stdout, "local application connected\n")
	if os.Getenv("TUNNEX_WORKLOAD_RUN_HELPER") == "crash" {
		os.Exit(7)
	}
}
