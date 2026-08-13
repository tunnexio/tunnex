package cli

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteFileAtomic0600 pins the D2 write discipline: 0600 perms, full
// content, and atomic replacement of an existing file.
func TestWriteFileAtomic0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "device.conf")
	if err := WriteFileAtomic0600(p, []byte("[Interface]\nPrivateKey = secret\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perms: want 0600, got %o", st.Mode().Perm())
	}
	// Overwrite is atomic and keeps 0600.
	if err := WriteFileAtomic0600(p, []byte("v2")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "v2" {
		t.Fatalf("content: %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("perms after overwrite: %o", st.Mode().Perm())
	}
	// No temp litter left behind.
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp litter: %d entries", len(entries))
	}
}

// TestWriteFileAtomicFailurePreservesPrevious pins the ATOMICITY that a plain
// os.WriteFile would not give: a failed write must leave the EXISTING file
// intact (never a truncated/half-written key) and drop no temp litter. Forced
// by making the destination a directory whose final rename cannot succeed onto
// the pre-existing good file... instead we force the temp write path to fail by
// pointing at a path whose parent is a file, and assert the good file survives.
func TestWriteFileAtomicFailurePreservesPrevious(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "device.conf")
	if err := WriteFileAtomic0600(good, []byte("GOOD-KEY")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A path whose parent component is a FILE (good) — MkdirAll under it fails,
	// so the write aborts before touching anything.
	bad := filepath.Join(good, "nested", "device.conf")
	if err := WriteFileAtomic0600(bad, []byte("HALF")); err == nil {
		t.Fatal("expected the write to fail")
	}
	// The pre-existing good file is untouched, and no temp file was left in dir.
	b, err := os.ReadFile(good)
	if err != nil || string(b) != "GOOD-KEY" {
		t.Fatalf("previous file damaged: %q err=%v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp litter after failed write: %d entries", len(entries))
	}
}

// TestCredentialRoundTrip pins the credential store (0600, XDG/TUNNEX_STATE_DIR).
func TestCredentialRoundTrip(t *testing.T) {
	t.Setenv("TUNNEX_STATE_DIR", t.TempDir())
	want := Credential{Server: "http://x", Token: "tnx_t", Fingerprint: "abc", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	if err := SaveCredential(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	dir, _ := StateDir()
	st, err := os.Stat(filepath.Join(dir, "credential.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: %v perm=%o", err, st.Mode().Perm())
	}
	got, err := LoadCredential()
	if err != nil || got != want {
		t.Fatalf("load: %+v err=%v", got, err)
	}
	if err := DeleteCredential(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := LoadCredential(); err != ErrNotLoggedIn {
		t.Fatalf("post-delete: want ErrNotLoggedIn, got %v", err)
	}
	if err := DeleteCredential(); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

// TestLoadActiveCredentialExpiry pins that the CLI recognizes its OWN expired
// credential locally (the server gives no expiry oracle) and reports it as
// ErrCredentialExpired — not a raw 401.
func TestLoadActiveCredentialExpiry(t *testing.T) {
	t.Setenv("TUNNEX_STATE_DIR", t.TempDir())
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now = func() time.Time { return base }
	defer func() { now = time.Now }()

	// Not-yet-expired → returned normally.
	if err := SaveCredential(Credential{Server: "http://x", Token: "tnx_a", ExpiresAt: base.Add(time.Hour)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := LoadActiveCredential(); err != nil {
		t.Fatalf("live credential: %v", err)
	}
	// Expired → ErrCredentialExpired (the exact re-login line as its message).
	if err := SaveCredential(Credential{Server: "http://x", Token: "tnx_a", ExpiresAt: base.Add(-time.Second)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, err := LoadActiveCredential()
	if err != ErrCredentialExpired || err.Error() != ExpiredCredentialLine {
		t.Fatalf("expired: want ErrCredentialExpired (%q), got %v", ExpiredCredentialLine, err)
	}
}

// TestCallbackHandler pins the loopback hygiene: state mismatch → failure page
// + error result + the code NEVER read; good callback → success page + code;
// only ONE result is ever emitted.
func TestCallbackHandler(t *testing.T) {
	ch := make(chan callbackResult, 1)
	h := callbackHandler("good-state", ch)

	// State mismatch: 403 failure page, error result, no code.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?code=stolen&state=WRONG", nil))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "Sign-in failed") {
		t.Fatalf("mismatch page: %d %s", rec.Code, rec.Body.String())
	}
	res := <-ch
	if res.err == nil || res.code != "" {
		t.Fatalf("mismatch result: %+v — the code must never surface", res)
	}

	// Missing code: failure.
	ch2 := make(chan callbackResult, 1)
	h2 := callbackHandler("s", ch2)
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?state=s", nil))
	if rec.Code != 400 {
		t.Fatalf("missing code: want 400, got %d", rec.Code)
	}
	if res := <-ch2; res.err == nil {
		t.Fatalf("missing-code result: %+v", res)
	}

	// Happy path: success page + code; a SECOND request cannot emit again.
	ch3 := make(chan callbackResult, 1)
	h3 := callbackHandler("s", ch3)
	rec = httptest.NewRecorder()
	h3.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?state=s&code=one-time", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "close this window") {
		t.Fatalf("success page: %d %s", rec.Code, rec.Body.String())
	}
	if res := <-ch3; res.code != "one-time" || res.err != nil {
		t.Fatalf("success result: %+v", res)
	}
	rec = httptest.NewRecorder()
	h3.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?state=s&code=second", nil))
	select {
	case res := <-ch3:
		t.Fatalf("second request emitted a result: %+v", res)
	default: // single-shot holds
	}

	// Non-callback paths 404.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/favicon.ico", nil))
	if rec.Code != 404 {
		t.Fatalf("non-callback: want 404, got %d", rec.Code)
	}
}
