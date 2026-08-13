package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

// ExpiredCredentialLine is the exact one-line UX printed when the CLI detects
// its own credential has aged out (from the LOCAL expires_at — the server gives
// no expiry oracle). S5.1 acceptance: never a raw error dump.
const ExpiredCredentialLine = "credential expired — run 'tunnex login'"

// NewClient builds an unauthenticated API client for server.
func NewClient(server string) (*api.ClientWithResponses, error) {
	return api.NewClientWithResponses(strings.TrimRight(server, "/"))
}

// NewAuthedClient builds a client that sends the stored bearer credential.
func NewAuthedClient(cred Credential) (*api.ClientWithResponses, error) {
	return api.NewClientWithResponses(strings.TrimRight(cred.Server, "/"),
		api.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+cred.Token)
			return nil
		}))
}

// envelope mirrors the server's error envelope for message extraction.
type envelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// apiErr renders a non-2xx response as a short human error.
func apiErr(status int, body []byte, fallback string) error {
	var e envelope
	_ = json.Unmarshal(body, &e)
	if e.Error.Message != "" {
		return fmt.Errorf("%s (%s)", e.Error.Message, e.Error.Code)
	}
	return fmt.Errorf("%s (HTTP %d)", fallback, status)
}

// LoadActiveCredential loads the stored credential and enforces its LOCALLY
// known expiry BEFORE any request. The server gives no expiry oracle
// (revoked/expired/unknown are one generic 401), so the CLI recognizes its own
// aged-out credential here and reports the exact re-login line — never a raw
// 401. Returns ErrCredentialExpired so callers exit cleanly.
func LoadActiveCredential() (Credential, error) {
	cred, err := LoadCredential()
	if err != nil {
		return Credential{}, err
	}
	if !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(now()) {
		return Credential{}, ErrCredentialExpired
	}
	return cred, nil
}

// ErrCredentialExpired signals a locally-known expired credential; main renders
// ExpiredCredentialLine and exits 1.
var ErrCredentialExpired = fmt.Errorf("%s", ExpiredCredentialLine)

// now is a seam for expiry tests.
var now = time.Now
