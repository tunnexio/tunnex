package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

// listenerTimeout bounds how long `tunnex login` waits for the browser leg.
const listenerTimeout = 2 * time.Minute

// callbackResult is what the single-request loopback listener produces.
type callbackResult struct {
	code string
	err  error
}

// Login runs the loopback flow: local listener → browser consent → one-time
// code → exchange → stored credential. LISTENER HYGIENE (S5.1 sign-off):
// single request only, explicit success/failure pages, a state mismatch never
// reaches the exchange and exits non-zero, and the whole wait is bounded.
func Login(ctx context.Context, server string) error {
	verifier, challenge, err := pkce()
	if err != nil {
		return err
	}
	state, err := randomToken()
	if err != nil {
		return err
	}

	// 127.0.0.1:0 — the OS picks the port; the server-side allowlist accepts any
	// loopback port on exactly /callback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("could not open the loopback listener: %w", err)
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	// SINGLE-REQUEST listener: the first /callback hit is consumed and the
	// server stops; anything after it hits a dead socket.
	resultCh := make(chan callbackResult, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: callbackHandler(state, resultCh)}
	go srv.Serve(ln) //nolint:errcheck // shut down below; Serve error is the closed listener

	// The consent page (SPA) — the human checkpoint that calls cliAuthorize on an
	// explicit click and then redirects the browser to our loopback.
	consent := server + "/cli-auth?" + url.Values{
		"redirect_uri":   {redirect},
		"code_challenge": {challenge},
		"state":          {state},
	}.Encode()
	fmt.Printf("Opening your browser to sign in…\n  %s\n", consent)
	openBrowser(consent)

	var res callbackResult
	select {
	case res = <-resultCh:
	case <-time.After(listenerTimeout):
		res = callbackResult{err: fmt.Errorf("timed out after %s waiting for the browser sign-in", listenerTimeout)}
	case <-ctx.Done():
		res = callbackResult{err: ctx.Err()}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if res.err != nil {
		return res.err
	}

	// Exchange: code + PKCE verifier + the EXACT redirect the code was bound to.
	client, err := NewClient(server)
	if err != nil {
		return err
	}
	resp, err := client.CliTokenWithResponse(ctx, api.CliTokenJSONRequestBody{
		Code: res.code, CodeVerifier: verifier, RedirectUri: redirect,
	})
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	if resp.JSON200 == nil {
		return apiErr(resp.StatusCode(), resp.Body, "token exchange refused")
	}
	cred := Credential{
		Server: server, Token: resp.JSON200.Token,
		Fingerprint: resp.JSON200.Fingerprint, ExpiresAt: resp.JSON200.ExpiresAt,
	}
	if err := SaveCredential(cred); err != nil {
		return err
	}
	fmt.Printf("Logged in. Credential %s (expires %s).\n", cred.Fingerprint, cred.ExpiresAt.Format("2006-01-02"))
	return nil
}

// LoginDevice runs the device-code fallback for browserless hosts.
func LoginDevice(ctx context.Context, server string) error {
	client, err := NewClient(server)
	if err != nil {
		return err
	}
	start, err := client.CliDeviceStartWithResponse(ctx)
	if err != nil {
		return err
	}
	if start.JSON200 == nil {
		return apiErr(start.StatusCode(), start.Body, "could not start the device flow")
	}
	d := start.JSON200
	fmt.Printf("On any browser, open:\n  %s\nand enter the code:\n  %s\n\nWaiting for approval…\n", d.VerificationUri, d.UserCode)

	interval := time.Duration(d.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
		resp, err := client.CliDeviceTokenWithResponse(ctx, api.CliDeviceTokenJSONRequestBody{DeviceCode: d.DeviceCode})
		if err != nil {
			continue // transient network error — keep polling until the deadline
		}
		if resp.JSON200 != nil {
			cred := Credential{
				Server: server, Token: resp.JSON200.Token,
				Fingerprint: resp.JSON200.Fingerprint, ExpiresAt: resp.JSON200.ExpiresAt,
			}
			if err := SaveCredential(cred); err != nil {
				return err
			}
			fmt.Printf("Logged in. Credential %s (expires %s).\n", cred.Fingerprint, cred.ExpiresAt.Format("2006-01-02"))
			return nil
		}
		var e envelope
		_ = json.Unmarshal(resp.Body, &e)
		if e.Error.Code == "authorization_pending" {
			continue
		}
		return apiErr(resp.StatusCode(), resp.Body, "device flow refused")
	}
	return errors.New("the device code expired before approval — run 'tunnex login --device' again")
}

// Logout revokes the server-side credential (matched by fingerprint) and
// deletes the local file. Local deletion happens even if the server is
// unreachable — the sweep endpoints still protect the server side.
func Logout(ctx context.Context) error {
	cred, err := LoadCredential()
	if errors.Is(err, ErrNotLoggedIn) {
		fmt.Println("Already logged out.")
		return nil
	}
	if err != nil {
		return err
	}
	if client, cerr := NewAuthedClient(cred); cerr == nil {
		if list, lerr := client.ListCliCredentialsWithResponse(ctx); lerr == nil && list.JSON200 != nil {
			for _, c := range *list.JSON200 {
				if c.Fingerprint == cred.Fingerprint {
					if resp, derr := client.RevokeCliCredentialWithResponse(ctx, c.Id); derr != nil || resp.StatusCode() != 204 {
						fmt.Fprintln(os.Stderr, "warning: could not revoke the credential server-side; it remains valid until expiry or a sweep")
					}
					break
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "warning: could not reach the server to revoke; deleting the local credential anyway")
		}
	}
	if err := DeleteCredential(); err != nil {
		return err
	}
	fmt.Println("Logged out.")
	return nil
}

// callbackHandler is the SINGLE-SHOT loopback endpoint: exactly one request is
// ever processed (sync.Once); anything after it gets a terminal page and is
// ignored. STATE IS CHECKED FIRST: on a mismatch the code is never read and no
// exchange can follow — the caller receives an error (non-zero exit).
func callbackHandler(state string, resultCh chan<- callbackResult) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		handled := false
		once.Do(func() {
			handled = true
			q := r.URL.Query()
			if q.Get("state") != state {
				page(w, http.StatusForbidden, "Sign-in failed",
					"The response did not match this login attempt (state mismatch). Close this window and run 'tunnex login' again.")
				resultCh <- callbackResult{err: errors.New("state mismatch on the loopback callback — no exchange attempted")}
				return
			}
			code := q.Get("code")
			if code == "" {
				page(w, http.StatusBadRequest, "Sign-in failed",
					"No authorization code was returned. Close this window and run 'tunnex login' again.")
				resultCh <- callbackResult{err: errors.New("callback carried no code")}
				return
			}
			page(w, http.StatusOK, "Signed in",
				"tunnex is connected. You can close this window and return to the terminal.")
			resultCh <- callbackResult{code: code}
		})
		if !handled {
			page(w, http.StatusGone, "Already completed",
				"This sign-in attempt has already been handled. Return to the terminal.")
		}
	})
}

// ---- helpers ----------------------------------------------------------------

func pkce() (verifier, challenge string, err error) {
	verifier, err = randomToken()
	if err != nil {
		return "", "", err
	}
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:]), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// page writes a minimal self-contained browser page (success or failure).
func page(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>tunnex — %s</title>
<body style="font-family:system-ui;background:#0b0b12;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0">
<div style="max-width:26rem;text-align:center"><h1 style="font-size:1.2rem">%s</h1><p style="color:#94a3b8">%s</p></div>`,
		title, title, body)
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "could not open a browser automatically — open the URL above manually")
	}
}
