// Nonshipping owned-local launch qualification. No browser cookie import or TLS bypass.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const owned = "/Users/pawangupta/tunnex/tests/app-access-local"
const appHost = "payroll.apps.127.0.0.1.nip.io"
const consoleHost = "console.127.0.0.1.sslip.io"
const cpBase = "http://127.0.0.1:15174"
const appBase = "https://" + appHost

func privatePath(path string) error {
	if filepath.Clean(path) != path || filepath.Dir(path) != owned+"/.runtime" {
		return errors.New("private runtime path required")
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	if e := privatePath(path); e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("private input refused")
	}
	return os.ReadFile(path)
}
func persist(path string, value any) error {
	if e := privatePath(path); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("private output exists or refused")
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(value); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return f.Close()
}
func client() (*http.Client, error) {
	pem, e := os.ReadFile(owned + "/.runtime/aa6-proxy/ca-cert.pem")
	if e != nil {
		return nil, errors.New("owned CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("owned CA invalid")
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: false, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("dial target refused")
		}
		if !(host == appHost && port == "443" || host == consoleHost && port == "15180" || host == "127.0.0.1" && port == "15174") {
			return nil, errors.New("dial target refused")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	}}
	return &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func request(c *http.Client, method, target string, input any, headers map[string]string) (int, http.Header, []byte, error) {
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return 0, nil, nil, e
		}
		body = bytes.NewReader(raw)
	}
	r, e := http.NewRequest(method, target, body)
	if e != nil {
		return 0, nil, nil, errors.New("request refused")
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		r.Header.Set("X-Tunnex-CSRF", "1")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	response, e := c.Do(r)
	if e != nil {
		return 0, nil, nil, errors.New("owned request failed")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, response.Header, raw, e
}
func queryOne(u *url.URL, key string) (string, error) {
	values := u.Query()[key]
	if len(values) != 1 || values[0] == "" {
		return "", errors.New("launch correlation refused")
	}
	return values[0], nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Owned launch qualification refused:", e)
		os.Exit(1)
	}
}
func run() error {
	account := flag.String("account-file", owned+"/.runtime/ui-account.env", "private test account")
	output := flag.String("session-file", owned+"/.runtime/aa8-session.json", "exclusive private driver output")
	control := flag.String("control-file", owned+"/.runtime/aa8-control.json", "exclusive private CP cookie output")
	loginOnly := flag.Bool("login-only", false, "persist independent CP jar without app launch")
	baseline := flag.Bool("baseline-root-only", false, "qualify root delivery only; compatibility routes remain unqualified")
	flag.Parse()
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != owned {
		return errors.New("owned context required")
	}
	if e := exec.Command(owned + "/ownership.py").Run(); e != nil {
		return errors.New("resource ownership refused")
	}
	if e := privatePath(*output); e != nil {
		return e
	}
	if e := privatePath(*control); e != nil {
		return e
	}
	credentials, e := readPrivate(*account)
	if e != nil {
		return e
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(credentials), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[parts[0]] = parts[1]
		}
	}
	if values["AA1_UI_EMAIL"] == "" || values["AA1_UI_PASSWORD"] == "" {
		return errors.New("account fields required")
	}
	c, e := client()
	if e != nil {
		return e
	}
	status, _, raw, e := request(c, "POST", cpBase+"/api/v1/auth/login", map[string]string{"email": values["AA1_UI_EMAIL"], "password": values["AA1_UI_PASSWORD"]}, nil)
	if e != nil || status != 200 {
		return errors.New("fresh normal login failed")
	}
	var login struct {
		MFARequired bool `json:"mfa_required"`
		User        struct {
			ID         string `json:"id"`
			MustChange bool   `json:"must_change_password"`
		} `json:"user"`
	}
	if json.Unmarshal(raw, &login) != nil || login.MFARequired || login.User.MustChange || login.User.ID == "" {
		return errors.New("native login gate incomplete")
	}
	if *loginOnly {
		cpURL, _ := url.Parse(cpBase)
		if e = persist(*control, map[string]any{"cp_base_url": cpBase, "user_id": login.User.ID, "cp_cookies": c.Jar.Cookies(cpURL)}); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": "cp_login_ready", "user_id": login.User.ID, "control_file": *control})
	}
	status, headers, _, e := request(c, "GET", appBase+"/__tunnex_app/start", nil, nil)
	if e != nil || status != 303 {
		return errors.New("active app pending launch unavailable")
	}
	next, e := url.Parse(headers.Get("Location"))
	if e != nil || next.Scheme != "https" || next.Host != consoleHost+":15180" || next.Path != "/app-access/launch" || next.User != nil {
		return errors.New("trusted console return refused")
	}
	org, e := queryOne(next, "orgId")
	if e != nil {
		return e
	}
	app, e := queryOne(next, "appId")
	if e != nil {
		return e
	}
	nonce, e := queryOne(next, "nonce_hash")
	if e != nil {
		return e
	}
	target, e := queryOne(next, "target")
	if e != nil || target != "/" {
		return errors.New("safe launch target refused")
	}
	// Verify the actual console TLS hostname independently; native CP login uses its own jar.
	status, _, _, e = request(c, "GET", next.String(), nil, nil)
	if e != nil || status != 200 {
		return errors.New("trusted HTTPS console unavailable")
	}
	status, _, raw, e = request(c, "POST", cpBase+"/api/v1/organizations/"+org+"/app-access/my-apps/"+app+"/launch", map[string]string{"nonce_hash": nonce, "relative_target": target}, nil)
	if e != nil || status != 200 {
		return errors.New("native launch authority refused")
	}
	var launch struct {
		URL string `json:"redirect_url"`
	}
	if json.Unmarshal(raw, &launch) != nil {
		return errors.New("launch response malformed")
	}
	redeem, e := url.Parse(launch.URL)
	if e != nil || redeem.Scheme != "https" || redeem.Host != appHost || redeem.Path != "/__tunnex_app/redeem" || redeem.User != nil {
		return errors.New("redemption host refused")
	}
	appURL, _ := url.Parse(appBase)
	nonceCookie := ""
	for _, cookie := range c.Jar.Cookies(appURL) {
		if cookie.Name == "__Host-tunnex_app_nonce" {
			nonceCookie = cookie.Value
		}
	}
	if nonceCookie == "" {
		return errors.New("pending browser nonce missing")
	}
	redeemStarted := time.Now()
	status, headers, _, e = request(c, "GET", redeem.String(), nil, nil)
	if e != nil || status != 303 || headers.Get("Location") != "/" {
		return fmt.Errorf("single redemption refused: status=%d elapsed_ms=%d root_location=%t transport_error=%t", status, time.Since(redeemStarted).Milliseconds(), headers.Get("Location") == "/", e != nil)
	}
	token := ""
	for _, cookie := range c.Jar.Cookies(appURL) {
		if cookie.Name == "__Host-tunnex_app_session" {
			token = cookie.Value
		}
	}
	if token == "" {
		return errors.New("app cookie missing")
	}
	// A consumed code must not succeed again; no secret/code URL is printed or persisted.
	status, _, _, e = request(c, "GET", redeem.String(), nil, map[string]string{"Cookie": "__Host-tunnex_app_nonce=" + nonceCookie})
	if e != nil || status != 403 {
		return errors.New("code replay was not refused")
	}
	paths := []string{"/"}
	if !*baseline {
		paths = append(paths, "/assets/app.css", "/assets/app.js")
	}
	for _, path := range paths {
		var navigation map[string]string
		if path == "/" {
			navigation = map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}
		}
		status, _, raw, e = request(c, "GET", appBase+path, nil, navigation)
		if e != nil || status != 200 || len(raw) == 0 {
			return errors.New("origin content or assets unavailable")
		}
	}
	if !*baseline {
		status, headers, _, e = request(c, "GET", appBase+"/redirect", nil, nil)
		if e != nil || status != 302 || headers.Get("Location") != appBase+"/" {
			return errors.New("origin redirect mismatch")
		}
		status, headers, _, e = request(c, "GET", appBase+"/cookie", nil, nil)
		if e != nil || status != 302 {
			return errors.New("origin cookie route failed")
		}
		found := false
		for _, cookie := range headers.Values("Set-Cookie") {
			if strings.HasPrefix(cookie, "fixture_preference=") && strings.Contains(cookie, "Secure") {
				found = true
			}
		}
		if !found {
			return errors.New("rewritten origin cookie missing")
		}
		// Known-length ordinary form POST uses actual Origin evidence and no replay.
		form := url.Values{"message": {"Owned launch compatibility"}}.Encode()
		r, _ := http.NewRequest("POST", appBase+"/form", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", appBase)
		response, e := c.Do(r)
		if e != nil {
			return errors.New("form request failed")
		}
		raw, e = io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || !bytes.Contains(raw, []byte("Owned launch compatibility")) {
			return errors.New("form compatibility failed")
		}
	}
	status, _, raw, e = request(c, "GET", cpBase+"/api/v1/organizations/"+org+"/app-access/my-sessions?limit=100", nil, nil)
	if e != nil || status != 200 {
		return errors.New("own session metadata failed")
	}
	var metadata struct {
		Items []struct {
			ID            string    `json:"id"`
			AppID         string    `json:"app_id"`
			CurrentParent bool      `json:"current_parent"`
			CreatedAt     time.Time `json:"created_at"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return errors.New("session metadata malformed")
	}
	id := ""
	latest := time.Time{}
	for _, item := range metadata.Items {
		if item.AppID == app && item.CurrentParent && item.CreatedAt.After(latest) {
			id = item.ID
			latest = item.CreatedAt
		}
	}
	if id == "" {
		return errors.New("new app session metadata missing")
	}
	if e = persist(*output, map[string]string{"app_session_token": token}); e != nil {
		return e
	}
	cpURL, _ := url.Parse(cpBase)
	if e = persist(*control, map[string]any{"cp_base_url": cpBase, "org_id": org, "app_id": app, "user_id": login.User.ID, "session_id": id, "cp_cookies": c.Jar.Cookies(cpURL)}); e != nil {
		return e
	}
	compatibility := "passed"
	if *baseline {
		compatibility = "unqualified: root-only baseline"
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"state": "ready", "org_id": org, "app_id": app, "session_id": id, "strict_tls": true, "code_replay_refused": true, "content_form_assets_redirect_cookie": compatibility, "session_file": *output, "control_file": *control})
}
