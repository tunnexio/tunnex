package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

type EditorOptions struct{ Server, Org, Target, Account, CA string }
type editorConnection struct {
	Server, CA string
	Connection api.ServerAccessEditorConnection
}

var editorAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func editorURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("editor access requires a canonical HTTPS control-plane URL")
	}
	return u, nil
}
func editorTLS(ca string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil {
			return nil, e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid control-plane CA file")
		}
		config.RootCAs = roots
	}
	return config, nil
}

// Editor opens a narrowly scoped browser approval, not a stored CLI bearer login.
// OpenSSH ControlMaster reuses the single authorized SSH connection for VS Code's
// install and tunnel phases. All remote traffic still ends with the API lease.
func Editor(ctx context.Context, options EditorOptions) error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errors.New("native editor launch currently supports macOS and Linux clients")
	}
	server, e := editorURL(options.Server)
	if e != nil {
		return e
	}
	org, e := uuid.Parse(options.Org)
	if e != nil {
		return errors.New("invalid organization ID")
	}
	target, e := uuid.Parse(options.Target)
	if e != nil {
		return errors.New("invalid server ID")
	}
	if !editorAccount.MatchString(options.Account) || options.Account == "root" {
		return errors.New("invalid Linux account")
	}
	code, e := exec.LookPath("code")
	if e != nil {
		return errors.New("install VS Code and its 'code' shell command, plus the Remote - SSH extension")
	}
	if _, e = exec.LookPath("ssh"); e != nil {
		return errors.New("OpenSSH client is required")
	}
	config, e := editorTLS(options.CA)
	if e != nil {
		return e
	}
	verifier, challenge, e := pkce()
	if e != nil {
		return e
	}
	state, e := randomToken()
	if e != nil {
		return e
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		return e
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer ln.Close()
	result := make(chan callbackResult, 1)
	callback := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: callbackHandler(state, result)}
	go func() { _ = callback.Serve(ln) }()
	defer func() {
		bounded, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = callback.Shutdown(bounded)
	}()
	redirect := "http://" + ln.Addr().String() + "/callback"
	approval := strings.TrimRight(server.String(), "/") + "/editor-auth?" + url.Values{"org": {org.String()}, "server": {target.String()}, "account": {options.Account}, "public_key": {string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}, "code_challenge": {challenge}, "redirect_uri": {redirect}, "state": {state}}.Encode()
	fmt.Println("Approve Developer access in your browser. Recording is off.")
	fmt.Println("If your browser does not open, visit:", approval)
	openBrowser(approval)
	var approved callbackResult
	select {
	case approved = <-result:
	case <-time.After(listenerTimeout):
		return errors.New("editor approval timed out; run the command again")
	case <-ctx.Done():
		return ctx.Err()
	}
	if approved.err != nil {
		return approved.err
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: config}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, e := api.NewClientWithResponses(server.String(), api.WithHTTPClient(httpClient))
	if e != nil {
		return e
	}
	exchange, e := client.ExchangeServerAccessEditorWithResponse(ctx, api.ExchangeServerAccessEditorJSONRequestBody{Code: approved.code, CodeVerifier: verifier})
	if e != nil {
		return errors.New("editor exchange failed; verify control-plane TLS trust and retry")
	}
	if exchange.JSON200 == nil {
		return apiErr(exchange.StatusCode(), exchange.Body, "editor approval refused")
	}
	conn := exchange.JSON200
	if conn.Account != options.Account || !conn.ExpiresAt.After(time.Now()) || conn.SessionId == uuid.Nil {
		return errors.New("invalid editor connection")
	}
	dir, e := StateDir()
	if e != nil {
		return e
	}
	dir, e = filepath.Abs(filepath.Join(dir, "editor"))
	if e != nil {
		return e
	}
	if strings.ContainsAny(dir, "\r\n\x00%") {
		return errors.New("unsupported editor state path")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	if strings.ContainsAny(home, "\r\n\x00%") {
		return errors.New("unsupported home path")
	}
	alias := "tunnex-" + conn.SessionId.String()
	prefix := filepath.Join(dir, alias)
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	executable, e = filepath.Abs(executable)
	if e != nil {
		return e
	}
	if strings.ContainsAny(executable, "\r\n\x00%") {
		return errors.New("unsupported CLI executable path")
	}
	block, e := ssh.MarshalPrivateKey(private, "Tunnex editor")
	if e != nil {
		return e
	}
	host, _, hostOptions, rest, e := ssh.ParseAuthorizedKey([]byte(conn.HostPublicKey))
	if e != nil || len(hostOptions) != 0 || len(rest) != 0 || host.Type() != ssh.KeyAlgoED25519 {
		return errors.New("invalid editor host identity")
	}
	if e = WriteFileAtomic0600(prefix+".key", pem.EncodeToMemory(block)); e != nil {
		return e
	}
	if e = WriteFileAtomic0600(prefix+".hosts", []byte(alias+" "+string(ssh.MarshalAuthorizedKey(host)))); e != nil {
		return e
	}
	caPath := ""
	if options.CA != "" {
		raw, err := os.ReadFile(options.CA)
		if err != nil {
			return err
		}
		caPath = prefix + ".ca"
		if e = WriteFileAtomic0600(caPath, raw); e != nil {
			return e
		}
	}
	bundle, e := json.Marshal(editorConnection{strings.TrimRight(server.String(), "/"), caPath, *conn})
	if e != nil {
		return e
	}
	if e = WriteFileAtomic0600(prefix+".json", bundle); e != nil {
		return e
	}
	sshConfig := editorSSHConfig(alias, conn.Account, executable, prefix)
	if e = WriteFileAtomic0600(prefix+".conf", []byte(sshConfig)); e != nil {
		return e
	}
	// The exact managed Include is prepended, preserving every existing SSH entry.
	if e = includeEditorConfig(home, dir); e != nil {
		return e
	}
	command := exec.CommandContext(ctx, code, "--new-window", "--remote", "ssh-remote+"+alias)
	if e = command.Run(); e != nil {
		return errors.New("could not launch VS Code; verify the Remote - SSH extension is installed")
	}
	fmt.Printf("VS Code opened for %s. Recording off; access expires at %s.\n", options.Account, conn.ExpiresAt.Local().Format(time.RFC3339))
	return nil
}
func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'" }
func sshQuote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}
func editorSSHConfig(alias, account, executable, prefix string) string {
	return fmt.Sprintf("Host %s\n  HostName tunnex-editor\n  User %s\n  ProxyCommand %s editor-proxy --connection %s\n  IdentityFile %s\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n  HostKeyAlias %s\n  ControlMaster auto\n  ControlPersist 60\n  ControlPath ~/.ssh/tunnex-%%C\n  ForwardAgent no\n  ForwardX11 no\n  RequestTTY no\n\n", alias, account, shellQuote(executable), shellQuote(prefix+".json"), sshQuote(prefix+".key"), sshQuote(prefix+".hosts"), alias)
}
func includeEditorConfig(home, dir string) error {
	path := filepath.Join(home, ".ssh", "config")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	lock := flock.New(path + ".tunnex-lock")
	if e := lock.Lock(); e != nil {
		return e
	}
	defer lock.Unlock()
	// Refuse symlinks: never replace a user's linked or shared SSH configuration.
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("SSH config is not a regular file; add the Tunnex editor Include manually")
	}
	original, e := os.ReadFile(path)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	include := "Include " + sshQuote(filepath.Join(dir, "*.conf")) + "\n"
	if strings.Contains(string(original), include) {
		return nil
	}
	return WriteFileAtomic0600(path, []byte("# Tunnex Developer access\n"+include+"\n"+string(original)))
}

// EditorProxy is invoked by OpenSSH. Stdout is exclusively SSH bytes. The
// capability appears only in a 0600 file and TLS header, never argv or URLs.
func EditorProxy(ctx context.Context, path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("editor connection must be a private regular file (0600)")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var bundle editorConnection
	if len(raw) > 16384 || json.Unmarshal(raw, &bundle) != nil {
		return errors.New("invalid editor connection")
	}
	server, e := editorURL(bundle.Server)
	if e != nil {
		return e
	}
	if !bundle.Connection.ExpiresAt.After(time.Now()) {
		return errors.New("editor connection expired; approve a new connection")
	}
	config, e := editorTLS(bundle.CA)
	if e != nil {
		return e
	}
	endpoint := *server
	endpoint.Scheme = "wss"
	endpoint.Path = "/api/v1/server-access/editor/" + bundle.Connection.SessionId.String()
	wsConfig, e := websocket.NewConfig(endpoint.String(), server.String())
	if e != nil {
		return e
	}
	wsConfig.TlsConfig = config
	wsConfig.Header.Set("Authorization", "TunnexEditor "+bundle.Connection.Token)
	wsConfig.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	ws, e := websocket.DialConfig(wsConfig)
	if e != nil {
		return errors.New("editor connection refused; approve a new connection")
	}
	defer ws.Close()
	defer cleanupEditorProfile(path)
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = 65536
	bounded, cancel := context.WithDeadline(ctx, bundle.Connection.ExpiresAt)
	defer cancel()
	go func() { <-bounded.Done(); _ = ws.Close() }()
	go func() { _, _ = io.Copy(ws, os.Stdin); _ = ws.Close() }()
	_, e = io.Copy(os.Stdout, ws)
	if e != nil && bounded.Err() != nil {
		return nil
	}
	return e
}

// Only this CLI's private per-session files are eligible for retirement.
func cleanupEditorProfile(path string) {
	dir, e := StateDir()
	if e != nil {
		return
	}
	owned, e := filepath.Abs(filepath.Join(dir, "editor"))
	if e != nil {
		return
	}
	actual, e := filepath.Abs(path)
	if e != nil || filepath.Dir(actual) != owned {
		return
	}
	base := strings.TrimSuffix(filepath.Base(actual), ".json")
	id := strings.TrimPrefix(base, "tunnex-")
	if _, e = uuid.Parse(id); e != nil || base != "tunnex-"+id || !strings.HasSuffix(actual, ".json") {
		return
	}
	for _, ext := range []string{".conf", ".key", ".hosts", ".json", ".ca"} {
		_ = os.Remove(filepath.Join(owned, base+ext))
	}
}
