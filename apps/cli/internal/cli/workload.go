package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

const workloadStateVersion = 1
const workloadFileLimit = 64 << 10
const workloadAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type workloadConfig struct {
	Server            string `json:"server"`
	EnrollmentKeyFile string `json:"enrollment_key_file"`
	StateDirectory    string `json:"state_directory"`
}
type workloadRotation struct {
	RequestID  uuid.UUID `json:"request_id"`
	PrivateKey []byte    `json:"private_key"`
}
type workloadState struct {
	Version         int                    `json:"version"`
	Server          string                 `json:"server"`
	PrivateKey      []byte                 `json:"private_key"`
	RequestID       uuid.UUID              `json:"request_id"`
	EnrollmentHash  string                 `json:"enrollment_hash,omitempty"`
	Receipt         *api.AIWorkloadReceipt `json:"receipt,omitempty"`
	PendingRotation *workloadRotation      `json:"pending_rotation,omitempty"`
	Retired         bool                   `json:"retired,omitempty"`
}
type workloadSession struct {
	config     workloadConfig
	state      workloadState
	directory  os.FileInfo
	lock       *flock.Flock
	client     *http.Client
	retryDelay time.Duration
}
type workloadHTTPError struct{ status int }

func (e workloadHTTPError) Error() string {
	if e.status == 401 || e.status == 403 {
		return fmt.Sprintf("workload access refused (HTTP %d); instance state was preserved; contact your AI administrator", e.status)
	}
	return fmt.Sprintf("workload request failed (HTTP %d)", e.status)
}

func (e workloadHTTPError) retryable() bool {
	switch e.status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// Workload never reads or writes the saved human login. Explicit token output is
// confined to the advanced token command; run keeps remote tokens in memory.
func Workload(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: tunnex workload run|enroll|token|rotate|retire --config /absolute/workload.json [-- command args]")
	}
	command := args[0]
	if command != "run" && command != "enroll" && command != "token" && command != "rotate" && command != "retire" {
		return errors.New("unknown workload command; use run, enroll, token, rotate or retire")
	}
	flags := flag.NewFlagSet("workload", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "private configuration file")
	if flags.Parse(args[1:]) != nil {
		return errors.New("invalid workload arguments; use --config /absolute/workload.json")
	}
	if *configPath == "" || command == "run" && flags.NArg() == 0 || command != "run" && flags.NArg() != 0 {
		return errors.New("workload requires --config; run also requires -- followed by a command")
	}
	s, err := openWorkloadSession(*configPath)
	if err != nil {
		return err
	}
	defer s.close()
	if s.state.Retired && command != "retire" {
		return errors.New("this workload instance was retired; provision a new private state directory for an explicitly authorized new deployment")
	}
	if command == "retire" && s.state.Receipt == nil {
		return errors.New("workload instance has not enrolled; retirement does not create a new instance")
	}
	if err = s.enroll(ctx); err != nil {
		return err
	}
	if s.state.PendingRotation != nil {
		if err = s.rotate(ctx); err != nil {
			return err
		}
	} else if command == "rotate" {
		if err = s.rotate(ctx); err != nil {
			return err
		}
	}
	switch command {
	case "retire":
		return s.retire(ctx, newWorkloadTokens(s))
	case "token":
		token, err := s.issueToken(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(token)
	case "enroll", "rotate":
		return json.NewEncoder(out).Encode(s.state.Receipt)
	default:
		return s.run(ctx, flags.Args(), out)
	}
}

func workloadPrivateRead(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("workload file paths must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o177 != 0 {
		return nil, errors.New("workload files must be regular, non-symlink files with permissions 0600 or stricter")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, actual) || !os.SameFile(after, actual) || actual.Mode().Perm()&0o177 != 0 {
		return nil, errors.New("workload file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, workloadFileLimit+1))
	if err != nil || len(b) > workloadFileLimit {
		return nil, errors.New("workload file could not be read within its size limit")
	}
	return b, nil
}

func workloadDecode(b []byte, into any) error {
	value := reflect.ValueOf(into)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("invalid workload JSON destination")
	}
	candidate := reflect.New(value.Elem().Type())
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(candidate.Interface()) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid workload JSON")
	}
	value.Elem().Set(candidate.Elem())
	return nil
}

func workloadServer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("workload server must be an HTTPS origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return "", errors.New("workload server requires HTTPS; HTTP is allowed only for loopback development")
	}
	u.Path = ""
	return u.String(), nil
}

// Resolve trusted system symlinks (for example macOS /var) but refuse a symlink
// in an ancestor writable by another user. The final state directory is private.
func workloadCheckParents(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			owner, err := os.Stat(filepath.Dir(parent))
			if err != nil {
				return err
			}
			if owner.Mode().Perm()&0o022 != 0 {
				return errors.New("workload paths cannot traverse a symlink in a writable parent")
			}
		}
		if parent == filepath.Dir(parent) {
			return nil
		}
	}
}

func openWorkloadSession(configPath string) (*workloadSession, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("workload private storage on Windows requires ACL qualification; use Linux or macOS for this version")
	}
	if err := workloadCheckParents(configPath); err != nil {
		return nil, errors.New("workload configuration parent directory is unavailable or unsafe")
	}
	b, err := workloadPrivateRead(configPath)
	if err != nil {
		return nil, fmt.Errorf("read private workload configuration: %w", err)
	}
	defer clear(b)
	var config workloadConfig
	if workloadDecode(b, &config) != nil {
		return nil, errors.New("invalid workload configuration")
	}
	config.Server, err = workloadServer(config.Server)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.StateDirectory) || !filepath.IsAbs(config.EnrollmentKeyFile) || filepath.Clean(config.StateDirectory) != config.StateDirectory || filepath.Clean(config.EnrollmentKeyFile) != config.EnrollmentKeyFile {
		return nil, errors.New("workload state directory and enrollment key file must be absolute paths")
	}
	if err = workloadCheckParents(config.StateDirectory); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(config.StateDirectory, 0o700); err != nil {
		return nil, errors.New("could not create the private workload state directory")
	}
	dir, err := os.Lstat(config.StateDirectory)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm() != 0o700 {
		return nil, errors.New("workload state directory must be a non-symlink directory with permissions 0700")
	}
	lockPath := filepath.Join(config.StateDirectory, "instance.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
			return nil, errors.New("unsafe workload instance lock file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("could not inspect the workload instance lock")
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		_ = lock.Close()
		return nil, errors.New("workload state is already in use or cannot be locked; each replica needs a unique private state directory")
	}
	s := &workloadSession{config: config, directory: dir, lock: lock, retryDelay: 200 * time.Millisecond, client: &http.Client{Timeout: 10 * time.Second, Transport: workloadTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	stateBytes, err := workloadPrivateRead(filepath.Join(config.StateDirectory, "instance.json"))
	if errors.Is(err, os.ErrNotExist) {
		_, private, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			s.close()
			return nil, errors.New("could not generate workload instance key")
		}
		s.state = workloadState{Version: workloadStateVersion, Server: config.Server, PrivateKey: private, RequestID: uuid.New()}
		err = s.saveState()
	} else if err == nil {
		err = workloadDecode(stateBytes, &s.state)
		clear(stateBytes)
	}
	if err != nil {
		s.close()
		return nil, errors.New("could not read or persist private workload instance state")
	}
	if s.state.Version != workloadStateVersion || s.state.Server != config.Server || s.state.RequestID == uuid.Nil || !workloadPrivateKeyValid(s.state.PrivateKey) || s.state.Receipt != nil && !s.receiptValid(*s.state.Receipt) || s.state.PendingRotation != nil && (s.state.Receipt == nil || s.state.PendingRotation.RequestID == uuid.Nil || !workloadPrivateKeyValid(s.state.PendingRotation.PrivateKey)) {
		s.close()
		return nil, errors.New("workload instance state does not match this configuration")
	}
	return s, nil
}

func workloadPrivateKeyValid(private []byte) bool {
	return len(private) == ed25519.PrivateKeySize && subtle.ConstantTimeCompare(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) == 1
}
func workloadTransport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true}
}
func (s *workloadSession) close() {
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	clear(s.state.PrivateKey)
	if s.state.PendingRotation != nil {
		clear(s.state.PendingRotation.PrivateKey)
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
}
func (s *workloadSession) saveState() error {
	directory, err := os.Lstat(s.config.StateDirectory)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 || s.directory == nil || !os.SameFile(directory, s.directory) {
		return errors.New("private workload state directory changed while locked")
	}
	path := filepath.Join(s.config.StateDirectory, "instance.json")
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0) {
		return errors.New("unsafe workload state file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	defer clear(b)
	if err = WriteFileAtomic0600(path, b); err != nil {
		return err
	}
	dir, err := os.Open(s.config.StateDirectory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *workloadSession) receiptValid(receipt api.AIWorkloadReceipt) bool {
	return receipt.InstanceId != uuid.Nil && receipt.OrganizationId != uuid.Nil && receipt.WorkloadId != uuid.Nil && receipt.KeyGeneration >= 1 && receipt.TokenEndpoint == s.config.Server+"/api/v1/workload/token" && receipt.GatewayBase == s.config.Server+"/ai/v1"
}

func workloadSign(private []byte, audience, subject string, extra map[string]string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ed25519.PrivateKey(private)}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", errors.New("could not sign workload proof")
	}
	now := time.Now()
	claims := jwt.Claims{Issuer: subject, Subject: subject, Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)), ID: uuid.NewString()}
	additional := make(map[string]any, len(extra))
	for key, value := range extra {
		additional[key] = value
	}
	return jwt.Signed(signer).Claims(claims).Claims(additional).Serialize()
}

func workloadJSONRequest(ctx context.Context, endpoint string, input any) (*http.Request, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, err
}

// Only control requests are retried, with a freshly signed JWT each time.
// Network loss keeps the request ID and key binding needed to recover receipts.
func (s *workloadSession) control(ctx context.Context, build func() (*http.Request, error), expected int, output any) error {
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := build()
		if err != nil {
			return errors.New("could not prepare workload authentication request")
		}
		res, err := s.client.Do(req)
		if err == nil {
			b, readErr := io.ReadAll(io.LimitReader(res.Body, workloadFileLimit+1))
			_ = res.Body.Close()
			if res.StatusCode == expected {
				if readErr == nil && len(b) <= workloadFileLimit && (output == nil || workloadDecode(b, output) == nil) {
					clear(b)
					return nil
				}
				clear(b)
				err = errors.New("incomplete workload response")
			} else {
				clear(b)
				failure := workloadHTTPError{res.StatusCode}
				if !failure.retryable() || attempt == 2 {
					return failure
				}
			}
		}
		if attempt == 2 {
			return errors.New("could not reach or read the workload authority; private instance state was preserved")
		}
		timer := time.NewTimer(s.retryDelay * time.Duration(1<<attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("workload authority unavailable")
}

func (s *workloadSession) enroll(ctx context.Context) error {
	if s.state.Receipt != nil {
		return nil
	}
	if err := workloadCheckParents(s.config.EnrollmentKeyFile); err != nil {
		return errors.New("workload enrollment key parent directory is unavailable or unsafe")
	}
	b, err := workloadPrivateRead(s.config.EnrollmentKeyFile)
	if err != nil {
		return errors.New("read enrollment key from a private regular file (0600); copy mounted symlink secrets into a private file first")
	}
	defer clear(b)
	secret := strings.TrimSpace(string(b))
	if secret == "" || len(secret) > 128 || strings.ContainsAny(secret, " \r\n\t") {
		return errors.New("invalid enrollment key file")
	}
	hash := sha256.Sum256([]byte(secret))
	digest := hex.EncodeToString(hash[:])
	if s.state.EnrollmentHash != "" && s.state.EnrollmentHash != digest {
		return errors.New("enrollment key changed while a receipt is pending; restore the original key to recover this instance")
	}
	s.state.EnrollmentHash = digest
	if err = s.saveState(); err != nil {
		return errors.New("could not persist enrollment identity before contacting the server")
	}
	endpoint := s.config.Server + "/api/v1/workload/enroll"
	var receipt api.AIWorkloadReceipt
	err = s.control(ctx, func() (*http.Request, error) {
		proof, err := workloadSign(s.state.PrivateKey, endpoint, "enrollment", map[string]string{"request_id": s.state.RequestID.String(), "enrollment_hash": digest})
		if err != nil {
			return nil, err
		}
		return workloadJSONRequest(ctx, endpoint, api.AIWorkloadEnrollInput{EnrollmentKey: secret, RequestId: s.state.RequestID, PublicKey: base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(s.state.PrivateKey).Public().(ed25519.PublicKey)), Proof: proof})
	}, 200, &receipt)
	if err != nil {
		return err
	}
	if !s.receiptValid(receipt) || receipt.KeyGeneration != 1 {
		return errors.New("invalid enrollment receipt; original private state was preserved")
	}
	s.state.Receipt = &receipt
	if s.saveState() != nil {
		return errors.New("could not persist enrollment receipt; retry with the same private state")
	}
	return nil
}

func (s *workloadSession) issueToken(ctx context.Context) (api.AIWorkloadToken, error) {
	if s.state.Receipt == nil {
		return api.AIWorkloadToken{}, errors.New("workload instance has not enrolled")
	}
	endpoint := s.config.Server + "/api/v1/workload/token"
	var token api.AIWorkloadToken
	err := s.control(ctx, func() (*http.Request, error) {
		proof, err := workloadSign(s.state.PrivateKey, endpoint, s.state.Receipt.InstanceId.String(), nil)
		if err != nil {
			return nil, err
		}
		form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {workloadAssertionType}, "client_id": {s.state.Receipt.InstanceId.String()}, "client_assertion": {proof}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return req, err
	}, 200, &token)
	if err != nil {
		return api.AIWorkloadToken{}, err
	}
	if token.TokenType != "Bearer" || token.Scope != "tunnex-ai" || token.ExpiresIn < 1 || token.ExpiresIn > 300 || token.AccessToken == "" || len(token.AccessToken) > 128 || strings.ContainsAny(token.AccessToken, " \r\n\t") {
		return api.AIWorkloadToken{}, errors.New("invalid workload token response")
	}
	return token, nil
}

func (s *workloadSession) rotate(ctx context.Context) error {
	if s.state.Receipt == nil {
		return errors.New("workload instance has not enrolled")
	}
	if s.state.PendingRotation == nil {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return errors.New("could not generate candidate workload key")
		}
		s.state.PendingRotation = &workloadRotation{RequestID: uuid.New(), PrivateKey: private}
		if s.saveState() != nil {
			return errors.New("could not persist candidate key before rotation")
		}
	}
	pending := s.state.PendingRotation
	public := base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(pending.PrivateKey).Public().(ed25519.PublicKey))
	endpoint := s.config.Server + "/api/v1/workload/rotate"
	var receipt api.AIWorkloadReceipt
	err := s.control(ctx, func() (*http.Request, error) {
		extra := map[string]string{"request_id": pending.RequestID.String(), "next_key": public}
		oldProof, err := workloadSign(s.state.PrivateKey, endpoint, s.state.Receipt.InstanceId.String(), extra)
		if err != nil {
			return nil, err
		}
		newProof, err := workloadSign(pending.PrivateKey, endpoint, s.state.Receipt.InstanceId.String(), extra)
		if err != nil {
			return nil, err
		}
		return workloadJSONRequest(ctx, endpoint, api.AIWorkloadRotationInput{InstanceId: s.state.Receipt.InstanceId, RequestId: pending.RequestID, PublicKey: public, OldProof: oldProof, NewProof: newProof})
	}, 200, &receipt)
	if err != nil {
		return err
	}
	old := s.state.Receipt
	if !s.receiptValid(receipt) || receipt.InstanceId != old.InstanceId || receipt.OrganizationId != old.OrganizationId || receipt.WorkloadId != old.WorkloadId || receipt.KeyGeneration != old.KeyGeneration+1 {
		return errors.New("invalid rotation receipt; both private keys were preserved")
	}
	previous := s.state.PrivateKey
	s.state.PrivateKey = pending.PrivateKey
	s.state.PendingRotation = nil
	s.state.Receipt = &receipt
	if s.saveState() != nil {
		return errors.New("could not persist rotation receipt; reopen the same state to recover")
	}
	clear(previous)
	return nil
}

type workloadTokenTiming struct {
	lead, tick, retry time.Duration
	jitter            func() time.Duration
}
type workloadTokens struct {
	session                   *workloadSession
	mu                        sync.Mutex
	value                     string
	expires, refresh, nextTry time.Time
	terminal                  error
	timing                    workloadTokenTiming
}

func newWorkloadTokens(s *workloadSession) *workloadTokens {
	return &workloadTokens{session: s, timing: workloadTokenTiming{lead: time.Minute, tick: time.Second, retry: 5 * time.Second, jitter: func() time.Duration {
		var b [1]byte
		_, _ = rand.Read(b[:])
		return time.Duration(b[0]%16) * time.Second
	}}}
}
func (t *workloadTokens) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminal != nil {
		return "", t.terminal
	}
	now := time.Now()
	if t.value != "" && now.Before(t.expires) && (now.Before(t.refresh) || now.Before(t.nextTry)) {
		return t.value, nil
	}
	if now.Before(t.nextTry) {
		return "", errors.New("workload token renewal is unavailable")
	}
	token, err := t.session.issueToken(ctx)
	if err != nil {
		var domain workloadHTTPError
		if errors.As(err, &domain) && (domain.status == http.StatusUnauthorized || domain.status == http.StatusForbidden) {
			t.terminal = err
			t.value = ""
			return "", err
		}
		t.nextTry = time.Now().Add(t.timing.retry)
		if t.value != "" && time.Now().Before(t.expires) {
			return t.value, nil
		}
		return "", err
	}
	t.value = token.AccessToken
	t.expires = now.Add(time.Duration(token.ExpiresIn) * time.Second)
	t.nextTry = time.Time{}
	lead := t.timing.lead + t.timing.jitter()
	ttl := t.expires.Sub(now)
	if lead >= ttl {
		lead = ttl / 2
	}
	t.refresh = t.expires.Add(-lead)
	if !time.Now().Before(t.expires) {
		t.value = ""
		return "", errors.New("workload token expired before receipt")
	}
	return t.value, nil
}
func (t *workloadTokens) renew(ctx context.Context, fatal chan<- error) {
	ticker := time.NewTicker(t.timing.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = t.get(ctx)
			t.mu.Lock()
			err := t.terminal
			t.mu.Unlock()
			if err != nil {
				select {
				case fatal <- err:
				case <-ctx.Done():
				}
				return
			}
		}
	}
}

func workloadProxyPath(method, path string) (string, bool) {
	if method == http.MethodPost {
		switch path {
		case "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/audio/speech", "/v1/audio/transcriptions", "/v1/images/generations", "/v1/videos", "/v1/rerank":
			return "/ai" + path, true
		case "/v1/messages":
			return "/ai/anthropic/v1/messages", true
		}
	}
	if method == http.MethodGet {
		if path == "/v1/models" {
			return "/ai/v1/models", true
		}
		if strings.HasPrefix(path, "/v1/videos/") {
			id := strings.TrimPrefix(path, "/v1/videos/")
			id = strings.TrimSuffix(id, "/content")
			parsed, err := uuid.Parse(id)
			if err == nil && parsed != uuid.Nil && parsed.String() == id {
				return "/ai" + path, true
			}
		}
	}
	return "", false
}

type workloadProxyIdentity struct {
	target string
	token  string
}
type workloadProxyContextKey struct{}

func workloadProxy(tokens *workloadTokens, localHost, secret string) http.Handler {
	remote, _ := url.Parse(tokens.session.config.Server)
	proxy := &httputil.ReverseProxy{Transport: workloadTransport(), FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0),
		Rewrite: func(p *httputil.ProxyRequest) {
			identity := p.In.Context().Value(workloadProxyContextKey{}).(workloadProxyIdentity)
			p.Out.URL = &url.URL{Scheme: remote.Scheme, Host: remote.Host, Path: identity.target}
			p.Out.Host = remote.Host
			p.Out.GetBody = nil
			p.Out.Header = make(http.Header)
			for _, name := range []string{"Content-Type", "Accept", "Idempotency-Key", "Anthropic-Version", "Anthropic-Beta"} {
				for _, value := range p.In.Header.Values(name) {
					p.Out.Header.Add(name, value)
				}
			}
			p.Out.Header.Set("Authorization", "Bearer "+identity.token)
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Set-Cookie")
			res.Header.Del("Location")
			res.Header.Set("Cache-Control", "no-store")
			if res.StatusCode >= 300 && res.StatusCode < 400 {
				return errors.New("upstream redirects are refused")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "workload gateway is unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != localHost || len(r.Header.Values("Origin")) != 0 || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
			http.Error(w, "invalid local gateway request", 400)
			return
		}
		auth, apiKey := r.Header.Values("Authorization"), r.Header.Values("X-Api-Key")
		provided := ""
		if len(auth) == 1 && len(apiKey) == 0 && strings.HasPrefix(auth[0], "Bearer ") {
			provided = strings.TrimPrefix(auth[0], "Bearer ")
		}
		if len(apiKey) == 1 && len(auth) == 0 {
			provided = apiKey[0]
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
			http.Error(w, "local gateway authentication required", 401)
			return
		}
		target, ok := workloadProxyPath(r.Method, r.URL.Path)
		if !ok {
			http.Error(w, "unsupported gateway route", 404)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		token, err := tokens.get(ctx)
		if err != nil {
			http.Error(w, "workload authentication is unavailable", 503)
			return
		}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(ctx, workloadProxyContextKey{}, workloadProxyIdentity{target, token})))
	})
}

func workloadEnvironment(base, secret string) []string {
	env := make([]string, 0, len(os.Environ())+4)
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		switch strings.ToUpper(key) {
		case "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			continue
		}
		env = append(env, pair)
	}
	return append(env, "OPENAI_BASE_URL="+base+"/v1", "OPENAI_API_KEY="+secret, "ANTHROPIC_BASE_URL="+base, "ANTHROPIC_API_KEY="+secret)
}

func (s *workloadSession) retire(ctx context.Context, tokens *workloadTokens) error {
	// Persist intent first: a lost retirement response must not turn the next
	// run into an implicit reenrollment or reuse a deliberately retired identity.
	s.state.Retired = true
	if s.saveState() != nil {
		return errors.New("could not persist workload retirement intent")
	}
	raw, err := tokens.get(ctx)
	if err != nil {
		return errors.New("instance marked retired locally; remote retirement could not be confirmed")
	}
	err = s.control(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.Server+"/api/v1/workload/retire", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+raw)
		}
		return req, err
	}, 204, nil)
	if err != nil {
		return errors.New("instance marked retired locally; remote retirement could not be confirmed")
	}
	return nil
}

func (s *workloadSession) run(ctx context.Context, args []string, out io.Writer) error {
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	tokens := newWorkloadTokens(s)
	raw, err := tokens.get(runCtx)
	if err != nil {
		return err
	}
	var models api.AIWorkloadModelList
	if err = s.control(runCtx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(runCtx, http.MethodGet, s.config.Server+"/ai/v1/models", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+raw)
		}
		return req, err
	}, 200, &models); err != nil {
		return err
	}
	if models.Object != "list" || len(models.Data) == 0 {
		return errors.New("no models are currently authorized for this workload; application was not started")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("could not start local workload gateway")
	}
	defer listener.Close()
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return errors.New("could not create local gateway credential")
	}
	secret := base64.RawURLEncoding.EncodeToString(random[:])
	clear(random[:])
	server := &http.Server{Handler: workloadProxy(tokens, listener.Addr().String(), secret), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	server.BaseContext = func(net.Listener) context.Context { return runCtx }
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	renewed := make(chan struct{})
	fatal := make(chan error, 1)
	go func() { defer close(renewed); tokens.renew(runCtx, fatal) }()
	child := exec.CommandContext(runCtx, args[0], args[1:]...)
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
	child.WaitDelay = 5 * time.Second
	child.Env = workloadEnvironment("http://"+listener.Addr().String(), secret)
	child.Stdin = os.Stdin
	child.Stdout = out
	child.Stderr = out
	if err = child.Start(); err != nil {
		cancel()
		_ = server.Close()
		<-renewed
		return errors.New("could not start workload application")
	}
	wait := make(chan error, 1)
	go func() { wait <- child.Wait() }()
	var result error
	select {
	case result = <-wait:
	case result = <-fatal:
		cancel()
		<-wait
	case <-ctx.Done():
		result = ctx.Err()
		cancel()
		<-wait
	case <-served:
		result = errors.New("local workload gateway stopped")
		cancel()
		<-wait
	}
	cancel()
	<-renewed
	shutdown, stopShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	if server.Shutdown(shutdown) != nil {
		_ = server.Close()
	}
	stopShutdown()
	return result
}
