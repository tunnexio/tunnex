package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

var editorChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var editorVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

type editorIdentity struct {
	Org, Session uuid.UUID
	Key          []byte
}

func editorRandom() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}

// AuthorizeEditor requires an explicit browser approval. Its capability is bound
// to the initiating human session, account grant, PKCE verifier and local SSH key.
func (s *Service) AuthorizeEditor(ctx context.Context, org uuid.UUID, p *authctx.Principal, in api.ServerAccessEditorInput) (api.ServerAccessEditorApproval, error) {
	key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
	if e != nil || len(options) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 || !editorChallenge.MatchString(in.CodeChallenge) {
		return api.ServerAccessEditorApproval{}, bad()
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	host, e := ssh.NewSignerFromKey(private)
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	code, e := editorRandom()
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	session, e := s.startSession(ctx, org, p, api.ServerAccessConnectInput{ServerId: in.ServerId, Account: in.Account}, false, true)
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	success := false
	defer func() {
		if !success {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.end(cleanup, org, session.Id, p.UserID, "editor_authorization_failed")
		}
	}()
	bound, e := json.Marshal(editorIdentity{org, session.Id, private})
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	sealed, e := s.sealer.Seal(bound)
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	hash := sha256.Sum256([]byte(code))
	_, e = s.pool.Exec(ctx, `INSERT INTO server_access_editor_connections(org_id,session_id,code_hash,challenge,client_public_key,host_private_sealed,host_public_key) VALUES($1,$2,$3,$4,$5,$6,$7)`, org, session.Id, hash[:], in.CodeChallenge, string(ssh.MarshalAuthorizedKey(key)), []byte(sealed), string(ssh.MarshalAuthorizedKey(host.PublicKey())))
	if e != nil {
		return api.ServerAccessEditorApproval{}, e
	}
	success = true
	return api.ServerAccessEditorApproval{Code: code}, nil
}

// ExchangeEditor is deliberately not a general bearer login. The code is
// single-use, expires with pending admission (30 seconds), and requires PKCE.
func (s *Service) ExchangeEditor(ctx context.Context, in api.ServerAccessEditorExchangeInput) (api.ServerAccessEditorConnection, error) {
	if !editorChallenge.MatchString(in.Code) || !editorVerifier.MatchString(in.CodeVerifier) {
		return api.ServerAccessEditorConnection{}, deny("editor_authorization_invalid")
	}
	hash := sha256.Sum256([]byte(in.Code))
	challenge := sha256.Sum256([]byte(in.CodeVerifier))
	token, e := editorRandom()
	if e != nil {
		return api.ServerAccessEditorConnection{}, e
	}
	tokenHash := sha256.Sum256([]byte(token))
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessEditorConnection{}, e
	}
	defer tx.Rollback(ctx)
	var org, id uuid.UUID
	var host string
	e = tx.QueryRow(ctx, `UPDATE server_access_editor_connections c SET exchanged_at=now(),token_hash=$3 FROM server_access_sessions s WHERE c.session_id=s.id AND c.org_id=s.org_id AND c.code_hash=$1 AND c.challenge=$2 AND c.exchanged_at IS NULL AND s.status='pending' AND s.kind='editor' AND s.created_at>now()-interval '30 seconds' AND s.expires_at>now() RETURNING c.org_id,c.session_id,c.host_public_key`, hash[:], base64.RawURLEncoding.EncodeToString(challenge[:]), tokenHash[:]).Scan(&org, &id, &host)
	if e != nil {
		return api.ServerAccessEditorConnection{}, deny("editor_authorization_invalid")
	}
	r, e := s.load(ctx, org, id)
	if e != nil {
		return api.ServerAccessEditorConnection{}, e
	}
	if _, _, e = s.validate(ctx, org, r); e != nil {
		return api.ServerAccessEditorConnection{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return api.ServerAccessEditorConnection{}, e
	}
	return api.ServerAccessEditorConnection{SessionId: id, Token: token, HostPublicKey: host, Account: r.View.Account, ExpiresAt: r.View.ExpiresAt}, nil
}

func (s *Service) editorMaterial(ctx context.Context, org, id uuid.UUID, m *terminalwire.Material) error {
	var sealed []byte
	e := s.pool.QueryRow(ctx, `SELECT client_public_key,host_private_sealed FROM server_access_editor_connections WHERE org_id=$1 AND session_id=$2 AND exchanged_at IS NOT NULL`, org, id).Scan(&m.EditorClientKey, &sealed)
	if e != nil {
		return e
	}
	raw, e := s.sealer.Open(string(sealed))
	if e != nil {
		return e
	}
	var identity editorIdentity
	if json.Unmarshal(raw, &identity) != nil || identity.Org != org || identity.Session != id || len(identity.Key) != ed25519.PrivateKeySize {
		return deny("invalid_editor_identity")
	}
	m.EditorHostKey = identity.Key
	return nil
}

// Editor carries encrypted native SSH bytes, never terminal frames. Each
// connection can be claimed once; browser cookie and general CLI bearer tokens
// cannot attach. Recording is always off. Existing leases revoke both legs.
func (s *Service) Editor(w http.ResponseWriter, req *http.Request, id uuid.UUID, secure bool) error {
	if !secure {
		return deny("editor_requires_https")
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return bad()
	}
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "TunnexEditor ")
	if !editorChallenge.MatchString(token) {
		return deny("editor_authorization_invalid")
	}
	hash := sha256.Sum256([]byte(token))
	var org uuid.UUID
	e := s.pool.QueryRow(req.Context(), `SELECT org_id FROM server_access_editor_connections WHERE session_id=$1 AND token_hash=$2 AND exchanged_at IS NOT NULL`, id, hash[:]).Scan(&org)
	if e != nil {
		return deny("editor_authorization_invalid")
	}
	r, e := s.load(req.Context(), org, id)
	if e != nil {
		return e
	}
	_, until, e := s.validate(req.Context(), org, r)
	if e != nil {
		return e
	}
	if r.View.Kind != "editor" || r.View.RecordingEnabled {
		return deny("invalid_editor_session")
	}
	l := &liveSession{attached: make(chan struct{}), done: make(chan struct{}), started: time.Now()}
	s.mu.Lock()
	if s.live[id] != nil || len(s.live) >= 128 {
		s.mu.Unlock()
		return deny("channel_already_claimed")
	}
	s.live[id] = l
	s.mu.Unlock()
	defer s.closeLive(id)
	tag, e := s.pool.Exec(req.Context(), `UPDATE server_access_sessions SET browser_claimed_at=now(),status='connecting' WHERE org_id=$1 AND id=$2 AND kind='editor' AND status='pending' AND browser_claimed_at IS NULL`, org, id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return deny("channel_already_claimed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lease atomic.Int64
	lease.Store(until.UnixNano())
	fail := func(reason string) { l.reason.CompareAndSwap(nil, &reason); l.close() }
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				if time.Now().UnixNano() >= lease.Load() {
					fail("authority_expired")
					return
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				bounded, stop := context.WithTimeout(ctx, time.Second)
				fresh, err := s.load(bounded, org, id)
				var next time.Time
				if err == nil {
					_, next, err = s.validate(bounded, org, fresh)
				}
				stop()
				if err != nil {
					fail(authorityReason(err))
					return
				}
				lease.Store(next.UnixNano())
			}
		}
	}()
	websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
		ws.MaxPayloadBytes = 65536
		ws.PayloadType = websocket.BinaryFrame
		_ = ws.SetDeadline(time.Time{})
		l.mu.Lock()
		l.browser = ws
		l.mu.Unlock()
		defer l.close()
		select {
		case <-l.done:
			return
		case <-l.attached:
		}
		l.mu.Lock()
		gateway := l.gateway
		l.mu.Unlock()
		go func() { defer l.close(); _, _ = io.Copy(ws, gateway) }()
		// SSH is encrypted here: idle means transport inactivity, not keystrokes.
		writer := &editorActivityWriter{Writer: gateway, touch: func() error {
			bounded, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			tag, err := s.pool.Exec(bounded, `UPDATE server_access_sessions SET idle_deadline=LEAST(expires_at,now()+make_interval(secs => (SELECT idle_timeout_seconds FROM server_access_servers WHERE org_id=$1 AND id=$3))) WHERE org_id=$1 AND id=$2 AND status='connected' AND idle_deadline>now() AND expires_at>now()`, org, id, r.View.ServerId)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("editor activity expired")
			}
			return nil
		}}
		_, _ = io.Copy(writer, ws)
	}}.ServeHTTP(w, req)
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	reason := "editor_closed"
	if why := l.reason.Load(); why != nil {
		reason = *why
	}
	return s.end(cleanup, org, id, r.View.UserId, reason)
}

type editorActivityWriter struct {
	io.Writer
	touch func() error
	last  time.Time
}

func (w *editorActivityWriter) Write(p []byte) (int, error) {
	if time.Since(w.last) >= time.Second {
		if e := w.touch(); e != nil {
			return 0, e
		}
		w.last = time.Now()
	}
	return w.Writer.Write(p)
}
