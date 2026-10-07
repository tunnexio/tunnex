package beam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"net/url"
	"strings"
	"time"
)

type LaunchInput struct {
	RelativeTarget string `json:"relative_target"`
	NonceHash      string `json:"nonce_hash"`
}
type Launch struct {
	RedirectURL string    `json:"redirect_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type Redeemed struct {
	Token          string    `json:"app_session_token"`
	RelativeTarget string    `json:"relative_target"`
	ExpiresAt      time.Time `json:"expires_at"`
}
type Decision struct {
	StreamID  uuid.UUID `json:"stream_id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Metadata struct {
	Method    string `json:"method"`
	Path      string `json:"relative_path"`
	Origin    string `json:"origin"`
	Referer   string `json:"referer"`
	FetchMode string `json:"fetch_mode,omitempty"`
	FetchDest string `json:"fetch_dest,omitempty"`
	FetchUser string `json:"fetch_user,omitempty"`
}

func secret(prefix string) (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b), e
}
func (s *Service) Pending(ctx context.Context, b Binding, nonce, target string) (time.Time, error) {
	if !relative(target) {
		return time.Time{}, invalid("Invalid relative target")
	}
	nh, e := nonceHash(nonce)
	if e != nil {
		return time.Time{}, e
	}
	_, _, deadline, e := s.current(ctx, s.pool, b)
	if e != nil {
		return time.Time{}, e
	}
	// A first browser login (including SSO/MFA on mobile) may take several minutes.
	// This nonce grants no access; Launch still checks all current authority.
	until := time.Now().Add(10 * time.Minute)
	if deadline.Before(until) {
		until = deadline
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO beam_pending_launches(nonce_hash,org_id,share_id,relative_target,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, nh, b.OrgID, b.AppID, target, until)
	return until, e
}
func (s *Service) Launch(ctx context.Context, org, id uuid.UUID, a Actor, in LaunchInput) (Launch, error) {
	var out Launch
	if a.SessionID == "" || a.CredentialID != uuid.Nil || !relative(in.RelativeTarget) {
		return out, deny()
	}
	nh, e := nonceHash(in.NonceHash)
	if e != nil {
		return out, e
	}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, org, id))
	if e != nil {
		return out, missing()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return out, e
	}
	deadline, e := s.source(ctx, tx, r, p)
	if e != nil || r.State != "active" || r.Connectivity != "online" {
		return out, deny()
	}
	if e = s.reviewer(ctx, tx, r, a.ID, p); e != nil {
		return out, e
	}
	parentDeadline, e := s.parent(ctx, tx, org, a.ID, a.SessionID, p.RequireMFA)
	if e != nil {
		return out, e
	}
	var pendingTarget string
	var pendingUntil time.Time
	e = tx.QueryRow(ctx, `DELETE FROM beam_pending_launches WHERE org_id=$1 AND share_id=$2 AND nonce_hash=$3 AND expires_at>now() RETURNING relative_target,expires_at`, org, id, nh).Scan(&pendingTarget, &pendingUntil)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, apierr.Conflict("beam_launch_expired", "This sign-in link expired or was already used. Open a fresh link to continue.")
	}
	if e != nil {
		return out, e
	}
	if pendingTarget != in.RelativeTarget {
		return out, deny()
	}
	code, e := secret("tnxbc_")
	if e != nil {
		return out, e
	}
	until := time.Now().Add(30 * time.Second)
	for _, t := range []time.Time{deadline, parentDeadline, pendingUntil} {
		if t.Before(until) {
			until = t
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO beam_launch_codes(code_hash,org_id,share_id,user_id,parent_session_id,nonce_hash,relative_target,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, hash(code), org, id, a.ID, a.SessionID, nh, in.RelativeTarget, until)
	if e != nil {
		return out, e
	}
	if e = audit(ctx, tx, org, a.ID, "launch.created", id); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	return Launch{"https://" + r.Hostname + "/_beam/redeem?code=" + url.QueryEscape(code), until}, nil
}
func (s *Service) Redeem(ctx context.Context, hostname, code, nonce string) (Redeemed, error) {
	var out Redeemed
	if !strings.HasPrefix(code, "tnxbc_") || len(code) != 49 || len(nonce) != 43 {
		return out, deny()
	}
	nh := hash(nonce)
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var org, id, user uuid.UUID
	var parent, target string
	var codeUntil time.Time
	e = tx.QueryRow(ctx, `UPDATE beam_launch_codes c SET consumed_at=now() FROM beam_shares s WHERE s.org_id=c.org_id AND s.id=c.share_id AND s.hostname=$1 AND c.code_hash=$2 AND c.nonce_hash=$3 AND c.expires_at>now() AND c.consumed_at IS NULL RETURNING c.org_id,c.share_id,c.user_id,c.parent_session_id,c.relative_target,c.expires_at`, hostname, hash(code), nh).Scan(&org, &id, &user, &parent, &target, &codeUntil)
	if e != nil {
		return out, deny()
	}
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, org, id))
	if e != nil {
		return out, deny()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return out, e
	}
	deadline, e := s.source(ctx, tx, r, p)
	if e != nil || r.State != "active" {
		return out, deny()
	}
	if e = s.reviewer(ctx, tx, r, user, p); e != nil {
		return out, e
	}
	parentUntil, e := s.parent(ctx, tx, org, user, parent, p.RequireMFA)
	if e != nil {
		return out, e
	}
	if parentUntil.Before(deadline) {
		deadline = parentUntil
	}
	token, e := secret("tnxbs_")
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO beam_browser_sessions(token_hash,org_id,share_id,user_id,parent_session_id,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, hash(token), org, id, user, parent, parentUntil)
	if e != nil {
		return out, e
	}
	if e = audit(ctx, tx, org, user, "session.created", id); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	return Redeemed{token, target, deadline}, nil
}
func (s *Service) browser(ctx context.Context, q reader, b Binding, tokenHash []byte) (Share, time.Time, error) {
	r, p, deadline, e := s.current(ctx, q, b)
	if e != nil || r.State != "active" || r.Connectivity != "online" {
		return r, time.Time{}, deny()
	}
	var user uuid.UUID
	var parent string
	var until time.Time
	e = q.QueryRow(ctx, `SELECT user_id,parent_session_id,expires_at FROM beam_browser_sessions WHERE org_id=$1 AND share_id=$2 AND token_hash=$3 AND expires_at>now()`, b.OrgID, b.AppID, tokenHash).Scan(&user, &parent, &until)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, time.Time{}, apierr.Forbidden("beam_session_invalid", "Beam browser session expired")
	}
	if e != nil {
		return r, time.Time{}, e
	}
	if e = s.reviewer(ctx, q, r, user, p); e != nil {
		return r, time.Time{}, e
	}
	parentUntil, e := s.parent(ctx, q, r.OrgID, user, parent, p.RequireMFA)
	if e != nil {
		return r, time.Time{}, apierr.Forbidden("beam_session_invalid", "Beam browser login is no longer valid")
	}
	for _, t := range []time.Time{until, parentUntil} {
		if t.Before(deadline) {
			deadline = t
		}
	}
	return r, capLease(deadline), nil
}
func (s *Service) Authorize(ctx context.Context, b Binding, token string, m Metadata) (decision Decision, err error) {
	defer func() {
		if err != nil {
			s.auditDenied(ctx, b, token)
		}
	}()
	started := time.Now()
	var out Decision
	if !strings.HasPrefix(token, "tnxbs_") || len(token) != 49 {
		return out, apierr.Forbidden("beam_session_invalid", "Beam browser session is invalid")
	}
	if !relative(m.Path) || len(m.Method) > 12 {
		return out, deny()
	}
	if m.Method == "CONNECT" || m.Method == "TRACE" {
		return out, deny()
	}
	unsafe := m.Method != "GET" && m.Method != "HEAD" && m.Method != "OPTIONS"
	if (unsafe || m.Origin != "") && m.Origin != "https://"+b.Hostname {
		return out, deny()
	}
	if m.Referer != "" {
		u, e := url.Parse(m.Referer)
		if e != nil || u.Scheme != "https" || u.Host != b.Hostname || u.User != nil {
			return out, deny()
		}
	}
	tx, e := s.transaction(ctx, b.OrgID)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	_, until, e := s.browser(ctx, tx, b, hash(token))
	if e != nil {
		return out, e
	}
	var count int
	e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_streams WHERE org_id=$1 AND share_id=$2 AND expires_at>now()`, b.OrgID, b.AppID).Scan(&count)
	if e != nil {
		return out, e
	}
	if count >= 32 {
		return out, apierr.New(429, "beam_stream_capacity", "Share stream capacity reached")
	}
	until = capLeaseAt(until, started)
	if !until.After(time.Now()) {
		return out, deny()
	}
	out = Decision{uuid.New(), until}
	_, e = tx.Exec(ctx, `INSERT INTO beam_streams(id,org_id,share_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, out.StreamID, b.OrgID, b.AppID, hash(token), until)
	if e != nil {
		return out, e
	}
	if e = auditAllowed(ctx, tx, b, hash(token)); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	return out, nil
}
func (s *Service) Renew(ctx context.Context, b Binding, id uuid.UUID) (Decision, error) {
	started := time.Now()
	var out Decision
	tx, e := s.transaction(ctx, b.OrgID)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var th []byte
	e = tx.QueryRow(ctx, `SELECT token_hash FROM beam_streams WHERE org_id=$1 AND share_id=$2 AND id=$3 AND expires_at>now() FOR UPDATE`, b.OrgID, b.AppID, id).Scan(&th)
	if e != nil {
		return out, deny()
	}
	_, until, e := s.browser(ctx, tx, b, th)
	if e != nil {
		return out, e
	}
	until = capLeaseAt(until, started)
	if !until.After(time.Now()) {
		return out, deny()
	}
	_, e = tx.Exec(ctx, `UPDATE beam_streams SET expires_at=$4 WHERE org_id=$1 AND share_id=$2 AND id=$3`, b.OrgID, b.AppID, id, until)
	if e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	return Decision{id, until}, nil
}
func (s *Service) Terminated(ctx context.Context, b Binding, id uuid.UUID) error {
	_, e := s.pool.Exec(ctx, `DELETE FROM beam_streams WHERE org_id=$1 AND share_id=$2 AND id=$3`, b.OrgID, b.AppID, id)
	return e
}
func (s *Service) Domains() (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.DomainsContext(ctx)
}

func (s *Service) DomainsContext(ctx context.Context) (string, string, error) {
	r, e := s.installation(ctx, s.pool)
	if e != nil || !s.installationReady(r) {
		return "", "", unavailable()
	}
	return s.config.PortalURL, r.base, nil
}

func (s *Service) NonceHash(nonce string) string { return hex.EncodeToString(hash(nonce)) }
