package serveraccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
)

const sessionColumns = `id,server_id,account,status,reason,expires_at,user_id,recording_enabled,kind,gateway_id,parent_sealed,parent_hash,parent_epoch,grant_id,revision,gateway_serial,idle_deadline,created_at`

type record struct {
	View                     api.ServerAccessSession
	Gateway                  uuid.UUID
	ParentSealed, ParentHash []byte
	Epoch                    int64
	Grant                    *uuid.UUID
	Revision                 int64
	Serial                   string
	Idle, Created            time.Time
}

func scanSession(row interface{ Scan(...any) error }) (record, error) {
	var r record
	e := row.Scan(&r.View.Id, &r.View.ServerId, &r.View.Account, &r.View.Status, &r.View.Reason, &r.View.ExpiresAt, &r.View.UserId, &r.View.RecordingEnabled, &r.View.Kind, &r.Gateway, &r.ParentSealed, &r.ParentHash, &r.Epoch, &r.Grant, &r.Revision, &r.Serial, &r.Idle, &r.Created)
	return r, e
}
func (s *Service) load(ctx context.Context, org, id uuid.UUID) (record, error) {
	r, e := scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM server_access_sessions WHERE org_id=$1 AND id=$2`, org, id))
	if errors.Is(e, pgx.ErrNoRows) {
		e = missing()
	}
	return r, e
}

type parentBinding struct {
	Org, User     uuid.UUID
	Token         string
	AuthorityHash []byte
}

func (s *Service) validate(ctx context.Context, org uuid.UUID, r record) (api.ServerAccessServer, time.Time, error) {
	now := time.Now()
	if e := s.available(); e != nil {
		return api.ServerAccessServer{}, now, e
	}
	if r.View.Status != "pending" && r.View.Status != "connecting" && r.View.Status != "connected" {
		return api.ServerAccessServer{}, now, deny("session_ended")
	}
	if !r.View.ExpiresAt.After(now) || (r.View.Status == "pending" || r.View.Status == "connecting") && r.Created.Add(pendingLifetime(r.View.Kind)).Before(now) {
		return api.ServerAccessServer{}, now, deny("session_expired")
	}
	if !r.Idle.After(now) {
		return api.ServerAccessServer{}, now, deny("idle_timeout")
	}
	enabled, e := s.Enabled(ctx, org)
	if e != nil || !enabled {
		return api.ServerAccessServer{}, now, deny("organization_disabled")
	}
	raw, e := s.sealer.Open(string(r.ParentSealed))
	if e != nil {
		return api.ServerAccessServer{}, now, deny("invalid_parent_binding")
	}
	var bound parentBinding
	if json.Unmarshal(raw, &bound) != nil || bound.Org != org || bound.User != r.View.UserId {
		return api.ServerAccessServer{}, now, deny("invalid_parent_binding")
	}
	hash := sha256.Sum256([]byte(bound.Token))
	if string(hash[:]) != string(r.ParentHash) {
		return api.ServerAccessServer{}, now, deny("invalid_parent_binding")
	}
	parent, until, e := s.parent(ctx, org, r.View.UserId, bound.Token)
	if e != nil {
		return api.ServerAccessServer{}, now, e
	}
	if parent.AppAuthEpoch != r.Epoch {
		return api.ServerAccessServer{}, now, deny("parent_authority_changed")
	}
	server, e := s.Server(ctx, org, r.View.ServerId)
	if e != nil {
		return server, now, e
	}
	if subtle.ConstantTimeCompare(bound.AuthorityHash, serverAuthorityHash(server)) != 1 || server.GatewayId != r.Gateway || !contains(server.Accounts, r.View.Account) {
		return server, now, deny("server_authority_changed")
	}
	var live bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE org_id=$1 AND id=$2 AND cert_serial=$3 AND status='active' AND enrolled_kind='gateway' AND last_seen_at>now()-interval '90 seconds' AND cert_not_after>now())`, org, r.Gateway, r.Serial).Scan(&live)
	if e != nil || !live {
		return server, now, deny("gateway_authority_changed")
	}
	if r.View.Kind == "terminal" || r.View.Kind == "editor" {
		if r.View.Kind == "editor" && (serverOS(server) != "linux" || !developerEnabled(server) || r.View.RecordingEnabled) {
			return server, now, deny("developer_access_disabled")
		}
		if !server.Enabled {
			return server, now, deny("server_disabled")
		}

		if r.Grant == nil {
			return server, now, deny("account_not_granted")
		}
		var permitted bool
		e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM server_access_grants g WHERE org_id=$1 AND id=$2 AND server_id=$3 AND account=$4 AND enabled AND starts_at<=now() AND expires_at>now() AND (user_id=$5 OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.org_id=g.org_id AND gm.group_id=g.group_id AND gm.user_id=$5)))`, org, *r.Grant, server.Id, r.View.Account, r.View.UserId).Scan(&permitted)
		if e != nil {
			return server, now, e
		}
		if !permitted {
			return server, now, deny("grant_revoked")
		}
		until = minTime(until, r.View.ExpiresAt)
	} else {
		var roles []string
		e = s.pool.QueryRow(ctx, `SELECT roles FROM memberships WHERE org_id=$1 AND user_id=$2 AND access_revoked_at IS NULL`, org, r.View.UserId).Scan(&roles)
		if e != nil || !rbac.CanAny(roles, rbac.PermServerAccessManage) {
			return server, now, deny("management_authority_changed")
		}
	}
	return server, minTime(now.Add(4*time.Second), until, r.View.ExpiresAt), nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func (s *Service) StartSession(ctx context.Context, org uuid.UUID, p *authctx.Principal, in api.ServerAccessConnectInput, check bool) (api.ServerAccessSession, error) {
	return s.startSession(ctx, org, p, in, check, false)
}
func (s *Service) startSession(ctx context.Context, org uuid.UUID, p *authctx.Principal, in api.ServerAccessConnectInput, check, editor bool) (api.ServerAccessSession, error) {
	if e := s.available(); e != nil {
		return api.ServerAccessSession{}, e
	}
	parent, until, e := s.parent(ctx, org, p.UserID, p.SessionID)
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	server, e := s.Server(ctx, org, in.ServerId)
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	if !contains(server.Accounts, in.Account) {
		return api.ServerAccessSession{}, deny("account_not_allowed")
	}
	enabled, e := s.Enabled(ctx, org)
	if e != nil || !enabled {
		return api.ServerAccessSession{}, deny("organization_disabled")
	}
	if editor && (check || serverOS(server) != "linux" || !developerEnabled(server)) {
		return api.ServerAccessSession{}, deny("developer_access_disabled")
	}
	recording := server.RecordingEnabled && !editor
	var grant *uuid.UUID
	kind := "terminal"
	if editor {
		kind = "editor"
	}
	if check {
		kind = "check"
		if !rbac.CanAny(p.RolesIn(org), rbac.PermServerAccessManage) {
			return api.ServerAccessSession{}, deny("management_required")
		}
		until = minTime(until, time.Now().Add(20*time.Second))
	} else {
		if !server.Enabled {
			return api.ServerAccessSession{}, deny("server_disabled")
		}

		if !contains(server.ReadyAccounts, in.Account) {
			return api.ServerAccessSession{}, deny("connection_check_required")
		}
		g, e := s.effectiveGrant(ctx, org, server.Id, p.UserID, in.Account)
		if e != nil {
			return api.ServerAccessSession{}, e
		}
		grant = &g.Id
		until = minTime(until, g.ExpiresAt, time.Now().Add(time.Duration(server.MaxSessionSeconds)*time.Second))
	}
	var serial string
	e = s.pool.QueryRow(ctx, `SELECT n.cert_serial FROM nodes n JOIN server_access_gateway_runtime rt ON rt.org_id=n.org_id AND rt.gateway_id=n.id AND rt.cert_serial=n.cert_serial WHERE n.org_id=$1 AND n.id=$2 AND n.status='active' AND n.enrolled_kind='gateway' AND n.cert_not_after>now() AND n.last_seen_at>now()-interval '90 seconds' AND rt.observed_at>now()-interval '10 seconds' AND rt.protocol_version=1 AND (NOT $3::boolean OR rt.editor_protocol_version=1)`, org, server.GatewayId, editor).Scan(&serial)
	if e != nil {
		return api.ServerAccessSession{}, deny("gateway_terminal_unavailable")
	}
	bound, e := json.Marshal(parentBinding{org, p.UserID, p.SessionID, serverAuthorityHash(server)})
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	sealed, e := s.sealer.Seal(bound)
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	hash := sha256.Sum256([]byte(p.SessionID))
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_admission'))`); e != nil {
		return api.ServerAccessSession{}, e
	}
	var locked uuid.UUID
	if e = tx.QueryRow(ctx, `SELECT id FROM server_access_servers WHERE org_id=$1 AND id=$2 AND removed_at IS NULL FOR SHARE`, org, server.Id).Scan(&locked); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return api.ServerAccessSession{}, missing()
		}
		return api.ServerAccessSession{}, e
	}
	var global, user, gateway int
	e = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE user_id=$1),count(*) FILTER(WHERE gateway_id=$2) FROM server_access_sessions WHERE status IN ('pending','connecting','connected') AND expires_at>now()`, p.UserID, server.GatewayId).Scan(&global, &user, &gateway)
	if e != nil {
		return api.ServerAccessSession{}, e
	}
	if global >= 128 || user >= 4 || gateway >= 16 {
		return api.ServerAccessSession{}, deny("terminal_capacity_reached")
	}
	r, e := scanSession(tx.QueryRow(ctx, `INSERT INTO server_access_sessions(org_id,server_id,gateway_id,user_id,parent_sealed,parent_hash,parent_epoch,grant_id,account,revision,gateway_serial,kind,expires_at,idle_deadline,recording_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING `+sessionColumns, org, server.Id, server.GatewayId, p.UserID, []byte(sealed), hash[:], parent.AppAuthEpoch, grant, in.Account, server.Revision, serial, kind, until, minTime(until, time.Now().Add(time.Duration(server.IdleTimeoutSeconds)*time.Second)), recording))
	if e != nil {
		return r.View, e
	}
	if !check && r.View.RecordingEnabled {
		if e = s.prepareRecording(ctx, tx, org, r.View.Id); e != nil {
			return r.View, e
		}
	}
	if e = s.audit(ctx, tx, org, p.UserID, "session_requested", r.View.Id, map[string]any{"server_id": server.Id, "account": in.Account, "kind": kind, "recording_enabled": recording, "gateway_id": server.GatewayId, "grant_id": grant, "revision": server.Revision}); e != nil {
		return r.View, e
	}
	return r.View, tx.Commit(ctx)
}
func (s *Service) Desired(ctx context.Context, org, gateway uuid.UUID, serial string, editor bool) ([]terminalwire.Assignment, error) {
	if e := s.available(); e != nil {
		return nil, e
	}
	_, e := s.pool.Exec(ctx, `INSERT INTO server_access_gateway_runtime(org_id,gateway_id,cert_serial,protocol_version,observed_at,editor_protocol_version) VALUES($1,$2,$3,1,now(),$4) ON CONFLICT(org_id,gateway_id) DO UPDATE SET cert_serial=EXCLUDED.cert_serial,protocol_version=1,observed_at=now(),editor_protocol_version=EXCLUDED.editor_protocol_version`, org, gateway, serial, editorVersion(editor))
	if e != nil {
		return nil, e
	}
	rows, e := s.pool.Query(ctx, `SELECT id,kind FROM server_access_sessions WHERE org_id=$1 AND gateway_id=$2 AND gateway_serial=$3 AND expires_at>now() AND (kind='check' AND status='pending' OR kind IN ('terminal','editor') AND status='connecting' AND browser_claimed_at IS NOT NULL) AND (kind<>'editor' OR $4::boolean) ORDER BY created_at LIMIT 16`, org, gateway, serial, editor)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []terminalwire.Assignment{}
	for rows.Next() {
		var a terminalwire.Assignment
		if e = rows.Scan(&a.ID, &a.Kind); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Service) Material(ctx context.Context, org, gateway, id uuid.UUID, serial, public string) (terminalwire.Material, error) {
	r, e := s.load(ctx, org, id)
	if e != nil {
		return terminalwire.Material{}, e
	}
	if r.Gateway != gateway || r.Serial != serial {
		return terminalwire.Material{}, deny("gateway_binding_mismatch")
	}
	server, until, e := s.validate(ctx, org, r)
	if e != nil {
		return terminalwire.Material{}, e
	}
	if (r.View.Kind == "terminal" || r.View.Kind == "editor") && r.View.Status != "connecting" {
		return terminalwire.Material{}, deny("channel_already_claimed")
	}

	if len(public) > 4096 {
		return terminalwire.Material{}, bad()
	}
	key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(public))
	if e != nil || len(options) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return terminalwire.Material{}, bad()
	}
	hash := sha256.Sum256(key.Marshal())
	tag, e := s.pool.Exec(ctx, `UPDATE server_access_sessions SET public_key_hash=$3 WHERE org_id=$1 AND id=$2 AND (public_key_hash IS NULL OR public_key_hash=$3) AND status IN ('pending','connecting')`, org, id, hash[:])
	if e != nil {
		return terminalwire.Material{}, e
	}
	if tag.RowsAffected() != 1 {
		return terminalwire.Material{}, deny("session_key_changed")
	}
	// Bind the gateway channel claim for both SSH and RDP before returning material.
	if serverOS(server) == "windows" {
		return terminalwire.Material{ClipboardPolicy: serverClipboardPolicy(server), OS: "windows", Domain: domainValue(server.RdpDomain), SessionID: id.String(), IP: *server.PrivateIp, Port: *server.SshPort, Account: r.View.Account, Fingerprint: *server.HostFingerprint, ExpiresAt: r.View.ExpiresAt, LeaseUntil: until, Kind: r.View.Kind}, nil
	}
	ca, e := s.signer(ctx, org)
	if e != nil {
		return terminalwire.Material{}, e
	}
	serialHash := sha256.Sum256([]byte(id.String()))
	cert := &ssh.Certificate{Key: key, Serial: binary.BigEndian.Uint64(serialHash[:8]), CertType: ssh.UserCert, KeyId: org.String() + "/" + r.View.UserId.String() + "/" + id.String(), ValidPrincipals: []string{"tunnex:" + org.String() + ":" + server.Id.String() + ":" + r.View.Account}, ValidAfter: uint64(time.Now().Add(-10 * time.Second).Unix()), ValidBefore: uint64(minTime(r.View.ExpiresAt, time.Now().Add(5*time.Minute)).Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
	if e = cert.SignCert(rand.Reader, ca); e != nil {
		return terminalwire.Material{}, e
	}
	material := terminalwire.Material{SessionID: id.String(), IP: *server.PrivateIp, Port: *server.SshPort, Account: r.View.Account, Fingerprint: *server.HostFingerprint, Certificate: string(ssh.MarshalAuthorizedKey(cert)), ExpiresAt: r.View.ExpiresAt, LeaseUntil: until, Kind: r.View.Kind}
	if r.View.Kind == "editor" {
		if e = s.editorMaterial(ctx, org, id, &material); e != nil {
			return terminalwire.Material{}, e
		}
	}
	return material, nil
}
func (s *Service) Lease(ctx context.Context, org, gateway, id uuid.UUID, serial string) (terminalwire.Lease, error) {
	r, e := s.load(ctx, org, id)
	if e != nil {
		return terminalwire.Lease{}, e
	}
	if r.Gateway != gateway || r.Serial != serial {
		return terminalwire.Lease{}, deny("gateway_binding_mismatch")
	}
	_, until, e := s.validate(ctx, org, r)
	return terminalwire.Lease{Until: until}, e
}
func (s *Service) Complete(ctx context.Context, org, gateway, id uuid.UUID, serial, result string) error {
	r, e := s.load(ctx, org, id)
	if e != nil {
		return e
	}
	if r.Gateway != gateway || r.Serial != serial {
		return deny("gateway_binding_mismatch")
	}
	if r.View.Kind != "check" {
		reason := "gateway_closed"
		if specific, valid := terminalwire.ResultReason(result); valid && specific != "" && result != "failed" {
			reason = specific
		}
		if _, _, err := s.validate(ctx, org, r); err != nil {
			reason = authorityReason(err)
		}
		return s.end(ctx, org, id, r.View.UserId, reason)
	}
	_, _, e = s.validate(ctx, org, r)
	if e != nil {
		return e
	}
	reason, valid := terminalwire.ResultReason(result)
	if !valid {
		return bad()
	}
	status := "failed"
	if result == "ok" {
		status = "passed"
		reason = ""
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE server_access_sessions SET status=$3,reason=$4,ended_at=now() WHERE org_id=$1 AND id=$2 AND status='pending' AND kind='check'`, org, id, status, reason)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return deny("check_already_completed")
	}
	if status == "passed" {
		_, e = tx.Exec(ctx, `UPDATE server_access_servers SET ready_accounts=ARRAY(SELECT DISTINCT unnest(ready_accounts||ARRAY[$3::text])),last_error='',checked_at=now() WHERE org_id=$1 AND id=$2 AND revision=$4`, org, r.View.ServerId, r.View.Account, r.Revision)
	} else {
		_, e = tx.Exec(ctx, `UPDATE server_access_servers SET ready_accounts=array_remove(ready_accounts,$3),last_error=$4,checked_at=now() WHERE org_id=$1 AND id=$2 AND revision=$5`, org, r.View.ServerId, r.View.Account, reason, r.Revision)
	}
	if e != nil {
		return e
	}
	if e = s.audit(ctx, tx, org, r.View.UserId, "connection_checked", id, map[string]any{"server_id": r.View.ServerId, "account": r.View.Account, "status": status}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Service) End(ctx context.Context, org, id uuid.UUID, p *authctx.Principal) error {
	r, e := s.load(ctx, org, id)
	if e != nil {
		return e
	}
	if r.View.UserId != p.UserID && !rbac.CanAny(p.RolesIn(org), rbac.PermServerAccessSessionManage) {
		return deny("session_permission_denied")
	}
	return s.end(ctx, org, id, p.UserID, "revoked")
}
func (s *Service) end(ctx context.Context, org, id, actor uuid.UUID, reason string) error {
	if reason == "gateway_closed" || reason == "terminal_closed" {
		s.mu.Lock()
		live := s.live[id]
		s.mu.Unlock()
		if live != nil {
			if precise := live.reason.Load(); precise != nil {
				reason = *precise
			}
		}
	}

	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var account string
	var server, gateway, owner uuid.UUID
	var grant *uuid.UUID
	var revision int64
	e = tx.QueryRow(ctx, `UPDATE server_access_sessions SET status='ended',reason=$3,ended_at=now() WHERE org_id=$1 AND id=$2 AND status IN ('pending','connecting','connected') RETURNING account,server_id,gateway_id,user_id,grant_id,revision`, org, id, reason).Scan(&account, &server, &gateway, &owner, &grant, &revision)
	if errors.Is(e, pgx.ErrNoRows) {
		s.closeLive(id)
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET status=CASE WHEN $3 IN ('recording_failed','recording_quota_reached','control_plane_restarted') THEN 'incomplete' WHEN next_seq=0 THEN 'failed' ELSE 'available' END WHERE org_id=$1 AND session_id=$2 AND status='capturing'`, org, id, reason); e != nil {
		return e
	}
	if e = s.audit(ctx, tx, org, actor, "session_ended", id, map[string]any{"server_id": server, "account": account, "reason": reason, "gateway_id": gateway, "owner_user_id": owner, "grant_id": grant, "revision": revision}); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	s.closeLive(id)
	return nil
}
func (s *Service) closeLive(id uuid.UUID) {
	s.mu.Lock()
	l := s.live[id]
	delete(s.live, id)
	s.mu.Unlock()
	if l != nil {
		l.close()
	}
}
func (s *Service) Boot(ctx context.Context) error {
	if !s.enabled {
		return nil
	}
	rows, e := s.pool.Query(ctx, `SELECT org_id,id,user_id FROM server_access_sessions WHERE status IN ('pending','connecting','connected')`)
	if e != nil {
		return e
	}
	type ids struct{ o, id, u uuid.UUID }
	list := []ids{}
	for rows.Next() {
		var i ids
		if e = rows.Scan(&i.o, &i.id, &i.u); e != nil {
			rows.Close()
			return e
		}
		list = append(list, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, i := range list {
		if e = s.end(ctx, i.o, i.id, i.u, "control_plane_restarted"); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Attach(ctx context.Context, org, gateway, id uuid.UUID, serial string, conn net.Conn) error {
	r, e := s.load(ctx, org, id)
	if e != nil {
		return e
	}
	if r.Gateway != gateway || r.Serial != serial || (r.View.Kind != "terminal" && r.View.Kind != "editor") {
		return deny("gateway_binding_mismatch")
	}
	_, _, e = s.validate(ctx, org, r)
	if e != nil {
		return e
	}
	s.mu.Lock()
	l := s.live[id]
	if l == nil {
		s.mu.Unlock()
		return deny("browser_channel_missing")
	}
	s.mu.Unlock()
	l.mu.Lock()
	if l.gateway != nil {
		l.mu.Unlock()
		return deny("channel_already_claimed")
	}
	select {
	case <-l.done:
		l.mu.Unlock()
		return deny("session_ended")
	default:
	}
	l.gateway = conn
	l.mu.Unlock()
	attached := false
	defer func() {
		if !attached {
			s.closeLive(id)
		}
	}()
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE server_access_sessions SET status='connected' WHERE org_id=$1 AND id=$2 AND status='connecting' AND public_key_hash IS NOT NULL`, org, id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return deny("channel_already_claimed")
	}
	if e = s.audit(ctx, tx, org, r.View.UserId, "session_started", id, map[string]any{"server_id": r.View.ServerId, "account": r.View.Account, "gateway_id": gateway, "recording_enabled": r.View.RecordingEnabled, "kind": r.View.Kind, "grant_id": r.Grant, "revision": r.Revision}); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	close(l.attached)
	attached = true
	return nil
}

func (s *Service) WaitChannel(id uuid.UUID) {
	s.mu.Lock()
	l := s.live[id]
	s.mu.Unlock()
	if l != nil {
		<-l.done
	}
}

func pendingLifetime(kind string) time.Duration {
	if kind == "editor" {
		return 120 * time.Second
	}
	return 30 * time.Second
}

func editorVersion(enabled bool) int {
	if enabled {
		return 1
	}
	return 0
}
