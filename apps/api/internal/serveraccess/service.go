// Package serveraccess owns tenant-scoped browser SSH authority. Installation
// opt-in is explicit and default-off; no VPN/App Access permission grants a shell.
package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport/rdpwire"
	"golang.org/x/crypto/ssh"
)

type Service struct {
	pool    *pgxpool.Pool
	parents *session.Store
	sealer  *secret.Sealer
	enabled bool
	mu      sync.Mutex
	live    map[uuid.UUID]*liveSession
}

func New(pool *pgxpool.Pool, parents *session.Store, sealer *secret.Sealer, enabled bool) *Service {
	return &Service{pool: pool, parents: parents, sealer: sealer, enabled: enabled, live: map[uuid.UUID]*liveSession{}}
}
func deny(reason string) error {
	return apierr.Forbidden(reason, "Terminal access is unavailable: "+reason)
}
func bad() error {
	return apierr.BadRequest("invalid_server_access", "Invalid server, account or grant configuration")
}
func missing() error {
	return apierr.NotFound("server_access_not_found", "Server access record not found")
}
func (s *Service) available() error {
	if !s.enabled {
		return apierr.New(503, "server_access_disabled", "Terminal capability is disabled on this installation")
	}
	return nil
}
func (s *Service) audit(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, action string, id uuid.UUID, meta any) error {
	b, e := json.Marshal(meta)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'server_access',$4,$5)`, org, actor, "server_access."+action, id.String(), b)
	return e
}
func (s *Service) Enabled(ctx context.Context, org uuid.UUID) (bool, error) {
	if !s.enabled {
		return false, nil
	}
	var enabled bool
	e := s.pool.QueryRow(ctx, `SELECT enabled FROM server_access_settings WHERE org_id=$1`, org).Scan(&enabled)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	return enabled, e
}
func (s *Service) SetEnabled(ctx context.Context, org, actor uuid.UUID, enabled bool) error {
	return s.Configure(ctx, org, actor, api.ServerAccessSettingsInput{Enabled: enabled})
}
func (s *Service) Configure(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessSettingsInput) error {
	enabled := in.Enabled
	if in.MfaFreshnessSeconds != nil && (*in.MfaFreshnessSeconds < 60 || *in.MfaFreshnessSeconds > 900) {
		return bad()
	}
	if in.RecordingRetentionDays != nil && (*in.RecordingRetentionDays < 1 || *in.RecordingRetentionDays > 3650) || in.RecordingMaxSessionBytes != nil && (*in.RecordingMaxSessionBytes < 65536 || *in.RecordingMaxSessionBytes > 16777216) || in.RecordingMaxOrgBytes != nil && (*in.RecordingMaxOrgBytes < 65536 || *in.RecordingMaxOrgBytes > 1073741824) {
		return bad()
	}
	if e := s.available(); e != nil {
		return e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	encoded, e := json.Marshal(struct {
		Org uuid.UUID `json:"org"`
		Key []byte    `json:"key"`
	}{org, key})
	if e != nil {
		return e
	}
	sealed, e := s.sealer.Seal(encoded)
	if e != nil {
		return e
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_config'),hashtext($1))`, org.String()); e != nil {
		return e
	}
	days, sessionBytes, orgBytes, freshness := 30, 4194304, 67108864, 900
	e = tx.QueryRow(ctx, `SELECT recording_retention_days,recording_max_session_bytes,recording_max_org_bytes,mfa_freshness_seconds FROM server_access_settings WHERE org_id=$1 FOR UPDATE`, org).Scan(&days, &sessionBytes, &orgBytes, &freshness)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if in.RecordingRetentionDays != nil {
		days = *in.RecordingRetentionDays
	}
	if in.RecordingMaxSessionBytes != nil {
		sessionBytes = *in.RecordingMaxSessionBytes
	}
	if in.RecordingMaxOrgBytes != nil {
		orgBytes = *in.RecordingMaxOrgBytes
	}
	if in.MfaFreshnessSeconds != nil {
		freshness = *in.MfaFreshnessSeconds
	}
	if orgBytes < sessionBytes {
		return bad()
	}
	_, e = tx.Exec(ctx, `INSERT INTO server_access_settings(org_id,enabled,ca_private_sealed,ca_public,recording_retention_days,recording_max_session_bytes,recording_max_org_bytes,mfa_freshness_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(org_id) DO UPDATE SET enabled=EXCLUDED.enabled,recording_retention_days=EXCLUDED.recording_retention_days,recording_max_session_bytes=EXCLUDED.recording_max_session_bytes,recording_max_org_bytes=EXCLUDED.recording_max_org_bytes,mfa_freshness_seconds=EXCLUDED.mfa_freshness_seconds,updated_at=now()`, org, enabled, []byte(sealed), string(ssh.MarshalAuthorizedKey(signer.PublicKey())), days, sessionBytes, orgBytes, freshness)
	if e != nil {
		return e
	}
	if e = s.audit(ctx, tx, org, actor, "settings_updated", org, map[string]any{"enabled": enabled, "recording_retention_days": days, "recording_max_session_bytes": sessionBytes, "recording_max_org_bytes": orgBytes, "mfa_freshness_seconds": freshness}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Service) signer(ctx context.Context, org uuid.UUID) (ssh.Signer, error) {
	var sealed []byte
	var public string
	var enabled bool
	e := s.pool.QueryRow(ctx, `SELECT enabled,ca_private_sealed,ca_public FROM server_access_settings WHERE org_id=$1`, org).Scan(&enabled, &sealed, &public)
	if e != nil || !enabled {
		return nil, deny("organization_disabled")
	}
	raw, e := s.sealer.Open(string(sealed))
	if e != nil {
		return nil, e
	}
	var bound struct {
		Org uuid.UUID `json:"org"`
		Key []byte    `json:"key"`
	}
	if json.Unmarshal(raw, &bound) != nil || bound.Org != org || len(bound.Key) != ed25519.PrivateKeySize {
		return nil, deny("invalid_ca_binding")
	}
	signer, e := ssh.NewSignerFromKey(ed25519.PrivateKey(bound.Key))
	if e != nil {
		return nil, e
	}
	if string(ssh.MarshalAuthorizedKey(signer.PublicKey())) != public {
		return nil, deny("invalid_ca_binding")
	}
	return signer, nil
}
func (s *Service) Trust(ctx context.Context, org uuid.UUID) (api.ServerAccessTrust, error) {
	if e := s.available(); e != nil {
		return api.ServerAccessTrust{}, e
	}
	signer, e := s.signer(ctx, org)
	if e != nil {
		return api.ServerAccessTrust{}, e
	}
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	return api.ServerAccessTrust{CaFingerprint: &fingerprint, PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), PrincipalPrefix: "tunnex:" + org.String() + ":", Instructions: []string{"Install this public key in a root-owned TrustedUserCAKeys file on each registered server.", "For each existing Linux account, set a root-owned AuthorizedPrincipalsFile entry: tunnex:<organization UUID>:<server UUID>:<Linux account>.", "Do not reuse a server UUID/principal on another host. Verify SSH host fingerprints independently before registration.", "Validate sshd configuration before applying it; existing Linux permissions and sudo policy remain unchanged."}}, nil
}

func serverOS(v api.ServerAccessServer) string {
	if v.Os != nil && string(*v.Os) == "windows" {
		return "windows"
	}
	return "linux"
}
func inputOS(v api.ServerAccessServerInput) string {
	if v.Os != nil {
		return string(*v.Os)
	}
	return "linux"
}

func inputClipboardPolicy(v api.ServerAccessServerInput) string {
	if v.ClipboardPolicy == nil {
		return "off"
	}
	return string(*v.ClipboardPolicy)
}
func serverClipboardPolicy(v api.ServerAccessServer) string {
	if v.ClipboardPolicy == nil {
		return "off"
	}
	return string(*v.ClipboardPolicy)
}
func authorityClipboardPolicy(v api.ServerAccessServer) string {
	p := serverClipboardPolicy(v)
	if p == "off" {
		return ""
	}
	return p
}

var windowsAccountPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@\\-]{0,31}$`)
var accountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func ValidateServer(in api.ServerAccessServerInput) error {
	os := inputOS(in)
	policy := inputClipboardPolicy(in)
	if !rdpwire.ValidClipboardPolicy(policy) || (os != "windows" && policy != "off") {
		return bad()
	}
	if os != "linux" && os != "windows" || os != "linux" && in.DeveloperAccessEnabled != nil && *in.DeveloperAccessEnabled {
		return bad()
	}
	if os == "windows" && (in.RecordingEnabled || len(in.Accounts) == 0) {
		return bad()
	}
	if in.RdpDomain != nil && (len(*in.RdpDomain) > 100 || strings.ContainsAny(*in.RdpDomain, "\r\n\x00")) {
		return bad()
	}
	fingerprint, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(in.HostFingerprint, "SHA256:"))
	if err != nil || len(fingerprint) != 32 {
		return bad()
	}
	ip, e := netip.ParseAddr(in.PrivateIp)
	if e != nil || !ip.IsPrivate() || ip.Zone() != "" || ip.IsLoopback() || ip.IsLinkLocalUnicast() || in.GatewayId == uuid.Nil || strings.TrimSpace(in.Name) == "" || len(in.Name) > 100 || in.SshPort < 1 || in.SshPort > 65535 || !strings.HasPrefix(in.HostFingerprint, "SHA256:") || len(in.HostFingerprint) != 50 || (len(in.Accounts) == 0 && (in.Enabled || in.SshPort < 1024 || in.HostFingerprint != "SHA256:"+strings.Repeat("A", 43))) || len(in.Accounts) > 16 || in.IdleTimeoutSeconds < 60 || in.IdleTimeoutSeconds > 900 || in.MaxSessionSeconds < 60 || in.MaxSessionSeconds > 3600 || in.IdleTimeoutSeconds > in.MaxSessionSeconds {
		return bad()
	}
	seen := map[string]bool{}
	for _, a := range in.Accounts {
		if (os == "linux" && (!accountPattern.MatchString(a) || a == "root")) || (os == "windows" && !windowsAccountPattern.MatchString(a)) || seen[a] {
			return bad()
		}
		seen[a] = true
	}
	return nil
}

const serverColumns = `id,gateway_id,name,host(private_ip),ssh_port,host_fingerprint,accounts,revision,enabled,recording_enabled,idle_timeout_seconds,max_session_seconds,ready_accounts,last_error,os,rdp_domain,clipboard_policy,developer_access_enabled`

func scanServer(row interface{ Scan(...any) error }) (api.ServerAccessServer, error) {
	var v api.ServerAccessServer
	var ip, fp, last string
	var port int
	e := row.Scan(&v.Id, &v.GatewayId, &v.Name, &ip, &port, &fp, &v.Accounts, &v.Revision, &v.Enabled, &v.RecordingEnabled, &v.IdleTimeoutSeconds, &v.MaxSessionSeconds, &v.ReadyAccounts, &last, &v.Os, &v.RdpDomain, &v.ClipboardPolicy, &v.DeveloperAccessEnabled)
	v.PrivateIp = &ip
	v.SshPort = &port
	v.HostFingerprint = &fp
	v.LastError = &last
	return v, e
}
func (s *Service) Server(ctx context.Context, org, id uuid.UUID) (api.ServerAccessServer, error) {
	v, e := scanServer(s.pool.QueryRow(ctx, `SELECT `+serverColumns+` FROM server_access_servers WHERE org_id=$1 AND id=$2 AND removed_at IS NULL`, org, id))
	if errors.Is(e, pgx.ErrNoRows) {
		e = missing()
	}
	return v, e
}
func (s *Service) SaveServer(ctx context.Context, org, actor, id uuid.UUID, in api.ServerAccessServerInput) (api.ServerAccessServer, error) {
	if e := s.available(); e != nil {
		return api.ServerAccessServer{}, e
	}
	if e := ValidateServer(in); e != nil {
		return api.ServerAccessServer{}, e
	}
	enabled, e := s.Enabled(ctx, org)
	if e != nil || !enabled {
		return api.ServerAccessServer{}, deny("organization_disabled")
	}
	var gatewayOK bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE org_id=$1 AND id=$2 AND status='active' AND enrolled_kind='gateway' AND cert_not_after>now() AND last_seen_at>now()-interval '90 seconds')`, org, in.GatewayId).Scan(&gatewayOK)
	if e != nil {
		return api.ServerAccessServer{}, e
	}
	if !gatewayOK {
		return api.ServerAccessServer{}, deny("gateway_unavailable")
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessServer{}, e
	}
	defer tx.Rollback(ctx)
	var row pgx.Row
	action := "server_updated"
	if id == uuid.Nil {
		action = "server_created"
		row = tx.QueryRow(ctx, `INSERT INTO server_access_servers(org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled,recording_enabled,idle_timeout_seconds,max_session_seconds,os,rdp_domain,clipboard_policy,developer_access_enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING `+serverColumns, org, in.GatewayId, strings.TrimSpace(in.Name), in.PrivateIp, in.SshPort, in.HostFingerprint, in.Accounts, in.Enabled, in.RecordingEnabled, in.IdleTimeoutSeconds, in.MaxSessionSeconds, inputOS(in), domainValue(in.RdpDomain), inputClipboardPolicy(in), developerInput(in))
	} else {
		row = tx.QueryRow(ctx, `UPDATE server_access_servers SET gateway_id=$3,name=$4,private_ip=$5,ssh_port=$6,host_fingerprint=$7,accounts=$8,enabled=$9,recording_enabled=$10,idle_timeout_seconds=$11,max_session_seconds=$12,os=$14,rdp_domain=$15,clipboard_policy=$16,developer_access_enabled=$17,revision=revision+1,ready_accounts=CASE WHEN (gateway_id,private_ip,ssh_port,host_fingerprint,accounts,idle_timeout_seconds,max_session_seconds,os,rdp_domain) IS DISTINCT FROM ($3::uuid,$5::inet,$6::int,$7::text,$8::text[],$11::int,$12::int,$14::text,$15::text) THEN '{}'::text[] ELSE ready_accounts END,checked_at=CASE WHEN (gateway_id,private_ip,ssh_port,host_fingerprint,accounts,idle_timeout_seconds,max_session_seconds,os,rdp_domain) IS DISTINCT FROM ($3::uuid,$5::inet,$6::int,$7::text,$8::text[],$11::int,$12::int,$14::text,$15::text) THEN NULL ELSE checked_at END,updated_at=now() WHERE org_id=$1 AND id=$2 AND revision=$13 AND removed_at IS NULL RETURNING `+serverColumns, org, id, in.GatewayId, strings.TrimSpace(in.Name), in.PrivateIp, in.SshPort, in.HostFingerprint, in.Accounts, in.Enabled, in.RecordingEnabled, in.IdleTimeoutSeconds, in.MaxSessionSeconds, in.Revision, inputOS(in), domainValue(in.RdpDomain), inputClipboardPolicy(in), developerInput(in))
	}
	out, e := scanServer(row)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, apierr.Conflict("server_revision_changed", "Reload the server before editing")
	}
	if e != nil {
		return out, e
	}
	if e = s.audit(ctx, tx, org, actor, action, out.Id, map[string]any{"revision": out.Revision, "recording_enabled": in.RecordingEnabled, "clipboard_policy": inputClipboardPolicy(in), "developer_access_enabled": developerInput(in)}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

// RemoveServer retires an identity without deleting historical evidence.
func (s *Service) RemoveServer(ctx context.Context, org, actor, id uuid.UUID) error {
	if e := s.available(); e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var removed bool
	e = tx.QueryRow(ctx, `SELECT removed_at IS NOT NULL FROM server_access_servers WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&removed)
	if errors.Is(e, pgx.ErrNoRows) {
		return missing()
	}
	if e != nil {
		return e
	}

	if removed {
		return tx.Commit(ctx)
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_servers SET removed_at=now(),enabled=false,ready_accounts='{}',checked_at=NULL,revision=revision+1,updated_at=now() WHERE org_id=$1 AND id=$2`, org, id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_grants SET enabled=false WHERE org_id=$1 AND server_id=$2`, org, id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_recordings SET status=CASE WHEN next_seq=0 THEN 'failed' ELSE 'incomplete' END WHERE org_id=$1 AND session_id IN (SELECT id FROM server_access_sessions WHERE org_id=$1 AND server_id=$2) AND status='capturing'`, org, id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE server_access_sessions SET status='ended',reason='server_removed',ended_at=now() WHERE org_id=$1 AND server_id=$2 AND status IN ('pending','connecting','connected')`, org, id); e != nil {
		return e
	}
	if e = s.audit(ctx, tx, org, actor, "server_removed", id, map[string]string{"status": "removed"}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

const grantColumns = `id,server_id,account,user_id,group_id,starts_at,expires_at,enabled`

func scanGrant(row interface{ Scan(...any) error }) (api.ServerAccessGrant, error) {
	var v api.ServerAccessGrant
	e := row.Scan(&v.Id, &v.ServerId, &v.Account, &v.UserId, &v.GroupId, &v.StartsAt, &v.ExpiresAt, &v.Enabled)
	return v, e
}
func (s *Service) Grant(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessGrantInput) (api.ServerAccessGrant, error) {
	if e := s.available(); e != nil {
		return api.ServerAccessGrant{}, e
	}
	if (in.UserId == nil) == (in.GroupId == nil) || !in.ExpiresAt.After(in.StartsAt) || in.ExpiresAt.Sub(in.StartsAt) > 7*24*time.Hour || !in.ExpiresAt.After(time.Now()) {
		return api.ServerAccessGrant{}, bad()
	}
	server, e := s.Server(ctx, org, in.ServerId)
	if e != nil {
		return api.ServerAccessGrant{}, e
	}
	if !slices.Contains(server.Accounts, in.Account) {
		return api.ServerAccessGrant{}, bad()
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessGrant{}, e
	}
	defer tx.Rollback(ctx)
	var locked uuid.UUID
	if e = tx.QueryRow(ctx, `SELECT id FROM server_access_servers WHERE org_id=$1 AND id=$2 AND removed_at IS NULL FOR SHARE`, org, in.ServerId).Scan(&locked); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return api.ServerAccessGrant{}, missing()
		}
		return api.ServerAccessGrant{}, e
	}
	out, e := scanGrant(tx.QueryRow(ctx, `INSERT INTO server_access_grants(org_id,server_id,account,user_id,group_id,starts_at,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+grantColumns, org, in.ServerId, in.Account, in.UserId, in.GroupId, in.StartsAt, in.ExpiresAt, actor))
	if e != nil {
		return out, bad()
	}
	if e = s.audit(ctx, tx, org, actor, "grant_created", out.Id, map[string]any{"server_id": in.ServerId, "account": in.Account}); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Service) RevokeGrant(ctx context.Context, org, actor, id uuid.UUID) error {
	if e := s.available(); e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE server_access_grants SET enabled=false WHERE org_id=$1 AND id=$2`, org, id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return missing()
	}
	if e = s.audit(ctx, tx, org, actor, "grant_revoked", id, map[string]string{"status": "revoked"}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

const effectiveGrantSQL = `SELECT ` + grantColumns + ` FROM server_access_grants g WHERE g.org_id=$1 AND g.server_id=$2 AND g.account=$3 AND g.enabled AND g.starts_at<=now() AND g.expires_at>now() AND (g.user_id=$4 OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.org_id=g.org_id AND gm.group_id=g.group_id AND gm.user_id=$4)) ORDER BY g.expires_at DESC,g.id LIMIT 1`

func (s *Service) effectiveGrant(ctx context.Context, org, server, user uuid.UUID, account string) (api.ServerAccessGrant, error) {
	v, e := scanGrant(s.pool.QueryRow(ctx, effectiveGrantSQL, org, server, account, user))
	if errors.Is(e, pgx.ErrNoRows) {
		return v, deny("account_not_granted")
	}
	return v, e
}
func (s *Service) Workspace(ctx context.Context, org uuid.UUID, p *authctx.Principal) (api.ServerAccessWorkspace, error) {
	out := api.ServerAccessWorkspace{Servers: []api.ServerAccessServer{}, Grants: []api.ServerAccessGrant{}, Sessions: []api.ServerAccessSession{}, Limitations: []string{"Sessions cannot resume after a disconnect or service restart.", "New recordings use PostgreSQL first with a 30-day default retention and configurable encrypted-byte quotas. Optional S3 archival verifies every chunk before deleting the PostgreSQL payload.", "Closing a terminal does not guarantee termination of background processes."}}
	if e := s.available(); e != nil {
		return out, e
	}
	out.CanManage = rbac.CanAny(p.RolesIn(org), rbac.PermServerAccessManage)
	out.CanGrant = rbac.CanAny(p.RolesIn(org), rbac.PermServerAccessGrant)
	out.CanManageSessions = rbac.CanAny(p.RolesIn(org), rbac.PermServerAccessSessionManage)
	var e error
	out.Enabled, e = s.Enabled(ctx, org)
	if e == nil {
		out.MfaFreshnessSeconds = 900
		out.RecordingRetentionDays = 7
		out.RecordingMaxSessionBytes = 4194304
		out.RecordingMaxOrgBytes = 67108864
		policyErr := s.pool.QueryRow(ctx, `SELECT recording_retention_days,recording_max_session_bytes,recording_max_org_bytes,mfa_freshness_seconds FROM server_access_settings WHERE org_id=$1`, org).Scan(&out.RecordingRetentionDays, &out.RecordingMaxSessionBytes, &out.RecordingMaxOrgBytes, &out.MfaFreshnessSeconds)
		if policyErr != nil && !errors.Is(policyErr, pgx.ErrNoRows) {
			return out, policyErr
		}
	}
	if e != nil {
		return out, e
	}
	rows, e := s.pool.Query(ctx, `SELECT `+serverColumns+` FROM server_access_servers WHERE org_id=$1 AND removed_at IS NULL ORDER BY name,id LIMIT 100`, org)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		v, e := scanServer(rows)
		if e != nil {
			return out, e
		}
		if !out.CanManage {
			accounts := []string{}
			for _, a := range v.Accounts {
				if _, e = s.effectiveGrant(ctx, org, v.Id, p.UserID, a); e == nil {
					accounts = append(accounts, a)
				}
			}
			if len(accounts) == 0 {
				continue
			}
			v.Accounts = accounts
			ready := []string{}
			for _, a := range v.ReadyAccounts {
				if slices.Contains(accounts, a) {
					ready = append(ready, a)
				}
			}
			v.ReadyAccounts = ready
			v.GatewayId = uuid.Nil
			v.PrivateIp = nil
			v.SshPort = nil
			v.HostFingerprint = nil
			v.LastError = nil
		}
		out.Servers = append(out.Servers, v)
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	rows.Close()
	if out.CanGrant {
		grants, e := s.pool.Query(ctx, `SELECT `+grantColumns+` FROM server_access_grants WHERE org_id=$1 ORDER BY created_at DESC LIMIT 100`, org)
		if e != nil {
			return out, e
		}
		for grants.Next() {
			v, e := scanGrant(grants)
			if e != nil {
				grants.Close()
				return out, e
			}
			out.Grants = append(out.Grants, v)
		}
		e = grants.Err()
		grants.Close()
		if e != nil {
			return out, e
		}
	}
	sessions, e := s.pool.Query(ctx, `SELECT `+sessionColumns+` FROM server_access_sessions WHERE org_id=$1 AND ($2::boolean OR user_id=$3) ORDER BY created_at DESC LIMIT 100`, org, out.CanManageSessions, p.UserID)
	if e != nil {
		return out, e
	}
	defer sessions.Close()
	for sessions.Next() {
		v, e := scanSession(sessions)
		if e != nil {
			return out, e
		}
		out.Sessions = append(out.Sessions, v.View)
	}
	if e = sessions.Err(); e != nil {
		return out, e
	}
	sessions.Close()
	if len(out.Sessions) > 0 {
		ids := make([]uuid.UUID, 0, len(out.Sessions))
		indices := map[uuid.UUID]int{}
		for i, v := range out.Sessions {
			ids = append(ids, v.Id)
			indices[v.Id] = i
		}
		metadata, err := s.pool.Query(ctx, `SELECT session_id,archive_status,archive_error,archive_retry_after FROM server_access_recordings WHERE org_id=$1 AND session_id=ANY($2::uuid[])`, org, ids)
		if err != nil {
			return out, err
		}
		for metadata.Next() {
			var id uuid.UUID
			var status, code string
			var retry *time.Time
			if err = metadata.Scan(&id, &status, &code, &retry); err != nil {
				metadata.Close()
				return out, err
			}
			if i, ok := indices[id]; ok {
				out.Sessions[i].ArchiveStatus = &status
				out.Sessions[i].ArchiveRetryAt = retry
				if code != "" {
					out.Sessions[i].ArchiveError = &code
				}
			}
		}
		err = metadata.Err()
		metadata.Close()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
func (s *Service) parent(ctx context.Context, org, user uuid.UUID, token string) (session.Session, time.Time, error) {
	if token == "" {
		return session.Session{}, time.Time{}, deny("human_session_required")
	}
	p, until, e := s.parents.GetNoTouch(ctx, token)
	if e != nil || p.UserID != user {
		return p, until, deny("parent_session_expired")
	}
	q := sqlc.New(s.pool)
	u, e := q.GetUserByID(ctx, user)
	if e != nil || u.Status != "active" || !u.EmailVerifiedAt.Valid || u.MustChangePassword || p.AppAuthEpoch <= 0 || p.AppAuthEpoch != u.AppAuthEpoch {
		return p, until, deny("user_authority_changed")
	}
	hash := sha256.Sum256([]byte(token))
	revoked, e := q.IsAppParentLogoutRevoked(ctx, hash[:])
	if e != nil || revoked {
		return p, until, deny("parent_logout")
	}
	m, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: org, UserID: user})
	if e != nil || m.AccessRevokedAt.Valid || !rbac.CanAny(m.Roles, rbac.PermServerAccessUse) {
		return p, until, deny("membership_changed")
	}
	freshness := 900
	err := s.pool.QueryRow(ctx, `SELECT mfa_freshness_seconds FROM server_access_settings WHERE org_id=$1`, org).Scan(&freshness)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return p, until, err
	}
	mfaUntil := p.MFAVerifiedAt.Add(time.Duration(freshness) * time.Second)
	if !session.ValidMFAAssurance(p.MFAVerifiedAt, p.MFAAssuranceSource, time.Now()) || !mfaUntil.After(time.Now()) {
		return p, until, deny("mfa_required")
	}
	until = minTime(until, p.ExpiresAt, mfaUntil)
	return p, until, nil
}
func minTime(first time.Time, rest ...time.Time) time.Time {
	for _, v := range rest {
		if v.Before(first) {
			first = v
		}
	}
	return first
}

// Registry revisions protect every edit from stale overwrites. The immutable
// session binding separately fingerprints authority, so a recording toggle or
// display-name edit affects new sessions without changing an existing policy.
func domainValue(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}
func serverAuthorityHash(v api.ServerAccessServer) []byte {
	raw, _ := json.Marshal(struct {
		Developer   bool   `json:",omitempty"`
		Clipboard   string `json:",omitempty"`
		OS, Domain  string
		Gateway     uuid.UUID
		IP          *string
		Port        *int
		Fingerprint *string
		Accounts    []string
		Idle, Max   int
	}{developerEnabled(v), authorityClipboardPolicy(v), serverOS(v), domainValue(v.RdpDomain), v.GatewayId, v.PrivateIp, v.SshPort, v.HostFingerprint, v.Accounts, v.IdleTimeoutSeconds, v.MaxSessionSeconds})
	hash := sha256.Sum256(raw)
	return hash[:]
}

// Denied records a redacted admission decision without request/terminal payload.
func (s *Service) Denied(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessConnectInput, cause error) {
	bounded, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	tx, e := s.pool.Begin(bounded)
	if e != nil {
		return
	}
	defer tx.Rollback(bounded)
	account := ""
	if accountPattern.MatchString(in.Account) {
		account = in.Account
	}
	if s.audit(bounded, tx, org, actor, "session_denied", in.ServerId, map[string]any{"server_id": in.ServerId, "account": account, "reason": authorityReason(cause)}) == nil {
		tx.Commit(bounded)
	}
}

func developerEnabled(v api.ServerAccessServer) bool {
	return v.DeveloperAccessEnabled != nil && *v.DeveloperAccessEnabled
}
func developerInput(v api.ServerAccessServerInput) bool {
	return v.DeveloperAccessEnabled != nil && *v.DeveloperAccessEnabled
}
