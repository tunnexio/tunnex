package serveraccess

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"golang.org/x/crypto/ssh"
)

type enrollment struct {
	Sync         bool                       `json:"sync"`
	CreatedAt    time.Time                  `json:"created_at"`
	View         api.ServerAccessEnrollment `json:"view"`
	Material     bootstrap.Job              `json:"material"`
	Org          uuid.UUID                  `json:"org"`
	Actor        uuid.UUID                  `json:"actor"`
	Gateway      uuid.UUID                  `json:"gateway"`
	Serial       string                     `json:"serial"`
	Revision     int64                      `json:"revision"`
	ParentSealed string                     `json:"parent_sealed"`
	Epoch        int64                      `json:"epoch"`
	Accounts     []string                   `json:"accounts"`
	Key          string                     `json:"key"`
}

func activeEnrollment(state string) bool {
	return state == "preparing" || state == "awaiting_authorization" || state == "queued" || state == "running"
}
func validFingerprint(fp string) bool {
	b, e := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fp, "SHA256:"))
	return e == nil && len(b) == 32 && strings.HasPrefix(fp, "SHA256:") && len(fp) == 50
}
func validateEnrollmentInput(in api.ServerAccessEnrollmentInput) error {
	if !accountPattern.MatchString(in.ManagementAccount) || in.ManagementAccount == "root" || in.ManagementPort < 1 || in.ManagementPort > 65535 || !validFingerprint(in.ManagementFingerprint) || len(in.Accounts) > 16 {
		return bad()
	}
	seen := map[string]bool{}
	for _, a := range in.Accounts {
		if !accountPattern.MatchString(a) || a == "root" || seen[a] {
			return bad()
		}
		seen[a] = true
	}
	return nil
}
func pythonJSON(value any) string {
	raw, _ := json.Marshal(value)
	return "json.loads(base64.b64decode('" + base64.StdEncoding.EncodeToString(raw) + "'))"
}
func bundleScript(org uuid.UUID, server api.ServerAccessServer, trust api.ServerAccessTrust) string {
	bound := map[string]any{"version": 1, "org_id": org.String(), "server_id": server.Id.String(), "private_ip": *server.PrivateIp, "ssh_port": *server.SshPort, "public_key": trust.PublicKey, "ca_fingerprint": *trust.CaFingerprint}
	return strings.Replace(bootstrap.Helper, "BUNDLE = None", "BUNDLE = "+pythonJSON(bound), 1)
}
func authorizationCommand(j enrollment) string {
	digest := sha256.Sum256([]byte(j.Material.Script))
	setup := map[string]any{"id": j.View.Id.String(), "account": j.Material.Account, "expires": j.View.ExpiresAt.Unix(), "expiry_ssh": j.View.ExpiresAt.UTC().Format("20060102150405Z"), "key": j.Key, "digest": fmt.Sprintf("%x", digest), "accounts": j.Accounts}
	source := strings.Replace(bootstrap.Authorize, "SETUP = None", "SETUP = "+pythonJSON(setup), 1)
	return "sudo /usr/bin/python3 -c \"import base64;exec(base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(source)) + "'))\""
}
func (s *Service) PrepareEnrollment(ctx context.Context, org uuid.UUID, p *authctx.Principal, id uuid.UUID, in api.ServerAccessEnrollmentInput) (api.ServerAccessEnrollment, error) {
	empty := api.ServerAccessEnrollment{}
	if e := s.available(); e != nil {
		return empty, e
	}
	if e := validateEnrollmentInput(in); e != nil {
		return empty, e
	}
	parent, until, e := s.parent(ctx, org, p.UserID, p.SessionID)
	if e != nil {
		return empty, e
	}
	if time.Until(until) < 2*time.Minute {
		return empty, deny("mfa_required")
	}
	server, e := s.Server(ctx, org, id)
	if e != nil {
		return empty, e
	}
	if serverOS(server) != "linux" {
		return api.ServerAccessEnrollment{}, deny("ssh_setup_requires_linux")
	}
	if server.Enabled && len(server.Accounts) == 0 {
		return empty, apierr.Conflict("disable_before_setup", "Disable this server before provisioning or syncing accounts")
	}
	if *server.SshPort == in.ManagementPort || *server.SshPort < 1024 {
		return empty, bad()
	}
	trust, e := s.Trust(ctx, org)
	if e != nil {
		return empty, e
	}
	var serial string
	e = s.pool.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE org_id=$1 AND id=$2 AND status='active' AND enrolled_kind='gateway' AND last_seen_at>now()-interval '90 seconds' AND cert_not_after>now()`, org, server.GatewayId).Scan(&serial)
	if e != nil {
		return empty, deny("gateway_unavailable")
	}
	raw, _ := json.Marshal(parentBinding{Org: org, User: p.UserID, Token: p.SessionID})
	sealed, e := s.sealer.Seal(raw)
	if e != nil {
		return empty, e
	}
	job := enrollment{Sync: len(server.Accounts) > 0, CreatedAt: time.Now().UTC(), Org: org, Actor: p.UserID, Gateway: server.GatewayId, Serial: serial, Revision: server.Revision, ParentSealed: sealed, Epoch: parent.AppAuthEpoch, Accounts: in.Accounts}
	job.View = api.ServerAccessEnrollment{Id: uuid.New(), ServerId: id, ExpiresAt: minTime(until, time.Now().Add(15*time.Minute)), State: "preparing", Message: "Preparing a temporary key on the selected gateway."}
	job.Material = bootstrap.Job{ID: job.View.Id.String(), State: "preparing", IP: *server.PrivateIp, Port: in.ManagementPort, Account: in.ManagementAccount, Fingerprint: in.ManagementFingerprint, Script: bundleScript(org, server, trust), ExpiresAt: job.View.ExpiresAt}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_enrollment'))`); e != nil {
		return empty, e
	}
	_, e = tx.Exec(ctx, `UPDATE server_access_enrollments SET state='expired' WHERE expires_at<=now() AND state IN ('preparing','awaiting_authorization','queued','running')`)
	if e != nil {
		return empty, e
	}
	var count int
	e = tx.QueryRow(ctx, `SELECT count(*) FROM server_access_enrollments WHERE state IN ('preparing','awaiting_authorization','queued','running')`).Scan(&count)
	if e != nil {
		return empty, e
	}
	if count >= 16 {
		return empty, apierr.Conflict("setup_capacity", "Too many active setup jobs; cancel or wait before retrying")
	}
	var exists bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM server_access_enrollments WHERE org_id=$1 AND server_id=$2 AND state IN ('preparing','awaiting_authorization','queued','running'))`, org, id).Scan(&exists)
	if e != nil {
		return empty, e
	}
	if exists {
		return empty, apierr.Conflict("setup_in_progress", "An enrollment job already exists for this server")
	}
	encoded, _ := json.Marshal(job)
	_, e = tx.Exec(ctx, `INSERT INTO server_access_enrollments(id,org_id,server_id,gateway_id,state,expires_at,payload) VALUES($1,$2,$3,$4,$5,$6,$7)`, job.View.Id, org, id, job.Gateway, job.View.State, job.View.ExpiresAt, encoded)
	if e != nil {
		return empty, e
	}
	if e = s.audit(ctx, tx, org, p.UserID, "enrollment_prepared", id, map[string]any{"job_id": job.View.Id, "gateway_id": job.Gateway, "management_account": in.ManagementAccount}); e != nil {
		return empty, e
	}
	return job.View, tx.Commit(ctx)
}
func loadEnrollment(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (enrollment, error) {
	var j enrollment
	var raw []byte
	var state string
	e := tx.QueryRow(ctx, `SELECT payload,state FROM server_access_enrollments WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&raw, &state)
	if e == pgx.ErrNoRows {
		return j, missing()
	}
	if e != nil {
		return j, e
	}
	if e = json.Unmarshal(raw, &j); e != nil {
		return j, e
	}
	if string(j.View.State) != state && !activeEnrollment(state) {
		j.View.Message = "Setup authorization expired or server was removed. Prepare a new job."
		j.View.AuthorizationCommand = ""
	}
	j.View.State = api.ServerAccessEnrollmentState(state)
	j.Material.State = state
	return j, nil
}
func (s *Service) enrollmentAuthority(ctx context.Context, j enrollment) (*authctx.Principal, error) {
	if e := s.available(); e != nil {
		return nil, e
	}
	if !j.View.ExpiresAt.After(time.Now()) {
		return nil, deny("setup_expired")
	}
	enabled, e := s.Enabled(ctx, j.Org)
	if e != nil || !enabled {
		return nil, deny("organization_disabled")
	}
	raw, e := s.sealer.Open(j.ParentSealed)
	if e != nil {
		return nil, e
	}
	var bound parentBinding
	if json.Unmarshal(raw, &bound) != nil || bound.Org != j.Org || bound.User != j.Actor {
		return nil, deny("invalid_parent_binding")
	}
	parent, _, e := s.parent(ctx, j.Org, j.Actor, bound.Token)
	if e != nil {
		return nil, e
	}
	if parent.AppAuthEpoch != j.Epoch {
		return nil, deny("parent_authority_changed")
	}
	var roles []string
	e = s.pool.QueryRow(ctx, `SELECT roles FROM memberships WHERE org_id=$1 AND user_id=$2 AND access_revoked_at IS NULL`, j.Org, j.Actor).Scan(&roles)
	if e != nil || !rbac.CanAny(roles, rbac.PermServerAccessManage) {
		return nil, deny("management_authority_changed")
	}
	server, e := s.Server(ctx, j.Org, j.View.ServerId)
	if e != nil {
		return nil, e
	}
	if server.Revision != j.Revision || server.GatewayId != j.Gateway || (server.Enabled && !j.Sync) {
		return nil, deny("server_authority_changed")
	}
	var live bool
	e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE org_id=$1 AND id=$2 AND cert_serial=$3 AND status='active' AND enrolled_kind='gateway' AND last_seen_at>now()-interval '90 seconds' AND cert_not_after>now())`, j.Org, j.Gateway, j.Serial).Scan(&live)
	if e != nil || !live {
		return nil, deny("gateway_authority_changed")
	}
	// StartSession independently authorizes check requests using the sealed initiating session.
	return &authctx.Principal{UserID: j.Actor, SessionID: bound.Token, RoleSets: map[uuid.UUID][]string{j.Org: roles}}, nil
}
func (s *Service) storeEnrollment(ctx context.Context, tx pgx.Tx, j enrollment) error {
	if !activeEnrollment(string(j.View.State)) {
		j.ParentSealed = ""
		j.View.AuthorizationCommand = ""
		j.Material.Script = ""
	}
	raw, _ := json.Marshal(j)
	_, e := tx.Exec(ctx, `UPDATE server_access_enrollments SET payload=$3,state=$4 WHERE org_id=$1 AND id=$2`, j.Org, j.View.Id, raw, j.View.State)
	return e
}
func (s *Service) Enrollment(ctx context.Context, org uuid.UUID, p *authctx.Principal, id uuid.UUID, operation string) (api.ServerAccessEnrollment, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return api.ServerAccessEnrollment{}, e
	}
	defer tx.Rollback(ctx)
	j, e := loadEnrollment(ctx, tx, org, id)
	if e != nil {
		return j.View, e
	}
	if j.Actor != p.UserID {
		return api.ServerAccessEnrollment{}, missing()
	}
	if activeEnrollment(string(j.View.State)) {
		if _, e = s.enrollmentAuthority(ctx, j); e != nil {
			j.View.State = "expired"
			j.View.Message = "Setup authorization is no longer valid. Prepare a new job."
		}
	}
	if operation == "cancel" && activeEnrollment(string(j.View.State)) {
		j.View.State = "cancelled"
		j.View.Message = "Setup cancelled. Temporary authorization will be cleaned up on the target at expiry."
	}
	if operation == "start" {
		if j.View.State != "awaiting_authorization" {
			return j.View, apierr.Conflict("setup_not_ready", "Wait for the gateway key and authorize it before starting setup")
		}
		j.View.State = "queued"
		j.View.Message = "Waiting for the gateway to connect and configure the target."
	}
	if operation != "get" {
		if e = s.audit(ctx, tx, org, p.UserID, "enrollment_"+operation, j.View.ServerId, map[string]any{"job_id": id}); e != nil {
			return j.View, e
		}
	}
	if e = s.storeEnrollment(ctx, tx, j); e != nil {
		return j.View, e
	}
	return j.View, tx.Commit(ctx)
}
func (s *Service) EnrollmentDesired(ctx context.Context, org, gateway uuid.UUID, serial string) ([]bootstrap.Job, error) {
	rows, e := s.pool.Query(ctx, `SELECT id FROM server_access_enrollments WHERE org_id=$1 AND gateway_id=$2 AND state IN ('preparing','awaiting_authorization','queued','running') ORDER BY expires_at LIMIT 16`, org, gateway)
	if e != nil {
		return nil, e
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := []bootstrap.Job{}
	for _, id := range ids {
		tx, e := s.pool.Begin(ctx)
		if e != nil {
			return nil, e
		}
		j, e := loadEnrollment(ctx, tx, org, id)
		if e != nil {
			tx.Rollback(ctx)
			return nil, e
		}
		if j.Gateway != gateway || j.Serial != serial {
			tx.Rollback(ctx)
			continue
		}
		if _, e = s.enrollmentAuthority(ctx, j); e != nil {
			j.View.State = "expired"
			j.View.Message = "Setup authorization expired or server authority changed."
			e = s.storeEnrollment(ctx, tx, j)
		} else {
			j.Material.State = string(j.View.State)
			material := j.Material
			if j.View.State != "queued" {
				material.Script = ""
			}
			out = append(out, material)
		}
		if e != nil {
			tx.Rollback(ctx)
			return nil, e
		}
		if e = tx.Commit(ctx); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func validateEnrollmentResult(j enrollment, result *bootstrap.Result) error {
	if result == nil || result.Version != 1 || result.OrgID != j.Org.String() || result.ServerID != j.View.ServerId.String() || !validFingerprint(result.HostFingerprint) || len(result.Accounts) < 1 || len(result.Accounts) > 16 {
		return bad()
	}
	// Port is verified against the current server before configuration is accepted.
	seen := map[string]bool{}
	for _, a := range result.Accounts {
		if !accountPattern.MatchString(a) || a == "root" || seen[a] {
			return bad()
		}
		seen[a] = true
	}
	for _, a := range j.Accounts {
		if !seen[a] {
			return bad()
		}
	}
	return nil
}
func (s *Service) EnrollmentReport(ctx context.Context, org, gateway, id uuid.UUID, serial string, in bootstrap.Report) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	j, e := loadEnrollment(ctx, tx, org, id)
	if e != nil {
		return e
	}
	if j.Gateway != gateway || j.Serial != serial {
		return missing()
	}
	principal, e := s.enrollmentAuthority(ctx, j)
	if e != nil {
		return e
	}
	switch {
	case in.PublicKey != "":
		if j.View.State != "preparing" || in.Result != "" || in.Setup != nil {
			return bad()
		}
		key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
		if e != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
			return bad()
		}
		j.Key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		j.View.AuthorizationCommand = authorizationCommand(j)
		j.View.State = "awaiting_authorization"
		j.View.Message = "Run the one-time authorization command on the target through your trusted management SSH connection."
	case in.Result == "running":
		if j.View.State != "queued" || in.Setup != nil {
			return bad()
		}
		j.View.State = "running"
		j.View.Message = "Detecting OS, configuring SSH trust and discovering login accounts."
	case in.Result == "ok":
		if j.View.State != "running" {
			return bad()
		}
		if e = validateEnrollmentResult(j, in.Setup); e != nil {
			return e
		}
		server, e := s.Server(ctx, org, j.View.ServerId)
		if e != nil {
			return e
		}
		if in.Setup.SSHPort != *server.SshPort {
			return bad()
		}
		// This revision guard prevents a stale installer result from overwriting edits or retirement.
		var updated api.ServerAccessServer
		if j.Sync {
			if e = validateAccountSync(server, in.Setup); e != nil {
				return e
			}
			updated, e = scanServer(tx.QueryRow(ctx, `UPDATE server_access_servers SET accounts=$4,updated_at=now() WHERE org_id=$1 AND id=$2 AND revision=$3 AND removed_at IS NULL RETURNING `+serverColumns, org, server.Id, j.Revision, in.Setup.Accounts))
			if e == nil {
				e = s.audit(ctx, tx, org, j.Actor, "accounts_synced", server.Id, map[string]any{"accounts": in.Setup.Accounts, "revision": j.Revision})
			}
		} else {
			updated, e = s.SaveServer(ctx, org, j.Actor, server.Id, api.ServerAccessServerInput{GatewayId: server.GatewayId, Name: server.Name, PrivateIp: *server.PrivateIp, SshPort: *server.SshPort, HostFingerprint: in.Setup.HostFingerprint, Accounts: in.Setup.Accounts, Revision: j.Revision, Enabled: false, RecordingEnabled: server.RecordingEnabled, IdleTimeoutSeconds: server.IdleTimeoutSeconds, MaxSessionSeconds: server.MaxSessionSeconds})
		}
		if e != nil {
			return e
		}
		checks := true
		for _, account := range updated.Accounts {
			if j.Sync {
				continue
			}
			if _, err := s.StartSession(ctx, org, principal, api.ServerAccessConnectInput{ServerId: updated.Id, Account: account}, true); err != nil {
				checks = false
			}
		}
		j.View.State = "succeeded"
		j.View.Message = "Setup complete; accounts and host identity were saved automatically. SSH checks were queued. Once they pass, enable the server and grant access."
		if j.Sync {
			j.View.Message = "Accounts synced. Existing access remains available. Run Check for each new account, then grant access explicitly."
		}
		if !checks {
			j.View.Message = "Setup complete; accounts and host identity were saved. Run any remaining SSH checks, enable the server, then grant access."
		}
	default:
		if !activeEnrollment(string(j.View.State)) || in.Setup != nil {
			return bad()
		}
		allowed := map[string]string{"ssh_host_key_mismatch": "Management SSH host identity did not match. No installer was sent.", "ssh_unreachable": "Gateway cannot reach the management SSH port. Check routing and firewall rules.", "ssh_authentication_failed": "Temporary SSH authorization was refused or expired. Prepare a new job.", "setup_failed": "Target setup failed. Check the target journal; prerequisites include Python 3, OpenSSH and systemd. Unsupported OS and enforcing SELinux are refused.", "gateway_key_lost": "Gateway restarted and discarded the temporary private key. Cancel and prepare a new job."}
		message, ok := allowed[in.Result]
		if !ok {
			return bad()
		}
		j.View.State = "failed"
		j.View.Message = message
	}
	if e = s.audit(ctx, tx, org, j.Actor, "enrollment_status", j.View.ServerId, map[string]any{"job_id": id, "state": j.View.State}); e != nil {
		return e
	}
	if e = s.storeEnrollment(ctx, tx, j); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Service) CurrentEnrollment(ctx context.Context, org uuid.UUID, p *authctx.Principal, server uuid.UUID) (api.ServerAccessEnrollment, error) {
	var id uuid.UUID
	e := s.pool.QueryRow(ctx, `SELECT id FROM server_access_enrollments WHERE org_id=$1 AND server_id=$2 AND payload->>'actor'=$3 ORDER BY (state IN ('preparing','awaiting_authorization','queued','running')) DESC, COALESCE((payload->>'created_at')::timestamptz, expires_at) DESC, id DESC LIMIT 1`, org, server, p.UserID.String()).Scan(&id)
	if e == pgx.ErrNoRows {
		return api.ServerAccessEnrollment{}, missing()
	}
	if e != nil {
		return api.ServerAccessEnrollment{}, e
	}
	return s.Enrollment(ctx, org, p, id, "get")
}

// Account discovery is additive; trust changes and removals use normal server edits.
func validateAccountSync(server api.ServerAccessServer, result *bootstrap.Result) error {
	if result.HostFingerprint != *server.HostFingerprint || result.SSHPort != *server.SshPort {
		return bad()
	}
	for _, old := range server.Accounts {
		found := false
		for _, a := range result.Accounts {
			if a == old {
				found = true
			}
		}
		if !found {
			return bad()
		}
	}
	return nil
}
