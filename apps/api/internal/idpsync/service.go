package idpsync

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsyncspec"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// Pusher fires the org-wide gateway recompile (<5s). Wired to the device pusher (same one the
// tenancy deactivate sweep uses), so a synced membership change reaches the data plane promptly.
type Pusher interface {
	PushOrgNodes(ctx context.Context, orgID uuid.UUID)
}

// ProviderFactory builds a DirectoryProvider from a stored config + its decrypted secret. Injectable
// so the box-walk (slice 5) can drive a faked directory; the default builds an EntraProvider.
type ProviderFactory func(cfg sqlc.IdpSyncConfig, secret string) (DirectoryProvider, error)

// DefaultProviderFactory builds the real provider for a config. Entra-only in v1 (D4); google is a
// fast-follow behind the same DirectoryProvider interface, rejected loudly until then.
func DefaultProviderFactory(cfg sqlc.IdpSyncConfig, secret string) (DirectoryProvider, error) {
	switch cfg.Provider {
	case "microsoft":
		tenant := ""
		if cfg.TenantID != nil {
			tenant = *cfg.TenantID
		}
		return NewEntraProvider(tenant, cfg.ClientID, secret, nil), nil
	case "google":
		admin := ""
		if cfg.DelegatedAdminEmail != nil {
			admin = *cfg.DelegatedAdminEmail
		}
		return NewGoogleWorkspaceProvider(secret, admin, nil)
	default:
		return nil, apierr.BadRequest("provider_not_supported", "directory sync for this provider is not yet available")
	}
}

// Service is the enterprise IdP-sync port + poller. It OWNS the config credential lifecycle and the
// group mapping; the per-poll convergence is delegated to a Reconciler (slice 3) built per config.
// Service also IS the reconciler's Store (methods below), so the sqlc + push wiring lives in one place.
type Service struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	sealer  *crypto.Sealer
	push    Pusher
	deprov  Deprovisioner
	factory ProviderFactory
	now     func() time.Time
	logger  *slog.Logger
	// licence answers ONE question: may the ADDITIVE half of a reconcile run. ⚠ nil => yes, the fail-open
	// default. There is deliberately no licence hook on the subtractive half anywhere in this package.
	licence *licence.Manager
}

func NewService(pool *pgxpool.Pool, sealer *crypto.Sealer, push Pusher, deprov Deprovisioner, logger *slog.Logger) *Service {
	return &Service{
		pool: pool, q: sqlc.New(pool), sealer: sealer, push: push, deprov: deprov,
		factory: DefaultProviderFactory, now: time.Now, logger: logger,
	}
}

// mayProvision is the predicate handed to the reconciler. ⭐ Extracted so the WIRING is provable without a
// database — the defect this slice fixes was never a wrong predicate, it was a right one nobody called.
// ⚠ nil manager => true, the fail-open default.
func (s *Service) mayProvision() bool {
	return s.licence == nil || s.licence.Has(licence.FeatIdpSync, s.now())
}

// WithLicence wires the entitlement manager. ⛔ It can only ever narrow the ADDITIVE half: the subtractive
// half has no seam to attach to, by construction.
func (s *Service) WithLicence(m *licence.Manager) *Service {
	s.licence = m
	return s
}

// SetProviderFactory overrides the directory-client factory (box-walk faked directory).
func (s *Service) SetProviderFactory(f ProviderFactory) { s.factory = f }

// SetClock overrides the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// perConfigPollTimeout bounds one org's reconcile so a large or hung tenant cannot stall the whole
// poll tick for every other tenant (#5).
const perConfigPollTimeout = 2 * time.Minute

func supportedProvider(p string) error {
	if p != "microsoft" && p != "google" {
		return apierr.BadRequest("provider_not_supported", "directory sync provider is not supported")
	}
	return nil
}

// ── config lifecycle (the port) ──────────────────────────────────────────────────

// UpsertConfig connects/updates a provider credential, sealing the secret at rest.
func (s *Service) UpsertConfig(ctx context.Context, orgID uuid.UUID, provider string, in idpsyncspec.ConfigInput) (idpsyncspec.ConfigView, error) {
	if err := supportedProvider(provider); err != nil {
		return idpsyncspec.ConfigView{}, err
	}
	secret := in.ClientSecret
	if provider == "google" {
		secret = in.ServiceAccountJSON
		if strings.TrimSpace(secret) == "" || strings.TrimSpace(in.DelegatedAdminEmail) == "" {
			return idpsyncspec.ConfigView{}, apierr.BadRequest("invalid_google_credentials", "Google Workspace sync requires service-account JSON and a delegated admin email")
		}
	} else if strings.TrimSpace(secret) == "" || strings.TrimSpace(in.ClientID) == "" || strings.TrimSpace(in.TenantID) == "" {
		return idpsyncspec.ConfigView{}, apierr.BadRequest("invalid_microsoft_credentials", "Microsoft sync requires client id, client secret, and tenant id")
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		return idpsyncspec.ConfigView{}, err
	}
	fp := s.sealer.Fingerprint([]byte(secret)) // keyed proof-of-secret (S4.5) — never the secret
	var tid *string
	if strings.TrimSpace(in.TenantID) != "" {
		t := in.TenantID
		tid = &t
	}
	var row sqlc.IdpSyncConfig
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		var e error
		row, e = q.UpsertIdpSyncConfig(ctx, sqlc.UpsertIdpSyncConfigParams{
			OrgID: orgID, Provider: provider, ClientID: in.ClientID,
			SecretSealed: []byte(sealed), TenantID: tid, DelegatedAdminEmail: nullableString(in.DelegatedAdminEmail), Enabled: in.Enabled,
		})
		if e != nil {
			return e
		}
		// A credential change is high-privilege — audit it (human actor). Metadata is secret-free:
		// only the fingerprint proves WHICH secret, never the secret or the sealed bytes.
		return s.humanAudit(ctx, q, orgID, "idp_sync.config_updated", "idp_sync_config", provider,
			map[string]any{"provider": provider, "client_id": in.ClientID, "secret_fingerprint": fp, "enabled": in.Enabled})
	})
	if err != nil {
		return idpsyncspec.ConfigView{}, err
	}
	view := s.viewOf(row)
	view.SecretFingerprint = fp
	return view, nil
}

// Health returns the two-tier sync health (derived at read time).
func (s *Service) Health(ctx context.Context, orgID uuid.UUID, provider string) (idpsyncspec.HealthView, error) {
	if err := supportedProvider(provider); err != nil {
		return idpsyncspec.HealthView{}, err
	}
	row, err := s.q.GetIdpSyncConfig(ctx, sqlc.GetIdpSyncConfigParams{OrgID: orgID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return idpsyncspec.HealthView{}, apierr.NotFound("idp_sync_not_configured", "directory sync is not configured for this provider")
	}
	if err != nil {
		return idpsyncspec.HealthView{}, err
	}
	v := s.viewOf(row)
	return idpsyncspec.HealthView{
		Provider: v.Provider, SyncHealth: v.SyncHealth, LastSyncOk: v.LastSyncOk,
		LastSyncAt: v.LastSyncAt, LastSyncError: v.LastSyncError,
	}, nil
}

// Trigger reconciles one org+provider now (the manual "sync now"), returning the resulting health.
func (s *Service) Trigger(ctx context.Context, orgID uuid.UUID, provider string) (idpsyncspec.HealthView, error) {
	if err := supportedProvider(provider); err != nil {
		return idpsyncspec.HealthView{}, err
	}
	cfg, err := s.q.GetIdpSyncConfig(ctx, sqlc.GetIdpSyncConfigParams{OrgID: orgID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return idpsyncspec.HealthView{}, apierr.NotFound("idp_sync_not_configured", "directory sync is not configured for this provider")
	}
	if err != nil {
		return idpsyncspec.HealthView{}, err
	}
	// A reconcile error is recorded on the config's health by the reconciler; we still return the
	// (now-degraded) health view rather than a 500, so "sync now" surfaces the failure legibly.
	_ = s.reconcileConfig(ctx, cfg)
	return s.Health(ctx, orgID, provider)
}

// PollAll reconciles every enabled config across all orgs — the background poller's unit of work.
func (s *Service) PollAll(ctx context.Context) {
	cfgs, err := s.q.ListEnabledIdpSyncConfigs(ctx)
	if err != nil {
		s.logger.Error("idp_sync_poll_list_failed", slog.String("error", err.Error()))
		return
	}
	for _, cfg := range cfgs {
		// #5: bound each org so one huge/hung tenant can't consume the whole tick for everyone else.
		cctx, cancel := context.WithTimeout(ctx, perConfigPollTimeout)
		err := s.reconcileConfig(cctx, cfg)
		cancel()
		if err != nil {
			s.logger.Warn("idp_sync_poll_config_degraded",
				slog.String("org_id", cfg.OrgID.String()), slog.String("provider", cfg.Provider),
				slog.String("error", err.Error()))
		}
	}
}

// reconcileConfig decrypts the credential, builds the provider, and runs a Reconciler for one config.
func (s *Service) reconcileConfig(ctx context.Context, cfg sqlc.IdpSyncConfig) error {
	secret, err := s.sealer.Open(string(cfg.SecretSealed))
	if err != nil {
		// A credential we can't decrypt is a hard failure — record it (fail-static: no membership
		// change) so the operator sees a broken config rather than a silent no-op.
		msg := "credential decrypt failed"
		_ = s.RecordResult(ctx, cfg.OrgID, cfg.Provider, false, false, msg, s.now())
		return errors.New(msg)
	}
	prov, err := s.factory(cfg, string(secret))
	if err != nil {
		msg := "provider unavailable: " + err.Error()
		_ = s.RecordResult(ctx, cfg.OrgID, cfg.Provider, false, false, msg, s.now())
		return err
	}
	// ⛔ D1 — THE PROVISIONING GATE, WIRED (S12.1 slice 9). ⚠ THIS LINE IS THE ENTIRE STORY OF THE SLICE.
	//
	// `WithProvisioningGate` and its three reds have existed since S7.5.2. The gate was correct, the tests
	// were correct, and NOTHING EVER CALLED IT — `mayProvision()` returns true for a nil predicate, so in
	// production every deployment provisioned unconditionally while a green test suite described a licence
	// gate in detail (docs/laws.md: unit tests prove BEHAVIOUR, not REACHABILITY — name the trigger and
	// check it can co-occur with the gate).
	//
	// ⭐ AND THE GATE IS HERE, AT THE SEAM, NOT AT A CALL SITE. reconcileConfig is the one path every
	// reconcile takes — the scheduled poll and the operator's manual Trigger both land here. A gate on
	// Trigger alone would leave the poller ungated, which is the shape the story paper names.
	r := NewReconciler(prov, s, s.deprov, s.now).WithProvisioningGate(s.mayProvision)
	return r.ReconcileConfig(ctx, cfg.OrgID, cfg.Provider)
}

// ── group mapping (the port) ─────────────────────────────────────────────────────

// MapGroup binds a directory group to a Tunnex group: either a NEW idp_sync group (Name), or an
// EXISTING manual group (GroupID) — the latter refused unless it is empty (D1 refuse-unless-empty).
func (s *Service) MapGroup(ctx context.Context, orgID uuid.UUID, provider string, in idpsyncspec.MapInput) (sqlc.UserGroup, error) {
	if err := supportedProvider(provider); err != nil {
		return sqlc.UserGroup{}, err
	}
	if strings.TrimSpace(in.IdpGroupID) == "" {
		return sqlc.UserGroup{}, apierr.BadRequest("invalid_request", "idp_group_id is required")
	}
	if in.GroupID != nil && strings.TrimSpace(in.Name) != "" {
		return sqlc.UserGroup{}, apierr.BadRequest("invalid_request", "provide either name (create) or group_id (bind), not both")
	}
	// A config must exist first (the mapping references a configured provider).
	if _, err := s.q.GetIdpSyncConfig(ctx, sqlc.GetIdpSyncConfigParams{OrgID: orgID, Provider: provider}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.UserGroup{}, apierr.BadRequest("idp_sync_not_configured", "configure the provider credential before mapping groups")
		}
		return sqlc.UserGroup{}, err
	}

	var out sqlc.UserGroup
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		var e error
		if in.GroupID != nil {
			// BIND an existing group. Refuse-unless-empty (D1): a populated manual group cannot flip.
			g, ge := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: *in.GroupID, OrgID: orgID})
			if errors.Is(ge, pgx.ErrNoRows) {
				return apierr.NotFound("group_not_found", "group not found")
			}
			if ge != nil {
				return ge
			}
			if g.Origin != "manual" {
				return apierr.Conflict("group_already_synced", "group is already directory-managed")
			}
			n, ce := q.CountGroupMembers(ctx, sqlc.CountGroupMembersParams{OrgID: orgID, GroupID: *in.GroupID})
			if ce != nil {
				return ce
			}
			if n > 0 {
				return apierr.Conflict("group_not_empty", "only an empty group can be converted to directory sync; remove its members first")
			}
			out, e = q.BindGroupToIdp(ctx, sqlc.BindGroupToIdpParams{
				ID: *in.GroupID, OrgID: orgID, IdpProvider: &provider, IdpGroupID: &in.IdpGroupID,
			})
			if errors.Is(e, pgx.ErrNoRows) { // lost the manual race
				return apierr.Conflict("group_already_synced", "group is already directory-managed")
			}
			return conflictIfDup(e)
		}
		// CREATE a new idp_sync group.
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = in.IdpGroupID
		}
		out, e = q.CreateIdpSyncGroup(ctx, sqlc.CreateIdpSyncGroupParams{
			OrgID: orgID, Name: name, IdpProvider: &provider, IdpGroupID: &in.IdpGroupID,
		})
		return conflictIfDup(e)
	})
	return out, err
}

// UnmapGroup reverts an idp_sync group to a plain, empty manual group + pushes (its members leave).
func (s *Service) UnmapGroup(ctx context.Context, orgID uuid.UUID, provider string, groupID uuid.UUID) error {
	if err := supportedProvider(provider); err != nil {
		return err
	}
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, e := q.UnbindIdpGroup(ctx, sqlc.UnbindIdpGroupParams{ID: groupID, OrgID: orgID}); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("group_not_found", "no synced group with that id")
			}
			return e
		}
		removed, e := q.DeleteGroupMembersByGroup(ctx, sqlc.DeleteGroupMembersByGroupParams{OrgID: orgID, GroupID: groupID})
		if e != nil {
			return e
		}
		// ⛔ DESTRUCTIVE AND, UNTIL NOW, SILENT. This verb removes EVERY member of a group and pushes the
		// change org-wide, and its sibling operations all audit (`UpsertConfig` at :123, the reconciler's own
		// membership writes) — this one wrote nothing. An access-affecting deletion with no record that a
		// human did it, on the surface that decides who can reach what.
		//
		// `removed` is the SERVER'S OWN count, taken inside the same transaction as the delete, so the audit
		// row states a number nobody has to re-derive later. The 204 still carries no body; this is the
		// record, not the response.
		return s.humanAudit(ctx, q, orgID, "idp_sync.group_unmapped", "user_group", groupID.String(),
			map[string]any{"provider": provider, "members_removed": removed})
	})
	if err != nil {
		return err
	}
	s.push.PushOrgNodes(ctx, orgID) // the group's grants disappear org-wide
	return nil
}

// ── reconciler Store (S7.5.2 slice 3) ────────────────────────────────────────────

func (s *Service) ListIdpSyncGroups(ctx context.Context, orgID uuid.UUID, provider string) ([]SyncGroup, error) {
	rows, err := s.q.ListIdpSyncGroups(ctx, sqlc.ListIdpSyncGroupsParams{OrgID: orgID, IdpProvider: &provider})
	if err != nil {
		return nil, err
	}
	out := make([]SyncGroup, 0, len(rows))
	for _, r := range rows {
		gid := ""
		if r.IdpGroupID != nil {
			gid = *r.IdpGroupID
		}
		out = append(out, SyncGroup{ID: r.ID, IdpGroupID: gid})
	}
	return out, nil
}

func (s *Service) ListIdpGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]SyncedMember, error) {
	rows, err := s.q.ListIdpGroupMembers(ctx, sqlc.ListIdpGroupMembersParams{OrgID: orgID, GroupID: groupID})
	if err != nil {
		return nil, err
	}
	out := make([]SyncedMember, 0, len(rows))
	for _, r := range rows {
		ext := ""
		if r.IdpExternalID != nil {
			ext = *r.IdpExternalID
		}
		out = append(out, SyncedMember{UserID: r.UserID, ExternalID: ext})
	}
	return out, nil
}

func (s *Service) ResolveOrgUser(ctx context.Context, orgID uuid.UUID, email string) (uuid.UUID, bool, error) {
	row, err := s.q.GetOrgUserByEmail(ctx, sqlc.GetOrgUserByEmailParams{OrgID: orgID, Email: email})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return row.ID, true, nil
}

func (s *Service) AddIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID, externalID string) (bool, error) {
	var ext *string
	if externalID != "" {
		ext = &externalID
	}
	n, err := s.q.AddIdpGroupMember(ctx, sqlc.AddIdpGroupMemberParams{OrgID: orgID, GroupID: groupID, UserID: userID, IdpExternalID: ext})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil // already present (ON CONFLICT DO NOTHING) — no audit, no push
	}
	if err := s.q.AddIdpAccessSource(ctx, sqlc.AddIdpAccessSourceParams{OrgID: orgID, UserID: userID, SourceKey: groupID.String()}); err != nil {
		return false, err
	}
	if err := s.q.RestoreMembershipAfterIdpGrant(ctx, sqlc.RestoreMembershipAfterIdpGrantParams{OrgID: orgID, UserID: userID}); err != nil {
		return false, err
	}
	return true, s.systemAudit(ctx, orgID, "group.member_synced_added", groupID, userID, "present_in_directory_group")
}

func (s *Service) RemoveIdpGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) (bool, error) {
	n, err := s.q.RemoveIdpGroupMember(ctx, sqlc.RemoveIdpGroupMemberParams{OrgID: orgID, GroupID: groupID, UserID: userID})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil // nothing to remove (concurrent converge already did) — no audit, no push
	}
	if err := s.q.RemoveIdpAccessSource(ctx, sqlc.RemoveIdpAccessSourceParams{OrgID: orgID, UserID: userID, SourceKey: groupID.String()}); err != nil {
		return false, err
	}
	count, err := s.q.CountAccessSources(ctx, sqlc.CountAccessSourcesParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return false, err
	}
	if count == 0 && s.deprov != nil {
		if _, err := s.deprov.RevokeOrgAccess(ctx, orgID, userID, "removed_from_directory_group"); err != nil {
			return false, err
		}
	}
	return true, s.systemAudit(ctx, orgID, "group.member_synced_removed", groupID, userID, "absent_from_directory_group")
}

func (s *Service) RecordResult(ctx context.Context, orgID uuid.UUID, provider string, ok, advanceClock bool, errMsg string, now time.Time) error {
	var ep *string
	if errMsg != "" {
		ep = &errMsg
	}
	return s.q.RecordIdpSyncResult(ctx, sqlc.RecordIdpSyncResultParams{
		OrgID: orgID, Provider: provider, LastSyncOk: ok, LastSyncError: ep,
		Column5: advanceClock, UpdatedAt: now,
	})
}

func (s *Service) PushOrg(ctx context.Context, orgID uuid.UUID) { s.push.PushOrgNodes(ctx, orgID) }

// ── helpers ──────────────────────────────────────────────────────────────────────

func (s *Service) viewOf(row sqlc.IdpSyncConfig) idpsyncspec.ConfigView {
	v := idpsyncspec.ConfigView{
		Provider: row.Provider, ClientID: row.ClientID, Enabled: row.Enabled, LastSyncOk: row.LastSyncOk,
	}
	if row.TenantID != nil {
		v.TenantID = *row.TenantID
	}
	if row.DelegatedAdminEmail != nil {
		v.DelegatedAdminEmail = *row.DelegatedAdminEmail
	}
	if row.LastSyncError != nil {
		v.LastSyncError = *row.LastSyncError
	}
	var lastAt *time.Time
	if row.LastSyncAt.Valid {
		t := row.LastSyncAt.Time
		lastAt = &t
		v.LastSyncAt = &t
	}
	v.SyncHealth = ClassifySyncHealth(row.LastSyncOk, lastAt, row.CreatedAt, s.now(), EscalationCeiling).String()
	return v
}

func nullableString(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

// humanAudit records a principal-attributed audit row (config changes are human actions via the
// authenticated PUT). Secret-free metadata only.
func (s *Service) humanAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	actor := pgtype.UUID{}
	if p, ok := authctx.PrincipalFrom(ctx); ok {
		actor = pgtype.UUID{Bytes: p.UserID, Valid: true}
	}
	tt, tid := targetType, targetID
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorUserID: actor,
		Action:      action,
		TargetType:  &tt,
		TargetID:    &tid,
		Metadata:    b,
	})
	return err
}

func (s *Service) systemAudit(ctx context.Context, orgID uuid.UUID, action string, groupID, userID uuid.UUID, cause string) error {
	tt, tid := "group", groupID.String()
	as := "idp-sync"
	meta, err := json.Marshal(map[string]any{"user_id": userID.String(), "cause": cause})
	if err != nil {
		return err
	}
	_, err = s.q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorSystem: &as,
		Action:      action,
		TargetType:  &tt,
		TargetID:    &tid,
		Metadata:    meta,
	})
	return err
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func conflictIfDup(err error) error {
	if err == nil {
		return nil
	}
	// #9: match the SQLSTATE structurally (like enterprise/policy/service.go), not the error text —
	// a driver upgrade or a wrapped/localized message must not silently turn a 409 into a 500.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return apierr.New(http.StatusConflict, "conflict", "that directory group is already mapped")
	}
	return err
}
