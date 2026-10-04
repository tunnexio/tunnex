// Package appaccess owns draft registry authority. Drafts confer no content access.
package appaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

type Config struct {
	AppBaseDomain string
	ConsoleURL    string
	ConsoleHosts  []string
	Now           func() time.Time
}
type Service struct {
	pool             *pgxpool.Pool
	config           Config
	domainReady      bool
	domains          DomainProvider
	sessionAuthority *SessionAuthority
	events           *EventProducer
	mfaEnrolled      func(context.Context, uuid.UUID) (bool, error)
}
type Settings struct {
	Enabled     bool
	Version     int64
	BaseDomain  string
	DomainReady bool
}
type DraftInput struct {
	AllowedDestinationCIDRs    []string
	OriginCAPEM                string
	OriginCADigest             string
	AllowedDestinationCIDRsSet bool `json:"-"`
	OriginCAPEMSet             bool `json:"-"`
	Name                       string
	Description                string
	Icon                       string
	// Omit empty images from revision digests to retain pre-upload revision identities.
	IconDataURL            string `json:",omitempty"`
	IconDataURLSet         bool   `json:"-"`
	OriginURL              string
	GatewayID              uuid.UUID
	PublicHostname         string
	IdleTimeoutSeconds     int32
	AbsoluteTimeoutSeconds int32
}
type Revision struct {
	DraftInput
	Revision  int64
	Digest    string
	CreatedAt time.Time
}
type Application struct {
	RequireMFA       bool
	PublicationState string
	ActiveRevision   *int64
	ID               uuid.UUID
	OrgID            uuid.UUID
	Version          int64
	DraftRevision    int64
	State            string
	Draft            Revision
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ConnectorStatus  string
}

func NewService(pool *pgxpool.Pool, config Config) *Service {
	config.AppBaseDomain = strings.ToLower(config.AppBaseDomain)
	ready := validHost(config.AppBaseDomain) && len(config.ConsoleHosts) > 0
	for _, host := range config.ConsoleHosts {
		if !appdomains.Boundary(strings.ToLower(host), config.AppBaseDomain) {
			ready = false
		}
	}
	return &Service{pool: pool, config: config, domainReady: ready}
}
func validHost(host string) bool {
	if len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (s *Service) validate(in DraftInput) (DraftInput, string, error) {
	return s.validateWithExistingHost(in, "")
}
func (s *Service) validateWithExistingHost(in DraftInput, existingHost string) (DraftInput, string, error) {
	bad := func() (DraftInput, string, error) {
		return in, "", apierr.BadRequest("invalid_application", "invalid draft configuration")
	}
	policy, err := originpolicy.Normalize(in.AllowedDestinationCIDRs, in.OriginCAPEM)
	if err != nil {
		return in, "", apierr.BadRequest("invalid_origin_policy", "invalid origin destination or CA policy")
	}
	in.AllowedDestinationCIDRs, in.OriginCAPEM, in.OriginCADigest = policy.AllowedDestinationCIDRs, policy.OriginCAPEM, policy.OriginCADigest
	if in.Icon == "" {
		in.Icon = "app"
	}
	if in.Icon != "app" && in.Icon != "globe" && in.Icon != "dashboard" && in.Icon != "terminal" {
		return bad()
	}
	in.IconDataURL, err = normalizeIcon(in.IconDataURL)
	if err != nil {
		return in, "", err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.PublicHostname = strings.ToLower(in.PublicHostname)
	if !utf8.ValidString(in.Name+in.Description+in.Icon) || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 100 || utf8.RuneCountInString(in.Description) > 1000 || len(in.Icon) > 64 || strings.IndexFunc(in.Name+in.Description+in.Icon, unicode.IsControl) >= 0 {
		return bad()
	}
	if !s.domainReady {
		return in, "", apierr.Conflict("app_domain_unavailable", "configure App Access domain settings first")
	}
	if !validHost(in.PublicHostname) || (in.PublicHostname != existingHost && !directChild(in.PublicHostname, s.config.AppBaseDomain)) {
		return bad()
	}
	for _, host := range s.config.ConsoleHosts {
		if strings.EqualFold(host, in.PublicHostname) {
			return bad()
		}
	}
	u, e := url.Parse(in.OriginURL)
	if e != nil || len(in.OriginURL) > 2048 || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(in.OriginURL, "#") || strings.Contains(u.Hostname(), "%") || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" || strings.ContainsAny(in.OriginURL, "\\\r\n\t ") {
		return bad()
	}
	if u.RawPath != "" || strings.HasSuffix(u.Host, ":") {
		return bad()
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return bad()
		}
	}
	originHost := strings.ToLower(u.Hostname())
	if net.ParseIP(originHost) == nil {
		for _, label := range strings.Split(originHost, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return bad()
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return bad()
				}
			}
		}
	}
	if in.GatewayID == uuid.Nil || in.IdleTimeoutSeconds < 60 || in.IdleTimeoutSeconds > 1800 || in.AbsoluteTimeoutSeconds < 300 || in.AbsoluteTimeoutSeconds > 28800 || in.IdleTimeoutSeconds > in.AbsoluteTimeoutSeconds {
		return bad()
	}
	b, e := json.Marshal(in)
	if e != nil {
		return in, "", e
	}
	h := sha256.Sum256(b)
	return in, hex.EncodeToString(h[:]), nil
}
func (s *Service) GetSettings(ctx context.Context, org uuid.UUID) (Settings, error) {
	configured, configErr := s.effectiveDomains(ctx)
	if configErr != nil {
		return Settings{}, configErr
	}
	out := Settings{Version: 1, BaseDomain: configured.config.AppBaseDomain, DomainReady: configured.domainReady}
	q := sqlc.New(s.pool)
	exists, e := q.AppAccessOrganizationExists(ctx, org)
	if e != nil {
		return out, e
	}
	if !exists {
		return out, notFound()
	}
	r, e := q.GetAppAccessSettings(ctx, org)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, notFound()
	}
	out.Enabled = r.Enabled
	out.Version = r.Version
	return out, e
}
func notFound() error {
	return apierr.NotFound("application_not_found", "no such App Access resource in this organization")
}
func conflict() error {
	return apierr.Conflict("version_conflict", "the resource changed; reload before editing")
}
func (s *Service) transaction(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = fn(sqlc.New(tx)); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func audit(ctx context.Context, q *sqlc.Queries, org, actor uuid.UUID, target, action string, version int64) error {
	b, _ := json.Marshal(map[string]int64{"version": version})
	kind := "app_access"
	_, e := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: action, TargetType: &kind, TargetID: &target, Metadata: b})
	return e
}
func (s *Service) UpdateSettings(ctx context.Context, org, actor uuid.UUID, enabled bool, expectedVersion int64, entitled bool) (Settings, error) {
	if enabled && !entitled {
		return Settings{}, apierr.Forbidden("feature_unavailable", "App Access entitlement required")
	}
	if enabled && !s.domainConfigured(ctx) {
		return Settings{}, apierr.Conflict("app_domain_unavailable", "configure App Access domain settings first")
	}
	e := s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, e := q.LockActiveAppAccessOrganization(ctx, org); errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		} else if e != nil {
			return e
		}
		if e := q.EnsureAppAccessSettings(ctx, org); e != nil {
			return e
		}
		n, e := q.UpdateAppAccessSettings(ctx, sqlc.UpdateAppAccessSettingsParams{OrgID: org, Enabled: enabled, Version: expectedVersion})
		if e != nil {
			return e
		}
		if n != 1 {
			return conflict()
		}
		return audit(ctx, q, org, actor, org.String(), "app_access.settings_updated", expectedVersion+1)
	})
	if e != nil {
		return Settings{}, e
	}
	return s.GetSettings(ctx, org)
}
func requireDraft(ctx context.Context, q *sqlc.Queries, org, gateway uuid.UUID, entitled bool) error {
	if _, e := q.LockActiveAppAccessOrganization(ctx, org); errors.Is(e, pgx.ErrNoRows) {
		return notFound()
	} else if e != nil {
		return e
	}
	if !entitled {
		return apierr.Forbidden("feature_unavailable", "App Access entitlement required")
	}
	enabled, e := q.LockAppAccessSettings(ctx, org)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !enabled {
		return apierr.Forbidden("app_access_disabled", "enable App Access for this organization first")
	}
	if e != nil {
		return e
	}
	exists, e := q.AppAccessGatewayExists(ctx, sqlc.AppAccessGatewayExistsParams{OrgID: org, ID: gateway})
	if e != nil {
		return e
	}
	if !exists {
		return notFound()
	}
	return nil
}
func reserveHost(ctx context.Context, q *sqlc.Queries, org, app uuid.UUID, hostname string) error {
	e := q.ReserveAppAccessHostname(ctx, sqlc.ReserveAppAccessHostnameParams{Hostname: hostname, OrgID: org, AppID: app})
	if e != nil {
		return e
	}
	owns, e := q.OwnsAppAccessHostname(ctx, sqlc.OwnsAppAccessHostnameParams{Hostname: hostname, OrgID: org, AppID: app})
	if e != nil {
		return e
	}
	if owns == nil || !*owns {
		return apierr.Conflict("hostname_taken", "hostname is already registered")
	}
	return nil
}
func insertRevision(ctx context.Context, q *sqlc.Queries, org, app uuid.UUID, revision int64, in DraftInput, digest string) error {
	return q.InsertAppAccessRevision(ctx, sqlc.InsertAppAccessRevisionParams{OrgID: org, AppID: app, Revision: revision, Name: in.Name, Description: in.Description, Icon: in.Icon, IconDataUrl: in.IconDataURL, OriginUrl: in.OriginURL, GatewayID: in.GatewayID, PublicHostname: in.PublicHostname, IdleTimeoutSeconds: in.IdleTimeoutSeconds, AbsoluteTimeoutSeconds: in.AbsoluteTimeoutSeconds, Digest: digest, AllowedDestinationCidrs: in.AllowedDestinationCIDRs, OriginCaPem: in.OriginCAPEM, OriginCaDigest: in.OriginCADigest})
}
func (s *Service) CreateDraft(ctx context.Context, org, actor uuid.UUID, input DraftInput, entitled bool) (Application, error) {
	in, digest, e := s.validateCurrent(ctx, input, "")
	if e != nil {
		return Application{}, e
	}
	var id uuid.UUID
	e = s.transaction(ctx, func(q *sqlc.Queries) error {
		if e := requireDraft(ctx, q, org, in.GatewayID, entitled); e != nil {
			return e
		}
		var e error
		id, e = q.CreateAppAccessApplication(ctx, org)
		if e != nil {
			return e
		}
		if e = reserveHost(ctx, q, org, id, in.PublicHostname); e != nil {
			return e
		}
		if e = insertRevision(ctx, q, org, id, 1, in, digest); e != nil {
			return e
		}
		return audit(ctx, q, org, actor, id.String(), "app_access.draft_created", 1)
	})
	if e != nil {
		return Application{}, mapDB(e)
	}
	return s.GetApplication(ctx, org, id)
}
func (s *Service) UpdateDraft(ctx context.Context, org, actor, app uuid.UUID, input DraftInput, expectedVersion int64, entitled bool) (Application, error) {
	current, e := s.GetApplication(ctx, org, app)
	if e != nil {
		return Application{}, e
	}
	if !input.AllowedDestinationCIDRsSet {
		input.AllowedDestinationCIDRs = current.Draft.AllowedDestinationCIDRs
	}
	if !input.IconDataURLSet {
		input.IconDataURL = current.Draft.IconDataURL
	}
	if !input.OriginCAPEMSet {
		input.OriginCAPEM = current.Draft.OriginCAPEM
	}
	existingHost := current.Draft.PublicHostname
	// Historical hostnames stay reserved to this exact tenant/application and
	// remain valid rollback targets after the installation base domain changes.
	candidateHost := strings.ToLower(input.PublicHostname)
	if candidateHost != existingHost {
		owns, err := sqlc.New(s.pool).OwnsAppAccessHostname(ctx, sqlc.OwnsAppAccessHostnameParams{OrgID: org, AppID: app, Hostname: candidateHost})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Application{}, err
		}
		if owns != nil && *owns {
			existingHost = candidateHost
		}
	}
	in, digest, e := s.validateCurrent(ctx, input, existingHost)
	if e != nil {
		return Application{}, e
	}
	e = s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, e := q.LockActiveAppAccessOrganization(ctx, org); errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		} else if e != nil {
			return e
		}
		version, e := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if errors.Is(e, pgx.ErrNoRows) {
			return notFound()
		}
		if e != nil {
			return e
		}
		current, e := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
		if e != nil {
			return e
		}
		if current.State != "draft" {
			return apierr.Conflict("application_archived", "archived application cannot be edited")
		}
		if version != expectedVersion {
			return conflict()
		}
		if e = requireDraft(ctx, q, org, in.GatewayID, entitled); e != nil {
			return e
		}
		if e = reserveHost(ctx, q, org, app, in.PublicHostname); e != nil {
			return e
		}
		if e = insertRevision(ctx, q, org, app, version+1, in, digest); e != nil {
			return e
		}
		if e = q.AdvanceAppAccessDraft(ctx, sqlc.AdvanceAppAccessDraftParams{OrgID: org, ID: app}); e != nil {
			return e
		}
		return audit(ctx, q, org, actor, app.String(), "app_access.draft_updated", version+1)
	})
	if e != nil {
		return Application{}, mapDB(e)
	}
	return s.GetApplication(ctx, org, app)
}
func mapDB(e error) error {
	var pe *pgconn.PgError
	if errors.As(e, &pe) && pe.Code == "23503" {
		return notFound()
	}
	return e
}
func (s *Service) requireActiveOrg(ctx context.Context, org uuid.UUID) error {
	exists, e := sqlc.New(s.pool).AppAccessOrganizationExists(ctx, org)
	if e != nil {
		return e
	}
	if !exists {
		return notFound()
	}
	return nil
}
func (s *Service) GetRevision(ctx context.Context, org, app uuid.UUID, revision int64) (Revision, error) {
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return Revision{}, e
	}
	r, e := sqlc.New(s.pool).GetAppAccessRevision(ctx, sqlc.GetAppAccessRevisionParams{OrgID: org, AppID: app, Revision: revision})
	if errors.Is(e, pgx.ErrNoRows) {
		e = notFound()
	}
	return Revision{DraftInput: DraftInput{Name: r.Name, Description: r.Description, Icon: r.Icon, IconDataURL: r.IconDataUrl, OriginURL: r.OriginUrl, GatewayID: r.GatewayID, PublicHostname: r.PublicHostname, IdleTimeoutSeconds: r.IdleTimeoutSeconds, AbsoluteTimeoutSeconds: r.AbsoluteTimeoutSeconds, AllowedDestinationCIDRs: r.AllowedDestinationCidrs, OriginCAPEM: r.OriginCaPem, OriginCADigest: r.OriginCaDigest}, Revision: r.Revision, Digest: r.Digest, CreatedAt: r.CreatedAt}, e
}
func (s *Service) GetApplication(ctx context.Context, org, app uuid.UUID) (Application, error) {
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return Application{}, e
	}
	r, e := sqlc.New(s.pool).GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
	a := Application{ID: r.ID, OrgID: r.OrgID, Version: r.Version, DraftRevision: r.DraftRevision, State: r.State, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ConnectorStatus: "unknown"}
	if errors.Is(e, pgx.ErrNoRows) {
		return a, notFound()
	}
	if e != nil {
		return a, e
	}
	a.RequireMFA, e = s.currentMFAPolicy(ctx, org, app)
	if e != nil {
		return a, e
	}
	a.PublicationState = "unpublished"
	pub, pe := sqlc.New(s.pool).GetAppAccessServingPublication(ctx, sqlc.GetAppAccessServingPublicationParams{OrgID: org, AppID: app})
	if pe != nil && !errors.Is(pe, pgx.ErrNoRows) {
		return a, publicationUnavailable()
	}
	if pe == nil {
		a.PublicationState = "disabled"
		if pub.State == "active" {
			a.PublicationState = "published"
			a.ActiveRevision = &pub.Revision
		}
	}
	if a.State == "archived" {
		a.PublicationState = "archived"
		a.ActiveRevision = nil
	}
	a.Draft, e = s.GetRevision(ctx, org, app, a.DraftRevision)
	if e != nil {
		return a, e
	}
	runtime, e := s.GetGatewayRuntime(ctx, org, a.Draft.GatewayID)
	if e == nil {
		a.ConnectorStatus = runtime.Status
	}
	return a, e
}
func (s *Service) ListApplications(ctx context.Context, org uuid.UUID, search string, limit, offset int32, publicationState ...string) ([]Application, error) {
	if e := s.requireActiveOrg(ctx, org); e != nil {
		return nil, e
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 || !utf8.ValidString(search) || utf8.RuneCountInString(search) > 100 {
		return nil, apierr.BadRequest("invalid_pagination", "invalid pagination or search")
	}
	filter := ""
	if len(publicationState) > 1 {
		return nil, apierr.BadRequest("invalid_publication_state", "invalid publication filter")
	}
	if len(publicationState) == 1 {
		filter = publicationState[0]
	}
	if filter != "" && filter != "unpublished" && filter != "published" && filter != "disabled" && filter != "archived" {
		return nil, apierr.BadRequest("invalid_publication_state", "invalid publication filter")
	}
	ids, e := sqlc.New(s.pool).ListAppAccessApplicationIDs(ctx, sqlc.ListAppAccessApplicationIDsParams{OrgID: org, Search: search, PageLimit: limit, PageOffset: offset, PublicationState: filter})
	if e != nil {
		return nil, e
	}
	out := make([]Application, 0, len(ids))
	for _, id := range ids {
		a, e := s.GetApplication(ctx, org, id)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, nil
}
