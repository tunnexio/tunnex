// Package beam owns desktop publication resources and continuous browser authority.
package beam

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appdomains"
	"github.com/tunnexio/tunnex/apps/api/internal/beamreadiness"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/packages/apptransport"
	beamtransport "github.com/tunnexio/tunnex/packages/apptransport/beam"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
)

type Config struct {
	BaseDomain, ProxyURL, PortalURL, RestoreMarker string
	DomainReady                                    bool
	DevelopmentAllowLoopback                       bool
	DevelopmentPublicCA                            []byte
}
type Signer interface {
	SignCSR([]byte, string) (agentca.Issued, error)
	CertPEM() []byte
}
type Sessions interface {
	GetNoTouch(context.Context, string) (session.Session, time.Time, error)
}
type Service struct {
	pool           *pgxpool.Pool
	config         Config
	signer         Signer
	sessions       Sessions
	sweepMu        sync.Mutex
	sweepAfterTime time.Time
	sweepAfterID   uuid.UUID
	inspector      *beamreadiness.Inspector
	inspectorError error
}

func New(pool *pgxpool.Pool, cfg Config, signer Signer, sessions Sessions) *Service {
	inspector, e := beamreadiness.NewConfigured(cfg.DevelopmentAllowLoopback, cfg.DevelopmentPublicCA)
	return &Service{pool: pool, config: cfg, signer: signer, sessions: sessions, inspector: inspector, inspectorError: e}
}

type reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}
type Actor struct {
	ID                      uuid.UUID
	SessionID               string
	CredentialID            uuid.UUID
	ManagePolicy, ManageAll bool
}
type Target struct {
	Protocol string  `json:"protocol"`
	Address  string  `json:"address"`
	Port     int     `json:"port"`
	CAPEM    string  `json:"ca_pem,omitempty"`
	Routes   []Route `json:"routes,omitempty"`
}
type Route struct {
	PathPrefix string `json:"path_prefix"`
	Target     Target `json:"target"`
}
type Grant struct {
	SubjectKind string    `json:"subject_kind"`
	SubjectID   uuid.UUID `json:"subject_id"`
}
type Policy struct {
	Capabilities     []string    `json:"capabilities"`
	OpenForAllUsers  bool        `json:"open_for_all_users"`
	Enabled          bool        `json:"enabled"`
	Version          int64       `json:"version"`
	PublisherGroups  []uuid.UUID `json:"publisher_group_ids"`
	ReviewerUsers    []uuid.UUID `json:"reviewer_user_ids"`
	ReviewerGroups   []uuid.UUID `json:"reviewer_group_ids"`
	MaxDuration      int         `json:"max_duration_seconds"`
	MaxShares        int         `json:"max_shares"`
	RequireMFA       bool        `json:"require_mfa"`
	BaseDomain       string      `json:"base_domain"`
	DomainReady      bool        `json:"domain_ready"`
	domainReadyUntil time.Time
	domainProxyURL   string
	CanPublish       bool   `json:"can_publish"`
	CanManagePolicy  bool   `json:"can_manage_policy"`
	ProtocolVersion  int    `json:"protocol_version"`
	MinClientVersion string `json:"min_client_version"`
}
type PolicyInput struct {
	// Omission preserves the current mode for older policy editors.
	OpenForAllUsers        *bool       `json:"open_for_all_users,omitempty"`
	Enabled                bool        `json:"enabled"`
	ExpectedVersion        int64       `json:"expected_version"`
	PublisherGroups        []uuid.UUID `json:"publisher_group_ids"`
	ReviewerUsers          []uuid.UUID `json:"reviewer_user_ids"`
	ReviewerGroups         []uuid.UUID `json:"reviewer_group_ids"`
	MaxDuration            int         `json:"max_duration_seconds"`
	MaxShares              int         `json:"max_shares"`
	RequireMFA             bool        `json:"require_mfa"`
	ConfirmEndActiveShares bool        `json:"confirm_end_active_shares,omitempty"`
}
type Share struct {
	ProjectID               *uuid.UUID `json:"project_id,omitempty"`
	ID                      uuid.UUID  `json:"id"`
	OrgID                   uuid.UUID  `json:"org_id"`
	PublisherID             uuid.UUID  `json:"publisher_id"`
	Name                    string     `json:"name"`
	PublisherName           string     `json:"publisher_name,omitempty"`
	Hostname                string     `json:"hostname"`
	URL                     string     `json:"url"`
	Target                  *Target    `json:"target,omitempty"`
	State                   string     `json:"state"`
	Connectivity            string     `json:"connectivity"`
	Version                 int64      `json:"version"`
	AuthorityVersion        int64      `json:"authority_version"`
	ExpiresAt               time.Time  `json:"expires_at"`
	CreatedAt               time.Time  `json:"created_at"`
	Grants                  []Grant    `json:"grants,omitempty"`
	CanManage               bool       `json:"can_manage"`
	CanOpen                 bool       `json:"can_open"`
	ConnectorID             uuid.UUID  `json:"-"`
	Generation              uuid.UUID  `json:"-"`
	Digest                  string     `json:"-"`
	Serial                  *string    `json:"-"`
	SourceCredentialID      *uuid.UUID `json:"-"`
	SourceSessionID         string     `json:"-"`
	OriginReady             bool       `json:"-"`
	LastHeartbeat           *time.Time `json:"-"`
	ServingAuthorityVersion int64      `json:"-"`
	LastChannel             *time.Time `json:"-"`
}
type CreateInput struct {
	ProjectID      *uuid.UUID `json:"project_id,omitempty"`
	Name           string     `json:"name"`
	Target         Target     `json:"target"`
	Duration       int        `json:"duration_seconds"`
	Grants         []Grant    `json:"grants"`
	IdempotencyKey uuid.UUID  `json:"idempotency_key"`
}
type ActionInput struct {
	Action          string     `json:"action"`
	ExpectedVersion int64      `json:"expected_version"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}
type GrantsInput struct {
	ExpectedVersion        int64   `json:"expected_version"`
	Grants                 []Grant `json:"grants"`
	ConfirmReviewerRemoval bool    `json:"confirm_reviewer_removal,omitempty"`
}
type ConnectorInput struct {
	Capabilities    []string `json:"capabilities,omitempty"`
	ExpectedVersion int64    `json:"expected_version"`
	CSR             string   `json:"csr_pem"`
}
type Binding struct {
	OrgID            uuid.UUID `json:"org_id"`
	AppID            uuid.UUID `json:"app_id"`
	GatewayID        uuid.UUID `json:"gateway_id"`
	Generation       uuid.UUID `json:"generation"`
	Revision         int64     `json:"revision"`
	AuthorityVersion int64     `json:"authority_version"`
	Digest           string    `json:"digest"`
	Hostname         string    `json:"hostname"`
	Purpose          string    `json:"purpose"`
}

func (b Binding) Transport() apptransport.Binding {
	return apptransport.Binding{OrgID: b.OrgID.String(), AppID: b.AppID.String(), GatewayID: b.GatewayID.String(), Generation: b.Generation.String(), Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Digest: b.Digest, Hostname: b.Hostname, Purpose: b.Purpose}
}
func (r Share) Binding() Binding {
	return Binding{r.OrgID, r.ID, r.ConnectorID, r.Generation, 1, r.ServingAuthorityVersion, r.Digest, r.Hostname, "beam_proxy"}
}

type Connector struct {
	Binding              Binding   `json:"binding"`
	ShareVersion         int64     `json:"share_version"`
	ProxyURL             string    `json:"proxy_url"`
	ProxyServerName      string    `json:"proxy_server_name"`
	CAPEM                string    `json:"ca_pem"`
	CertificatePEM       string    `json:"certificate_pem"`
	ExpiresAt            time.Time `json:"expires_at"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}
type Heartbeat struct {
	Generation  uuid.UUID `json:"generation"`
	OriginReady bool      `json:"origin_ready"`
}
type User struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
}
type Group struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}
type Audience struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
}
type Event struct {
	ID        uuid.UUID  `json:"id"`
	ShareID   string     `json:"share_id"`
	Action    string     `json:"action"`
	Outcome   string     `json:"outcome"`
	Reason    string     `json:"reason"`
	ActorID   *uuid.UUID `json:"actor_id"`
	CreatedAt time.Time  `json:"created_at"`
}
type Page[T any] struct {
	Items      []T       `json:"items"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
	ServerTime time.Time `json:"server_time"`
	Quota      *Quota    `json:"quota,omitempty"`
}

// Quota counts the publisher's complete inventory, independently of list filters.
type Quota struct {
	ActiveShares int `json:"active_shares"`
	MaxShares    int `json:"max_shares"`
}

func deny() error {
	return apierr.Forbidden("beam_authority_unavailable", "Beam authority is unavailable")
}
func unavailable() error {
	return apierr.New(503, "beam_unavailable", "Beam is not configured or enabled")
}
func conflict() error {
	return apierr.Conflict("beam_version_conflict", "Share or policy changed; refresh and retry")
}
func missing() error           { return apierr.NotFound("beam_share_not_found", "Share not found") }
func invalid(msg string) error { return apierr.BadRequest("beam_invalid", msg) }
func terminal(state string) bool {
	return state == "stopped" || state == "expired" || state == "revoked"
}
func hash(v string) []byte { h := sha256.Sum256([]byte(v)); return h[:] }
func digest(v any) string  { b, _ := json.Marshal(v); return hex.EncodeToString(hash(string(b))) }
func ValidateTarget(t Target) error {
	if len(t.Routes) > 8 {
		return invalid("At most eight routes are supported")
	}
	seen := map[string]bool{}
	for _, r := range t.Routes {
		if !beamtransport.ValidPathPrefix(r.PathPrefix) || seen[r.PathPrefix] || len(r.Target.Routes) > 0 {
			return invalid("Invalid or duplicate route prefix")
		}
		seen[r.PathPrefix] = true
		if e := ValidateTarget(r.Target); e != nil {
			return e
		}
	}
	if (t.Protocol != "http" && t.Protocol != "https") || (t.Address != "127.0.0.1" && t.Address != "::1") || t.Port < 1 || t.Port > 65535 || len(t.CAPEM) > 16384 || strings.ContainsAny(t.CAPEM, "\x00") {
		return invalid("Select HTTP or HTTPS and an exact numeric loopback address and valid port")
	}
	if t.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(t.CAPEM)) {
		return invalid("Invalid local HTTPS trust anchor")
	}
	if t.Protocol == "http" && t.CAPEM != "" {
		return invalid("HTTP targets do not accept a trust anchor")
	}
	return nil
}
func relative(v string) bool {
	u, e := url.Parse(v)
	return e == nil && len(v) <= 2048 && utf8.ValidString(v) && strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.ContainsAny(v, "\\\r\n\x00") && u.IsAbs() == false && u.Host == "" && u.Fragment == ""
}
func (s *Service) domainReady() bool {
	u, e := url.Parse(s.config.ProxyURL)
	_, ep := appdomains.Normalize(appdomains.Config{PortalURL: s.config.PortalURL, AppBaseDomain: s.config.BaseDomain})
	return restorebarrier.Check(s.config.RestoreMarker) == nil && s.config.DomainReady && len(s.config.BaseDomain) <= 218 && appdomains.Host(s.config.BaseDomain) && e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && ep == nil
}

func canonicalSerial(raw string) string {
	if len(raw) == 0 || len(raw) > 64 {
		return ""
	}
	for _, digit := range raw {
		if !((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') || (digit >= 'A' && digit <= 'F')) {
			return ""
		}
	}
	n, ok := new(big.Int).SetString(raw, 16)
	if !ok || n.Sign() <= 0 {
		return ""
	}
	return n.Text(16)
}

const shareColumns = `id,org_id,publisher_id,name,hostname,target,state,version,authority_version,expires_at,created_at,connector_id,generation,digest,certificate_serial,source_credential_id,source_session_id,origin_ready,last_heartbeat_at,serving_authority_version,last_channel_at,project_id`

func scanShare(row pgx.Row) (Share, error) {
	var r Share
	var raw []byte
	e := row.Scan(&r.ID, &r.OrgID, &r.PublisherID, &r.Name, &r.Hostname, &raw, &r.State, &r.Version, &r.AuthorityVersion, &r.ExpiresAt, &r.CreatedAt, &r.ConnectorID, &r.Generation, &r.Digest, &r.Serial, &r.SourceCredentialID, &r.SourceSessionID, &r.OriginReady, &r.LastHeartbeat, &r.ServingAuthorityVersion, &r.LastChannel, &r.ProjectID)
	if e != nil {
		return r, e
	}
	var t Target
	if e = json.Unmarshal(raw, &t); e != nil {
		return r, e
	}
	r.Target = &t
	r.URL = "https://" + r.Hostname
	r.Connectivity = "offline"
	if r.LastHeartbeat != nil && r.LastHeartbeat.After(time.Now().Add(-6*time.Second)) && r.LastChannel != nil && r.LastChannel.After(time.Now().Add(-6*time.Second)) {
		r.Connectivity = "online"
		if !r.OriginReady {
			r.Connectivity = "origin_unavailable"
		}
	}
	if !r.ExpiresAt.After(time.Now()) && !terminal(r.State) {
		r.State = "expired"
	}
	return r, nil
}

// Owner projections include an empty audience; reviewer projections omit it.
func (r Share) MarshalJSON() ([]byte, error) {
	type alias Share
	var grants *[]Grant
	if r.Grants != nil {
		grants = &r.Grants
	}
	return json.Marshal(struct {
		alias
		Grants *[]Grant `json:"grants,omitempty"`
	}{alias(r), grants})
}
