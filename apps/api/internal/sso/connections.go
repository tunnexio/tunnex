package sso

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type ConnectionInput struct {
	Name, Provider, Issuer, ClientID string
	Secret                           *string
}
type connectionFlow struct {
	BrowserHash                [32]byte
	ConnectionID, OrgID, Actor uuid.UUID
	Revision                   int64
	Nonce, Verifier, Mode      string
	Link                       bool
}
type ConnectionResult struct {
	UserID, OrgID, ConnectionID uuid.UUID
	Test                        bool
	Link                        bool
}

func (s *Service) ConnectionCallbackURL() string {
	return s.baseURL + "/api/v1/auth/sso-connections/callback"
}
func (s *Service) ListConnections(ctx context.Context, org uuid.UUID) ([]sqlc.SsoConnection, error) {
	return s.q.ListSSOConnections(ctx, org)
}
func (s *Service) SaveConnection(ctx context.Context, actor, org, id uuid.UUID, in ConnectionInput) (out sqlc.SsoConnection, err error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Issuer = strings.TrimRight(strings.TrimSpace(in.Issuer), "/")
	in.ClientID = strings.TrimSpace(in.ClientID)
	if id == uuid.Nil || in.Name == "" || len(in.Name) > 80 || in.ClientID == "" || len(in.ClientID) > 500 || (in.Provider != "okta" && in.Provider != "oidc") {
		return out, apierr.BadRequest("invalid_connection", "connection name, provider and client ID are required")
	}
	if e := ValidateCustomIssuer(in.Issuer); e != nil {
		return out, apierr.BadRequest("invalid_issuer", e.Error())
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		old, e := q.LockSSOConnection(ctx, id)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil && old.OrgID != org {
			return apierr.NotFound("sso_not_configured", "connection not found")
		}
		if e == nil && (old.IssuerUrl != in.Issuer || old.ClientID != in.ClientID || old.Provider != in.Provider) {
			linked, lookup := q.HasSSOConnectionIdentities(ctx, id)
			if lookup != nil {
				return lookup
			}
			managed, lookup := q.IsDirectoryManagedConnection(ctx, pgtype.UUID{Bytes: id, Valid: true})
			if lookup != nil {
				return lookup
			}
			if linked || managed {
				return apierr.New(409, "sso_identity_namespace_locked", "create a new connection to change the issuer or client ID after accounts have been linked")
			}
		}
		sealed := old.ClientSecretSealed
		if in.Secret != nil {
			if *in.Secret == "" || len(*in.Secret) > 4000 {
				return apierr.BadRequest("invalid_secret", "client secret is required")
			}
			var encoded string
			encoded, e = s.configs.sealer.Seal([]byte(*in.Secret))
			sealed = []byte(encoded)
			if e != nil {
				return e
			}
		}
		if len(sealed) == 0 {
			return apierr.BadRequest("invalid_secret", "client secret is required for a new connection")
		}
		out, e = q.SaveSSOConnection(ctx, sqlc.SaveSSOConnectionParams{ID: id, OrgID: org, Name: in.Name, Provider: in.Provider, IssuerUrl: in.Issuer, ClientID: in.ClientID, ClientSecretSealed: sealed})
		if e != nil {
			return e
		}
		return audit(ctx, q, org, &actor, "sso.connection_saved", "sso_connection", id.String(), map[string]any{"revision": out.Revision, "enabled": false})
	})
	return
}
func (s *Service) ActivateConnection(ctx context.Context, actor, org, id uuid.UUID, revision int64, enabled bool) (out sqlc.SsoConnection, err error) {
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		var e error
		out, e = q.ActivateSSOConnection(ctx, sqlc.ActivateSSOConnectionParams{OrgID: org, ID: id, Revision: revision, Enabled: enabled})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.New(409, "sso_test_required", "reload the connection and complete a successful test before enabling")
		}
		if e != nil {
			return e
		}
		return audit(ctx, q, org, &actor, "sso.connection_activation_changed", "sso_connection", id.String(), map[string]any{"enabled": enabled, "revision": revision})
	})
	return
}
func (s *Service) connectionProvider(ctx context.Context, c sqlc.SsoConnection) (Provider, error) {
	if s.connectionFactory != nil {
		return s.connectionFactory(ctx, c)
	}
	secret, err := s.configs.sealer.Open(string(c.ClientSecretSealed))
	if err != nil {
		return nil, err
	}
	return NewCustomProvider(ctx, c.IssuerUrl, c.ClientID, string(secret), s.ConnectionCallbackURL())
}
func (s *Service) StartConnection(ctx context.Context, org, id, actor uuid.UUID, test, link bool, browserBinding string) (string, error) {
	if len(browserBinding) < 32 {
		return "", apierr.BadRequest("invalid_state", "browser binding required")
	}
	c, err := s.q.GetSSOConnection(ctx, id)
	if err != nil {
		return "", apierr.NotFound("sso_not_configured", "connection not available")
	}
	if test || link {
		if c.OrgID != org || actor == uuid.Nil {
			return "", apierr.NotFound("sso_not_configured", "connection not available")
		}
	}
	if !test && !c.Enabled {
		return "", apierr.NotFound("sso_not_configured", "connection not available")
	}
	p, err := s.connectionProvider(ctx, c)
	if err != nil {
		return "", apierr.BadRequest("sso_discovery_failed", "could not discover the HTTPS issuer; check the issuer URL and its public OIDC endpoints")
	}
	state, err := RandomToken()
	if err != nil {
		return "", err
	}
	nonce, err := RandomToken()
	if err != nil {
		return "", err
	}
	verifier, challenge, err := PKCE()
	if err != nil {
		return "", err
	}
	mode := "login"
	if link && !test {
		mode = "link"
	}
	if test {
		mode = "test"
	}
	raw, err := json.Marshal(connectionFlow{ConnectionID: id, OrgID: c.OrgID, Actor: actor, Revision: c.Revision, Nonce: nonce, Verifier: verifier, Mode: mode, Link: link, BrowserHash: sha256.Sum256([]byte(browserBinding))})
	if err != nil {
		return "", err
	}
	if err = s.flows.rdb.Set(ctx, "ssoconnection:"+state, raw, 10*time.Minute).Err(); err != nil {
		return "", err
	}
	return p.AuthCodeURL(state, nonce, challenge), nil
}
func connectionFlowCurrent(f connectionFlow, c sqlc.SsoConnection, actor uuid.UUID) bool {
	return f.ConnectionID == c.ID && f.OrgID == c.OrgID && f.Revision == c.Revision && (((f.Mode == "test" || (f.Mode == "link" && c.Enabled)) && actor != uuid.Nil && actor == f.Actor) || (f.Mode == "login" && c.Enabled))
}
func (s *Service) CompleteConnection(ctx context.Context, code, state, browserBinding string, actor uuid.UUID) (result ConnectionResult, err error) {
	raw, e := s.flows.rdb.Get(ctx, "ssoconnection:"+state).Bytes()
	if e != nil {
		return result, apierr.BadRequest("invalid_state", "the SSO request expired or was already used")
	}
	var flow connectionFlow
	if json.Unmarshal(raw, &flow) != nil {
		return result, apierr.BadRequest("invalid_state", "invalid SSO request")
	}
	if !validBrowserBinding(flow.BrowserHash, browserBinding) {
		return result, apierr.BadRequest("invalid_state", "finish sign-in in the browser where you started it")
	}
	consumed, e := s.flows.rdb.GetDel(ctx, "ssoconnection:"+state).Bytes()
	if e != nil || string(consumed) != string(raw) {
		return result, apierr.BadRequest("invalid_state", "the SSO request expired or was already used")
	}
	result.ConnectionID = flow.ConnectionID
	result.Link = flow.Mode == "link"
	result.OrgID = flow.OrgID
	result.Test = flow.Mode == "test"
	if code == "" {
		return result, apierr.BadRequest("sso_consent_denied", "sign-in was cancelled or the provider did not return an authorization code")
	}
	c, e := s.q.GetSSOConnection(ctx, flow.ConnectionID)
	if e != nil || !connectionFlowCurrent(flow, c, actor) {
		return result, apierr.New(409, "sso_test_stale", "connection changed or the initiating administrator session is no longer active")
	}
	p, e := s.connectionProvider(ctx, c)
	if e != nil {
		return result, apierr.BadRequest("sso_discovery_failed", "could not reach the configured issuer")
	}
	identity, e := p.Exchange(ctx, code, flow.Verifier, flow.Nonce)
	if e != nil {
		return result, apierr.New(401, "sso_verification_failed", "could not verify the SSO identity")
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		current, e := q.LockSSOConnection(ctx, c.ID)
		if e != nil {
			return e
		}
		if !connectionFlowCurrent(flow, current, actor) {
			return apierr.New(409, "sso_test_stale", "connection changed during verification")
		}
		if result.Test || result.Link {
			// Recheck current admin membership after the external round-trip.
			membership, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: c.OrgID, UserID: actor})
			if e != nil || (result.Test && membership.Role != "owner" && membership.Role != "admin") {
				return apierr.New(403, "forbidden", "organization administrator access is required")
			}
			if flow.Link {
				u, e := q.GetUserByID(ctx, actor)
				if e != nil {
					return e
				}
				if !u.EmailVerifiedAt.Valid || !strings.EqualFold(u.Email, identity.Email) {
					return apierr.New(409, "sso_link_required", "the test identity must match your verified account email to link")
				}
				if e = s.linkConnectionIdentity(ctx, q, c, identity, actor); e != nil {
					return e
				}
			}
			if result.Link {
				return audit(ctx, q, c.OrgID, &actor, "sso.identity_linked", "sso_connection", c.ID.String(), map[string]any{"revision": c.Revision})
			}
			if _, e = q.VerifySSOConnection(ctx, sqlc.VerifySSOConnectionParams{ID: c.ID, Revision: c.Revision}); e != nil {
				return e
			}
			return audit(ctx, q, c.OrgID, &actor, "sso.connection_verified", "sso_connection", c.ID.String(), map[string]any{"revision": c.Revision, "linked": flow.Link})
		}
		managed, e := q.IsDirectoryManagedConnection(ctx, pgtype.UUID{Bytes: c.ID, Valid: true})
		if e != nil {
			return e
		}
		uid, e := q.GetSSOConnectionIdentity(ctx, sqlc.GetSSOConnectionIdentityParams{ConnectionID: c.ID, IssuerUrl: c.IssuerUrl, Subject: identity.Subject})
		if errors.Is(e, pgx.ErrNoRows) {
			if managed {
				return apierr.New(403, "directory_membership_required", "your account must be synced from a mapped Okta group before sign-in")
			}
			_, lookup := q.GetUserByEmail(ctx, identity.Email)
			if lookup == nil {
				return apierr.New(409, "sso_link_required", "sign in using an existing method, then link company sign-in in Settings → Authentication")
			}
			if !errors.Is(lookup, pgx.ErrNoRows) {
				return lookup
			}
			if !s.mayOnboard() {
				return apierr.New(403, "edition_required", "new SSO users require an active entitlement")
			}
			u, create := q.CreateUser(ctx, sqlc.CreateUserParams{Email: identity.Email, Name: identity.Name})
			if create != nil {
				return create
			}
			uid = u.ID
			if e = q.MarkEmailVerified(ctx, uid); e != nil {
				return e
			}
			if e = s.linkConnectionIdentity(ctx, q, c, identity, uid); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if managed {
			if _, e = q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: c.OrgID, UserID: uid}); e != nil {
				return apierr.New(403, "directory_membership_required", "your directory-managed organization access is not active")
			}
		} else if e = s.ensureMembership(ctx, q, c.OrgID, uid, "sso_connection", identity); e != nil {
			return e
		}
		if managed {
			imported, check := q.IsDirectoryImportedIdentity(ctx, sqlc.IsDirectoryImportedIdentityParams{ConnectionID: c.ID, IssuerUrl: c.IssuerUrl, Subject: identity.Subject})
			if check != nil {
				return check
			}
			if imported {
				account, check := q.GetUserByEmail(ctx, identity.Email)
				if check != nil || account.ID != uid || !identity.EmailVerified {
					return apierr.New(403, "directory_identity_conflict", "verified sign-in email does not match the imported account")
				}
				if check = q.MarkEmailVerified(ctx, uid); check != nil {
					return check
				}
			}
		}
		result.UserID = uid
		return nil
	})
	return
}
func (s *Service) linkConnectionIdentity(ctx context.Context, q *sqlc.Queries, c sqlc.SsoConnection, id Identity, uid uuid.UUID) error {
	existing, e := q.GetSSOConnectionIdentity(ctx, sqlc.GetSSOConnectionIdentityParams{ConnectionID: c.ID, IssuerUrl: c.IssuerUrl, Subject: id.Subject})
	if e == nil {
		if existing != uid {
			return apierr.New(409, "sso_link_required", "identity is already linked to another account")
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	return q.LinkSSOConnectionIdentity(ctx, sqlc.LinkSSOConnectionIdentityParams{ConnectionID: c.ID, IssuerUrl: c.IssuerUrl, Subject: id.Subject, UserID: uid})
}

func validBrowserBinding(expected [32]byte, binding string) bool {
	if len(binding) < 32 {
		return false
	}
	got := sha256.Sum256([]byte(binding))
	return subtle.ConstantTimeCompare(expected[:], got[:]) == 1
}
