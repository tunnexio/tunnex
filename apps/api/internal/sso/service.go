package sso

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ProviderFactory builds a Provider from a decrypted Config (injectable for tests).
type ProviderFactory func(ctx context.Context, cfg Config, redirectURL string) (Provider, error)

// DefaultProviderFactory maps a config to its provider. Adding Microsoft is one
// case: config (TenantID) + adapter (NewMicrosoft) — no change to the shared flow.
func DefaultProviderFactory(ctx context.Context, cfg Config, redirectURL string) (Provider, error) {
	switch cfg.Provider {
	case "google":
		return NewGoogle(ctx, cfg.ClientID, cfg.ClientSecret, redirectURL)
	case "microsoft":
		return NewMicrosoft(ctx, cfg.TenantID, cfg.ClientID, cfg.ClientSecret, redirectURL)
	default:
		return nil, apierr.BadRequest("unknown_provider", "unknown SSO provider: "+cfg.Provider)
	}
}

// Service orchestrates the SSO login flow.
type Service struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	configs *ConfigService
	flows   *FlowStore
	factory ProviderFactory
	baseURL string
	logger  *slog.Logger
	// licence answers "may this deployment still ONBOARD somebody through SSO". ⚠ nil => permitted, the
	// fail-open default every other consumer uses: a deployment that upgrades into this code keeps working.
	licence *licence.Manager
}

// WithLicence wires the entitlement source. Optional; without it, onboarding is permitted.
func (s *Service) WithLicence(m *licence.Manager) *Service { s.licence = m; return s }

// mayOnboard reports whether SSO may bring a NEW person into this deployment.
//
// ⛔ THIS IS NOT "MAY SSO LOGIN WORK". Login is never gated and must never be — an org whose only identity
// source is Entra would otherwise lose access to the screen where the licence is renewed, and the refusal
// would delete the remedy along with the capability.
//
// ⭐ WHAT IT GATES IS ADMISSION: minting a local account for an identity we have never seen (JIT), and
// auto-joining a captured domain. Both CREATE something; neither is something an existing person already
// depends on. That line is what makes the trial's SSO grant bounded rather than permanent — a lapsed
// trial keeps the humans it had and stops collecting new ones.
func (s *Service) mayOnboard() bool {
	return s.licence == nil || s.licence.Has(licence.FeatSSO, time.Now())
}

// NewService builds the SSO service.
func NewService(pool *pgxpool.Pool, configs *ConfigService, flows *FlowStore, factory ProviderFactory, baseURL string, logger *slog.Logger) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), configs: configs, flows: flows, factory: factory, baseURL: baseURL, logger: logger}
}

// Configs exposes the config service (for the admin set-config endpoint).
func (s *Service) Configs() *ConfigService { return s.configs }

func (s *Service) redirectURL(provider string) string {
	return s.baseURL + "/api/v1/auth/sso/" + provider + "/callback"
}

// StartLogin builds the IdP redirect URL for org/provider and stores flow state.
func (s *Service) StartLogin(ctx context.Context, orgID uuid.UUID, provider string) (string, error) {
	cfg, err := s.configs.Get(ctx, orgID, provider)
	if err != nil {
		return "", err
	}
	if !cfg.Enabled {
		return "", apierr.NotFound("sso_not_configured", "SSO is not enabled for this provider")
	}
	prov, err := s.factory(ctx, cfg, s.redirectURL(provider))
	if err != nil {
		return "", err
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
	if err := s.flows.Save(ctx, state, flowState{Nonce: nonce, Verifier: verifier, OrgID: orgID, Provider: provider}); err != nil {
		return "", err
	}
	return prov.AuthCodeURL(state, nonce, challenge), nil
}

// HandleCallback validates state, exchanges+verifies the code, applies the
// linking policy, provisions/links the user, ensures org membership, and returns
// the resolved user id for the caller to mint a session.
func (s *Service) HandleCallback(ctx context.Context, provider, code, state string) (uuid.UUID, error) {
	fs, err := s.flows.Take(ctx, state)
	if err != nil {
		return uuid.Nil, apierr.BadRequest("invalid_state", "the SSO login could not be verified; please try again")
	}
	if fs.Provider != provider {
		return uuid.Nil, apierr.BadRequest("invalid_state", "provider mismatch")
	}
	cfg, err := s.configs.Get(ctx, fs.OrgID, provider)
	if err != nil {
		return uuid.Nil, err
	}
	prov, err := s.factory(ctx, cfg, s.redirectURL(provider))
	if err != nil {
		return uuid.Nil, err
	}
	identity, err := prov.Exchange(ctx, code, fs.Verifier, fs.Nonce)
	if err != nil {
		return uuid.Nil, apierr.New(401, "sso_verification_failed", "could not verify the SSO login")
	}
	return s.resolveUser(ctx, identity, fs.OrgID)
}

// resolveUser applies DecideLink and provisions/links the user + org membership.
func (s *Service) resolveUser(ctx context.Context, id Identity, orgID uuid.UUID) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		local, err := q.GetUserByEmail(ctx, id.Email)
		localExists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		localVerified := localExists && local.EmailVerifiedAt.Valid

		switch DecideLink(localExists, localVerified, id.EmailVerified) {
		case LinkReject:
			return apierr.New(409, "sso_link_required",
				"an account with this email exists; sign in and link SSO from settings")
		case LinkCreate:
			// ⛔ ADMISSION IS WHAT LAPSES, NOT ACCESS. A deployment past its licence keeps every person it
			// already has — they sign in exactly as before — and stops minting accounts for identities it
			// has never seen. The refusal is 403 with a reason a human can act on, not a silent no-op.
			if !s.mayOnboard() {
				return apierr.New(403, "edition_required",
					"This deployment's licence does not cover adding new people through SSO. Existing "+
						"sign-ins are unaffected — install a licence, or have an administrator invite "+
						"this person.")
			}
			created, e := q.CreateUser(ctx, sqlc.CreateUserParams{Email: id.Email, Name: id.Name, PasswordHash: nil})
			if e != nil {
				return e
			}
			if e := q.MarkEmailVerified(ctx, created.ID); e != nil { // IdP asserted verified
				return e
			}
			userID = created.ID
		case LinkAttach:
			userID = local.ID
		}

		// JIT membership into the org the user logged in through.
		if e := s.ensureMembership(ctx, q, orgID, userID, "sso_login", id); e != nil {
			return e
		}

		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// ensureMembership adds a member-role membership if absent, auditing the JIT join
// (with the IdP subject) only when it actually creates one — no audit spam on
// repeat logins. Role is always member (least privilege; group mapping is a
// separate future story).
func (s *Service) ensureMembership(ctx context.Context, q *sqlc.Queries, orgID, userID uuid.UUID, via string, id Identity) error {
	if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: userID}); err == nil {
		return nil // already a member
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := q.UpsertMembership(ctx, sqlc.UpsertMembershipParams{OrgID: orgID, UserID: userID, Role: rbac.RoleMember}); err != nil {
		return err
	}
	// A JIT join makes any pending invite for this (org, email) moot.
	if err := q.SupersedePendingInvites(ctx, sqlc.SupersedePendingInvitesParams{OrgID: orgID, Email: id.Email}); err != nil {
		return err
	}
	uid := userID
	return audit(ctx, q, orgID, &uid, "member.jit_joined", "membership", userID.String(),
		map[string]any{"via": via, "provider": id.Provider, "idp_subject": id.Subject})
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
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
