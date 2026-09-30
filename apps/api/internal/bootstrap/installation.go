package bootstrap

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

// Installation is first-boot intent, never an instruction to change an existing
// deployment. Only the gateway token hash reaches the API process.
type Installation struct {
	OrganizationName string
	GatewayTokenHash string
	GatewayName      string
}

type installationQueries interface {
	Store
	CountOrganizationsEver(context.Context) (int64, error)
	CreateOrganization(context.Context, sqlc.CreateOrganizationParams) (sqlc.Organization, error)
	UpsertMembership(context.Context, sqlc.UpsertMembershipParams) (sqlc.Membership, error)
	CreateJoinToken(context.Context, sqlc.CreateJoinTokenParams) (sqlc.NodeJoinToken, error)
	InsertAuditLog(context.Context, sqlc.InsertAuditLogParams) (sqlc.AuditLog, error)
}

// EnsureInstallation commits the administrator, first organization and optional
// gateway grant together, before EnsureAdmin releases the one-time credential.
// Serializing first boot also prevents concurrent replicas minting two admins.
func EnsureInstallation(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, out io.Writer, email string, mailer mail.Mailer, intent Installation) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // also handles no-op and failed setup
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724196203)"); err != nil {
		return err
	}
	store := &installationStore{installationQueries: sqlc.New(tx), intent: intent, commit: tx.Commit}
	return EnsureAdmin(ctx, store, logger, out, email, mailer)
}

type installationStore struct {
	installationQueries
	intent Installation
	commit func(context.Context) error
}

func (s *installationStore) CreateBootstrapAdmin(ctx context.Context, params sqlc.CreateBootstrapAdminParams) (sqlc.User, error) {
	name := strings.TrimSpace(s.intent.OrganizationName)
	if (name == "" && s.intent.OrganizationName != "") || utf8.RuneCountInString(name) > 120 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return sqlc.User{}, errors.New("first organization name must contain 1 to 120 characters without control characters")
	}
	var hash []byte
	if s.intent.GatewayTokenHash != "" {
		var err error
		hash, err = hex.DecodeString(s.intent.GatewayTokenHash)
		if err != nil || len(hash) != 32 || name == "" || s.intent.GatewayName == "" || len(s.intent.GatewayName) > 128 || strings.IndexFunc(s.intent.GatewayName, unicode.IsControl) >= 0 {
			return sqlc.User{}, errors.New("local gateway bootstrap requires a first organization, gateway name and SHA-256 token hash")
		}
	}
	if name != "" {
		ever, err := s.CountOrganizationsEver(ctx)
		if err != nil {
			return sqlc.User{}, err
		}
		if ever != 0 {
			return sqlc.User{}, errors.New("refusing first-organization bootstrap on a previously configured deployment")
		}
	}
	user, err := s.installationQueries.CreateBootstrapAdmin(ctx, params)
	if err != nil {
		return sqlc.User{}, err
	}
	if name != "" {
		// The first organization has a stable URL-safe slug; its display name is
		// unrestricted Unicode and can be changed through the normal org API.
		org, err := s.CreateOrganization(ctx, sqlc.CreateOrganizationParams{Name: name, Slug: "first-organization"})
		if err != nil {
			return sqlc.User{}, err
		}
		if _, err = s.UpsertMembership(ctx, sqlc.UpsertMembershipParams{OrgID: org.ID, UserID: user.ID, Role: "owner"}); err != nil {
			return sqlc.User{}, err
		}
		if err = s.audit(ctx, org.ID, user.ID, "org.created", "organization", org.ID.String(), map[string]string{"name": name, "slug": org.Slug, "source": "installer"}); err != nil {
			return sqlc.User{}, err
		}
		if len(hash) != 0 {
			if _, err = s.CreateJoinToken(ctx, sqlc.CreateJoinTokenParams{
				OrgID: org.ID, NodeName: &s.intent.GatewayName, TokenHash: hash,
				ExpiresAt: time.Now().Add(time.Hour), IssuedBy: pgtype.UUID{Bytes: user.ID, Valid: true}, EnrolsKind: "gateway",
			}); err != nil {
				return sqlc.User{}, err
			}
			if err = s.audit(ctx, org.ID, user.ID, "node.token_issued", "node", s.intent.GatewayName, map[string]string{"node_name": s.intent.GatewayName, "source": "installer"}); err != nil {
				return sqlc.User{}, err
			}
		}
	}
	if err = s.commit(ctx); err != nil {
		return sqlc.User{}, err
	}
	return user, nil
}

func (s *installationStore) audit(ctx context.Context, org, actor uuid.UUID, action, kind, target string, metadata map[string]string) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = s.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true},
		Action: action, TargetType: &kind, TargetID: &target, Metadata: b,
	})
	return err
}
