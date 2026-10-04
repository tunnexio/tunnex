package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// MFAFreshnessSeconds is deliberately fixed for the first per-app MFA policy.
// Assurances are reused across apps in the same current parent login.
const MFAFreshnessSeconds = 15 * 60

func (s *Service) WithMFAEnrollmentChecker(check func(context.Context, uuid.UUID) (bool, error)) *Service {
	s.mfaEnrolled = check
	return s
}

func (s *Service) currentMFAPolicy(ctx context.Context, org, app uuid.UUID) (bool, error) {
	required, err := sqlc.New(s.pool).GetAppAccessMFAPolicy(ctx, sqlc.GetAppAccessMFAPolicyParams{OrgID: org, ID: app})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, notFound()
	}
	if err != nil {
		return false, appInfrastructureUnavailable()
	}
	return required, nil
}

type appMFAStatus struct {
	Required, SetupRequired bool
	Deadline                time.Time
}

func trustedMFADeadline(parent session.Session, now time.Time) time.Time {
	verified := parent.MFAVerifiedAt
	if !session.ValidMFAAssurance(verified, parent.MFAAssuranceSource, now) {
		return time.Time{}
	}
	deadline := verified.Add(MFAFreshnessSeconds * time.Second)
	if !deadline.After(now) {
		return time.Time{}
	}
	return deadline
}

func (s *Service) applicationMFAStatus(ctx context.Context, required bool, parent session.Session) (appMFAStatus, error) {
	if !required {
		return appMFAStatus{}, nil
	}
	// Fresh verified SSO assurance is sufficient without enrolling a local factor.
	// AuthMethod by itself is never evidence of a successful second factor.
	if deadline := trustedMFADeadline(parent, s.now()); !deadline.IsZero() {
		return appMFAStatus{Deadline: deadline}, nil
	}
	if s.mfaEnrolled == nil {
		return appMFAStatus{}, appInfrastructureUnavailable()
	}
	enrolled, err := s.mfaEnrolled(ctx, parent.UserID)
	if err != nil {
		return appMFAStatus{}, appInfrastructureUnavailable()
	}
	return appMFAStatus{Required: true, SetupRequired: !enrolled}, nil
}

func (s *Service) requireAppMFA(ctx context.Context, org, app uuid.UUID, parent session.Session) (time.Time, error) {
	required, err := s.currentMFAPolicy(ctx, org, app)
	if err != nil {
		return time.Time{}, err
	}
	status, err := s.applicationMFAStatus(ctx, required, parent)
	if err != nil {
		return time.Time{}, err
	}
	if status.SetupRequired {
		return time.Time{}, apierr.Forbidden("app_mfa_setup_required", "set up your account authenticator to open this application")
	}
	if status.Required {
		return time.Time{}, apierr.Forbidden("app_mfa_required", "verify your account MFA to open this application")
	}
	return status.Deadline, nil
}

func (s *Service) UpdateMFAPolicy(ctx context.Context, org, actor, app uuid.UUID, required bool, expectedVersion int64) (Application, error) {
	if expectedVersion < 1 {
		return Application{}, apierr.BadRequest("invalid_version", "expected version must be positive")
	}
	err := s.transaction(ctx, func(q *sqlc.Queries) error {
		if _, err := q.LockActiveAppAccessOrganization(ctx, org); errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		} else if err != nil {
			return err
		}
		version, err := q.LockAppAccessApplication(ctx, sqlc.LockAppAccessApplicationParams{OrgID: org, ID: app})
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound()
		}
		if err != nil {
			return err
		}
		current, err := q.GetAppAccessApplication(ctx, sqlc.GetAppAccessApplicationParams{OrgID: org, ID: app})
		if err != nil {
			return err
		}
		if current.State != "draft" {
			return apierr.Conflict("application_archived", "archived application policy cannot be changed")
		}
		if version != expectedVersion {
			return conflict()
		}
		previous, err := q.GetAppAccessMFAPolicy(ctx, sqlc.GetAppAccessMFAPolicyParams{OrgID: org, ID: app})
		if err != nil {
			return err
		}
		if previous == required {
			return nil
		}
		changed, err := q.UpdateAppAccessMFAPolicy(ctx, sqlc.UpdateAppAccessMFAPolicyParams{OrgID: org, ID: app, RequireMfa: required, ExpectedVersion: expectedVersion})
		if err != nil {
			return err
		}
		if changed != 1 {
			return conflict()
		}
		metadata, err := json.Marshal(map[string]any{"version": version + 1, "require_mfa": required, "previous_require_mfa": previous, "mfa_freshness_seconds": MFAFreshnessSeconds})
		if err != nil {
			return err
		}
		kind, target := "app_access", app.String()
		_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Action: "app_access.mfa_policy_updated", TargetType: &kind, TargetID: &target, Metadata: metadata})
		return err
	})
	if err != nil {
		return Application{}, mapDB(err)
	}
	return s.GetApplication(ctx, org, app)
}
