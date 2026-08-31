package nodes

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const (
	LifecycleInstallActive         = "active"
	LifecycleInstallAbortRequested = "abort_requested"
	LifecycleInstallExpired        = "expired"
	LifecycleInstallReleased       = "released"
	LifecycleInstallAborting       = "aborting"
	LifecycleInstallCompleted      = "completed"
	LifecycleInstallAborted        = "aborted"

	MaxLifecycleInstallDuration = 15 * time.Minute
)

var lifecycleInstallDNSLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// LifecycleInstallOperationStatus is token-blind. The release scope and exact
// install-intent digest are non-secret approval provenance; Kubernetes
// credentials and chart contents never cross this boundary.
type LifecycleInstallOperationStatus struct {
	Claim                    uuid.UUID
	Generation               int32
	RequestID                uuid.UUID
	OperationID              uuid.UUID
	Epoch                    int64
	State                    string
	ReleaseNamespace         string
	ReleaseName              string
	InstallIntentDigest      string
	RequestedDurationSeconds int32
	NotAfter                 time.Time
	ServerTime               time.Time
	HeartbeatAt              time.Time
	AbortRequestedAt         *time.Time
	ReleasedAt               *time.Time
	CompletedAt              *time.Time
	TakenOverAt              *time.Time
	AbortedAt                *time.Time
}

type LifecycleInstallBegin struct {
	Claim                    uuid.UUID
	ExpectedGeneration       int32
	RequestID                uuid.UUID
	OperationID              uuid.UUID
	ReleaseNamespace         string
	ReleaseName              string
	InstallIntentDigest      string
	RequestedDurationSeconds int32
}

type LifecycleInstallCAS struct {
	Claim              uuid.UUID
	ExpectedGeneration int32
	RequestID          uuid.UUID
	OperationID        uuid.UUID
	ExpectedEpoch      int64
}

type LifecycleInstallComplete struct {
	LifecycleInstallCAS
	ReleaseReady bool
}

type LifecycleInstallAbortFinalize struct {
	LifecycleInstallCAS
	ReleaseAbsent bool
}

// LifecycleClaimAbortCoordination is either a terminal claim result (200) or
// an operation that still requires holder release/deadline or exact-release
// reconciliation (202). Pending never authorizes recovery-metadata deletion.
type LifecycleClaimAbortCoordination struct {
	ClaimStatus     *LifecycleClaimStatus
	OperationStatus *LifecycleInstallOperationStatus
	Pending         bool
}

func validLifecycleInstallDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func validateLifecycleInstallBegin(input *LifecycleInstallBegin) error {
	input.ReleaseNamespace = strings.TrimSpace(input.ReleaseNamespace)
	input.ReleaseName = strings.TrimSpace(input.ReleaseName)
	input.InstallIntentDigest = strings.TrimSpace(input.InstallIntentDigest)
	if input.Claim == uuid.Nil || input.RequestID == uuid.Nil || input.OperationID == uuid.Nil || input.ExpectedGeneration <= 0 {
		return apierr.BadRequest("invalid_lifecycle_install_operation", "claim, request_id, operation_id, and positive expected_generation are required")
	}
	if input.RequestedDurationSeconds <= 0 || time.Duration(input.RequestedDurationSeconds)*time.Second > MaxLifecycleInstallDuration {
		return apierr.BadRequest("invalid_lifecycle_install_duration", "requested_duration_seconds must be between 1 and 900")
	}
	if len(input.ReleaseNamespace) > 63 || !lifecycleInstallDNSLabelRE.MatchString(input.ReleaseNamespace) {
		return apierr.BadRequest("invalid_lifecycle_install_release_scope", "release_namespace must be a lowercase DNS label no longer than 63 characters")
	}
	if len(input.ReleaseName) > 42 || !lifecycleInstallDNSLabelRE.MatchString(input.ReleaseName) {
		return apierr.BadRequest("invalid_lifecycle_install_release_scope", "release_name must be a lowercase DNS label no longer than 42 characters")
	}
	if !validLifecycleInstallDigest(input.InstallIntentDigest) {
		return apierr.BadRequest("invalid_lifecycle_install_intent_digest", "install_intent_digest must be a lowercase sha256 digest")
	}
	return nil
}

func validateLifecycleInstallCAS(input LifecycleInstallCAS) error {
	if input.Claim == uuid.Nil || input.RequestID == uuid.Nil || input.OperationID == uuid.Nil || input.ExpectedGeneration <= 0 || input.ExpectedEpoch <= 0 {
		return apierr.BadRequest("invalid_lifecycle_install_operation_cas", "claim, request_id, operation_id, positive expected_generation, and positive expected_epoch are required")
	}
	return nil
}

func lifecycleInstallOperationStatus(operation sqlc.NodeLifecycleInstallOperation, serverTime time.Time) (LifecycleInstallOperationStatus, error) {
	if operation.OperationID == uuid.Nil || operation.OrgID == uuid.Nil || operation.LifecycleClaim == uuid.Nil || operation.LifecycleRequestID == uuid.Nil || operation.LifecycleGeneration <= 0 || operation.Epoch <= 0 || !validLifecycleInstallDigest(operation.InstallIntentDigest) {
		return LifecycleInstallOperationStatus{}, errors.New("stored Kubernetes lifecycle install operation is malformed")
	}
	state := operation.State
	switch operation.State {
	case LifecycleInstallActive:
		switch {
		case operation.AbortRequestedAt.Valid:
			state = LifecycleInstallAbortRequested
		case !operation.NotAfter.After(serverTime):
			state = LifecycleInstallExpired
		}
	case LifecycleInstallReleased, LifecycleInstallCompleted, LifecycleInstallAborted:
	case "taken_over":
		state = LifecycleInstallAborting
	default:
		return LifecycleInstallOperationStatus{}, errors.New("stored Kubernetes lifecycle install operation has an unknown state")
	}
	return LifecycleInstallOperationStatus{
		Claim: operation.LifecycleClaim, Generation: operation.LifecycleGeneration,
		RequestID: operation.LifecycleRequestID, OperationID: operation.OperationID,
		Epoch: operation.Epoch, State: state, ReleaseNamespace: operation.ReleaseNamespace,
		ReleaseName: operation.ReleaseName, InstallIntentDigest: operation.InstallIntentDigest,
		RequestedDurationSeconds: operation.RequestedDurationSeconds,
		NotAfter:                 operation.NotAfter, ServerTime: serverTime.UTC(), HeartbeatAt: operation.HeartbeatAt,
		AbortRequestedAt: nullableTime(operation.AbortRequestedAt), ReleasedAt: nullableTime(operation.ReleasedAt),
		CompletedAt: nullableTime(operation.CompletedAt), TakenOverAt: nullableTime(operation.TakenOverAt),
		AbortedAt: nullableTime(operation.AbortedAt),
	}, nil
}

func exactLifecycleInstallTuple(operation sqlc.NodeLifecycleInstallOperation, input LifecycleInstallCAS) bool {
	return operation.LifecycleClaim == input.Claim &&
		operation.LifecycleGeneration == input.ExpectedGeneration &&
		operation.LifecycleRequestID == input.RequestID &&
		operation.OperationID == input.OperationID &&
		operation.Epoch == input.ExpectedEpoch
}

func exactLifecycleTokenTuple(token sqlc.NodeJoinToken, claim uuid.UUID, generation int32, requestID uuid.UUID) bool {
	return token.LifecycleClaim.Valid && token.LifecycleRequestID.Valid &&
		uuid.UUID(token.LifecycleClaim.Bytes) == claim &&
		token.LifecycleGeneration == generation &&
		uuid.UUID(token.LifecycleRequestID.Bytes) == requestID
}

func lifecycleInstallAuditMetadata(operation sqlc.NodeLifecycleInstallOperation) map[string]any {
	return map[string]any{
		"claim": operation.LifecycleClaim.String(), "generation": operation.LifecycleGeneration,
		"request_id": operation.LifecycleRequestID.String(), "operation_id": operation.OperationID.String(),
		"epoch": operation.Epoch, "release_namespace": operation.ReleaseNamespace,
		"release_name": operation.ReleaseName, "install_intent_digest": operation.InstallIntentDigest,
		"not_after": operation.NotAfter.UTC().Format(time.RFC3339Nano),
	}
}

func auditLifecycleInstallTransition(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor LifecycleActor, action string, operation sqlc.NodeLifecycleInstallOperation) error {
	return auditLifecycle(ctx, q, orgID, actor, action, "node_lifecycle_install_operation", operation.OperationID.String(), lifecycleInstallAuditMetadata(operation))
}

func lockLifecycleInstallToken(ctx context.Context, q *sqlc.Queries, orgID, claim uuid.UUID) (sqlc.NodeJoinToken, error) {
	token, err := q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: requiredPGUUID(claim)})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.NodeJoinToken{}, apierr.NotFound("lifecycle_claim_not_found", "Kubernetes lifecycle claim was not found")
	}
	return token, err
}

func lifecycleDatabaseTime(ctx context.Context, q *sqlc.Queries) (time.Time, error) {
	value, err := q.GetLifecycleDatabaseTime(ctx)
	return value.UTC(), err
}

// GetLatestLifecycleInstallOperation returns the durable token-blind operation
// projection for one immutable lifecycle claim. Domain absence is deliberately
// distinct from an HTTP route miss so mixed-version CLI retry cannot mistake
// "no operation" for "this replica does not know the route".
func (s *Service) GetLatestLifecycleInstallOperation(ctx context.Context, orgID, claim uuid.UUID) (LifecycleInstallOperationStatus, error) {
	if orgID == uuid.Nil || claim == uuid.Nil {
		return LifecycleInstallOperationStatus{}, apierr.BadRequest("invalid_lifecycle_install_operation", "organization and lifecycle claim are required")
	}
	var status LifecycleInstallOperationStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		operation, err := q.GetLatestLifecycleInstallOperationForOrg(ctx, sqlc.GetLatestLifecycleInstallOperationForOrgParams{
			OrgID: orgID, LifecycleClaim: claim,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("lifecycle_install_operation_not_found", "no lifecycle install operation exists for this claim")
		}
		if err != nil {
			return err
		}
		serverTime, err := lifecycleDatabaseTime(ctx, q)
		if err != nil {
			return err
		}
		status, err = lifecycleInstallOperationStatus(operation, serverTime)
		return err
	})
	return status, err
}

// BeginLifecycleInstall is the control-plane linearization point. The caller
// supplies operation identity, approved release scope, and exact install
// intent, while only the server clock chooses the immutable absolute deadline.
func (s *Service) BeginLifecycleInstall(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallBegin) (LifecycleInstallOperationStatus, error) {
	if err := validateLifecycleInstallBegin(&input); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	if err := actor.validate(); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	var status LifecycleInstallOperationStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if err != nil {
			return err
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle generation or request identity changed before install begin")
		}

		existing, err := q.GetLifecycleInstallOperationForOrg(ctx, sqlc.GetLifecycleInstallOperationForOrgParams{
			OrgID: orgID, LifecycleClaim: input.Claim, OperationID: input.OperationID,
		})
		if err == nil {
			if existing.LifecycleGeneration != input.ExpectedGeneration || existing.LifecycleRequestID != input.RequestID ||
				existing.ReleaseNamespace != input.ReleaseNamespace || existing.ReleaseName != input.ReleaseName ||
				existing.InstallIntentDigest != input.InstallIntentDigest || existing.RequestedDurationSeconds != input.RequestedDurationSeconds {
				return apierr.Conflict("lifecycle_install_operation_cas_failed", "operation identity is already bound to different lifecycle or release inputs")
			}
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			status, err = lifecycleInstallOperationStatus(existing, serverTime)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		epoch := int64(1)
		latest, latestErr := q.LockLatestLifecycleInstallOperationForOrg(ctx, sqlc.LockLatestLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim})
		if latestErr == nil {
			if latest.State != LifecycleInstallReleased || latest.AbortRequestedAt.Valid {
				return apierr.Conflict("lifecycle_install_operation_held", "another install operation, abort, or terminal result already owns this lifecycle claim")
			}
			if latest.Epoch == int64(^uint64(0)>>1) {
				return errors.New("lifecycle install epoch exhausted")
			}
			epoch = latest.Epoch + 1
		} else if !errors.Is(latestErr, pgx.ErrNoRows) {
			return latestErr
		}

		if token.LifecycleAbortedAt.Valid || token.ConsumedAt.Valid {
			return apierr.Conflict("lifecycle_install_claim_terminal", "lifecycle claim is aborted or consumed")
		}
		if !token.LifecycleAcknowledgedAt.Valid {
			return apierr.Conflict("lifecycle_install_claim_not_acknowledged", "lifecycle token response must be durably acknowledged before install begin")
		}
		operation, createErr := q.CreateLifecycleInstallOperation(ctx, sqlc.CreateLifecycleInstallOperationParams{
			OperationID: input.OperationID, Epoch: epoch, ReleaseNamespace: input.ReleaseNamespace,
			ReleaseName: input.ReleaseName, InstallIntentDigest: input.InstallIntentDigest,
			RequestedDurationSeconds: input.RequestedDurationSeconds,
			TokenID:                  token.ID, OrgID: orgID, LifecycleClaim: requiredPGUUID(input.Claim),
			ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: requiredPGUUID(input.RequestID),
		})
		if errors.Is(createErr, pgx.ErrNoRows) {
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			if !token.ExpiresAt.After(serverTime) {
				node, nodeErr := loadLifecycleNode(ctx, q, orgID, input.Claim)
				if nodeErr != nil {
					return nodeErr
				}
				if node == nil {
					return apierr.Conflict("lifecycle_install_operation_absent_after_expiry", "the exact install operation was not created before the lifecycle credential expired")
				}
				return apierr.Conflict("lifecycle_install_claim_terminal", "lifecycle claim already identifies a bound node")
			}
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle claim or operation changed before install begin")
		}
		if createErr != nil {
			return createErr
		}
		if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_started", operation); auditErr != nil {
			return auditErr
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, err = lifecycleInstallOperationStatus(operation, serverTime)
		return err
	})
	return status, err
}

func (s *Service) HeartbeatLifecycleInstall(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallCAS) (LifecycleInstallOperationStatus, error) {
	if err := validateLifecycleInstallCAS(input); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	if err := actor.validate(); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	var status LifecycleInstallOperationStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if err != nil {
			return err
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle generation or request identity changed before heartbeat")
		}
		operation, updateErr := q.HeartbeatLifecycleInstallOperation(ctx, sqlc.HeartbeatLifecycleInstallOperationParams{
			OrgID: orgID, LifecycleClaim: input.Claim, ExpectedGeneration: input.ExpectedGeneration,
			LifecycleRequestID: input.RequestID, OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
		})
		if updateErr == nil {
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			status, err = lifecycleInstallOperationStatus(operation, serverTime)
			return err
		}
		if !errors.Is(updateErr, pgx.ErrNoRows) {
			return updateErr
		}
		current, readErr := q.GetLifecycleInstallOperationForOrg(ctx, sqlc.GetLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim, OperationID: input.OperationID})
		if readErr != nil {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "install operation changed before heartbeat")
		}
		if !exactLifecycleInstallTuple(current, input) {
			return apierr.Conflict("lifecycle_install_operation_fenced", "install operation epoch is no longer active")
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, err = lifecycleInstallOperationStatus(current, serverTime)
		if err != nil {
			return err
		}
		if status.State == LifecycleInstallAbortRequested {
			return nil
		}
		return apierr.Conflict("lifecycle_install_operation_not_active", "install operation is expired or terminal")
	})
	return status, err
}

func (s *Service) ReleaseLifecycleInstall(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallCAS) (LifecycleInstallOperationStatus, error) {
	if err := validateLifecycleInstallCAS(input); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	if err := actor.validate(); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	var status LifecycleInstallOperationStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if err != nil {
			return err
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle generation or request identity changed before release")
		}
		operation, updateErr := q.ReleaseLifecycleInstallOperation(ctx, sqlc.ReleaseLifecycleInstallOperationParams{
			OrgID: orgID, LifecycleClaim: input.Claim,
			ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: input.RequestID,
			OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
		})
		if errors.Is(updateErr, pgx.ErrNoRows) {
			operation, updateErr = q.GetLifecycleInstallOperationForOrg(ctx, sqlc.GetLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim, OperationID: input.OperationID})
			if updateErr != nil || !exactLifecycleInstallTuple(operation, input) || operation.State != LifecycleInstallReleased {
				return apierr.Conflict("lifecycle_install_operation_fenced", "install operation is stale or terminal and cannot be released")
			}
		} else if updateErr != nil {
			return updateErr
		} else if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_released", operation); auditErr != nil {
			return auditErr
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, err = lifecycleInstallOperationStatus(operation, serverTime)
		return err
	})
	return status, err
}

func (s *Service) CompleteLifecycleInstall(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallComplete) (LifecycleInstallOperationStatus, error) {
	if err := validateLifecycleInstallCAS(input.LifecycleInstallCAS); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	if !input.ReleaseReady {
		return LifecycleInstallOperationStatus{}, apierr.BadRequest("lifecycle_install_release_not_ready", "release_ready=true attestation is required")
	}
	if err := actor.validate(); err != nil {
		return LifecycleInstallOperationStatus{}, err
	}
	var status LifecycleInstallOperationStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if err != nil {
			return err
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle generation or request identity changed before completion")
		}
		operation, updateErr := q.CompleteLifecycleInstallOperation(ctx, sqlc.CompleteLifecycleInstallOperationParams{
			OrgID: orgID, LifecycleClaim: input.Claim,
			ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: input.RequestID,
			OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
		})
		if errors.Is(updateErr, pgx.ErrNoRows) {
			operation, updateErr = q.GetLifecycleInstallOperationForOrg(ctx, sqlc.GetLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim, OperationID: input.OperationID})
			if updateErr == nil && exactLifecycleInstallTuple(operation, input.LifecycleInstallCAS) && operation.State == LifecycleInstallCompleted {
				serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
				if clockErr != nil {
					return clockErr
				}
				status, err = lifecycleInstallOperationStatus(operation, serverTime)
				return err
			}
			return apierr.Conflict("lifecycle_install_completion_refused", "install operation is stale, expired, abort-requested, or lacks an exact active consumed node")
		}
		if updateErr != nil {
			return updateErr
		}
		if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_completed", operation); auditErr != nil {
			return auditErr
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, err = lifecycleInstallOperationStatus(operation, serverTime)
		return err
	})
	return status, err
}

func validateAbortAgainstOperation(input LifecycleInstallCAS, operation sqlc.NodeLifecycleInstallOperation) error {
	if operation.LifecycleClaim != input.Claim || operation.LifecycleGeneration != input.ExpectedGeneration ||
		operation.LifecycleRequestID != input.RequestID || operation.OperationID != input.OperationID {
		return apierr.Conflict("lifecycle_install_operation_fenced", lifecycleInstallCASMessage(operation))
	}
	if operation.Epoch == input.ExpectedEpoch {
		return nil
	}
	// A takeover response can be lost after the database committed epoch+1 but
	// before Kubernetes persisted it. Only that exact one-step transition for
	// the same operation tuple is replayable; every other stale/gapped epoch is
	// fenced.
	if (operation.State == "taken_over" || operation.State == LifecycleInstallAborted) &&
		input.ExpectedEpoch < int64(^uint64(0)>>1) && operation.Epoch == input.ExpectedEpoch+1 {
		return nil
	}
	return apierr.Conflict("lifecycle_install_operation_fenced", lifecycleInstallCASMessage(operation))
}

func terminalLifecycleClaimStatus(ctx context.Context, q *sqlc.Queries, token sqlc.NodeJoinToken, orgID, claim uuid.UUID) (LifecycleClaimStatus, error) {
	node, err := loadLifecycleNode(ctx, q, orgID, claim)
	if err != nil {
		return LifecycleClaimStatus{}, err
	}
	if node != nil && node.Status == "active" {
		return LifecycleClaimStatus{}, errors.New("terminal lifecycle install abort still has an active exact claim-bound node")
	}
	serverTime, err := lifecycleDatabaseTime(ctx, q)
	if err != nil {
		return LifecycleClaimStatus{}, err
	}
	return lifecycleStatus(token, node, serverTime)
}

// CoordinatedAbortLifecycleClaim is the new-route D13h abort request/takeover
// half. Legacy /abort remains byte-compatible and database-fenced. This method
// always names an existing exact operation, records the request, waits for
// holder release/deadline, then increments the epoch and returns aborting
// authority. It does not revoke the claim; FinalizeLifecycleInstallAbort does
// that after exact-release absence attestation.
func (s *Service) CoordinatedAbortLifecycleClaim(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallCAS) (LifecycleClaimAbortCoordination, error) {
	if err := validateLifecycleInstallCAS(input); err != nil {
		return LifecycleClaimAbortCoordination{}, err
	}
	if err := actor.validate(); err != nil {
		return LifecycleClaimAbortCoordination{}, err
	}
	var result LifecycleClaimAbortCoordination
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, tokenErr := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if tokenErr != nil {
			return tokenErr
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle generation or request identity changed before abort")
		}

		operation, operationErr := q.LockLatestLifecycleInstallOperationForOrg(ctx, sqlc.LockLatestLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim})
		if errors.Is(operationErr, pgx.ErrNoRows) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "no install operation exists for the supplied operation identity")
		}
		if operationErr != nil {
			return operationErr
		}
		if err := validateAbortAgainstOperation(input, operation); err != nil {
			return err
		}
		switch operation.State {
		case LifecycleInstallCompleted:
			return apierr.Conflict("lifecycle_install_already_completed", "a successfully completed install cannot also be aborted")
		case LifecycleInstallAborted:
			if !token.LifecycleAbortedAt.Valid {
				return errors.New("terminal lifecycle install abort is not bound to an aborted claim")
			}
			claimStatus, statusErr := terminalLifecycleClaimStatus(ctx, q, token, orgID, input.Claim)
			if statusErr != nil {
				return statusErr
			}
			result.ClaimStatus = &claimStatus
			return nil
		case "taken_over":
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			status, statusErr := lifecycleInstallOperationStatus(operation, serverTime)
			if statusErr != nil {
				return statusErr
			}
			result.OperationStatus, result.Pending = &status, true
			return nil
		case LifecycleInstallActive, LifecycleInstallReleased:
		default:
			return errors.New("stored Kubernetes lifecycle install operation has an unknown state")
		}

		if !operation.AbortRequestedAt.Valid {
			operation, operationErr = q.RequestAbortLifecycleInstallOperation(ctx, sqlc.RequestAbortLifecycleInstallOperationParams{
				OrgID: orgID, LifecycleClaim: input.Claim,
				ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: input.RequestID,
				OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
			})
			if operationErr != nil {
				return apierr.Conflict("lifecycle_install_operation_cas_failed", "install operation changed before abort request")
			}
			if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_abort_requested", operation); auditErr != nil {
				return auditErr
			}
		}
		takenOver, takeoverErr := q.TakeOverLifecycleInstallOperationForAbort(ctx, sqlc.TakeOverLifecycleInstallOperationForAbortParams{
			OrgID: orgID, LifecycleClaim: input.Claim,
			ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: input.RequestID,
			OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
		})
		if errors.Is(takeoverErr, pgx.ErrNoRows) && operation.State == LifecycleInstallActive {
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			status, statusErr := lifecycleInstallOperationStatus(operation, serverTime)
			if statusErr != nil {
				return statusErr
			}
			result.OperationStatus, result.Pending = &status, true
			return nil
		}
		if takeoverErr != nil {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "install operation changed before abort takeover")
		}
		operation = takenOver
		if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_abort_taken_over", operation); auditErr != nil {
			return auditErr
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, statusErr := lifecycleInstallOperationStatus(operation, serverTime)
		if statusErr != nil {
			return statusErr
		}
		result.OperationStatus, result.Pending = &status, true
		return nil
	})
	if err != nil {
		return LifecycleClaimAbortCoordination{}, err
	}
	return result, nil
}

// FinalizeLifecycleInstallAbort consumes the takeover epoch only after the CLI
// has reconciled the exact approved release/workloads to absence. The terminal
// operation transition and canonical claim/node revocation share one database
// transaction; either both commit or neither does.
func (s *Service) FinalizeLifecycleInstallAbort(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleInstallAbortFinalize) (LifecycleClaimStatus, error) {
	if err := validateLifecycleInstallCAS(input.LifecycleInstallCAS); err != nil {
		return LifecycleClaimStatus{}, err
	}
	if !input.ReleaseAbsent {
		return LifecycleClaimStatus{}, apierr.BadRequest("lifecycle_install_release_not_absent", "release_absent=true attestation is required")
	}
	if err := actor.validate(); err != nil {
		return LifecycleClaimStatus{}, err
	}
	var outcome lifecycleClaimAbortOutcome
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := lockLifecycleInstallToken(ctx, q, orgID, input.Claim)
		if err != nil {
			return err
		}
		if !exactLifecycleTokenTuple(token, input.Claim, input.ExpectedGeneration, input.RequestID) {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "lifecycle generation or request identity changed before abort finalization")
		}
		operation, operationErr := q.LockLatestLifecycleInstallOperationForOrg(ctx, sqlc.LockLatestLifecycleInstallOperationForOrgParams{OrgID: orgID, LifecycleClaim: input.Claim})
		if operationErr != nil {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "install operation was not found for abort finalization")
		}
		if !exactLifecycleInstallTuple(operation, input.LifecycleInstallCAS) {
			return apierr.Conflict("lifecycle_install_operation_fenced", lifecycleInstallCASMessage(operation))
		}
		if operation.State == LifecycleInstallAborted {
			if !token.LifecycleAbortedAt.Valid {
				return errors.New("terminal lifecycle install abort is not bound to an aborted claim")
			}
			status, statusErr := terminalLifecycleClaimStatus(ctx, q, token, orgID, input.Claim)
			outcome.status = status
			return statusErr
		}
		if operation.State != "taken_over" || !operation.AbortRequestedAt.Valid {
			return apierr.Conflict("lifecycle_install_abort_not_taken_over", "abort finalization requires the exact taken-over epoch")
		}
		operation, operationErr = q.MarkLifecycleInstallOperationAborted(ctx, sqlc.MarkLifecycleInstallOperationAbortedParams{
			OrgID: orgID, LifecycleClaim: input.Claim,
			ExpectedGeneration: input.ExpectedGeneration, LifecycleRequestID: input.RequestID,
			OperationID: input.OperationID, ExpectedEpoch: input.ExpectedEpoch,
		})
		if operationErr != nil {
			return apierr.Conflict("lifecycle_install_operation_cas_failed", "install operation changed before abort finalization")
		}
		if auditErr := auditLifecycleInstallTransition(ctx, q, orgID, actor, "node.lifecycle_install_aborted", operation); auditErr != nil {
			return auditErr
		}
		var abortErr error
		outcome, abortErr = s.abortLifecycleClaimInTx(ctx, q, actor, orgID, LifecycleClaimAbort{
			Claim: input.Claim, ExpectedGeneration: input.ExpectedGeneration, RequestID: input.RequestID,
		})
		return abortErr
	})
	if err != nil {
		return LifecycleClaimStatus{}, err
	}
	if outcome.node != nil && outcome.node.Status == "active" {
		s.afterNodeRevoke(ctx, orgID, outcome.wasGateway)
	}
	return outcome.status, nil
}

func lifecycleInstallCASMessage(operation sqlc.NodeLifecycleInstallOperation) string {
	return fmt.Sprintf("install operation is at epoch %d in %s state", operation.Epoch, operation.State)
}
