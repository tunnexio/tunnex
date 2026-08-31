package nodes

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const (
	LifecycleClaimIssued       = "issued"
	LifecycleClaimAcknowledged = "acknowledged"
	LifecycleClaimExpired      = "expired"
	LifecycleClaimConsumed     = "consumed"
	LifecycleClaimAborted      = "aborted"
)

// LifecycleClaimStatus is deliberately token-blind. It is the exact control-
// plane half of the Kubernetes CAS protocol and never carries a token hash,
// sealed response, or other credential material.
type LifecycleClaimStatus struct {
	Claim          uuid.UUID
	State          string
	NodeName       string
	Generation     int32
	RequestID      uuid.UUID
	ExpiresAt      time.Time
	AcknowledgedAt *time.Time
	ConsumedAt     *time.Time
	AbortedAt      *time.Time
	NodeID         *uuid.UUID
}

type LifecycleClaimRemint struct {
	Claim              uuid.UUID
	NodeName           string
	ExpectedGeneration int32
	RequestID          uuid.UUID
}

type LifecycleClaimRemintResult struct {
	Claim      uuid.UUID
	JoinToken  string
	Generation int32
	RequestID  uuid.UUID
	ExpiresAt  time.Time
}

type LifecycleClaimAbort struct {
	Claim              uuid.UUID
	NodeName           string
	ExpectedGeneration int32
	RequestID          uuid.UUID
}

// LifecycleActor separates the human accountable for the enrolled node from
// the audit principal that performed the lifecycle operation. For a human the
// two are the same; for a machine, IssuerUserID is its active owner while audit
// attribution remains actor_system=operator:<name> plus cause.
type LifecycleActor struct {
	IssuerUserID uuid.UUID
	AuditUserID  uuid.UUID
	AuditSystem  string
	Cause        string
}

func (a LifecycleActor) validate() error {
	if a.IssuerUserID == uuid.Nil {
		return apierr.New(401, "unattributed_lifecycle_actor", "Kubernetes lifecycle operations require an accountable human or machine owner")
	}
	if (a.AuditUserID == uuid.Nil) == (strings.TrimSpace(a.AuditSystem) == "") {
		return errors.New("lifecycle audit actor must be exactly one human or system principal")
	}
	return nil
}

func requiredPGUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: value, Valid: value != uuid.Nil}
}

func nullableTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func lifecycleStatus(token sqlc.NodeJoinToken, node *sqlc.Node, now time.Time) (LifecycleClaimStatus, error) {
	if !token.LifecycleClaim.Valid || !token.LifecycleRequestID.Valid || token.LifecycleGeneration < 0 || token.NodeName == nil || strings.TrimSpace(*token.NodeName) == "" {
		return LifecycleClaimStatus{}, errors.New("stored Kubernetes lifecycle claim is malformed")
	}
	if token.LifecycleGeneration == 0 && (!token.LifecycleAbortedAt.Valid || token.LifecycleTokenSealed != nil || token.LifecycleAcknowledgedAt.Valid || token.ConsumedAt.Valid || token.ConsumedNodeID.Valid || node != nil) {
		return LifecycleClaimStatus{}, errors.New("stored Kubernetes lifecycle claim is malformed")
	}
	status := LifecycleClaimStatus{
		Claim:          uuid.UUID(token.LifecycleClaim.Bytes),
		State:          LifecycleClaimIssued,
		NodeName:       *token.NodeName,
		Generation:     token.LifecycleGeneration,
		RequestID:      uuid.UUID(token.LifecycleRequestID.Bytes),
		ExpiresAt:      token.ExpiresAt,
		AcknowledgedAt: nullableTime(token.LifecycleAcknowledgedAt),
		ConsumedAt:     nullableTime(token.ConsumedAt),
		AbortedAt:      nullableTime(token.LifecycleAbortedAt),
	}
	switch {
	case token.LifecycleAbortedAt.Valid:
		status.State = LifecycleClaimAborted
	case token.ConsumedAt.Valid || node != nil:
		status.State = LifecycleClaimConsumed
	case !token.ExpiresAt.After(now):
		status.State = LifecycleClaimExpired
	case token.LifecycleAcknowledgedAt.Valid:
		status.State = LifecycleClaimAcknowledged
	}
	if node != nil {
		id := node.ID
		status.NodeID = &id
	}
	return status, nil
}

func loadLifecycleNode(ctx context.Context, q *sqlc.Queries, orgID, claim uuid.UUID) (*sqlc.Node, error) {
	node, err := q.GetNodeByLifecycleClaimForOrg(ctx, sqlc.GetNodeByLifecycleClaimForOrgParams{
		OrgID: orgID, LifecycleClaim: requiredPGUUID(claim),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *Service) openLifecycleRemintResponse(token sqlc.NodeJoinToken, now time.Time) (string, error) {
	if !token.ExpiresAt.After(now) {
		return "", apierr.Conflict("lifecycle_claim_response_expired", "the sealed lifecycle response expired; persist a new request identity and remint with the expired generation")
	}
	if token.LifecycleTokenSealed == nil {
		return "", apierr.Conflict("lifecycle_claim_response_unavailable", "the exact remint response was already acknowledged or consumed")
	}
	opened, err := s.sealer.Open(*token.LifecycleTokenSealed)
	if err != nil {
		return "", fmt.Errorf("open sealed lifecycle remint response: %w", err)
	}
	if subtle.ConstantTimeCompare(hashToken(string(opened)), token.TokenHash) != 1 {
		return "", errors.New("sealed lifecycle remint response does not match its credential hash")
	}
	return string(opened), nil
}

func (s *Service) auditLifecycleTokenReturn(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor LifecycleActor, action string, input LifecycleClaimRemint, generation int32, raw string) error {
	return auditLifecycle(ctx, q, orgID, actor, action, "node_lifecycle_claim", input.Claim.String(), map[string]any{
		"node_name": input.NodeName, "generation": generation, "request_id": input.RequestID.String(),
		"token_fingerprint": s.sealer.Fingerprint([]byte(raw)),
	})
}

// GetLifecycleClaimStatus returns the exact claim state without credential
// material. The opaque claim, not mutable node_name, binds token to node.
func (s *Service) GetLifecycleClaimStatus(ctx context.Context, orgID, claim uuid.UUID) (LifecycleClaimStatus, error) {
	if claim == uuid.Nil {
		return LifecycleClaimStatus{}, apierr.BadRequest("invalid_lifecycle_claim", "lifecycle claim is required")
	}
	var status LifecycleClaimStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := q.GetLifecycleJoinTokenForOrg(ctx, sqlc.GetLifecycleJoinTokenForOrgParams{
			OrgID: orgID, LifecycleClaim: requiredPGUUID(claim),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("lifecycle_claim_not_found", "Kubernetes lifecycle claim was not found")
		}
		if err != nil {
			return err
		}
		node, err := loadLifecycleNode(ctx, q, orgID, claim)
		if err != nil {
			return err
		}
		serverTime, err := lifecycleDatabaseTime(ctx, q)
		if err != nil {
			return err
		}
		status, err = lifecycleStatus(token, node, serverTime)
		return err
	})
	return status, err
}

// RemintLifecycleClaim creates generation one or rotates an expired,
// unconsumed generation under an exact compare-and-swap. Repeating the same
// request id redelivers the same sealed response until ack or consumption.
func (s *Service) RemintLifecycleClaim(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleClaimRemint) (LifecycleClaimRemintResult, error) {
	input.NodeName = strings.TrimSpace(input.NodeName)
	if input.Claim == uuid.Nil || input.RequestID == uuid.Nil || input.ExpectedGeneration < 0 || input.NodeName == "" || len(input.NodeName) > 100 {
		return LifecycleClaimRemintResult{}, apierr.BadRequest("invalid_lifecycle_claim_remint", "claim, request_id, expected_generation, and node_name are required")
	}
	if s.sealer == nil {
		return LifecycleClaimRemintResult{}, errors.New("lifecycle claim remint sealing is unavailable")
	}
	if err := actor.validate(); err != nil {
		return LifecycleClaimRemintResult{}, err
	}
	var result LifecycleClaimRemintResult
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		claimArg := requiredPGUUID(input.Claim)
		token, err := q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{
			OrgID: orgID, LifecycleClaim: claimArg,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			if input.ExpectedGeneration != 0 {
				return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim is absent; expected_generation must be 0")
			}
			if gateErr := s.checkNewPrincipalAllowed(); gateErr != nil {
				return gateErr
			}
			if gateErr := s.checkGatewayCeiling(ctx, q); gateErr != nil {
				return gateErr
			}
			raw, hash, mintErr := newToken()
			if mintErr != nil {
				return mintErr
			}
			sealed, sealErr := s.sealer.Seal([]byte(raw))
			if sealErr != nil {
				return sealErr
			}
			serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
			if clockErr != nil {
				return clockErr
			}
			expiresAt := serverTime.Add(joinTokenTTL)
			created := true
			token, err = q.CreateLifecycleJoinToken(ctx, sqlc.CreateLifecycleJoinTokenParams{
				OrgID: orgID, NodeName: &input.NodeName, TokenHash: hash, ExpiresAt: expiresAt,
				IssuedBy: requiredPGUUID(actor.IssuerUserID), LifecycleClaim: claimArg,
				LifecycleRequestID: requiredPGUUID(input.RequestID), LifecycleTokenSealed: &sealed,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				created = false
				// A concurrent creator won the partial-unique claim race. INSERT
				// used DO NOTHING, so this transaction remains usable and can
				// read the winner for exact idempotency validation below.
				token, err = q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{
					OrgID: orgID, LifecycleClaim: claimArg,
				})
				if errors.Is(err, pgx.ErrNoRows) {
					return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim changed before mint")
				}
			}
			if err != nil {
				return err
			}
			if token.NodeName == nil || *token.NodeName != input.NodeName {
				return apierr.Conflict("lifecycle_claim_identity_mismatch", "lifecycle claim is pinned to a different node name")
			}
			if token.LifecycleRequestID.Valid && uuid.UUID(token.LifecycleRequestID.Bytes) == input.RequestID && token.LifecycleGeneration == 1 {
				serverTime, clockErr = lifecycleDatabaseTime(ctx, q)
				if clockErr != nil {
					return clockErr
				}
				opened, openErr := s.openLifecycleRemintResponse(token, serverTime)
				if openErr != nil {
					return openErr
				}
				result = LifecycleClaimRemintResult{Claim: input.Claim, JoinToken: opened, Generation: 1, RequestID: input.RequestID, ExpiresAt: token.ExpiresAt}
				action := "node.lifecycle_claim_minted"
				if !created {
					action = "node.lifecycle_claim_redelivered"
				}
				return s.auditLifecycleTokenReturn(ctx, q, orgID, actor, action, input, 1, opened)
			}
			// Fall through for a concurrent non-matching creator.
		} else if err != nil {
			return err
		}

		if !token.LifecycleRequestID.Valid || !token.LifecycleClaim.Valid || token.NodeName == nil {
			return errors.New("stored Kubernetes lifecycle claim is malformed")
		}
		if *token.NodeName != input.NodeName {
			return apierr.Conflict("lifecycle_claim_identity_mismatch", "lifecycle claim is pinned to a different node name")
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		requestID := uuid.UUID(token.LifecycleRequestID.Bytes)
		if requestID == input.RequestID && token.LifecycleGeneration == input.ExpectedGeneration+1 {
			opened, openErr := s.openLifecycleRemintResponse(token, serverTime)
			if openErr != nil {
				return openErr
			}
			result = LifecycleClaimRemintResult{Claim: input.Claim, JoinToken: opened, Generation: token.LifecycleGeneration, RequestID: input.RequestID, ExpiresAt: token.ExpiresAt}
			return s.auditLifecycleTokenReturn(ctx, q, orgID, actor, "node.lifecycle_claim_redelivered", input, token.LifecycleGeneration, opened)
		}
		if token.LifecycleAbortedAt.Valid {
			return apierr.Conflict("lifecycle_claim_aborted", "lifecycle claim was aborted; create a fresh plan with a new claim")
		}
		if token.ConsumedAt.Valid {
			return apierr.Conflict("lifecycle_claim_consumed", "lifecycle claim already enrolled a node; remint is forbidden")
		}
		node, nodeErr := loadLifecycleNode(ctx, q, orgID, input.Claim)
		if nodeErr != nil {
			return nodeErr
		}
		if node != nil {
			return apierr.Conflict("lifecycle_claim_consumed", "lifecycle claim already identifies an enrolled node; remint is forbidden")
		}
		if token.LifecycleGeneration != input.ExpectedGeneration {
			return apierr.Conflict("lifecycle_claim_cas_failed", fmt.Sprintf("lifecycle generation is %d, not expected %d", token.LifecycleGeneration, input.ExpectedGeneration))
		}
		if token.ExpiresAt.After(serverTime) {
			return apierr.Conflict("lifecycle_claim_not_expired", "current lifecycle token has not expired")
		}
		latestOperation, operationErr := q.LockLatestLifecycleInstallOperationForOrg(ctx, sqlc.LockLatestLifecycleInstallOperationForOrgParams{
			OrgID: orgID, LifecycleClaim: input.Claim,
		})
		if operationErr == nil && (latestOperation.State != LifecycleInstallReleased || latestOperation.AbortRequestedAt.Valid) {
			return apierr.Conflict("lifecycle_install_operation_held", "install operation must be cleanly released before lifecycle remint")
		}
		if operationErr != nil && !errors.Is(operationErr, pgx.ErrNoRows) {
			return operationErr
		}
		if gateErr := s.checkNewPrincipalAllowed(); gateErr != nil {
			return gateErr
		}
		if gateErr := s.checkGatewayCeiling(ctx, q); gateErr != nil {
			return gateErr
		}
		raw, hash, mintErr := newToken()
		if mintErr != nil {
			return mintErr
		}
		sealed, sealErr := s.sealer.Seal([]byte(raw))
		if sealErr != nil {
			return sealErr
		}
		serverTime, clockErr = lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		expiresAt := serverTime.Add(joinTokenTTL)
		reminted, remintErr := q.RemintLifecycleJoinToken(ctx, sqlc.RemintLifecycleJoinTokenParams{
			TokenHash: hash, ExpiresAt: expiresAt, LifecycleRequestID: requiredPGUUID(input.RequestID),
			LifecycleTokenSealed: &sealed, ID: token.ID, OrgID: orgID, LifecycleClaim: claimArg,
			ExpectedGeneration: input.ExpectedGeneration, ServerTime: serverTime,
		})
		if errors.Is(remintErr, pgx.ErrNoRows) {
			return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim changed while reminting")
		}
		if remintErr != nil {
			return remintErr
		}
		result = LifecycleClaimRemintResult{Claim: input.Claim, JoinToken: raw, Generation: reminted.LifecycleGeneration, RequestID: input.RequestID, ExpiresAt: reminted.ExpiresAt}
		return s.auditLifecycleTokenReturn(ctx, q, orgID, actor, "node.lifecycle_claim_reminted", input, reminted.LifecycleGeneration, raw)
	})
	if err != nil {
		return LifecycleClaimRemintResult{}, err
	}
	return result, nil
}

// AcknowledgeLifecycleClaim destroys the sealed redelivery response only after
// Kubernetes has persisted the exact generation/request under its own CAS.
func (s *Service) AcknowledgeLifecycleClaim(ctx context.Context, actor LifecycleActor, orgID, claim, requestID uuid.UUID, generation int32) (LifecycleClaimStatus, error) {
	if claim == uuid.Nil || requestID == uuid.Nil || generation <= 0 {
		return LifecycleClaimStatus{}, apierr.BadRequest("invalid_lifecycle_claim_ack", "claim, request_id, and positive generation are required")
	}
	if err := actor.validate(); err != nil {
		return LifecycleClaimStatus{}, err
	}
	var status LifecycleClaimStatus
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		token, err := q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: requiredPGUUID(claim)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("lifecycle_claim_not_found", "Kubernetes lifecycle claim was not found")
		}
		if err != nil {
			return err
		}
		if !token.LifecycleRequestID.Valid || token.LifecycleGeneration != generation || uuid.UUID(token.LifecycleRequestID.Bytes) != requestID {
			return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle generation or request identity changed before acknowledgement")
		}
		if token.LifecycleAbortedAt.Valid || token.ConsumedAt.Valid {
			return apierr.Conflict("lifecycle_claim_not_acknowledgeable", "lifecycle claim is aborted or consumed")
		}
		if !token.LifecycleAcknowledgedAt.Valid {
			rows, updateErr := q.AcknowledgeLifecycleJoinToken(ctx, sqlc.AcknowledgeLifecycleJoinTokenParams{
				OrgID: orgID, LifecycleClaim: requiredPGUUID(claim), ExpectedGeneration: generation,
				LifecycleRequestID: requiredPGUUID(requestID),
			})
			if updateErr != nil {
				return updateErr
			}
			if rows != 1 {
				return apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim changed before acknowledgement")
			}
			if auditErr := auditLifecycle(ctx, q, orgID, actor, "node.lifecycle_claim_acknowledged", "node_lifecycle_claim", claim.String(), map[string]any{
				"generation": generation, "request_id": requestID.String(),
			}); auditErr != nil {
				return auditErr
			}
			token, err = q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: requiredPGUUID(claim)})
			if err != nil {
				return err
			}
		}
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return clockErr
		}
		status, err = lifecycleStatus(token, nil, serverTime)
		return err
	})
	return status, err
}

type lifecycleClaimAbortOutcome struct {
	status     LifecycleClaimStatus
	node       *sqlc.Node
	wasGateway bool
}

func validateLifecycleClaimAbort(actor LifecycleActor, input *LifecycleClaimAbort) error {
	input.NodeName = strings.TrimSpace(input.NodeName)
	if input.Claim == uuid.Nil || input.RequestID == uuid.Nil || input.ExpectedGeneration < 0 || len(input.NodeName) > 100 || (input.ExpectedGeneration == 0 && input.NodeName == "") {
		return apierr.BadRequest("invalid_lifecycle_claim_abort", "claim, request_id, expected_generation, and node_name for generation zero are required")
	}
	if err := actor.validate(); err != nil {
		return err
	}
	return nil
}

// AbortLifecycleClaim permanently closes an exact claim and atomically applies
// the canonical revocation sweep to any exact claim-bound enrolled node. D13h
// HTTP callers use CoordinatedAbortLifecycleClaim; this method remains the
// exact pre-D13h/no-operation primitive and is intentionally fenced by the
// migration trigger whenever an install operation is non-terminal.
func (s *Service) AbortLifecycleClaim(ctx context.Context, actor LifecycleActor, orgID uuid.UUID, input LifecycleClaimAbort) (LifecycleClaimStatus, error) {
	if err := validateLifecycleClaimAbort(actor, &input); err != nil {
		return LifecycleClaimStatus{}, err
	}
	var outcome lifecycleClaimAbortOutcome
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		var err error
		outcome, err = s.abortLifecycleClaimInTx(ctx, q, actor, orgID, input)
		return err
	})
	if err != nil {
		return LifecycleClaimStatus{}, err
	}
	if outcome.node != nil && outcome.node.Status == "active" {
		s.afterNodeRevoke(ctx, orgID, outcome.wasGateway)
	}
	return outcome.status, nil
}

// abortLifecycleClaimInTx requires the caller to own the transaction and the
// node_join_tokens row lock. FinalizeInstallAbort uses it only after changing
// the exact taken-over operation to terminal aborted in the same transaction,
// so the mixed-version database guard cannot observe a false-success window.
func (s *Service) abortLifecycleClaimInTx(ctx context.Context, q *sqlc.Queries, actor LifecycleActor, orgID uuid.UUID, input LifecycleClaimAbort) (lifecycleClaimAbortOutcome, error) {
	var node *sqlc.Node
	wasGateway := false
	var status LifecycleClaimStatus
	claimArg := requiredPGUUID(input.Claim)
	token, err := q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: claimArg})
	createdTombstone := false
	if errors.Is(err, pgx.ErrNoRows) {
		if input.ExpectedGeneration != 0 {
			return lifecycleClaimAbortOutcome{}, apierr.NotFound("lifecycle_claim_not_found", "Kubernetes lifecycle claim was not found")
		}
		_, tombstoneHash, tokenErr := newToken()
		if tokenErr != nil {
			return lifecycleClaimAbortOutcome{}, tokenErr
		}
		token, err = q.CreateAbortedLifecycleJoinToken(ctx, sqlc.CreateAbortedLifecycleJoinTokenParams{
			OrgID: orgID, NodeName: &input.NodeName, TokenHash: tombstoneHash,
			IssuedBy: requiredPGUUID(actor.IssuerUserID), LifecycleClaim: claimArg,
			LifecycleRequestID: requiredPGUUID(input.RequestID),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			token, err = q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: claimArg})
			if errors.Is(err, pgx.ErrNoRows) {
				return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim changed before pre-mint abort")
			}
		} else if err == nil {
			createdTombstone = true
		}
	}
	if err != nil {
		return lifecycleClaimAbortOutcome{}, err
	}
	if !token.LifecycleClaim.Valid || !token.LifecycleRequestID.Valid || token.NodeName == nil || strings.TrimSpace(*token.NodeName) == "" {
		return lifecycleClaimAbortOutcome{}, errors.New("stored Kubernetes lifecycle claim is malformed")
	}
	if uuid.UUID(token.LifecycleRequestID.Bytes) != input.RequestID {
		return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle generation or request identity changed before abort")
	}
	if input.NodeName != "" && *token.NodeName != input.NodeName {
		return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_identity_mismatch", "lifecycle claim is pinned to a different node name")
	}
	actualGeneration := token.LifecycleGeneration
	if input.ExpectedGeneration == 0 {
		if actualGeneration != 0 && actualGeneration != 1 {
			return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_cas_failed", "pre-mint abort found a lifecycle generation beyond the exact mint race")
		}
	} else if actualGeneration != input.ExpectedGeneration {
		return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle generation or request identity changed before abort")
	}
	if !token.LifecycleAbortedAt.Valid {
		rows, updateErr := q.AbortLifecycleJoinToken(ctx, sqlc.AbortLifecycleJoinTokenParams{
			OrgID: orgID, LifecycleClaim: claimArg, ExpectedGeneration: actualGeneration,
			LifecycleRequestID: requiredPGUUID(input.RequestID),
		})
		if updateErr != nil {
			return lifecycleClaimAbortOutcome{}, updateErr
		}
		if rows != 1 {
			return lifecycleClaimAbortOutcome{}, apierr.Conflict("lifecycle_claim_cas_failed", "lifecycle claim changed before abort")
		}
		if auditErr := auditLifecycle(ctx, q, orgID, actor, "node.lifecycle_claim_aborted", "node_lifecycle_claim", input.Claim.String(), map[string]any{
			"node_name": *token.NodeName, "generation": actualGeneration, "request_id": input.RequestID.String(),
		}); auditErr != nil {
			return lifecycleClaimAbortOutcome{}, auditErr
		}
		token, err = q.LockLifecycleJoinTokenForOrg(ctx, sqlc.LockLifecycleJoinTokenForOrgParams{OrgID: orgID, LifecycleClaim: claimArg})
		if err != nil {
			return lifecycleClaimAbortOutcome{}, err
		}
	} else if createdTombstone {
		if auditErr := auditLifecycle(ctx, q, orgID, actor, "node.lifecycle_claim_aborted_before_mint", "node_lifecycle_claim", input.Claim.String(), map[string]any{
			"node_name": *token.NodeName, "generation": 0, "request_id": input.RequestID.String(),
		}); auditErr != nil {
			return lifecycleClaimAbortOutcome{}, auditErr
		}
	}
	nodeRow, nodeErr := q.LockNodeByLifecycleClaimForOrg(ctx, sqlc.LockNodeByLifecycleClaimForOrgParams{OrgID: orgID, LifecycleClaim: claimArg})
	if errors.Is(nodeErr, pgx.ErrNoRows) {
		serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
		if clockErr != nil {
			return lifecycleClaimAbortOutcome{}, clockErr
		}
		status, err = lifecycleStatus(token, nil, serverTime)
		return lifecycleClaimAbortOutcome{status: status}, err
	}
	if nodeErr != nil {
		return lifecycleClaimAbortOutcome{}, nodeErr
	}
	if actualGeneration == 0 || nodeRow.Name != *token.NodeName {
		return lifecycleClaimAbortOutcome{}, errors.New("stored Kubernetes lifecycle claim node binding is malformed")
	}
	node = &nodeRow
	if nodeRow.Status == "active" {
		binding, bindingErr := q.GetNodeSiteBinding(ctx, sqlc.GetNodeSiteBindingParams{ID: nodeRow.ID, OrgID: orgID})
		wasGateway = bindingErr == nil && binding.Valid
		if err := s.revokeNodeInTxAttributed(ctx, q, actor.AuditUserID, actor.AuditSystem, actor.Cause, orgID, nodeRow.ID); err != nil {
			return lifecycleClaimAbortOutcome{}, err
		}
	}
	serverTime, clockErr := lifecycleDatabaseTime(ctx, q)
	if clockErr != nil {
		return lifecycleClaimAbortOutcome{}, clockErr
	}
	status, err = lifecycleStatus(token, node, serverTime)
	return lifecycleClaimAbortOutcome{status: status, node: node, wasGateway: wasGateway}, err
}
