package hostposture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

const (
	CNIAuthoritySchemaVersion = 1
	CNIAuthorityContract      = "tunnex-host-posture-cni/v1"
	CNIAuthorityGranted       = "granted"
	CNIAuthorityRevoked       = "revoked"
	CNIOperationLockTimeout   = 5 * time.Second
)

// CNIAuthority is a separate public capability receipt, not an extension to
// the strict v1 heartbeat. It never replaces heartbeat owner admission.
type CNIAuthority struct {
	SchemaVersion int                       `json:"schema_version"`
	Contract      string                    `json:"contract"`
	State         string                    `json:"state"`
	NodeName      string                    `json:"node_name,omitempty"`
	ManagerUID    string                    `json:"manager_uid,omitempty"`
	ManagerBootID string                    `json:"manager_boot_id,omitempty"`
	Sequence      uint64                    `json:"sequence,omitempty"`
	Epoch         uint64                    `json:"epoch,omitempty"`
	JournalSchema int                       `json:"journal_schema,omitempty"`
	Scope         k8snetprep.AuthorityScope `json:"scope,omitempty"`
	ObservedAt    time.Time                 `json:"observed_at"`
}

func journalCNIScope(schema int) (k8snetprep.AuthorityScope, error) {
	switch schema {
	case LegacyJournalSchemaVersion, StagedJournalSchemaVersion:
		return k8snetprep.ScopeIPMasqOnly, nil
	case AWSJournalSchemaVersion:
		return k8snetprep.ScopeIPMasqAndAWS, nil
	case JournalSchemaVersion:
		return k8snetprep.ScopeIPMasqAndAWSTransit, nil
	default:
		return "", fmt.Errorf("CNI journal schema is unsupported")
	}
}

func authorityForHeartbeat(heartbeat Heartbeat, journal Journal) (CNIAuthority, error) {
	if err := journal.validate(heartbeat.NodeName); err != nil {
		return CNIAuthority{}, err
	}
	if journal.State != StateActive || heartbeat.State != HeartbeatActive || !ownersEqual(journal.Owners, heartbeat.Owners) {
		return CNIAuthority{}, fmt.Errorf("CNI grant requires an active matching durable owner epoch")
	}
	scope, err := journalCNIScope(journal.SchemaVersion)
	if err != nil {
		return CNIAuthority{}, err
	}
	return CNIAuthority{
		SchemaVersion: CNIAuthoritySchemaVersion, Contract: CNIAuthorityContract, State: CNIAuthorityGranted,
		NodeName: heartbeat.NodeName, ManagerUID: heartbeat.ManagerUID, ManagerBootID: heartbeat.ManagerBootID,
		Sequence: heartbeat.Sequence, Epoch: journal.Epoch, JournalSchema: journal.SchemaVersion,
		Scope: scope, ObservedAt: heartbeat.ObservedAt,
	}, nil
}

func validateCNIAuthority(authority CNIAuthority, heartbeat Heartbeat, node, owner string, now time.Time) error {
	if err := validateHeartbeat(heartbeat, node, now); err != nil {
		return err
	}
	if heartbeat.State != HeartbeatActive || !heartbeatHasOwner(heartbeat, owner) {
		return fmt.Errorf("CNI authority requires active exact-owner heartbeat")
	}
	want, err := journalCNIScope(authority.JournalSchema)
	if err != nil {
		return err
	}
	if authority.SchemaVersion != CNIAuthoritySchemaVersion || authority.Contract != CNIAuthorityContract ||
		authority.State != CNIAuthorityGranted || authority.NodeName != heartbeat.NodeName ||
		authority.ManagerUID != heartbeat.ManagerUID || authority.ManagerBootID != heartbeat.ManagerBootID ||
		authority.Sequence != heartbeat.Sequence || !authority.ObservedAt.Equal(heartbeat.ObservedAt) ||
		authority.Epoch == 0 || authority.Scope != want {
		return fmt.Errorf("CNI authority is absent, revoked, or does not match the active heartbeat epoch")
	}
	return nil
}

func (s *Store) LoadCNIAuthority() (CNIAuthority, error) {
	var authority CNIAuthority
	if err := readStrictJSON(s.CNIAuthorityPath(), maxHeartbeat, &authority); err != nil {
		return CNIAuthority{}, fmt.Errorf("read host-posture CNI authority: %w", err)
	}
	return authority, nil
}

func (s *Store) SaveCNIAuthority(authority CNIAuthority) error {
	if s.readOnly {
		return fmt.Errorf("read-only posture store cannot publish CNI authority")
	}
	return s.atomicJSON(cniAuthorityFile, authority, 0o644)
}

func (s *Store) RevokeCNIAuthority() error {
	return s.SaveCNIAuthority(CNIAuthority{SchemaVersion: CNIAuthoritySchemaVersion, Contract: CNIAuthorityContract, State: CNIAuthorityRevoked})
}

func (s *Store) createCNIOperationLock() error {
	f, err := os.OpenFile(s.CNIOperationLockPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(s.CNIOperationLockPath())
		if statErr != nil || !validCNILockFile(info) {
			return fmt.Errorf("CNI operation lock is not a fixed public regular file")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("create CNI operation lock: %w", err)
	}
	modeErr := f.Chmod(0o644)
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(modeErr, syncErr, closeErr)
}

func validCNILockFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() == 0 && info.Mode().Perm() == 0o644
}

// AcquireCNIOperationLock never creates or replaces the lock. Both the manager
// and a gateway's read-only mount lock the same manager-created inode.
func (s *Store) AcquireCNIOperationLock(ctx context.Context) (func(), error) {
	bounded, cancel := context.WithTimeout(ctx, CNIOperationLockTimeout)
	defer cancel()
	return acquireCNIOperationLock(bounded, s.CNIOperationLockPath())
}

// cniOwnerProof is one bounded admission history, not an owner-indexed cache.
// Any identity/epoch/scope change needs two new advancing observations.
type cniOwnerProof struct {
	node, owner, manager, boot string
	epoch                      uint64
	schema                     int
	scope                      k8snetprep.AuthorityScope
	sequence                   uint64
	observedAt                 time.Time
	proofs                     int
}

func (s *Store) resetCNIProof() {
	s.proofMu.Lock()
	s.cniProof = cniOwnerProof{}
	s.proofMu.Unlock()
}

// AcquireCNIAuthority returns a release function only after two advancing
// fresh exact-owner proofs. The caller MUST hold it across its complete CNI
// observation/mutation/readback operation. Waiting for the next heartbeat is
// always outside the lock, so the manager can advance its publication.
func (s *Store) AcquireCNIAuthority(ctx context.Context, node, owner string, now time.Time) (k8snetprep.AuthorityGrant, func(), error) {
	started := time.Now()
	if !validNodeName(node) || len(owner) > MaxOwnerUIDBytes || !uidRE.MatchString(owner) {
		s.resetCNIProof()
		return k8snetprep.AuthorityGrant{}, nil, fmt.Errorf("gateway CNI authority identity is invalid")
	}
	release, err := s.AcquireCNIOperationLock(ctx)
	if err != nil {
		s.resetCNIProof()
		return k8snetprep.AuthorityGrant{}, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			release()
		}
	}()
	s.proofMu.Lock()
	defer s.proofMu.Unlock()
	fail := func(err error) (k8snetprep.AuthorityGrant, func(), error) {
		s.cniProof = cniOwnerProof{}
		return k8snetprep.AuthorityGrant{}, nil, err
	}
	heartbeat, err := s.LoadHeartbeat()
	if err != nil {
		return fail(err)
	}
	authority, err := s.LoadCNIAuthority()
	if err != nil {
		return fail(err)
	}
	if err := validateCNIAuthority(authority, heartbeat, node, owner, now.Add(time.Since(started))); err != nil {
		return fail(err)
	}
	proof := &s.cniProof
	if proof.node != node || proof.owner != owner || proof.manager != heartbeat.ManagerUID || proof.boot != heartbeat.ManagerBootID ||
		proof.epoch != authority.Epoch || proof.schema != authority.JournalSchema || proof.scope != authority.Scope || heartbeat.Sequence < proof.sequence ||
		now.Add(time.Since(started)).Sub(proof.observedAt) > HeartbeatFreshness {
		*proof = cniOwnerProof{node: node, owner: owner, manager: heartbeat.ManagerUID, boot: heartbeat.ManagerBootID,
			epoch: authority.Epoch, schema: authority.JournalSchema, scope: authority.Scope}
	}
	if heartbeat.Sequence > proof.sequence {
		proof.sequence = heartbeat.Sequence
		proof.observedAt = heartbeat.ObservedAt
		if proof.proofs < 2 {
			proof.proofs++
		}
	}
	if proof.proofs < 2 {
		return k8snetprep.AuthorityGrant{}, nil, fmt.Errorf("CNI authority awaits two advancing exact-owner heartbeats")
	}
	ok = true
	// The lock prevents cleanup races but does not extend heartbeat authority.
	// Consumers must bound their entire operation by this absolute expiry.
	return k8snetprep.AuthorityGrant{Scope: authority.Scope, NotAfter: heartbeat.ObservedAt.Add(HeartbeatFreshness)}, release, nil
}
