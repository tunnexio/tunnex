package hostposture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type Kernel interface {
	CaptureBaseline(context.Context, string) ([]SysctlReceipt, error)
	Prepare(context.Context, *Journal, func(*Journal) error) error
	Enforce(context.Context, Journal) error
	RestoreAndCleanup(context.Context, *Journal) error
}

type journalStore interface {
	LoadJournal() (Journal, error)
	SaveJournal(Journal) error
	SaveHeartbeat(Heartbeat) error
}

type Config struct {
	NodeName          string
	ManagerUID        string
	ManagerBootID     string
	MaxOwners         int
	ReconcileInterval time.Duration
}

type Manager struct {
	config Config
	source OwnerSource
	kernel Kernel
	store  journalStore
	now    func() time.Time
	log    *slog.Logger
	seq    uint64
}

func NewManager(config Config, source OwnerSource, kernel Kernel, store journalStore, log *slog.Logger) (*Manager, error) {
	if !validNodeName(config.NodeName) || !uidRE.MatchString(config.ManagerUID) || len(config.ManagerUID) > MaxOwnerUIDBytes {
		return nil, fmt.Errorf("host-posture manager identity is invalid")
	}
	if config.MaxOwners == 0 {
		config.MaxOwners = DefaultMaxOwners
	}
	if config.MaxOwners < 1 || config.MaxOwners > DefaultMaxOwners {
		return nil, fmt.Errorf("max owners must be between 1 and %d", DefaultMaxOwners)
	}
	if config.ManagerBootID == "" {
		var boot [16]byte
		if _, err := rand.Read(boot[:]); err != nil {
			return nil, fmt.Errorf("generate manager boot identity: %w", err)
		}
		config.ManagerBootID = hex.EncodeToString(boot[:])
	}
	if !validManagerBootID(config.ManagerBootID) {
		return nil, fmt.Errorf("host-posture manager boot identity is invalid")
	}
	if config.ReconcileInterval <= 0 {
		config.ReconcileInterval = DefaultReconcileInterval
	}
	if source == nil || kernel == nil || store == nil {
		return nil, fmt.Errorf("host-posture manager dependencies are incomplete")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Manager{config: config, source: source, kernel: kernel, store: store, now: time.Now, log: log}, nil
}

func (m *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.config.ReconcileInterval)
	defer ticker.Stop()
	for {
		if err := m.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
			m.log.Error("k8s_host_posture_reconcile_blocked", "error", boundedReason(err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *Manager) ReconcileOnce(ctx context.Context) error {
	now := m.now().UTC()
	owners, sourceErr := m.source.List(ctx, m.config.NodeName, m.config.MaxOwners)
	journal, loadErr := m.store.LoadJournal()
	haveJournal := loadErr == nil
	if loadErr != nil && !errors.Is(loadErr, ErrNoJournal) {
		return m.block(now, nil, fmt.Errorf("journal readback failed: %w", loadErr))
	}
	if haveJournal {
		if err := journal.validate(m.config.NodeName); err != nil {
			return m.block(now, journal.Owners, fmt.Errorf("journal validation failed: %w", err))
		}
	}
	if sourceErr != nil {
		// API ambiguity must never cause last-owner restoration. Existing ownership
		// remains enforced from the last durable API snapshot until a successful
		// exact-node list proves otherwise.
		if haveJournal && journal.State != StateRestored && len(journal.Owners) > 0 {
			if journal.State == StatePreparing {
				if err := m.prepare(ctx, &journal, now); err != nil {
					return m.block(now, journal.Owners, fmt.Errorf("resume preparation during API fault: %w", err))
				}
				journal.State = StateActive
				journal.UpdatedAt = now
				if err := m.store.SaveJournal(journal); err != nil {
					return m.block(now, journal.Owners, err)
				}
			}
			if err := m.kernel.Enforce(ctx, journal); err != nil {
				return m.block(now, journal.Owners, fmt.Errorf("enforce retained ownership during API fault: %w", err))
			}
		}
		return m.block(now, ownerFallback(journal, haveJournal), fmt.Errorf("authoritative live owner readback failed: %w", sourceErr))
	}
	owners = canonicalOwners(owners)
	if len(owners) > 0 {
		if !haveJournal || journal.State == StateRestored {
			epoch := uint64(1)
			if haveJournal {
				epoch = journal.Epoch + 1
			}
			stagingName, err := newWireGuardStagingName()
			if err != nil {
				return m.block(now, owners, fmt.Errorf("create WireGuard staging identity: %w", err))
			}
			originals, err := m.kernel.CaptureBaseline(ctx, stagingName)
			if err != nil {
				return m.block(now, owners, fmt.Errorf("capture pre-Tunnex host baseline: %w", err))
			}
			journal, err = newJournal(m.config.NodeName, epoch, originals, owners, stagingName, now)
			if err != nil {
				return m.block(now, owners, fmt.Errorf("create pre-mutation journal: %w", err))
			}
			// This durable write is the admission boundary. No kernel mutation may
			// occur before the exact originals and fixed ownership signatures exist.
			if err := m.store.SaveJournal(journal); err != nil {
				return m.block(now, owners, fmt.Errorf("persist pre-mutation journal: %w", err))
			}
			haveJournal = true
		} else if !ownersEqual(journal.Owners, owners) {
			journal.Owners = owners
			journal.UpdatedAt = now
			if err := m.store.SaveJournal(journal); err != nil {
				return m.block(now, owners, fmt.Errorf("persist live owner set: %w", err))
			}
		}
		wasPreparing := journal.State == StatePreparing
		oldIfIndex := journal.Artifacts.WireGuard.IfIndex
		if err := m.prepare(ctx, &journal, now); err != nil {
			journal.LastError = boundedReason(err.Error())
			journal.UpdatedAt = now
			_ = m.store.SaveJournal(journal)
			return m.block(now, owners, fmt.Errorf("prepare owned host artifacts: %w", err))
		}
		if wasPreparing || oldIfIndex != journal.Artifacts.WireGuard.IfIndex || journal.LastError != "" {
			journal.State = StateActive
			journal.LastError = ""
			journal.UpdatedAt = now
			if err := m.store.SaveJournal(journal); err != nil {
				return m.block(now, owners, fmt.Errorf("persist active host posture: %w", err))
			}
		}
		if err := m.kernel.Enforce(ctx, journal); err != nil {
			return m.block(now, owners, fmt.Errorf("enforce active host posture: %w", err))
		}
		return m.heartbeat(now, HeartbeatActive, owners, "")
	}

	if !haveJournal || journal.State == StateRestored {
		return m.heartbeat(now, HeartbeatIdle, nil, "")
	}
	if len(journal.Owners) != 0 {
		journal.Owners = nil
		journal.UpdatedAt = now
		if err := m.store.SaveJournal(journal); err != nil {
			return m.block(now, nil, fmt.Errorf("persist proven empty owner set: %w", err))
		}
	}
	if err := m.kernel.RestoreAndCleanup(ctx, &journal); err != nil {
		journal.LastError = boundedReason(err.Error())
		journal.UpdatedAt = now
		_ = m.store.SaveJournal(journal)
		return m.block(now, nil, fmt.Errorf("last-owner cleanup blocked: %w", err))
	}
	journal.State = StateRestored
	journal.LastError = ""
	journal.UpdatedAt = now
	if err := m.store.SaveJournal(journal); err != nil {
		return m.block(now, nil, fmt.Errorf("persist restored host posture: %w", err))
	}
	return m.heartbeat(now, HeartbeatIdle, nil, "")
}

func (m *Manager) prepare(ctx context.Context, journal *Journal, now time.Time) error {
	return m.kernel.Prepare(ctx, journal, func(checkpoint *Journal) error {
		checkpoint.UpdatedAt = now
		if err := m.store.SaveJournal(*checkpoint); err != nil {
			return fmt.Errorf("persist WireGuard preparation checkpoint: %w", err)
		}
		return nil
	})
}

func ownerFallback(journal Journal, have bool) []Owner {
	if !have {
		return nil
	}
	return journal.Owners
}

func (m *Manager) block(now time.Time, owners []Owner, err error) error {
	heartbeatErr := m.heartbeat(now, HeartbeatBlocked, owners, boundedReason(err.Error()))
	if heartbeatErr != nil {
		return errors.Join(err, heartbeatErr)
	}
	return err
}

func (m *Manager) heartbeat(now time.Time, state string, owners []Owner, reason string) error {
	m.seq++
	return m.store.SaveHeartbeat(Heartbeat{
		SchemaVersion: HeartbeatSchemaVersion,
		Contract:      Contract,
		NodeName:      m.config.NodeName,
		ManagerUID:    m.config.ManagerUID,
		ManagerBootID: m.config.ManagerBootID,
		Sequence:      m.seq,
		State:         state,
		Owners:        canonicalOwners(owners),
		ObservedAt:    now,
		Reason:        boundedReason(reason),
	})
}
