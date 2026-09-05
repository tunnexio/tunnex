package hostposture

import (
	"context"
	"fmt"
	"time"
)

type heartbeatReader interface{ LoadHeartbeat() (Heartbeat, error) }

// WaitForCNIOwner is the new gateway admission path. The old strict heartbeat
// reader above and WaitForOwner below remain byte- and behavior-compatible.
// Each attempt releases the operation lock before waiting for advancement.
func WaitForCNIOwner(ctx context.Context, store *Store, nodeName, ownerUID string, now func() time.Time, sleep func(context.Context, time.Duration) error) error {
	if store == nil || !validNodeName(nodeName) || len(ownerUID) > MaxOwnerUIDBytes || !uidRE.MatchString(ownerUID) {
		return fmt.Errorf("gateway CNI posture-check identity is invalid")
	}
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = sleepContext
	}
	for {
		_, release, err := store.AcquireCNIAuthority(ctx, nodeName, ownerUID, now())
		if err == nil {
			release()
			return nil
		}
		if err := sleep(ctx, 500*time.Millisecond); err != nil {
			return fmt.Errorf("wait for live host-posture CNI ownership: %w", err)
		}
	}
}

func CheckManagerHeartbeat(reader heartbeatReader, nodeName string, liveOnly bool, now time.Time) error {
	heartbeat, err := reader.LoadHeartbeat()
	if err != nil {
		return err
	}
	if err := validateHeartbeat(heartbeat, nodeName, now); err != nil {
		return err
	}
	if !liveOnly && heartbeat.State != HeartbeatIdle && heartbeat.State != HeartbeatActive {
		return fmt.Errorf("host-posture manager is not ready: %s", boundedReason(heartbeat.Reason))
	}
	return nil
}

// WaitForOwner requires two advancing heartbeats from the same live manager,
// both containing this exact Pod UID. A stale file left by a deleted DaemonSet
// can therefore never admit the gateway process.
func WaitForOwner(ctx context.Context, reader heartbeatReader, nodeName, ownerUID string, now func() time.Time, sleep func(context.Context, time.Duration) error) error {
	if !validNodeName(nodeName) || len(ownerUID) > MaxOwnerUIDBytes || !uidRE.MatchString(ownerUID) {
		return fmt.Errorf("gateway posture-check identity is invalid")
	}
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = sleepContext
	}
	managerUID := ""
	managerBootID := ""
	lastSequence := uint64(0)
	proofs := 0
	for {
		heartbeat, err := reader.LoadHeartbeat()
		if err == nil {
			err = validateHeartbeat(heartbeat, nodeName, now())
		}
		if err == nil && heartbeat.State == HeartbeatActive && heartbeatHasOwner(heartbeat, ownerUID) {
			if heartbeat.ManagerUID != managerUID || heartbeat.ManagerBootID != managerBootID {
				managerUID = heartbeat.ManagerUID
				managerBootID = heartbeat.ManagerBootID
				lastSequence = 0
				proofs = 0
			}
			if heartbeat.Sequence > lastSequence {
				lastSequence = heartbeat.Sequence
				proofs++
				if proofs >= 2 {
					return nil
				}
			}
		} else {
			managerUID = ""
			managerBootID = ""
			lastSequence = 0
			proofs = 0
		}
		if err := sleep(ctx, 500*time.Millisecond); err != nil {
			return fmt.Errorf("wait for live host-posture ownership: %w", err)
		}
	}
}

func validateHeartbeat(heartbeat Heartbeat, nodeName string, now time.Time) error {
	if heartbeat.SchemaVersion != HeartbeatSchemaVersion || heartbeat.Contract != Contract || heartbeat.NodeName != nodeName ||
		heartbeat.Sequence == 0 || len(heartbeat.ManagerUID) > MaxOwnerUIDBytes || !uidRE.MatchString(heartbeat.ManagerUID) ||
		!validManagerBootID(heartbeat.ManagerBootID) {
		return fmt.Errorf("host-posture heartbeat identity is invalid")
	}
	if heartbeat.State != HeartbeatIdle && heartbeat.State != HeartbeatActive && heartbeat.State != HeartbeatBlocked {
		return fmt.Errorf("host-posture heartbeat state is invalid")
	}
	if heartbeat.ObservedAt.IsZero() || heartbeat.ObservedAt.After(now.Add(2*time.Second)) || now.Sub(heartbeat.ObservedAt) > HeartbeatFreshness {
		return fmt.Errorf("host-posture heartbeat is stale or from the future")
	}
	if len(heartbeat.Owners) > DefaultMaxOwners || !ownersEqual(heartbeat.Owners, canonicalOwners(heartbeat.Owners)) {
		return fmt.Errorf("host-posture heartbeat owner set is invalid")
	}
	for _, owner := range heartbeat.Owners {
		if !validOwner(owner) {
			return fmt.Errorf("host-posture heartbeat contains an invalid owner")
		}
	}
	return nil
}

func validManagerBootID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func heartbeatHasOwner(heartbeat Heartbeat, uid string) bool {
	for _, owner := range heartbeat.Owners {
		if owner.UID == uid {
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
