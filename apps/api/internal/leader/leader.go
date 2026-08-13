// Package leader provides single-writer election for the control plane's in-process schedulers (S11 D4).
//
// WHY THIS EXISTS. The CP runs three schedulers — the hub failover tick, the CRL rebuild, and the flow-log
// retention sweep. N replicas meant N tickers, so the deployment was pinned to replicas=1 and "is the control
// plane HA?" had to be answered "no, and the fix is registered". Leader election unlocks N replicas without
// N writers.
//
// ONLY THE SCHEDULERS ARE GATED. Request serving runs on EVERY replica — a follower is a fully functional
// API server that simply does not tick. Gating request serving would take healthy replicas out of a load
// balancer for no reason.
//
// MECHANISM: a POSTGRES SESSION-SCOPED ADVISORY LOCK (pg_advisory_lock), argued against the alternatives:
//
//   - A LEASE TABLE (row with a TTL, renewed by the leader) requires comparing wall clocks across replicas.
//     Under clock skew — or a leader that stalls past its TTL and resumes — TWO replicas can believe they
//     hold the lease simultaneously. For these schedulers that means a double failover promotion or two
//     concurrent CRL rebuilds. The wrong failure direction.
//   - KUBERNETES LEASES (coordination.k8s.io) are unavailable by construction: the control plane must run on
//     a plain VM pair as well as in Kubernetes, and a mechanism that only works in one is not a mechanism.
//   - A SESSION-SCOPED ADVISORY LOCK is granted by Postgres to exactly ONE session, and is released BY THE
//     DATABASE when that session's connection ends — including when the leader is SIGKILLed, loses its
//     network, or panics. No TTL, no clock, no stale-lock reaper.
//
// WHAT THE LOCK DOES **NOT** GUARANTEE — three claims this package used to make and could not keep (found by a
// retroactive review of already-merged code):
//
//  1. "Releasing the connection also releases the session lock" — FALSE. pgxpool returns a connection to the pool
//     with its PostgreSQL session INTACT, and a session-scoped lock survives that. A campaign that exited without
//     unlocking parked the lock on an idle pooled connection that nothing could unlock, and the whole fleet went
//     leaderless while every replica reported "ok follower". Every exit path now unlocks explicitly.
//  2. "IsLeader() is stale only for microseconds" — FALSE. It was stale for up to RetryInterval, because loss was
//     detected only by the ping ticker. Writing schedulers now CONFIRM against pg_locks before writing.
//  3. "Every scheduler's work is idempotent, so the seam is harmless" — FALSE for the failover tick, whose
//     hysteresis counters are per-process: two leaders compute DIFFERENT demoted sets and write contradictory
//     promotion/failback audits for the same org.
//
// The lock is still the safety boundary. What changed is that this package no longer relies on prose about
// pgxpool semantics to enforce it.
//
// FAILURE DIRECTION (the safety property, stated deliberately): this fails toward NO LEADER, never toward
// two. A gap with nothing ticking delays a failover promotion or a CRL refresh by seconds; two leaders
// ticking would double-promote or double-rebuild. The lock is the safety boundary, and it is enforced by
// Postgres rather than by our code being correct.
//
// SESSION POOLING IS REQUIRED. Advisory locks are per-SESSION, so a transaction-pooling proxy (pgbouncer in
// transaction mode, RDS Proxy) hands the lock's server connection back after the statement and EVERY replica wins
// the lock permanently — N leaders, silently, in a topology operators are commonly advised to adopt for connection
// limits. ConfirmSessionPooling refuses to lead when that cannot be ruled out.
//
// HONEST LIMIT (the fourth such sentence in the S11 paper): after a leader dies, a follower takes over
// within RetryInterval plus however long Postgres takes to notice the dead connection. With the default
// RetryInterval that is bounded by ~10s in the clean case (process exit closes the socket immediately); a
// hard network partition of the leader's DB connection is bounded instead by the server's TCP keepalive
// settings, which can be minutes. During that window NOTHING ticks — which is safe, not degraded: the
// schedulers are periodic reconcilers, not request-path work, and running tunnels are unaffected.
package leader

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RetryInterval is how often a follower re-attempts acquisition. It bounds the failover gap.
const RetryInterval = 10 * time.Second

// AcquireTimeout bounds waiting for a pool connection. Deliberately shorter than RetryInterval so a saturated pool
// produces a logged failure and a retry rather than a silent indefinite block (finding #9).
const AcquireTimeout = 5 * time.Second

// SchedulerLockKey is the advisory-lock key for the CP scheduler leadership. Advisory locks live in a global
// int64 keyspace shared with every other advisory lock in the database, so the value is chosen to be
// distinctive and is declared exactly once.
const SchedulerLockKey int64 = 0x54554E4E58530001 // "TUNNXS" + slot 1

// Elector reports whether THIS process currently holds scheduler leadership.
type Elector struct {
	leading atomic.Bool
	// leaderPID is the Postgres backend pid of the DEDICATED connection that holds the lock, captured at acquire.
	//
	// ConfirmLeader needs it because a pool query runs on SOME connection, not THIS one — the first draft of that
	// check called pg_backend_pid() through the pool and was therefore asking about the wrong session entirely.
	// Storing the pid makes the confirmation a question about the lock we actually hold.
	leaderPID atomic.Int32
}

// IsLeader is a CHEAP, POSSIBLY STALE pre-filter. It is NOT an authorization to write.
//
// It can report true for up to RetryInterval after Postgres has already handed the lock to another replica,
// because loss is detected by the ping ticker rather than pushed by the database. A previous version of this
// comment called that window "microseconds" and justified it with "every scheduler's work is idempotent"; both
// were false, and the failover tick is specifically NOT idempotent across processes because its hysteresis
// counters are per-process.
//
// So: use IsLeader() to skip work cheaply, and ConfirmLeader() before writing anything.
func (e *Elector) IsLeader() bool { return e.leading.Load() }

// ConfirmLeader asks POSTGRES whether this process still holds the lock, rather than asking our own boolean.
//
// This is what a writing scheduler must call. It costs one round trip against pg_locks, which is nothing beside a
// tick that runs every 30 seconds to 15 minutes, and it closes the stale-true window that let two replicas write
// contradictory hub-set generations.
//
// Returns false on ANY doubt — a query error, a lost connection, a context that ended. Refusing to write because
// we could not confirm is the safe direction; writing because our own flag said so is how the split brain happened.
func (e *Elector) ConfirmLeader(ctx context.Context, pool *pgxpool.Pool) bool {
	if !e.leading.Load() {
		return false
	}
	pid := e.leaderPID.Load()
	if pid == 0 {
		return false
	}
	// A bigint advisory key is stored split across classid (high 32 bits) and objid (low 32), with objsubid = 1.
	// Matching on the PID of our own lock-holding backend is what makes this a question about THIS process's lock
	// rather than about whether anybody at all holds it — which would be true even when a follower had taken over.
	var held bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1
			  AND pid = $1
			  AND ((classid::bigint << 32) | (objid::bigint & 4294967295)) = $2
		)`, pid, SchedulerLockKey).Scan(&held)
	if err != nil {
		return false
	}
	return held
}

// Run campaigns for leadership until ctx is cancelled. It blocks, so callers run it in a goroutine.
//
// It holds a DEDICATED connection out of the pool for the whole duration of leadership: a session-scoped
// advisory lock belongs to a CONNECTION, and pgxpool recycles connections between queries, so the lock would
// be released the moment the connection returned to the pool. Holding it also means the lock's fate is tied
// to that connection's liveness — exactly the property the mechanism relies on.
func (e *Elector) Run(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := e.campaign(ctx, pool, log); err != nil && ctx.Err() == nil && log != nil {
			log.Warn("leader_campaign_error", "error", err.Error(), "retry_in", RetryInterval.String())
		}
		// Leadership lost (or never acquired) — always drop the flag before sleeping, so a replica that
		// lost its DB connection stops ticking immediately rather than at the next successful campaign.
		e.leading.Store(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(RetryInterval):
		}
	}
}

// campaign acquires a connection, tries the lock, and — if it wins — holds both until leadership ends.
func (e *Elector) campaign(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	// BOUNDED ACQUIRE (finding #9). Previously this used the caller's deadline-free context, so pool saturation
	// blocked the campaign INDEFINITELY — no error returned, nothing logged, and the cluster sat with no leader far
	// past the documented ~10s bound. Blocking forever is not the safe direction just because it writes nothing; it
	// is the invisible direction. A timeout turns it into a logged, retried failure.
	acqCtx, cancelAcq := context.WithTimeout(ctx, AcquireTimeout)
	conn, err := pool.Acquire(acqCtx)
	cancelAcq()
	if err != nil {
		return err
	}
	defer conn.Release() // releasing the connection also releases the session lock

	var got bool
	// TRY, never wait: pg_try_advisory_lock returns immediately. A blocking pg_advisory_lock would park this
	// goroutine inside Postgres indefinitely, making "am I the leader?" unanswerable and shutdown ugly.
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", SchedulerLockKey).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil // someone else leads; the caller sleeps and retries
	}

	// SESSION POOLING MUST BE CONFIRMED BEFORE LEADING (finding #8). Advisory locks are per-SESSION; behind a
	// TRANSACTION-pooling proxy the server connection is handed back after each statement, so every replica wins
	// this lock permanently and the mechanism silently reports N leaders — in a topology operators are routinely
	// advised to adopt for connection limits. Refusing to lead when we cannot rule that out is the same
	// refuse-loudly discipline as everything else in this product: an unsafe mechanism must not run quietly.
	if err := confirmSessionPooling(ctx, conn); err != nil {
		e.unlock(conn, log, "session_pooling_unconfirmed")
		if log != nil {
			log.Error("leader_refusing_transaction_pooling",
				"error", err.Error(),
				"consequence", "NOT claiming scheduler leadership. Advisory locks are per-session, so under "+
					"transaction-mode pooling every replica would win this lock and all of them would tick — "+
					"double hub promotion and double CRL rebuild.",
				"remedy", "point the control plane at Postgres directly, or configure the proxy for SESSION pooling")
		}
		return errors.New("session-level pooling could not be confirmed; refusing scheduler leadership")
	}

	// Capture the lock-holding backend's pid so ConfirmLeader can ask about THIS session (see Elector.leaderPID).
	var pid int32
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		// Cannot confirm later without it, so do not claim leadership at all. Unlock before returning: the lock is
		// held and conn.Release() will NOT free it.
		e.unlock(conn, log, "pid_lookup_failed")
		return err
	}
	e.leaderPID.Store(pid)
	e.leading.Store(true)
	if log != nil {
		log.Info("leader_acquired", "key", SchedulerLockKey, "backend_pid", pid)
	}
	// UNLOCK ON EVERY EXIT PATH. conn.Release() does NOT free a session-scoped advisory lock (finding #1): the
	// connection goes back to the pool with its session intact, so an un-unlocked exit parks the lock on an idle
	// pooled connection that nothing can ever unlock, and the whole fleet goes leaderless until that connection is
	// recycled. Previously only the graceful ctx.Done() branch unlocked; every other exit leaked.
	defer func() {
		e.leading.Store(false)
		e.leaderPID.Store(0)
		e.unlock(conn, log, "campaign_exit")
	}()

	// Hold leadership until the context ends or the connection dies. The ping detects a dead connection so
	// this replica stops claiming leadership promptly; Postgres has already released the lock by then.
	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown. The deferred unlock above handles it — this branch no longer unlocks inline,
			// because two unlock sites meant the non-graceful paths had none.
			return nil
		case <-ticker.C:
			if err := conn.Ping(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err // connection dead → leadership lost → Postgres has freed the lock
			}
		}
	}
}

// unlock releases the advisory lock and CHECKS THE RESULT (finding #5).
//
// The previous version was `_, _ = conn.Exec(...)`, discarding both the boolean and the error, and it ran on only
// one of the exit paths. So a failed unlock was indistinguishable from a successful one, and "leader_released" was
// logged either way — the promised immediate handoff could silently not happen while the log said it had.
//
// pg_advisory_unlock returns FALSE when this session did not hold the lock, which is a distinct and interesting
// condition: it means our bookkeeping and Postgres disagreed, and it is worth a warning rather than a shrug.
// Uses a detached context on purpose: this runs during shutdown, when the caller's context is already cancelled,
// and an unlock that gives up because ctx is done is exactly the leak this fixes.
func (e *Elector) unlock(conn *pgxpool.Conn, log *slog.Logger, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var released bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", SchedulerLockKey).Scan(&released); err != nil {
		if log != nil {
			log.Error("leader_unlock_failed",
				"key", SchedulerLockKey, "reason", reason, "error", err.Error(),
				"consequence", "the advisory lock may still be held by this connection's session; releasing the "+
					"connection to the pool does NOT free it, so scheduler leadership can be stranded until this "+
					"connection is recycled or the process exits")
		}
		return
	}
	if !released && log != nil {
		log.Warn("leader_unlock_not_held",
			"key", SchedulerLockKey, "reason", reason,
			"note", "pg_advisory_unlock reported this session did not hold the lock — our bookkeeping and Postgres "+
				"disagreed, which is worth investigating even though the outcome is safe")
		return
	}
	if log != nil {
		log.Info("leader_released", "key", SchedulerLockKey, "reason", reason)
	}
}

// confirmSessionPooling checks that this connection is a real, persistent PostgreSQL session rather than a
// transaction-scoped borrow from a pooling proxy.
//
// The test is direct rather than heuristic: set a SESSION-level parameter, then read it back on what should be the
// same session. Under transaction pooling the second statement can land on a different server connection and the
// value is gone. It cannot detect every proxy configuration — a proxy in session mode is indistinguishable from a
// direct connection, which is correct, because in session mode the mechanism is sound.
//
// This runs while the advisory lock is HELD, so it is a check on the very session that holds it.
func confirmSessionPooling(ctx context.Context, conn *pgxpool.Conn) error {
	const marker = "tunnex_leader_session_probe"
	// set_config rather than SET: PostgreSQL's SET does not accept bind parameters, so the parameterised form is a
	// syntax error — which the integration test caught as "never acquired leadership" rather than as a probe bug.
	if _, err := conn.Exec(ctx, "SELECT set_config('application_name', $1, false)", marker); err != nil {
		return err
	}
	var got string
	if err := conn.QueryRow(ctx, "SHOW application_name").Scan(&got); err != nil {
		return err
	}
	if got != marker {
		return errors.New("a SESSION-level setting did not survive to the next statement, which means this " +
			"connection is not a persistent session (transaction-mode pooling): advisory locks cannot elect a " +
			"single leader through it")
	}
	return nil
}
