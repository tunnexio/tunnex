# Agent credential rotation interruption walk

Scope: retained lab agent43.205.122.116, device01a090c2-d5e5-7c66-99b3-a56038bf9361. User authorized interruption/recovery verification. CP and client/gateway remain untouched.

Plan: retain old test credential only in root-only /run directory on agent; never export it. Watch actual atomic .previous handoff creation and pause the existing runtime at that boundary, record metadata only, kill/restart process to exercise real persisted recovery. Verify current credential authenticates, old credential receives401, runtime reconciles and WireGuard handshake recovers. No fabricated candidate state. Temporary watcher automatically resumes a paused process after60seconds if test control is lost. Remove scratch old credential after proof.

Result (2026-09-13): reproduced the real handoff boundary on the disposable
agent with watcher metadata only (`previous_handoff_SIGSTOP`; both recovery
files present). After a SIGKILL and service restart, the repaired runtime
reused the prepared successor: scratch files were removed only after the
successful successor poll, the predecessor probe returned HTTP 401 and the
current probe returned HTTP 200. The server advanced the retry past cancelled
history rather than reusing it; runtime credential revision 5 and WireGuard
revision 4 both converged to `current`. The managed runtime UI showed
connected/ready with a fresh report and an enabled Rotate credential control.

The CP API-only image was updated to `tunnex-api:rotation-recovery-9c9204b8`.
The gateway and desktop client were unchanged. The old API override and API
binary were retained on the CP for rollback. The local transaction suite covers
both suspend cancellation and expiry, gap promotion, replay, stale identity,
arbitrary revision refusal, and immutable revoked history.
