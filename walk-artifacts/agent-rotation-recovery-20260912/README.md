# Agent credential rotation interruption walk

Scope: retained lab agent43.205.122.116, device01a090c2-d5e5-7c66-99b3-a56038bf9361. User authorized interruption/recovery verification. CP and client/gateway remain untouched.

Plan: retain old test credential only in root-only /run directory on agent; never export it. Watch actual atomic .previous handoff creation and pause the existing runtime at that boundary, record metadata only, kill/restart process to exercise real persisted recovery. Verify current credential authenticates, old credential receives401, runtime reconciles and WireGuard handshake recovers. No fabricated candidate state. Temporary watcher automatically resumes a paused process after60seconds if test control is lost. Remove scratch old credential after proof.
