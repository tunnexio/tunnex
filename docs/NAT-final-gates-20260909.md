# NAT final gate continuation

Baseline HEAD `88ad7f0`, server content `cddcd57`, client `55f4267`.
Fresh isolated Compose project/cache prefix `tunnex-nat-final-20260909a`;
verified only its network and postgres volume are used. Default stack untouched.

Initial generate-check PASS, fresh migration141/dirty=false PASS, node and CLI
gates PASS. Open full API run failed only `TestQueriesScopeOrgID`: the issuance
existence query needs explicit tenant scoping. Enterprise was not reached.
Correction: add `org_id` to the existing query and pass canonical binding OrgID
at both callers; regenerate sqlc. No lint exemption or global-table annotation.
Add a real database regression that the same issuance ID is invisible under a
different org scope. Re-run affected checks and both full edition gates.

Initial web gate:1303 passed/1 failed (agent JIT wiring heading wait); focused
rerun passed6/6. Full rerun pending, not green by the focused result alone.

Review: server finder found no new blocker. Client finder found stale persisted
dial seeding after HA recovery. User explicitly approved that narrow fix and
focused tests; tracked in the separate client's active-dial decision paper.
No other finding is folded without disposition; no merge/release approval.
