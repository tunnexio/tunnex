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

## Follow-up results

Server product `82d1b48` implements canonical organization scoping at both
issuance existence checks. Generated-code drift check and focused database
race/query-scope checks PASS. Full open and enterprise edition tests PASS;
the separate build-editions target also PASS for both editions (command exit0).

Full server web rerun PASS:112 files,1304 tests, typecheck and production build.
The initial heading-wait failure above remains recorded; the focused rerun
alone was not used as the full gate result.

Client product `24b66e1` folds the explicitly approved P1: seed the monitor from
the actual connected dial, treat identical relay peer updates as no-ops after
ownership validation, and test A-to-B recovery followed by unchanged B polls.
Full main-process suite321/321, typecheck/build PASS. Renderer CI-scoped
clientapp suite64/64, typecheck/build PASS. Both narrow corrections received
clean bounded re-reviews; no unresolved finding from those reviews remains.

These latest changes have local test evidence, not a new exact-final live AWS
walk. The prior successful AWS recovery evidence retains its original server
`cddcd57` and client `55f4267` identities. Exact PR-head CI is still outstanding.
Companion client draft PR: https://github.com/tunnexio/tunnex-client/pull/6
(head `d77e39e208e52a054d8deb5eb3947fe043efc3a3`; CI started, not yet green).
