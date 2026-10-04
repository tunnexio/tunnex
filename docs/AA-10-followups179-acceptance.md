# App Access Story 11 follow-ups — isolated test-CP acceptance

Accepted on **2026-10-04**, clean **schema179**, within the scope below. Story 10
remains per-app MFA (2/2 original slices); Story 11 remains Company apps, assigned
App admin and access requests. Earlier acceptance records are preserved in
[the epic](EPIC-app-access.md).

## Behavior and evidence

- Current grants default to active/disabled; scheduled and unavailable subjects
  are explicit Current filters. Revoked/expired grants appear under History.
  Global and scoped App-admin queries filter before pagination.
- Revoked grant rows are retained for 90 days from `revoked_at`; grant-change audits
  for 365 days. Expired-only grants are not purged by the revoked-grant policy.
  Retention is bounded and lease-fenced. Approved request history preserves the
  original grant ID after live-row removal; terminal replay does not recreate access.
- Confirmed withdrawal and archival release a hostname for a **new app UUID**.
  Old revisions, publications and audit records retain their original identity.
  The archived app cannot republish or transfer its authority to its replacement.

Owned isolated PostgreSQL/Redis tests cover retention boundaries, batching,
lease/lock fencing, rollback, scope isolation and hostname authority. The retention
report combines recorded runs, including a final narrow test-only schema-expectation
correction; it does not claim a single clean full-suite invocation. Its sole declared
skip is a non-regression browser seed. Functional hostname tests passed without skips.

On the isolated test CP, normal APIs verified disable/reservation, archive/release,
new-UUID publication at the same hostname, archived republish denial, retained
history, exact routing and owner/member settings permissions. Existing member
login and private Wiki browser access passed; MFA labels were preserved. Owned
fixture apps were archived and both verification sessions logged out.

All 24 protected durable projections were preserved. The original live helper
reported an audit comparison failure: two new fixture-origin-check audits target
check IDs, outside its app-ID exclusions. The failed report remains unchanged.
An independent read-only appendix joins **those two exact audit IDs** to their
owned checks/apps and proves that removing only those appends restores the exact
original 119-row audit hash. No timestamp-wide exclusion, helper rerun or data repair
was used. The earlier attempt stopped before login because credential metadata
still named the old portal; its evidence also remains preserved.

## Provenance

| Evidence | SHA256 or identifier |
| --- | --- |
| Full frozen source | `fab588b77432d29b051437a18145353badc2b54f42e386fdd5382ce05fb54900` |
| Candidate manifest | `89866f564ae968e082a49291765554898d1cad8524fad887c23e7907967454fa` |
| API image | `tunnex-app-access-live-api:grant-hostname179-89866f564ae968e0` |
| Final acceptance record | `18d490e617fd0b50382e1c7ec44b947be741944d42413e08ad2109a6dc267419` |
| Retention qualification | `605ec130d417fef148b0b1d5eeaad5a458cb9d4ab5933fd55e867d9e9ac84223` |
| Hostname qualification | `0a04d7facd29ef21b1bfb99d882db534b6208cd4b3ee63a039384ac971c6329a` |
| Exact audit-append appendix | `dcc233c3d5bd74df03a0d787a4bc7ce7c66dfe5bd10227afd85544b1af6db100` |
| Existing member browser proof | `6e1ac2ce23bdc060d5714a9e18bad1c137594f60f43493bf2d7126738c5a2ffa` |

Acceptance/report artifacts are retained in the operator's private
`tunnex-story11-review-20261004` evidence directory. The runtime upgrade attestation
is `/opt/tunnex-app-access-live-updates/grant-hostname179-89866f564ae968e0/verification.json`.
Web, gateway, proxy, TLS and DNS stayed unchanged during this API/operator upgrade.
This documentation and CI follow-up is outside the frozen runtime source above.

## Qualification limits

Live retention found **zero eligible aged rows** and executed no purge; aged-data
behavior is proved by isolated synthetic fixtures. Old-cookie/stream rejection is
isolated integration-test evidence, not a live cookie minted by this helper.
Signed OIDC assurance is tested, but no live external customer/company IdP is
qualified. Automatic gateway failover and lossless per-request runtime auditing
are not claimed; runtime events remain bounded/best-effort. This is test-CP
acceptance, not a production release or completed latest-commit PR/CI acceptance.
