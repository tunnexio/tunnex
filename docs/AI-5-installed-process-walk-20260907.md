# AI gateway installed-process walkthrough — 2026-09-07

The first actual-process walkthrough ran on Linux ARM64 in the explicitly
isolated `tunnexaiwalk0907` Docker project/context `colima-tunnex-sso-review`.
The API executable SHA256 was
`50a934be80995529d94513257d869f7c07f5ee20f3afd7b3c261395c2aff3e37`.
No `AuthFn` test authentication hook or service fixture replaced production
HTTP authentication, authorization, policy or credential handling.

## Completed actual-process evidence

- Fresh PostgreSQL and Redis were isolated on the project's private network.
  Every explicit database operation printed and verified the project/container/
  network boundary. No host API or engine port was published.
- The actual API initialized its schema and bootstrap administrator. A human
  logged in with the one-time credential, changed that password through
  `/api/v1/auth/password`, and created an organization through the API.
- Canonical bootstrap-token issuance and redemption enrolled two agents with
  current runtime credentials. A locally generated, cryptographically verified
  **unpublished fixture** release descriptor supplied bootstrap metadata. No
  actual release assets or installed runtime were claimed.
- The human explicitly enabled ordinary Agent Groups, created a group and added
  both agents through the normal endpoints. The only seeded database record was
  an eligible gateway, with no gateway network/dataplane claim.
- Community AI settings started disabled; credential issuance was refused401.
  Organization opt-in alone still refused an unapplied policy403. Team and agent
  writes applied exact model/provider-key scopes, after which runtime credential
  exchange produced scoped AI tokens.
- Both agents completed a synthetic request through the installed API and pinned
  private Bifrost engine. A forbidden model was refused403. The public scoped
  usage endpoint converged to fourteen tokens.
- Canonical device revocation made an existing AI token fail401, while a separate
  healthy agent still completed inference200.
- After restarting the actual API process, the existing human Redis session
  remained usable, revoked runtime/AI identities remained refused, and the
  healthy runtime could exchange a new AI token and complete inference.

The reproducible scripts are in `deploy/ai-gateway/installed-walk/`. They require
an explicit Docker context, unused project and API binary. Their exact-name
collision and volume ownership refusal checks have zero-Docker mock regressions.
They refuse Python optimization so proof assertions cannot disappear.

## Boundaries

The first walkthrough was non-streaming. Separate full installed streaming,
distinct-team, threshold and retention checks are recorded below only after an
actual successful reproducer run. The earlier native HTTP test and Linux engine
restart/restore evidence remain distinct proof layers.

This is an actual API binary process inside a pinned Go container, with local
plaintext private-network transport and a synthetic provider. It does not prove
the packaged API image, public TLS termination, a real gateway/runtime install,
Helm/CNI behavior, a real provider on Linux or cross-version upgrades. Database
volumes, private logs and stopped containers are retained; they contain generated
fixture identities and must not be published as application artifacts.

## Complete reproducible extended run

The corrected reusable script passed end to end in the fresh
`tunnexaiwalk0907repro4` project, using the same API binary hash above. The safe
result log is committed at
`walk-artifacts/ai-gateway-20260907/installed-process.txt`
(local original: `/private/tmp/tunnexaiwalk0907repro4.log`). It repeated the real human
and agent lifecycle above, then established:

- A third enrolled agent used a distinct team and exact model scope. Cross-team
  model requests returned403 with unchanged instrumented provider arrival count.
- A streamed request traversed the actual API process and Linux Bifrost engine.
  The parser required complete SSE frames, nonempty text, a finish reason and a
  terminal event, and rejected error payloads, truncation or post-terminal data.
- Exact native model pricing was known. Before asserting monetary refusal, the
  test reconciled the assignment, verified applied/current revisions and checked
  that public scoped usage had zero uncosted requests and observed cost at least
  the configured tiny positive limit. A new request was then refused403 without
  provider arrival, while a separate team's successful response remained usable.
- Organization disable refused an existing token401 without provider dispatch.
  Explicit re-enable and reconciliation allowed the still-unexpired token again;
  a fresh scoped credential exchange also worked. Organization opt-in is a
  current-eligibility toggle, not permanent token revocation. Canonical device
  revocation remained a separate permanent refusal for that runtime identity.
- After stopping Bifrost, unique prompt and response markers were absent from
  both logical SQLite records and raw database/WAL bytes containing this run's
  streamed and ordinary traffic.

All successful non-streamed inference responses were parsed and required the
expected synthetic content with no error payload. The run ended by stopping its
own verified immutable container IDs and retaining every project volume/network.
Fixture images were pinned to the locally verified immutable digests in `run.py`.

Earlier reproducer attempts are retained transparently: one omitted an explicit
engine-readiness wait and caught unapplied policy; one was interrupted to fold
independent resource-isolation findings; one incorrectly expected organization
re-enable to permanently invalidate an otherwise-current token and observed200.
The final run added readiness and strict isolation checks and asserted the actual
agreed toggle behavior. None of those failures was erased by resetting a database
or relaxing authorization checks. Provider-secret rotation is a separate proof,
not inferred from this walkthrough or the earlier admin-password rotation.
