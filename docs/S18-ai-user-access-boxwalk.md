# AI user-group access and multiple-role walkthrough

Date: 2026-09-08. Branch: `ai-improvement`. Decision record:
[S18-ai-user-access-decisions.md](S18-ai-user-access-decisions.md).
User guide: [ai-user-model-access.md](ai-user-model-access.md).

## Environment and preservation

The local preview at `http://127.0.0.1:5180` uses the isolated Docker project
`tunnexaiwalk0907repro4`, with network `tunnexaiwalk0907repro4_engine`.
Container labels and network membership were checked before database-capable
commands. Migrations 149 and 150 were applied to this preview; schema 150 is clean.
The final API binary hash is recorded in [preview.txt](walk-artifacts/ai-user-access-20260908/preview.txt).

The existing provider rows were fingerprinted before and after preview updates
and access walks. They remained identical, including the saved `azure` credential
and its `gpt-5` model. No live Azure inference was attempted. Private backups,
login credentials, and scratch tokens remain outside the repository.

The retained **Engineering AI walkthrough** fixture group contains four members.
Its only model grant targets the existing `private-demo` fixture connection. The
fifth synthetic account is an outsider. One fixture member retains `member` and
`ai-admin` for visual inspection. No real user received new AI administration
permissions through this walk.

## Live proof

| Check | Observed result | Evidence |
| --- | --- | --- |
| Grant a configured fixture model to the four-user group | Native engine key provisioned; grant applied | [Group screen](walk-artifacts/ai-user-access-20260908/group-access.jpg) |
| Each of four members calls the model using Tunnex login | Four HTTP 200 responses | [Wire transcript](walk-artifacts/ai-user-access-20260908/group-wire.txt) |
| Outsider calls the same exact model | HTTP 403 | [Wire transcript](walk-artifacts/ai-user-access-20260908/group-wire.txt) |
| CLI authentication | Actual browser-consent/PKCE exchange issued a synthetic user's Tunnex credential; that credential called the model with HTTP 200 | [Wire transcript](walk-artifacts/ai-user-access-20260908/group-wire.txt) |
| Remove a member from the group | Their next browser and CLI calls both returned 403; membership was restored afterward | [Wire transcript](walk-artifacts/ai-user-access-20260908/group-wire.txt) |
| Actual CLI commands | `ai models` listed the granted model; `ai chat` returned the fixture completion | [Models](walk-artifacts/ai-user-access-20260908/cli-models.json), [response](walk-artifacts/ai-user-access-20260908/cli-response.json) |
| Browser Use model | Exact organization endpoint and terminal commands rendered; Call model returned the fixture completion and HTTP 200 Sonner toast | [Rendered response](walk-artifacts/ai-user-access-20260908/use-model.jpg), [DOM](walk-artifacts/ai-user-access-20260908/use-model.dom.txt) |
| Multiple roles in the UI | Saved `member` plus `ai-admin`; both checkboxes and roster roles remained selected | [Roles screen](walk-artifacts/ai-user-access-20260908/multiple-roles.jpg) |
| Remove AI-admin from an already logged-in user | Member retained; the same CLI credential changed from provider-read 200 to 403 | [Role transcript](walk-artifacts/ai-user-access-20260908/role-wire.txt) |
| AI-view | Provider read returned 200; grant mutation returned 403 | [Role transcript](walk-artifacts/ai-user-access-20260908/role-wire.txt) |
| AI-admin cannot assign owner | Role escalation returned 403 | [Role transcript](walk-artifacts/ai-user-access-20260908/role-wire.txt) |

The public human chat endpoint is:

```text
/api/v1/organizations/{orgId}/ai-gateway/inference/v1/chat/completions
```

Authentication is the user's Tunnex login. Provider and native engine key values
are never returned to that user. The fixture response contains a nonsecret
internal key *name* in routing metadata, not the credential value.

## Review and regression results

Two independent finders reviewed the role and access changes. The user approved
all four findings. Their fixes were regression-tested red before implementation
and green afterward:

1. AI-only audit reads are self-scoped; the UI mirrors that scope.
2. Deleted groups lose active provider references even when native revocation
   fails. Accounting remains retained and background retry recovers.
3. Tenant-scoped team mutations do not reconcile other organizations' human
   grants; global processing runs only through the background worker.
4. Legacy CP-admin role auditing uses actual stored before/after role sets,
   including retained secondary roles and previously revoked memberships.
   The revoked-membership correction preserves the revocation flag.

The folded fixes received a cross-lane review. Its remaining revoked-membership
audit edge was corrected within approved item 4 and received a failing-then-passing
regression. The parent inspected the final correction and ran the full tenancy
package in both editions afterward. No unresolved findings remain in these
bounded reviews.

## Local validation and limits

[checks.txt](walk-artifacts/ai-user-access-20260908/checks.txt) records package
results and hashes of the full local logs.

- Full API suite passed in open and enterprise editions, sequentially with
  `-count=1 -p 1 ./...`, using labeled isolated project `tunnexai0907`.
- Final audit correction: full tenancy package passed again in both editions.
- Both API editions built. The final Linux arm64 preview binary was rebuilt and
  the live access checks repeated against it.
- Linux node suite passed in a disposable container with OpenVPN and nftables.
  A preliminary macOS run could not compile the Linux agent command; the Linux
  run supplies the applicable node proof.
- Full CLI suite passed.
- Web typecheck and production build passed; 121 test files and 1,450 tests passed.
- OpenAPI, CLI, TS, RBAC, SQLC and token generation ran twice; the second pass
  produced zero drift across 50 generated artifacts. Diff whitespace check passed.
- Existing migration guard, query-scope and embedded-file classifier guards
  passed in the API suite. The classifier now includes the previously added
  LiteLLM reference catalog directory.

CSRF/MFA refusal, video ownership, tenant boundaries and key-envelope separation
have local regression coverage. These tests **substitute** for live MFA/video and
provider-mode walkthroughs; those remain required at public-beta acceptance with
designated MFA identities and compatible provider fixtures. This walk proves
human chat access through the existing private engine and egress proxy.

The repository's current checkout has no `apps/helper` or the helper targets
listed in the historical AGENTS gate list. Those targets are not applicable here.
No remote CI or desktop macOS/Windows release checks were run, and no production
deployment, push, PR, or merge was performed. Remote required checks must pass on
the published SHA before a merge.
