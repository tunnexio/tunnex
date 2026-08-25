# Tunnex.io — Product Build Plan (Story-Driven)

## Context

Tunnex.io is a self-hosted, multi-tenant VPN & Zero Trust access platform — a modern, open alternative to Pritunl. It manages WireGuard (and later OpenVPN), supports SSO (Google + Microsoft) alongside manual user creation, and ships its own desktop client (CLI first, then Electron) for Windows and macOS. The entire stack must come up with a single `docker compose up` (and down cleanly), auto-generating all required secrets/keys/config on first boot.

This plan defines **every story** up front. We then build **one story at a time**: implement → review → merge → next. Each story is independently shippable and testable. **Story numbers match their epic** (E3 → S3.1, S3.2, …) for clean branch names and cross-session continuity.

### Locked Decisions
- **Backend:** Go (chi router, `sqlc` for typed queries, PostgreSQL, Redis for sessions/cache)
- **Frontend:** React + Vite SPA + TypeScript + Tailwind — same bundle reused by the Electron renderer
- **Tenant routing:** Single domain (`app.tunnex.io`), org resolved from membership after login
- **Auth:** OIDC (Google + Microsoft Entra ID) + local users (argon2id); cookie sessions in Redis
- **Control/data plane:** API is the **control plane**; a **`tunnex-node` agent** owns the **data plane** (WireGuard/OpenVPN). The API NEVER calls `wgctrl` directly — it talks to an agent, which in the compose quickstart runs on the same host.
- **API contract:** **OpenAPI-first.** Spec is the source of truth; generate the TS client (`packages/shared`) and validate Go handlers against it — no hand-synced types.
- **VPN control:** `wgctrl-go` inside the node agent for WireGuard; OpenVPN via the node agent (later)
- **Deployment:** Self-hosted only. `docker compose` orchestrates postgres, redis, api, web, nginx, and node-agent.
- **K8s:** Helm chart + CRD-based operator — operator reconciliation reuses the agent's reconcile loop
- **Client:** CLI first (`tunnex` binary), then Electron (Windows + macOS)
- **Edition:** **Open-core** (see Edition Model section)
- **Repo:** Monorepo — `apps/api` (Go), `apps/node` (Go agent), `apps/cli` (Go), `apps/web` (React), `apps/client` (Electron), `packages/shared` (generated TS types), `deploy/` (docker, helm, operator)

### Cross-Cutting Principles (apply to every story)
- **Identity ↔ credential binding:** a device/peer credential is only ever valid for its owning user's identity. No floating credentials.
- **Revocation is a full sweep:** revoking a credential releases *everything it ever claimed* — its peer slot (removed from the gateway), its pool address (freed for reuse), and its live telemetry (cleared, so it can't report stale "online"). Established for WireGuard devices in S3.3/S3.5/S3.6; **EPIC 9's OpenVPN devices must apply the identical sweep** (cert/CRL revocation + address release + status clear), not just cert revocation.
- **Desired-state reconciliation:** data-plane state (WG interface) is continuously reconciled against control-plane desired state — never assumed in sync. Same pattern powers the K8s operator.
- **Structured logging + request IDs from day one** (S0.1 DoD), not retrofitted at the end.
- **Secrets encrypted at rest** under a bootstrap master key (S0.3); per-org IdP client secrets are never plaintext.

### Build Protocol (per story)
1. Implement the story on its own branch/commit.
2. Self-review + run `/code-review`; run tests; verify end-to-end.
3. Report outcome, get sign-off, then start the next story.

**Where a commit lives:** product code ALWAYS on the story branch (the sign-off/merge
gate depends on branch isolation). A process/docs correction whose value is *immediate*
(e.g. fixing this re-entry checkpoint) lands on `main` directly — a fix that only helps
pre-merge sessions is useless stuck on an unmerged branch. When main advances this way,
rebase the active story branch onto it to keep the ff-merge clean.

**Merge instructions are session-bound:** a merge instruction executes in the session that
receives it, or is RE-CONFIRMED at re-entry — a sign-off read out of a summary/handoff is not
authorization to merge. (Codified after S4.8's merge waited on an explicit re-confirmation.)

**Merge mechanics (confirmed S6.0b):** merges to `main` are ff-only + linear history. As of S6.0b,
`main` has GitHub branch protection REQUIRING the CI checks `gates` + `client (macos-latest)` +
`client (windows-latest)` (the `e2e` job is opportunistic, NOT required); `enforce_admins=false` so
an admin (iotunnex) can still push, but the social sign-off gate is now mechanized for PRs. The
standard flow: story branch → PR → CI green (required checks) → user sign-off → ff-merge → push.
CI is the CONTINUOUS invariant proof; the human sign-off is still required on top (CI green ≠ auto-merge).
**(Protection was found ABSENT — 404, not permissive — at S7.5.3/PR#24 and RE-ESTABLISHED 2026-07-16,
now belt-and-braces: repo `allow_merge_commit=false` + `required_linear_history` + required checks strict
+ no force-push + `enforce_admins=false`. Verify-present is now a PRE-MERGE check — see the Armed Guards
inventory "main branch protection can silently vanish". This claim is dated + true, not aspirational.)**

**Force-push standing authorization (S6.3):** `git push --force-with-lease` is pre-authorized for
`story/*` branches ONLY (e.g. after a rebase onto main) — no per-push ask needed. `main` is NEVER
force-pushed (protected + linear). This covers only the working story branches, whose history is
expected to be rewritten before merge.

---

## Story status (re-entry checkpoint)
**Update this on every merge (one line) — a stale pointer re-enters a fresh session in the wrong epic.**

**REGISTERED FUTURE EPIC (2026-08-25): EPIC 21 — PROVIDER-NEUTRAL FQDN ACCESS RESOURCES.** Exact service-DNS resources let an existing People/Agent policy source reach a named private service on approved protocol/ports while DNS answers change underneath it. The core is cloud-neutral manual FQDN entry; AWS/Azure/GCP discovery and strict shared-endpoint L7 hostname enforcement are separate follow-ups. Full story/UI plan, boundaries, proofs, and estimates: [`docs/EPIC-21-fqdn-access-resources.md`](docs/EPIC-21-fqdn-access-resources.md). **REGISTRATION ONLY — finish EPIC 20 first; no S21 branch, schema, API, compiler, resolver, routing, or UI implementation has started.**

**AUTHORITATIVE CURRENT (2026-08-23): S18 AI AGENTS CONSOLE WORKSPACE — PR #36, content tip `<post-merge sha>` (`b3691a013912886595bf3543c4f26d65c3d5370b` pre-merge). Founder-reviewed operational Agents inventory/detail/Add Agent flows; Agents-owned policy-template and MCP-profile workspaces; canonical Access-owned typed Groups/Resources; Access Rules and Devices ownership; one-binary Community-to-Scale entitlement behavior; exact group member counts; safe MCP assignment lifecycle; Agent quota/runtime settings; and device approval confirmations. Named deferrals remain S18.1 one-binary repository-wide licence-tier cleanup, S18.2 Agent query scalability, and S19 opaque enrollment status plus Gateway/Site-to-Site operations; Gateway/Sites/Kubernetes, Users & Roles, and broader Org Settings work are outside S18. Required GitHub checks and story-end review remain merge prerequisites.**

**AUTHORITATIVE CURRENT (2026-08-23): F20 ONE-COMMAND ONBOARDING — PR #35, content tip `<post-merge sha>` (`1985efff1943bda3642326c83bfd4f74630ca1c0` pre-merge). Follow-up live-wire fixes make the Linux upgrade runner systemd-valid, avoid a host UID lookup failure, add a safe QuickStart preview with visible progress, and give unsupported Windows Server hosts actionable recovery paths. Guided native Linux/macOS shell and Windows PowerShell entrypoints prepare a supported Docker/Compose runtime, review the plan before product mutation, install a verified release, verify startup, and isolate each target with its own Compose project. macOS and Windows remain portable-control-plane installs: their WireGuard gateway must be enrolled on a separate Linux host. Required GitHub checks and story-end review remain merge prerequisites.**

**AUTHORITATIVE CURRENT (2026-08-22): F19 CENTRALLY MANAGED MCP HARNESS PROFILES — PR #33, content tip `<post-merge sha>` (`c3c3da3` pre-merge). Shared MCP profiles now target reusable agent groups; the managed runtime converges both exact routes and the loopback proxy without host-local endpoint settings. The live DeepWiki walk proved `read_wiki_structure` allowed (HTTP 200) and `read_wiki_contents` denied (HTTP 403) after removal of the legacy agent-host override. Required GitHub checks and story-end review remain merge prerequisites.**

**AUTHORITATIVE CURRENT (2026-08-21): F14 MCP TOOL POLICY ENFORCEMENT — PR #29, content tip `9176c91` (`9176c91` pre-merge). Product code and the DeepWiki CP walk are complete: default deny, one allowed tool, denied sibling, header/body mismatch refusal, stale-inventory fail-close, audit, and the explicit direct-upstream boundary. Required GitHub checks and story-end review remain merge prerequisites.**

**AUTHORITATIVE CURRENT (2026-08-13): PRIVATE KUBERNETES SERVICE HANDOFF — PR #127, content tip `ed657460` (`a5aff92b` pre-merge). Adds selected in-cluster connector handoff, private DNS/VIPs, direct ready-endpoint DNAT, CNI-safe forwarding, persistent connector identity, and the deterministic client return route proven by the rc31 EKS walk. Earlier `CURRENT` entries below are historical.**

**CURRENT (2026-07-31): EPIC 13 = GATEWAY RECOVERY — BUILD COMPLETE INCLUDING SLICE 7 on `story/S13.1-gateway-recovery` (tip `7c1a127`; Slice 7 = `120ff0c`, since then docs-only), NOT MERGED. Slice 7 (operator-initiated restore, `POST /nodes/{nodeId}/restore-devices`, new perm `device:restore`, re-homes onto a named LIVE gateway because a revoked node never returns) closed the reachability defect and is RED-PROVEN REACHABLE + UI-exposed. **REVIEW STATE POINTER = `docs/S13.1-review-state.md`** (pass 1 COMPLETE — 20 findings + F3, HELD, nothing folded, `docs/S13.1-review-pass1-findings.md`; pass 3 launched before pass 2 by ruling; pass 2 not started and must cover Slice 7). Earlier note: pass 1 was once interrupted — (run `wf_642e5fe8-1ed`: 8/8 finders done, 127/144 verifiers returned, Critic and Synthesize never ran — resumable from cache). The review remains a merge precondition. Next session = REVIEW → WALK → merge word, nothing in between.** The epic exists for one observed event: an AWS gateway went offline past its 48h cert lifetime and could not come back — `/agent/renew` lives behind the mTLS channel its expired cert can no longer authenticate to. Commit-one `docs/S13.1-decisions.md` (six walls, D1–D10 ruled). **SHIPPED:** agent precedence (`identity.Decide`, no network argument — a failed handshake structurally cannot trigger re-key; `Recover` ranked above `UseToken`) · **PoP re-key** on the public listener (RSA over `nonce ‖ CSR DER`; gate BEFORE crypto so timing is not a liveness oracle; **D3 amended: expiry authorizes, revocation REFUSES** — expiry is an absence of action, revocation is the presence of a decision) · its own path-scoped throttle + body cap (registered before `middleware.RealIP` — review #1 was exactly that) · **cascade restore** (`revoked_cause`, reclaim-first via the canonical oracle) · **Slice 6 `provisioned_ip`** (`needs_reexport` gains the ADDRESS cause for EVERY mode; ranges stay static-only; both contract rewrites + the label the census under-scoped) · **D10 second identifier** (key fingerprint: a LOST RESPONSE no longer bricks a gateway; ambiguity refuses; three implementations of one digest pinned to a golden vector; agent persists its pending key before submitting and reuses it so retries CONVERGE; migration guard forced expand/contract with both shim halves). Retroactive review pass 1 (leader election) folded — *leadership was a boolean that lies*; `ConfirmLeader` now matches `pg_locks`. **OWED BEFORE MERGE, IN ORDER: (1) the epic-end review pass — three passes by surface family (unauthenticated re-key surface · identity/cascade data path + migrations 0054–0061 · agent recovery loop), ~4.5–6M tokens, a merge precondition alongside CI and the walk, and a truncated pass is worse than none; (2) the walk per `docs/S13-boxwalk.md` — seven legs, TWO GATEWAYS MUST BE OFFLINE 48h+ BEFORE the session (`agentca.CertTTL` is a constant; the clock is the only way to make a cert expire); (3) the merge word.** **RULED — cascade-restore reachability: SLICE 7 (operator-initiated restore), built AFTER the review pass and BEFORE the walk; two conditions — authorized as a deliberate operator act (same class as minting a join token) and RED-PROVEN REACHABLE, not merely correct. Un-revoke PERMANENTLY REFUSED (it is the attack chain D3 exists to prevent); removing the mechanism refused (re-opens Wall 6). Walk Leg 4 stays a falsification attempt. The defect:** `RestoreCascadeRevokedDevices` has one caller (`Rekey`), devices are cascade-revoked in one place (`Revoke`), and `Rekey` refuses a revoked node — so the trigger may put the node into the one state that can never reach the restorer (dormant-machinery law). Four faces in the paper; walk Leg 4 is written as a falsification attempt. Retroactive **pass 2 (backup/restore)** still attaches to the next natural merge boundary. Registered: the 0061 contract migration (trigger = the release after this one) · no general rate limiting · body caps only on the two re-key routes · failover hysteresis persistence (beta-blocking, owned by the failover story).
**CURRENT (2026-08-07): S12.13 MAIL VISIBILITY — PR #98, content tip `2f0a8174` (`c96246bc` pre-merge).**

⛔ **THE FOUNDER CONFIGURED FIVE SMTP VARIABLES CORRECTLY AND CONCLUDED MAIL WAS DISABLED. IT WAS SENDING
THE WHOLE TIME.** `DevLogging: !cfg.IsProduction()` meant `TUNNEX_ENV` — a variable about what KIND of
deployment this is — silently governed mail behaviour, producing a mailer labelled `smtp+log` and a log
line reading `email_not_sent_logged`. `teeMailer.Send` logs and then returns the SMTP send's own error; it
has never suppressed delivery. The defect was entirely in what it was called.

- **D1 — `MAIL_DEV_LOG` is its own variable, read, default off.** SMTP_HOST set means send; nothing
  overrides it. One flag must not govern two unrelated things.
- **D2 — the boot line names the DESTINATION, not the mechanism.** `mail_destination` reads
  `mail.spacemail.com:587`, or that mail is disabled and which variable fixes it. `smtp+log`'s `+` read as
  capability to one person and as "log INSTEAD of SMTP" to another.
- **Success is now as visible as failure** (`email_accepted_by_provider`). Only failures logged before, so
  an empty log meant BOTH "it worked" and "it never tried". It claims ACCEPTANCE, never delivery — the
  provider's outbound log owns that — and never carries a body.
- `email_not_sent_logged` → `email_copied_to_log`. **A log line naming an outcome must be true in every
  context it can be reached from**; the old name was true alone and a flat lie inside the tee.
- **The screen says it.** `/meta.smtp_configured` had ZERO web consumers — which is how this cost a session.

⭐ **MAIL PROVEN ON THE WIRE 2026-08-07: a real invitation reached a Gmail inbox from `support@tunnex.io`
via Spacemail.** SPF/DKIM fine. This closes the walk's delivery leg; the accept→membership legs remain.

**CURRENT (2026-08-07): S12.14 BRANDED PRODUCT EMAIL — PR #99, content tip `<post-merge sha>` (`3093c59d` pre-merge).**

⚠ **RE-POINTED, NOT RE-DATED — the third instance of the sequencing failure rule 6 names.** The checkpoint
was written at `a41dabac` and the go:embed classifier fix landed after it. Re-pointed in the same breath
rather than at merge time, which is what the rule asks; the rule was fine and the SEQUENCING was wrong, again.

Ported from `tunnex-web`'s `src/lib/email/{palette,layout}.ts` — same shell, colours and footer. Covers
invite, resend, password reset, email verification, account-exists, MFA-reset notice.

⛔ **THE LOGO TRAVELS WITH THE MESSAGE (`cid:`), IT IS NEVER FETCHED.** Three versions: tunnex.io (a
phone-home on the most private mail the product sends) → APP_BASE_URL (no phone-home, but the DEFAULT is
`http://localhost`, which resolves to the RECIPIENT's machine — every invitation from a default deployment
shipped a broken image; plus an accidental open-tracking pixel in the org's own logs; plus remote images
blocked by default in Outlook and corporate gateways) → **embedded**. It DELETED the branding wrapper
rather than adding one: a rendered message carries no deployment-specific value, so there is nothing to
forget. `data:` URIs rejected — Gmail and Outlook strip them.

⚠ **Both bodies always**, `multipart/related [ alternative [ text, html ], png ]`, text FIRST (RFC 2046
orders alternatives least-to-most preferred). **quoted-printable on both text parts** — a red asserting the
line limit caught 2,200-character HTML lines against RFC 5321's 998 cap, and multi-byte UTF-8 declared as
7bit. Proven with Python's stdlib MIME parser; decoded PNG sha256-identical to source.

⭐ **AND THIS PR FILLS IN #98's POST-MERGE SHA — WHICH IS HOW THE RULE-6 BYPASS DISAPPEARS.** Rule 6 sends
the post-merge fill to `main` as a "docs correction", and GitHub logs every one of those as
`Bypassed rule violations: 3 of 3 required status checks are expected` (observed on #97). But a merged PR's
post-merge sha is KNOWABLE by the time the NEXT PR is open — so it is filled here, inside a PR, under all
three checks. **The correction rides the next story instead of bypassing the gate.** Registered for the
rule-6 amendment the founder still owes a ruling on; the last PR in a run is the only one that still needs
a direct push, and it can simply wait for the one after it.

⛔ **AND A TOKEN ENDS AT WHITESPACE.** CI caught `captureMailer` taking everything to the end of the body —
correct only while the link was last in it. Fixed as the CLASS: `auth/service_test.go` carried the
identical extractor and was green by luck.

**HELD, unbuilt:** `go/email-injection` at `buildRFC822` (CRLF in To/Subject) — pre-existing on `main`, now
more reachable with SMTP on · `delivered` has no web consumer · `ResendInvitation` returns no token ·
**S12.12b** endpoint edit · rotation before launch · **the §7 full-surface walk, never run** · the `127/2`
ceiling numerator (third instance of the one-count-two-sources law) · the **rule-6 bypass** question.

**CURRENT (2026-08-07): S12.12 GATEWAY LIFECYCLE — transfer, delete, rename — PR #97,
content tip `c954572b` (`c061b265` pre-merge).**

⛔ **THE FOUNDER REVOKED A GATEWAY AND HIS DEVICE READ `revoked`, WHICH HE HAD NOT DONE.** `nodes.Revoke`
ran `RevokeDevicesForNode` inside its own transaction, sweeping every active and pending device homed there,
and a revoked gateway is never active again. Retiring a gateway meant disconnecting everyone on it with the
only remedy behind an endpoint the operator did not know existed.

**Commit-one is `docs/S12.12-gateway-lifecycle-decisions.md`** (D1–D7 ruled). **SHIPPED:**

- **D1 TRANSFER BEFORE REVOKE, as its own step.** `POST /nodes/{nodeId}/transfer-devices`, new perm
  `device:transfer`. Revoke now REFUSES with `devices_still_homed` (409, naming the count) while any device
  is homed there. Both halves ship together: the refusal alone is a dead end, the endpoint alone is an
  optional step nobody takes before the destructive one. **The order was ruled from the ABANDONED state, not
  the end state** — transfer-first leaves "devices moved, old gateway still running"; revoke-then-restore
  leaves a disconnected fleet and no un-revoke.
- **D4** pending devices move and STAY pending · **D6** one audit event naming the count and both gateways.
- **Addresses are NOT reallocated** — the pool is org-scoped (`organizations.pool_cidr`, uniqueness on
  `(org_id, ip)`), so a same-org move cannot collide. Measured, not assumed.
- **D7 — THE RESIDUAL THAT POINT 6 WOULD HAVE HIDDEN.** "Managed devices re-home themselves" is true ONLY
  for hub-set members: `activeHubDialFrom` returns `derived=false` otherwise and the client keeps its baked
  endpoint. `ProfileStale`'s gateway cause was static-only, so a managed device moved onto an ordinary
  gateway was moved in the database, broken on the wire, and reported `needs_reexport: false` everywhere.
  Acceptable while the only path was the rare operator restore; transfer makes re-homing routine. Now
  covered, gated on `nodes.SelfHomingNodes` so a device that genuinely heals is not flagged forever.
  ⚠ Unknown resolves in OPPOSITE directions on the two surfaces, deliberately — the transfer's one-shot
  report assumes a re-issue is needed; the standing Devices list does not.
- **D2 DELETE a revoked gateway** (`DELETE /nodes/{nodeId}`), and the enrolment token goes with it —
  `consumed_node_id` is `ON DELETE SET NULL`, so it would have survived UNLINKED and still enrolled one.
  The ruling was right; the premise it was ruled against (that the FK would block) was inverted.
- **D3 RENAME** ships. **THE ENDPOINT EDIT DOES NOT → S12.12b**: there is no snapshot of the endpoint a
  config was issued against, so the edit would be invisible to `needs_reexport` — point 6's defect with no
  row moving at all. Needs `devices.provisioned_endpoint` + a fourth `ProfileStale` cause. ⚠ Drags D3's
  ceiling clause: re-enrolment is the only correction and `CountLiveNodes` charges a slot for it.
- Earlier in the same PR: the invitation second-destination e2e spec (`e2e/tests/invitation.spec.ts` —
  a real invitation, no mocks, asserting the invitee lands INSIDE the org and NOT on `/create-org`), and two
  laws (guards-in-composition · one count, two sources).

**HELD FOR DISPOSITION, unbuilt:**
- ⛔ **THE CEILING NOTICE'S NUMERATOR IS STILL ORG-SCOPED against a deployment ceiling** (`Gateways.tsx:614`
  feeds `nodes.length` to `ceilingSentence`). On a box with 127 live gateways and a ceiling of 2 it renders
  the AT-ceiling sentence — so the over-ceiling branch, which exists to say "revoking one will not free a
  slot", can never fire. **Third instance of the one-count-two-sources law**, ten lines from the badge that
  was fixed for it.
- `delivered` (the invite 202's honest delivery flag) has NO web consumer — `Users.tsx:922` reads
  `invite_token` and ignores it, so the screen cannot tell a sent invitation from a failed one.
- `ResendInvitation` returns no token · `revoked_cause` not surfaced on the Devices list.
- **The §7 full-surface walk has never run.** Rotation before launch.



⚠ **RE-POINTED, NOT RE-DATED.** The checkpoint was written at `42a9c609` and the mail work landed after it
— which is the exact sequencing failure this rule was written for, twice. Re-pointed in the same breath
rather than at merge time.

⛔ **FOUR DEFECTS THE FOUNDER FOUND BY USING THE PRODUCT, each live on `main` when found:**

1. **THE GATEWAY CEILING COUNTED ONE ORGANIZATION.** Starter allows 5 gateways and UNLIMITED orgs, so the
   paid ceiling was 5 × N — lifted by the "+ New" button in the product's own header. No exploit, no API
   misuse. Community and trial only LOOKED safe: their org ceiling happens to be 1, which is two numbers
   agreeing rather than a boundary. Now `CountLiveNodes` (deployment-wide), and the nav badge's numerator
   moved to the same source — it paired an ORG count with a DEPLOYMENT ceiling, so a fresh org read "0 / 5"
   on a full deployment and the operator learned otherwise from a shell error minutes later.
2. **NO WAY TO DELETE AN ORGANIZATION.** `DELETE /organizations/{id}` had shipped since S1 with `org:delete`
   on it and NO CALL SITE. And it is a SOFT delete: gateways keep carrying traffic, devices keep pool
   addresses, credentials keep authenticating — owned by an org no screen shows again. Refuses now with
   `org_not_empty` naming every blocker at once; no force flag.
3. **THE TRIAL COULD NOT EVALUATE SSO** — the capability most likely to decide an enterprise purchase.
   Granted, and BOUNDED: what lapses is ADMISSION (JIT provisioning, domain-capture auto-join), never
   access, so a lapsed trial keeps its humans and stops collecting new ones.
4. **MAIL FAILURE WAS REPORTED AS SUCCESS.** `mail.New()` with no SMTP host returned a mailer that LOGGED
   the message and returned `nil` — so every invitation, verification link and password reset "sent" and
   vanished while the API answered 202. Invitations are now the ONLY way anyone joins, so that is a
   deployment nobody can enter, reporting success on every screen. Fixed: `ErrNotConfigured`, and the
   invite path carries BOTH facts (`delivered: false`, the link kept so it can be handed over). The body
   is no longer logged — it carried invitation and reset links into shipped logs. The development mail catcher was removed from
   the compose a customer can run** (it was never in `deploy/tunnex.yml`; the danger was
   `SMTP_HOST:-mailpit` in `docker-compose.yml`) and moved to `docker-compose.dev.yml`. A deployment with
   no SMTP now says so at STARTUP and via `/meta.smtp_configured`.
5. **D23 — A MACHINE CREDENTIAL OUTLIVED ITS OWNER'S DEACTIVATION**, indefinitely. D14 bound credentials to
   humans SO THAT accountability exists; the binding was checked at rest and never at use. RULED to
   deactivation alone — removed-from-org is unreachable (deactivation PRESERVES the membership row) and a
   guard for a state nothing produces is dormant machinery. ⚠ The cost is real and now has a warning where
   the act happens: the roster carries the count of credentials a person owns and the deactivate
   confirmation states that they stop immediately.

**S12.11 (onboarding, renumbered — PLAN's S12.6 is COMPLIANCE and one number named two stories):** no public
signup ever · CP-admin bootstrap with a printed one-time credential · forced password change as a WALL ·
**cross-org role grants** (`cp_admin` asked BESIDE `RoleIn` — synthesising owner roles would make every
org-scoped check in the product return true for tenants the caller is not in) · four invariants, reds both
directions, mutation-checked · the nine skipped e2e specs re-pointed, **two of which were never about signup**
(S12.5 org-switcher collateral, swept into a batch reason written over an unread failure).

**S12.6 COMPLIANCE (website repo):** the surface MEASURED, not assumed — seven tables, two free-text fields,
and `issued_by` making our own staff data subjects. **Retention SHIPPED:** a request that produced no key
expires after 90 days; the ledger is permanent because offline verification means we can never ask a
deployment what it is running. `/privacy` rewritten to name the tables and, finally, to say what we do NOT
hold. **S12.10:** `ADMIN_TOKEN` deleted — the admin gate is a VERIFIED Access assertion (JWKS, `iss`, `aud`),
and `issued_keys.issued_by` records who signed each key.

⚠ **Registered, not built:** no warning surface listing the credentials a person owns (only the count) ·
paid bands still cannot be issued (queue mints trial only) · `/auth/signup` has no rate limit · the
CreateOrg `org_limit_reached` re-check branch is dead code · deployment-scoped audit rows (`org_id NULL`)
are written and unread · retention for `subscribers`/`trials` and the residency question are HELD.

⛔ **AND S12.5 STILL NAMES TWO THINGS** — PLAN's EPIC-12 list says "Landing + payment", the pointer and
`docs/S12.5-org-question-decisions.md` say the org seam. Held: renaming a merged story touches PR #95's
record, and that is a founder call.

---

**PREVIOUS (2026-08-07): S12.5 — THE ORG SEAM, THE SIGNUP BOUNDARY, AND THE CP-ADMIN BOOTSTRAP — PR #95,
content tip `39ef3d0a` (`b1546ee6` pre-merge).**

Started as the org question: `multi_org` became payable in S12.1 while the web threw away every org but the
first (14 call sites, each indexing zero). Shape B ruled — the server was already multi-org, only the client
discarded. ⚠ `useOrg()` had NO consumers; the brief said 33 unchanged, measurement said fourteen changed.

⛔ **THEN THE FOUNDER FOUND THE REAL DEFECT.** `/auth/signup` was `security: []` — no invitation, no
allow-list, no setting that closed it — so a stranger could sign up, verify their own email, and become
OWNER of an organization on a private VPN control plane. **The only thing stopping them was the org CEILING,
a commercial number the customer PAYS TO RAISE.** The product was selling the removal of its own signup
control.

**RULED: THERE IS NO PUBLIC SIGNUP, EVER.** Install creates the CP admin; everyone else arrives by
invitation or SSO domain capture, both acts by someone already inside. `users.can_create_orgs` (0073,
DEFAULT false) is the first deployment-level authority in the product — ONE BOOLEAN, not a role system,
because every existing authority is `map[orgID]role` and a permission granted in org A cannot license
creating org B.

**THE CP-ADMIN BOOTSTRAP (0074):** first start with no users mints ONE account and prints a framed banner
with the credential — **surfaced by `make up` on the operator's terminal**, gated on the credential still
being unclaimed so a restart never republishes it. Forced password change is a WALL (403 everywhere but
`POST /auth/password`, which did not exist and had to be built). ⚠ Three attempts failed on the same blind
spot — a JSON log line, then a file inside the container, then a banner hidden by `up -d`: **the question
was never "where does the credential go", it was "where are the operator's eyes".**

**Also shipped:** `/meta` edition from the licence (a CONSTANT said "open" since S12.1 while 11 web files
gated on it) · licence PERSISTENCE (`system_settings`, read-through, TTL floor, last-good-verdict) · `gw`
authoritative when signed · cross-repo band guard · the standing ceiling notice + CeilingUpgrade route ·
`k2026` into `TrustedKeys` and **`k-golden-1` removed** (its private seed is published) · **peek-before-consume
on enrolment** — a refusal the operator can fix must not destroy the token they need to retry.

⚠ **Registered, not built:** paid bands cannot be issued (queue mints trial only) · granting
`can_create_orgs` to a second person · `/auth/signup` has no rate limit · one projection over one type for
`authUser`/`CurrentUser` · **nine e2e specs SKIPPED with a named trigger** — they assert the signup flow the
product no longer has, and their replacement is invitation-shaped.

⛔ **NEXT: the rest of the onboarding rebuild** — invitations (invitee sets their own password from the
link), CP-admin cross-org role grants, and the fixture/e2e repair that rides with them.

**`misc-development` — RAPID UI/UX BRANCH, FIRST MERGE (2026-08-05) — PR #91, content tip
`f5f84a8a` (`9c8f5bc6` pre-merge).** ⭐ **THE BRANCH STAYS OPEN** — founder-directed: a standing
lane for rapid UI/UX iteration, not a story branch, so it is NOT deleted on merge and re-merges from the
same name. It carries no story number and owes no walk; work that is *functionality* is flagged as such in
its own commit rather than folded into the UI narrative.

Overview was reshaped on direct instruction: panels size to their CONTENT (multi-column flow, the fix
already accepted on Settings — reading order becomes column-major); Recent Activity, Needs Attention,
System Health and Site-Link Traffic REMOVED; AI Agents became a stat card carrying the unattributable gap
in its sub-line. Each removal was checked against the absence question first and none was a sole surface.

⛔ **AND ONE SECURITY CHANGE, DELIBERATELY NOT BURIED IN THE UI WORK: deactivation now reaches the CRL.**
Before it, a deactivated user's OpenVPN certificate stayed cryptographically valid and the only thing
refusing the client was `ccd-exclusive` on the gateway — *a refusal that depends entirely on a config flag
on a remote box is not defence in depth.* Revoke is in the same tx as the status flip; the symmetric
restore ships with it (revoking without restoring is a one-way door). **Migration 0071** adds the
`user_deactivated` cause, distinct from `cascade` so a gateway restore cannot revive it.
⚠ **DEPLOY ORDER: 0071 BEFORE the new binary** — new binary on old schema violates the CHECK on every
deactivation.

⛔ **S11.1 (site-link throughput time-series) CUT** on a named trigger after the effort was scoped —
`docs/S11.1-throughput-commit-one.md`, `docs/CUT-REGISTER.md`. Nothing can backfill it, so it would ship
blank for seven days; `/metrics` already serves anyone who wants trending.

**S15.3 — THE AGENT SURFACE + THE UI PASS — MERGED (2026-08-05) — PR #90, content tip `19bdd375`
(`224aa883` pre-merge).** ⚠ *Re-pointed once before the merge: the first checkpoint named `dac3382f`, then
CI's gates red-lined and a fix landed after it. Re-pointed in the same breath rather than at merge time —
the rule is fine and the SEQUENCING is what slips (third instance, after S14.14 and S14.17–19).* Trees
verified byte-identical across the rebase; only the sha was re-parented. `docs/S15.3-decisions.md`, `docs/rule-validity-matrix.md`,
`docs/rule-model-review.md`, `walk-artifacts/S15.3-agent-e2e.md`.

⭐ **THE AGENT IS A PEER HOMED ON A GATEWAY, NOT A GATEWAY** — the model was rebuilt mid-story after the
founder's question exposed it. Traffic an agent originates ON a gateway is locally-originated, never
traverses `FORWARD`, so no grant could ever fire. **Proven end to end on the wire** with the product's OWN
generated command: grant counter `0→1` on the allowed port, `default_drop 0→4` on the adjacent one, deny
measured as 5 packets in / 0 out, revoke removing the peer from `wg0`.

**SHIPPED:** agent creation + connect command (`kind='agent'`, cap-exempt, static export) · `src_kind='agent'`
as a policy source · agent liveness with `gateway_reporting` (⛔ *a dead agent and a dead REPORTER produce an
identical absence of handshakes*) · `posture_not_applicable` — **device posture reached an agent's data plane
and killed its tunnel**, measured, because an agent's `user_id` is the admin who created it · agents removed
from the human device surfaces (`kind`, never `platform`) · `invalid_rule_self_site`, the **first cross-field
check `CreatePolicyRule` has ever had** · a rule form of one searchable picker per side, with the compiled
effect stated before Create.

**UI PASS across the product:** DataTable gained search, sort, pagination, selection, declarative `rowActions`
with `unavailable` reasons, row expansion and `rowAttrs`; Rules, Groups, Resources, Invitations, Machine
credentials and Pending devices converted; **Approve/Reject had no call site on the Devices page**; Edit for
groups and resources — **both `PATCH` endpoints existed and nothing called them**.

⛔ **OPEN AND HELD, NOT DONE:** one agent per gateway (and a revoke bricks the slot permanently) ·
`wg-quick` deletes the interface when `resolvconf` is absent · exported ranges can overlap the agent host's
own subnet, undetectably · whether `enrols_kind`/`enrolled_kind` should be RETIRED (zero consumers since the
peer-model rebuild) · client paging on the log surfaces (removed: `audit.spec` proves keyset stitching by
counting DOM rows).

**EPIC 15 WALK + THE ARMING — MERGED (2026-08-04) — PR #89, content tip `53e6d9c0` (`7a8baa8c` pre-merge).**
`docs/EPIC-15-CLOSE.md`. **Five legs PASS**; ⛔ **§7's FULL-SURFACE PASS IS UNRUN, NOT CLEAR** — five legs of
an epic walk is not a product walk.

**The enrolment refusal is ARMED**, licensed by the D14 restore proof discharged on the wire at Leg 1
(`401 → 204 → 200`, controlled). ⛔ **AND FLIPPING THE CONSTANT CHANGED NOTHING — the guard had ZERO CALL
SITES**; it is now called in `Enroll` and pinned by a test that fails if the call leaves `Enroll`.

⭐ **THE DEFECT THE WALK FOUND AND NOTHING ELSE COULD HAVE:** a placeholder public key made `wg syncconf`
reject the **entire interface** — a gateway with **zero** peers, every human device gone. The guard for it
existed since S9.1 and was **one predicate too narrow**. Fixed at the peer-set source; **15 files of fixture
keys `wg` would have rejected** were the defect's other half.

**SEQUENCE RULED: S15.3 → the FULL-SURFACE walk → the beta-bundle call.** The beta call comes after S15.3,
and §7 has not happened.

**S15.3 (`story/S15.3-agent-surface`) — commit-one RULED, all four decide-items:** nav **B** (inside
Devices) · the MCP marker is a **nullable free-text `label`, operator-asserted, NEVER inferred** ·
**serve `devices.kind`** · **NOT enterprise-gated**. ⛔ Nothing may reach `policyspec`.

**S15.2 SLICES 1–4 MERGED (2026-08-04) — PR #88, content tip `b292a51c` (`d22adf64` pre-merge).**
The address-bearing agent + the agent as an RBAC principal. Four slices in the chain's order.

**1 — the issuer column** (`0066`): `node_join_tokens.issued_by` + `nodes.owner_user_id`. ⛔ FIRST BECAUSE
IT STOPPED AN ONGOING LOSS — `IssueJoinToken` always received the human and wrote them to the audit log
ALONE. ⚠ Two FK actions, each argued not copied: node = **RESTRICT** (S15.1's choice), token = **SET NULL**
(a spent record of an act should survive losing the name). Both mutation-pinned.

**2 — degrade-and-flag** (D25(C)): an unowned agent RUNS, is flagged `unattributable`, and says so. ⛔ THE
REFUSAL (D25(B)) IS BUILT, TESTED, MUTATION-PROVEN AND **SHIPPED UNARMED** behind a build-time constant —
never a config flag, which would be the grandfather clause D14 refused. The rule is tested SEPARATELY from
its arming, so arming it later is not a leap of faith.

**3 — the agent IS a `devices` row** (`0067`, `kind`): D15 satisfied BY CONSTRUCTION (the /32 map) and the
revocation full-sweep inherited. ⭐ **§9.2's "collision" was not one** — `devices.user_id NOT NULL` means an
unowned agent has no row, no /32 and no attribution, which is EXACTLY what `unattributable` says. The
invariant and the flag are one fact. Cap exemption in the INDEX, mutation-proven both ways.

**4 — the agent principal** (`NewAgentPrincipal`, `AuthAgent`, `RoleAgent` with **NO PermPolicyManage**).
Six auth sites collapsed to ONE seam. ⛔ **THE CENSUS RE-RUN IS AN EXECUTABLE MERGE GATE** with a vacuity
floor, and it is PROVEN ABLE TO FAIL (a planted second construction site was caught by file and line).

⛔ **HELD:** arming the enrolment refusal — gated on the D14 restore proof (`S15.0 §15`), which does NOT
proceed on a substitute · **D26** (an agent is a `devices` row, so it inherits `ON DELETE CASCADE` —
LATENT, since no code path deletes a `users` row) · **D23** · step 4 · the org question.

**S15.2 COMMIT-ONE (2026-08-04) — content tip `5ead183b` pre-merge. PAPER ONLY; ALL FOUR DECIDE-ITEMS RULED.**
The address-bearing agent + the agent as an RBAC principal. `docs/S15.2-decisions.md`. **RULED: ONE STORY,
D15 THEN D4** — D4-then-D15 ships a role that names nothing for the length of the gap; the reverse has no
mirror problem, and D4 alone adds a role NOTHING CAN BE MINTED WITH.

⛔ **AGENTS ARE AUTHENTICATED AND NEVER AUTHORIZED — MEASURED.** `agentchannel.go` has ZERO `authorize(` /
`authctx.` references; an agent is a cert serial resolved to a `sqlc.Node`; `authctx` has exactly ONE
principal constructor. **S15.0's D4 blast radius is STRUCK IN PLACE on `main`** (`d7d4f411`) — it measured
adding a role to the table, not agents holding one.

⭐ **THE OWNERSHIP FACT EXISTS AT THE MOMENT IT IS DISCARDED:** `nodes` and `node_join_tokens` have no owner
column, and `IssueJoinToken` takes the human as `actor` and writes it to the audit log ALONE.

⚠ **AND A REFUSED AGENT FAILS A DATA PLANE**, not a pipeline — EPIC 13 exists because a gateway that cannot
come back is the worst failure this product has. Refusal semantics are not inheritable from S15.1 for free.

⛔ **ALL FOUR RULED (§7):** **D25 = B+C** — refuse at ENROLMENT, degrade-and-flag on decay, **never drop a
live tunnel for an identity reason** (an unattributable tunnel is a LOGGING failure, not an access-control
one; cold-start is fail-closed because its alternative is a BREACH, and this has none) · **owner = the join-
token ISSUER**, captured at issue, reassignable — the installer is **not capturable by construction** ·
**agent = a `devices` row**, per-user cap explicitly exempted · **D24 = a SECOND constructor with the CENSUS
RE-RUN AS A MERGE GATE** (a second principal kind **RETIRES** the one-site property; the guarantee was never
about `MachineID`).

⛔ **SLICE ORDER (§8), FIXED BY THE CHAIN:** issuer column FIRST — **it stops an ongoing loss**, every join
token minted today discards its issuer to the audit log — then the enrolment refusal, then `devices` reuse +
cap exemption, then the agent principal + its own constructor + the census re-run.

⚠ **KNOWN CARRIED DIVERGENCE (register row 4):** an agent is a `devices` row, so it inherits **`ON DELETE
CASCADE`** — deleting a user silently deletes every agent they enrolled, i.e. **a tunnel that disappears**.
D25 closed the refuse-at-use door and **not** this one. `devices` is out of step with S15.1's RESTRICT;
changing it is out of S15.2's scope.

⚠ **D23 HELD AND MOVED — ruled APART and SECOND, after D25's build**, so the expensive data-plane case does
not inherit a precedent set by the cheaper pipeline case.

**S15.1 MERGED (2026-08-04) — PR #86, content tip `07d54ae6` (`35a1042e` pre-merge). THE OWNED MACHINE PRINCIPAL SHIPS.**
`machine_credentials` had no `user_id`, so every machine principal that ever authenticated did so OWNERLESS —
the audit trail recorded *a machine*, never *whose*. Shipped: the column (`0065`, `ON DELETE RESTRICT`, NOT the
S14.12 cascade class) · `NewMachinePrincipal` at the ONE authenticating seam · the refusal (`MachineAuth`
returns `nil, nil` on a NULL owner) · the assignment surface with three distinguishable empty states.

⛔ **OPERATIONAL FACT, NOT A FOOTNOTE: THIS MERGE REFUSES EVERY EXISTING MACHINE CREDENTIAL UNTIL AN OWNER IS
ASSIGNED THROUGH THE NEW SCREEN.** That is D14 taking effect, scheduled by the founder — not a side effect.

**D21 RULED NO** — an unverified account cannot be named an accountable owner. Three layers, ONE authoritative:
the picker omits (presentation) · the handler returns 422 `owner_must_be_verified` (a legible refusal) · **the
UPDATE requires `email_verified_at IS NOT NULL`** (the decision, unraceable). Both reds, and the second is why
the first means anything — a guard that refuses everyone passes the exclusion half.

**D22 RULED POPULATE** — `owner_email` resolved server-side by LEFT JOIN on **`users`**, and the client's roster
lookup REMOVED rather than kept alongside. The roster cannot name an owner who LEFT THE ORG, and that is exactly
the row an accountability screen exists for. Red: a departed owner still renders their identity; mutation
re-pointing the join at `memberships` FAILS it. Without that red, D22 is a refactor.

⛔ **OPEN AND HELD — DO NOT RE-DERIVE:** **Step 4** (contract to NOT NULL — after every row is assigned; an
OPERATOR act, not code) · **D4** agent role, ruled not built · **D15** address-bearing enrolment, ruled not built ·
**D23** the deactivated-owner FAIL-OPEN, registered §14, already live on `main` and NOT introduced by this slice —
`MachineAuth` checks only `RevokedAt` and `UserID.Valid`, and enforcing it means an offboarding kills that
person's GitOps operators, an outage with a human cause needing an operational answer · **the org question**,
registered, recommendation **B**.

⚠ **`docs/REGISTER-shipped-delivery-defects.md` IS NEW AND IS NOT EPIC 15's.** Four rows, all found because a
review needed something the product could not give it: the `index.html` cache defect (FIXED — a correct deploy
could not reach a returning user) · **`orgs[0]`: `GET /organizations` returns every org and the UI reads index
zero, so a user in two orgs cannot reach the second by ANY means** · the Entra stale-seal ambiguity · a fixture
that put on screen the exact phrase the banner is barred from saying.

NEXT: the full product walk, then the beta-bundle call.

**S15.1 COMMIT-ONE (2026-08-04) — PR #84, content tip `43f5604` pre-merge. PAPER ONLY; NO PRODUCT CODE.**
The owned machine principal, D14/D19 steps 1–3. `docs/S15.0-decisions.md` §8.

⛔ **THE SEAM CENSUS SURVIVES, AND IT IS A MEASUREMENT NOT AN ASSUMPTION.** Censused **by the INPUT**, because
two of the three broken `policyHealthBadge` sites never called the function. **Five queries touch
`machine_credentials`; exactly ONE authenticates** (`machine_credentials.sql:14`). **`MachineID` has exactly
ONE construction site** (`http/machine_bearer.go:43`); every other hit READS an already-built principal.
**No second door — the constructor is necessary AND sufficient.** ⚠ The `policyHealthBadge` census found
SEVEN sites and four were wrong; this found one. **That difference is why a constructor works here.**

⚠ **`in use` IS NOT A FACT WE HAVE.** `last_used_at` is stamped on every successful auth — *"last
authenticated at"*, nothing more. A credential idle a day may be an hourly GitOps reconcile or abandoned; the
column cannot tell them apart. **The screen shows `last seen`, labelled `last seen`** — no in-use badge, no
threshold. *A number that cannot carry that weight must not be dressed as one.* **Machine credentials have no
liveness signal — registered, not built.**

⛔ **RULED: TWO SLICES, 1a THEN 1b — AND THE ORDERING ARGUMENT WAS TOO GENEROUS TO 1a.** *"Guard-first means
the nullable column is never a grandfather clause"* is true and **hides the cost**: after 1a lands, **EVERY
existing machine credential is refused at use, because every one has a NULL owner.** Correct, ruled, and
**breaking**. Two windows, not one virtue — **guard-first: credentials DOWN until assigned · surface-first: the
grandfather clause LIVE while the screen fills. Both are costs; only one is a SECURITY cost, and D14 ruled
which way that goes.**

⛔⛔ **D20 OPENED AND HELD — 1a BREAKS EVERY RUNNING GITOPS OPERATOR AT MERGE.** The `operator` machine
principal is what the K8s operator authenticates with; refusing NULL owners **stops it reconciling**. **That is
the exact class D19 rejected re-mint over — the S13.1 class. We did not avoid it; we MOVED it from re-mint to
the guard**, and inheriting that silently is how S13.1 happened.
**Three shapes, one recommended, none picked:** (A) one merge — ⛔ *the surface ships untested, first exercised
in production on a migration screen* · (B) refusal behind an org flag, default off — ⛔ **FAILS THE LAW**: *a
refusal that can be switched off is the grandfather clause with a switch*, off in every deployment that never
flips it · (C) **accept and SCHEDULE the window**. ⚠ A fourth recorded and NOT recommended: 1b first without
the refusal — no outage, no untested surface, **and it reverses a ruling, which is the founder's to do.**
**Recommendation HELD: C, window sized before announced.** ⚠ **The unknown that must close first: how many
machine credentials exist per deployment, and can one admin assign them in a sitting? Nobody has measured a
real deployment — the window's length IS that number.**

**CUT AS TWO, RULED:** **S15.1a the guard** (nullable `user_id` · ⭐ **the constructor, taken now
because the field does not exist yet and the moment does not return** · the seam refusal · **both reds — NULL
refused AND owned still accepted**) · **S15.1b the surface** (owner-gated, three empty states, no suggested
owner). ⛔ **Ordering is not arbitrary: guard first means the nullable column is NEVER a grandfather clause**,
because it is refused at use from day one.

⚠ **STEP 4 CARRIES ITS REASON:** contracting to `NOT NULL` needs every row assigned, and **assignment is an
operator action with NO CODE DATE — a precondition nobody on this side controls, not deferred work.**

---

**S15.0 COMMIT-ONE MERGED (2026-08-04) — PR #80 then #81, content tip `1f78186` pre-merge. PAPER ONLY; **ALL SEVEN RULED**.** `docs/S15.0-decisions.md`. **Nothing under S15.1 is authorized.**

**Scope argued in the paper itself with citations, so it is not re-derived later:** the destination half is
SHIPPED (`hashAllow` is five fields and `dst_kind` is not among them — a new kind would be **invisible to
enforcement by construction**) · the audit half is INHERITED **conditionally** (`ingest.go:40-75` — attribution
works **iff the principal is address-bearing**) · **the principal is the epic.**

⛔ **FOUNDER-RULED: D14 · D4 · D15 · D16 · D18. HELD: D17 (sequencing) — the only open item.**

⭐ **D14 — AGENTS ARE OWNED; OWNERLESS PRINCIPALS ARE NOT KEPT.** The mechanical argument IS the reason: an
ownerless agent is **outside the cap query, outside any delegation link, and still inside the pool — it costs
the scarce thing and escapes both accountable ones.** ⛔ **THIS CHANGES SHIPPED BEHAVIOUR**:
`machine_credentials` has no `user_id` today, so **every existing machine principal is ownerless and must
migrate** — the ruling is not "new principals get an owner", it is "the ones already running stop being
exempt".

⛔ **D14 CARRIES WORK, AND THE PAPER CARRIES IT SO IT CANNOT ARRIVE MID-SLICE.** There is **no `created_by`** on
`machine_credentials`, so the minting user is **not recoverable from the row** — foreclosing the cheapest
option before it is proposed. Three shapes costed: back-fill from audit (retention-dependent; **a partial
back-fill is the worst outcome, because nothing marks which rows are owned**) · require re-mint (honest and
complete; **breaks running GitOps operators at upgrade** — schedule it, do not discover it) · grandfather
(**rejected by the ruling's own logic**). ⚠ **A nullable `user_id` IS the grandfather clause whether or not it
is called one** — *absence must be the closed state*, so a NULL owner must be **refused AT USE**, and the paper
requires that enforcement point to be named.

**D4** new `agent` role — cheap, **and cheap BECAUSE machine roles are not user-assignable** (the condition,
not just the count). **D15** address-bearing, cost named (253 org-wide addresses on the default `/24`).
**D16** pool utilisation registered separately — not a ceiling; **the resize verb is reachable and the signal
that it is needed is missing.** **D18** both MCP revisions behind S8.1's fail-closed gate; **stdio out with the
reason stated publicly** — a child process on the same host has no network to police.

⛔ **D17 RULED (2026-08-04): EPIC 15 STAYS AN EPIC. BUILD ORDER UNCHANGED** — after EPIC 14, before the beta
bundle, **confirmed rather than edited**. *The ceremony was never for the build; it was for the rulings* — D14
changes shipped behaviour and its migration needs its own surface.

⛔ **~~THE BETA BUNDLE GATES ON EPIC 15~~ — RECORDED AND WITHDRAWN (2026-08-04).** That line landed after the
founder had corrected it — a timing overlap, not an error of fact. **EPIC 15 sitting before the bundle is a
POSITION IN THE ORDER, NOT A GATE**; recording it as one is a claim about a decision nobody has made.
**The only correct next-step reference: EPIC 15 → full product walk → the founder rules the beta bundle.**
⛔ **No EPIC 15 artifact sequences, scopes or costs the bundle.** Struck beside its withdrawal deliberately —
a claim removed without its retraction gets re-derived.

⛔ **D19 RULED: THE MIGRATION SHAPE IS ASSIGN-EXPLICITLY.** An admin names an owner for each existing machine
credential — a fourth shape beside the three costed, and the only one that **guesses nothing and breaks
nothing**. NOT derived from `audit_logs` (no retention dependency, **no partial back-fill** — the worst
outcome, since nothing marks which rows are owned). **The credential SURVIVES**, so a running GitOps operator
does not break at upgrade — ⚠ **breaking a live gateway during an ordinary maintenance action is the S13.1
CLASS, and S13.1 cost an entire epic.** Grandfather stays rejected.
**Contract: expand/contract, four steps, each independently provable** — (1) `user_id` nullable · (2) **the
assignment surface, real work not a footnote** (a capability with no caller is unreachable) · (3) ⛔ **refuse a
NULL owner AT USE, with a red** — *a nullable `user_id` IS the grandfather clause whether or not it is called
one* · (4) contract to `NOT NULL`.

**ALL SEVEN DECIDE-ITEMS RULED. NOTHING HELD. AND BOTH OWED QUESTIONS ARE NOW CLOSED (paper §7).**

⛔ **WHERE A NULL OWNER IS REFUSED — ONE SEAM, MEASURED.** The machine-credential USE path funnels through
exactly one function (`http/machine_bearer.go:25-51`) — the only place a `Principal` carrying a `MachineID` is
built — and it **already fails closed four times** there (unknown token · DB error · revoked · no-oracle). The
refusal is **one line beside four that already live there**. It must NOT be restated per handler: *a guard made
the caller's responsibility is inherited by every new caller*, which already cost seven call sites and a fourth
instance of the same fix. ⭐ **AND THE TYPE CAN MAKE IT IMPOSSIBLE RATHER THAN CHECKED** — `Principal` is a
struct literal today (the `policyHealthBadge` shape); **the owner field does not exist yet**, so a constructor
that cannot be called without an owner is available *now and not again*. Both are needed: **types make the
PRINCIPAL impossible to build wrong, the seam check makes the ROW impossible to use**, and the seam check
retires at step 4. **Two reds** — NULL-owner refused, **and an owned credential still ACCEPTED** (a guard that
refuses everything passes the first).

**THE ASSIGNMENT SURFACE** — name · fingerprint · `created_at` · `last_used_at` · in-use. ⛔ **`created_by` does
not exist, so THE ADMIN IS CHOOSING, NOT CONFIRMING**: no pre-selected or suggested owner — *a client-invented
value where a server fact belongs*. Owner-only (`machine:manage`), reasoned not inherited. ⚠ **Three
distinguishable empty states** — none exist · all owned · **the list failed to load** (an unreachable query
rendering as empty is *"migration complete"* written by an error path).

**`AuthMethod` MEASURED (2026-08-04), out of the unverified list.** `authctx.Principal.AuthMethod`
(`authctx/authctx.go:42`) ∈ {`AuthLocalPassword`, `AuthSSO`, `AuthBearer`, `AuthMachine`, `""`}; stamped at
mint and immutable (S7.5.5 confirmed). ⛔ **Consulted in EXACTLY ONE place and it is NOT an authorization
decision** — the MFA-enrollment gate (`mfa_enforce_handlers.go:124`). **No permission check reads it**, so an
agent's auth-method is an MFA-exemption discriminator, `AuthMachine` already exists exempt-by-construction,
and **D4 is unaffected by it.** ⚠ The first search failed because it was aimed at `internal/authn`, which does
not exist — *an absence found by one encoding is not an absence.* **Four unverified items remain, including
the pass itself.**

**§2 written against sources, not memory** — Teleport enforces on `tools/call` **and** filters `tools/list`
(nothing stops a client calling an unlisted tool), and their SHIPPED default is deny-if-unspecified, the
opposite of their own RFD · Octelium has **no bespoke MCP engine**, request-side only, which fixes the split:
**enforcement is the request half, catalog filtering is the UX half** · agentgateway's statefulness argument
was undercut by `2026-07-28` · **none has cross-org delegation, so intra-org is PARITY.**

**Header trap filed as the epic's first law.** Five items carried **unverified and not quotable, including the
pass itself.**

---

**EPIC 15 PAPER CORRECTED (2026-08-04) — PR #79, content tip `f189407` pre-merge. STILL UNRULED.**
A registered paper gets re-entered and believed, so one carrying a false premise is worse than none. The
measurement pass refuted its cost model; the corrections are folded in and **no S15.x work is authorized**.

⛔ **THE DESTINATION HALF IS ALREADY SHIPPED.** A port-scoped `resource` expresses an MCP server today
(`cidr` + `protocol` + `port_low/high`, live CHECKs). **`hashAllow` is five fields and `dst_kind` is not among
them** — the compiled artifact never sees a destination KIND, so a new one would be **invisible to enforcement
by construction**. The `k8s_service` precedent claim is struck: a new kind is a new discriminator column + two
CHECK rewrites + compiler resolution + goldens. No version bump — `RequiredVersion` cannot trigger on it.

**The audit half is inherited CONDITIONALLY** — `src_device_id` is agent-stamped from the artifact's `/32` map
(`ingest.go:40-75`), so attribution works **iff the principal is address-bearing**. That binds D4.

⛔ **D14 REFRAMED BY MEASUREMENT: `machine_credentials` HAS NO `user_id`. Every machine principal shipped
today is ALREADY OWNERLESS** — the ruling is not "permit ownerless agents", it is "keep the ownerless
principal we already have". **An ownerless agent is outside the cap query, outside any delegation link, and
still inside the pool: it costs the scarce thing and escapes both accountable ones.** `devices.user_id`
carries the cap, the posture cut's "which human", and any future delegation link — one column, three
questions, all three off together.

**Also folded:** MCP `2026-07-28` shipped after registration (stateless, `Mcp-Method`/`Mcp-Name` headers) — the
slice ORDER survives, the cost model does not, and **the header trap is the epic's first named law** (the body
stays authoritative; authorizing on `Mcp-Name` alone is `middleware.RealIP` one protocol over) · AP2 is not a
third protocol and gets **no support claim** · Versa/Aperture corrections · EMA flagged second-hand.

**THE BUILD SHRANK; THE DECISIONS DID NOT.** D14, D4 and the sequencing question are **held for the founder**.
Five items carried as unverified — including **the pass itself**, whose two sharpest corrections came from a
reader pushing back rather than from a measurement.

---

## REGISTERED, NOT STARTED — from the S13.1 merge (2026-08-04)

**WF-S13-7 — "the documented install ships the fix". ITS OWN RELEASE-PATH STORY. RE-COSTED, MUCH SMALLER.**
A gateway installed by the UI's emitted command loops forever on expiry, regardless of what merges.
⛔ **Publication is NOT the gate — it is automatic.** `publish` runs on every push to `main` and emits
`:latest` + `:sha-<sha>` for all five images; merging S13.1 published an S13.1 node-agent image by itself.
**The gate is the DIGEST PIN:** the CP sets `TUNNEX_NODE_AGENT_IMAGE=…@sha256:de8c9cef…` = tag **`v0.2.0`,
published 2026-07-23**, before EPIC 13 existed. Confirmed by registry lookup, not inferred.
**Cost:** (a) re-pin one `.env` line + api restart — the same mutation shape as §C′'s M1; (b) **a fourth
host** — `aws-gw-1` is now the §C/§C′ subject with a hand-built image and enrolling it would destroy that
provenance; (c) **~20 minutes** on the §C′ rig. **Closed ONLY by the copy-paste itself** — a digest version
check does not close it, and a locally-built image is exactly what hid it through all of §A.
⚠ **NOT coupled to the signing gate.** `sbom-sign`/cosign is `if: startsWith(github.ref, 'refs/tags/v')`;
S6.5b is macOS/Windows **desktop** signing. Container publication is a separate, already-live channel.

**`nodes[0]` — DEVICE CREATION COULD HOME ON A REVOKED GATEWAY. FIXED, and the register row is for the
LESSON.** `main` shipped it for weeks while the fix sat on a story branch, and **EPIC 14's rewrite added a
THIRD call site** to a bug it inherited. A conflict resolution taking either side wholesale drops it silently:
`--ours` keeps the bug, `--theirs` keeps the rewrite. Neither fails a test, because the test is on the branch
and the bug is on `main`. Re-applied at the merge and **mutation-proven** (reverting to `nodes[0]` fails
`devicespage.test.tsx`). **Standing check: on any long-lived branch merge, diff both sides' file lists and
count call sites on each — the overlap is where fixes go to die.**

---

**MERGED (2026-08-04): S13.1 GATEWAY RECOVERY — PR #43, content tip `e8bbd68` pre-merge (SQUASH-merged — see below).**
**S13.1 CLOSES WF-S13-6 AND DOES NOT CLOSE WF-S13-7. A gateway installed by the documented procedure still
loops forever on expiry until an S13.1 image is published AND the UI's emitted digest points at it.**
That sentence is the entry, not a register footnote — the two are different claims with different owners.

⛔ **WF-S13-6 IS CLOSED ON THE WIRE, AND THE PROOF IS STRONGER THAN THE DESIGN ASKED FOR.** §C′
(`walk-artifacts/S13.1/Cprime-record.md`, 2026-08-03, **21 minutes**): certificate expired at 18:14:40Z while
the agent ran; `agent_identity_recovery_at_runtime` at 18:17:40 from **local inputs**; recovered in place at
18:17:41 with `RestartCount`, `StartedAt` and pid all unchanged. **`:8443` WAS BLACK ACROSS THE ENTIRE EXPIRY** —
`attemptRekey` reaches `apiURL:80`, so the mTLS channel was unreachable for the twelve minutes spanning the
lapse and **no control-channel outcome could have triggered or assisted the recovery.** That is the claim
`identityWatchLoop` makes, demonstrated rather than argued, and a network-signal-driven design could not make it.

⛔ **§C — THE 48-HOUR RUN — WAS STRUCTURALLY INCAPABLE OF PRODUCING ITS SUBJECT.** `renewLoop` anchors its first
tick to `min(every, left/2)` and resets on success, so a reachable CP refreshes the certificate at half-life
**forever**. The invariant §C confirmed (`renewEvery 24h < TTL 48h`) is precisely the one guaranteeing
non-expiry. Three clean renewals 24h apart, and `cert_not_after` sitting 41h in the future at verification time,
are the proof it worked as designed. **Not slow — forbidden.** Its gate was `cert_not_after + 15m`, computed
once: **A DEADLINE DERIVED FROM A VALUE THE SUBJECT MUTATES IS NOT A DEADLINE.** General form: **a test that
waits must name the EVENT it waits for and show the path that produces it** — §C named a time.
Duration was never the variable: `identity.Decide`'s expiry test is `now.After(leaf.NotAfter)`, a boolean with
no threshold, so one second and 48 hours are indistinguishable to the code under test. **§C's three real
renewals are KEPT** as wire proof of the renewal path across 48 real hours, which §C′ cannot make.

⛔ **THE MERGE RESOLUTION FOUND A LIVE BUG ON `main`.** S13.1 fixes device creation homing on a **revoked**
gateway (`nodes[0]` indexes a list including revoked rows ordered by `created_at`). `main` still has it, and the
EPIC 14 rewrite **added a third call site** — so taking either side of the conflict wholesale would have dropped
the fix silently. Re-applied and mutation-proven.

**WF-S13-7 RE-SIZED FROM THE REGISTRY.** Publication is AUTOMATIC (`publish` runs on every push to `main`), so
merging S13.1 publishes an S13.1 image by itself. The gate is the **digest pin**: the CP pins `v0.2.0`,
published **2026-07-23**, before EPIC 13 existed. Remaining: re-pin, a fourth host, ~20 min on the §C′ rig.
⚠ **NOT coupled to the signing gate** — cosign is release-tag-scoped; S6.5b is desktop code-signing.
**Registered as its own release-path story.**

⚠ **MERGED BY SQUASH, DELIBERATELY.** The branch forked at EPIC 11 and was 358 commits behind; a rebase
replays 109 commits through that divergence and stops on the same files repeatedly, while a merge resolves the
**19 genuinely-overlapping files once**. Squash keeps `main` linear. The 109 commits were walk narrative and
that narrative lives in `docs/S13*.md` and `walk-artifacts/S13.1/` — which are FILES, and survive. The
content tip named above is therefore a **pre-merge** sha with no post-merge counterpart: squash creates one
new commit, so there is nothing for it to be preserved as.

---

**MERGED (2026-08-03): EPIC 14 S14.20 step 4 — the client becomes a product. PR #71, content tip `3d331f5`
on `main` (`fb4a147` pre-merge).** Founder-driven review ON THE RUNNING APP, one item at a time. Everything below
was found by USING it; none of it was visible in the code.

⛔ **THE SESSION'S RESULT IS THAT A REVIEW OF THE RUNNING THING FOUND WHAT EVERY OTHER INSTRUMENT
MISSED.** Panel tests, censuses, typechecks and CI were all green across a client that had an
inverted security toggle, permanently-fake statistics, a log file with no logging, and three
capabilities with no caller.

**The inverted control.** Routing was a checkbox LABELLED "Split tunnel" and BOUND to `fullTunnel`.
Unchecked read as *"split is off"* — a user concludes all traffic is protected — while meaning
`fullTunnel === false`, which IS split. **The label pointed the error at the dangerous side.**

**The fabricated plot.** Stats were hard-wired `null` with a comment saying they would arrive "in
step 3"; step 3 came and went. The graph beside them was fed by `Math.random`. *A plot of invented
data next to an honest `n/a` is worse than either alone* — the `n/a` says "not measured", the curve
says "measured", and the one that looks like evidence is lying.

**The log that was not a log.** 30 lines over weeks, all from the auto-updater; `not_authenticated`
appeared **zero** times. *A log file that exists is not logging* — "check the logs" reads as a real
instruction, the file opens with content and timestamps, and the incident is simply absent.

**Three stranded verbs.** Sign-out, change-server and import were on the preload allowlist with no
caller after the step-3 flip — the S14.12 class, inside our own client.

**Laws minted:** a design's container is not always part of the design (the 440px card needed a page
only because a wireframe IS a page) · a formatting rule with an exception is broken by whichever
value takes the exception (the rate, recomputed every second) · a cosmetic option on one platform is
a functional one on another (`hiddenInset` removes CLOSE on Windows) · an instruction that names a
feature is not an enumeration of its parts (I deleted the animation along with the fabrication) ·
asserting an absence proves nothing when the failure also produces that absence · **a drift check
must compare the thing that can drift** (byte-identity failed on Windows for calling CRLF a change
in artwork).

⛔ **AND `.gitignore`'s UNANCHORED `build/` WAS SWALLOWING PACKAGING SOURCE AGAIN** — the four files
under `apps/client/build` are in git only via `git add -f`, and the app icon would have been the
fifth: correct locally, absent on every fresh clone, packaged app back to Electron's atom with
nothing failing. **This repo already paid for this exact pattern with an unanchored `secrets/`.**

**Registered, unbuilt:** the mark asset needs a margin and no baked plate before it can return to
headers · no org-level policy pins the routing mode, so an enforced full-tunnel can be flipped by
any user · signing + a publish feed both remain before any update can be checked · imported profiles
have no revocation monitoring by construction.

**MERGED (2026-08-03): EPIC 14 S14.20 step 3 — PR #68. Content tip `51fc056` on `main` (`9cca701` pre-merge).**
⛔ **AND THE FIRST MERGE UNDER THE CORRECTED SEQUENCING EXPOSED THE REMAINING HALF OF THE RULE.** The checkpoint
was written LAST, inside the PR, naming the content tip `9cca701` — and **GitHub's rebase-merge rewrote every
sha in the PR** (`9cca701` → `51fc056`, `dd8dc6e` → `0342e81`; trees byte-identical). Merge commits are
disabled here for linear history, so **rebase is the only method available and it re-parents unconditionally.**
So the pointer landed on `main` naming a sha that exists only on the backup ref.

> ## **THE CONTENT-TIP SHA IS NOT KNOWABLE INSIDE THE PR. THE PR NUMBER IS.** Rule 6 already said the number
> ## survives rebase — I recorded the sha as if it were the identifier and the number as the backup, which is
> ## the wrong way round under the only merge method this repo permits.

**And the check that missed it was correctly run at the wrong subject:** before merging I verified that PR #67,
#66 and #65's head shas were present on `main` unchanged — true, and irrelevant, because **I never confirmed
those PRs were merged by the same method.** A preservation result from an unknown method predicts nothing
about this one. Corrected below; the sequencing fix itself stands and is unaffected.
⛔ **FIRST MERGE UNDER THE CORRECTED SEQUENCING: the checkpoint is the FINAL commit before the merge.** The
pointer had twice named a commit with content behind it because work landed after it — a procedure gap, not a
rule gap. Count stays at **8**.

**THE ONE-LINE FLIP.** `app://tunnex/index.html` → `app://tunnex/client.html`. The desktop client stops
loading the web SPA — router, sidebar, top bar and every dashboard screen, most of it hidden behind
`isDesktop()` branches — and loads its own four-region surface. **That line is the whole migration.**

**The census forced the disposition change, which is what it was built for:** `built_unadopted` asserts the
loader does NOT reference `client.html`; the flip made that false, so the census went red and the only way to
green was `built`. ⛔ **It then refused the first `built`** — that kind requires a route in `App.tsx`, and
`/client.html` is a separate vite entry with no router, so `built` now takes EITHER a route OR an entry.
⛔⛔ **And the new entry check was VACUOUS on its first run** — reverting the flip left it green because the
COMMENT explaining the flip contains "client.html". **Third instance this epic.** Now strips comments, proven
both ways.

**The client README** rewritten around real failures: one-clone rule · the THREE Electron states (the middle
one — `dist` present at ~9MB with no binary — passes every naive check) · `npx electron --version` from the
repo root is NOT a valid check (it resolves a foreign package and downloads electron@43.2.0) · `rm -rf` the
`.pnpm` entry, because `pnpm rebuild` does nothing and "resolution step is skipped" means a NO-OP · the app
data dir is `~/Library/Application Support/@tunnex/client` — the npm SCOPE, and `rm -rf` on the wrong path
succeeds silently · no dev flag exists to skip the setup screen.

⛔ **AND THE MERGE TURN'S OWN RULING PRODUCED THE BETTER FINDING.** *Any census over source strips comments
first — as the starting shape, not as a fix each time it bites.* Seven of ten censuses read source raw. All ten
stayed GREEN after the retrofit, so none was being ACTIVELY lied to — the exposure was latent. **One was
pointed:** `visualgallery.test.ts` asserts *"the route is guarded by an env flag, NOT BY A COMMENT"* and read
`App.tsx` raw. Mutation — guard replaced by `true /* was: …VITE_VISUAL_GALLERY === "1" */` — **passed
pre-retrofit, failed post-retrofit. The visual gallery could have shipped ALWAYS-ON with its guard green.**
Shared strippers, one per LANGUAGE; `censuscensus.test.ts` enforces the shape and checks the register against
the STRIPPED body of the test itself. **825 tests (+14).** Law filed.

**NEXT: founder tests the client against a REAL server** (real helper, real WireGuard, real handshake) → then
remove the `isDesktop()` branches from the seven web files → narrow packaging. ⛔ **The client remains
UNSIGNED and UN-NOTARIZED — a hard DISTRIBUTION gate, registered.**

---

**MERGED (2026-08-03): EPIC 14 S14.17–S14.19 + the wireframe census — PR #67, ff-only, content tip `943d7b4`.**
⛔ **EPIC 14 IS RE-OPENED. It was declared closed with FIVE wireframe blocks unaccounted for** — the closing
entry counted screens we HAD, not screens the design SPECIFIES. Three were unbuilt (Auth screens, Flow Logs,
Desktop client), one was a shell component no screen census could see (the collapsible sidebar), and two were
cut with reasons (Operations, License).

**⛔ THE FIX IS MECHANICAL, NOT A PROMISE:** `apps/web/test/wireframecensus.test.ts` enumerates the DESIGN's 17
banners and requires each to be **built / absorbed-with-a-destination / cut-with-a-reason** — a `built`
disposition must name a route that EXISTS in `App.tsx`, so it cannot be aspirational. **The epic cannot merge
while it is red.** A second ledger covers shell components, because the sidebar is neither a page nor a banner.

**This slice:** S14.17 auth screens (the hero transcribed from the design's own SVG + keyframes; **SOC 2 and
SCIM CUT as unevidenced claims**, gated on what would make them true) · S14.18 the user-controlled sidebar
collapse (`tnx-nav`, the designer's key) · S14.19 **Access Events — the FOURTH unreachable surface**
(`/access-events` + `/access-log/health` shipped in S7.5.1 with no consumer) · the real brand kit · and the
desktop client's own entry, **shipped INERT** — `client.html` exists and nothing loads it.

**⛔ DESKTOP CLIENT is `built_unadopted`, a state that FLIPS ITSELF.** "In progress" was rejected because
intent is unfalsifiable; this asserts a fact about the code instead — the surface exists, the consumer does
not reference it — and **the census FAILS the moment `apps/client/src/main/index.ts` points at `client.html`.**
Step 3 is a one-line PR and turning it green requires changing the disposition to `built`.

**NEXT: step 3 (the one-line Electron flip) → founder tests against a REAL server → remove the `isDesktop()`
branches from seven web files → narrow packaging.** ⛔ **And the client is UNSIGNED and UN-NOTARIZED — a hard
DISTRIBUTION gate, registered above the UI work.**

---

**MERGED (2026-08-03): EPIC 14 S14.15/S14.16 + EPIC-14 CLOSE — PR #64, ff-only, content tip `4898198`.**
⛔ **THIRD USE OF THE POINTER RULE, AND THE RULE IS NOW CLOSED — the count held at 8 across all three merges.**

**⛔⛔ EPIC 14 IS COMPLETE. Closing entry: `docs/EPIC-14-CLOSE.md`.** Twelve screens · the S14.1–S14.3
primitives · a test tier at ~730 web tests (from ~400) · the CI classifier split.

**This slice:** the INVITATION read — `resendInvitation`/`revokeInvitation` were keyed by EMAIL and nothing
served the addresses, so an invitation could be created and never seen, resent or revoked while staying
redeemable into a membership (**the only write-only state that IS an access grant**) · the AUDIT-WRITE fix for
`UnmapGroup` + `SuspendDomainClaim` (one class, two call shapes: the second is not a human action and needed
the system actor with a cause, filed against the CAPTURING org) · AUDIT LOG's four actor arms — `"system"` had
meant BOTH *a named subsystem did this* AND *nobody recorded who did this*, so an attribution gap was invisible
· DASHBOARD's feed now names an actor for the first time · and a SSO form default that read as a fact (Google
showed "Enabled" + a dotted secret on a provider the server 404s for).

**OPEN, each with a register row (see the closing entry §2):** the missing-audit-write class (**four writers
still unattributed**) · ⛔ the three-site non-human-principal register with **`operator` + `PermPolicyManage`
RANKED FIRST and live today** · `Kubernetes.tsx:403` · 51 mocks · one remaining unreachable verb
(`revokeCliCredential`) · D1/D1b/D2 · the cascade-preview endpoint · **S14.12's three items (section OPEN)** ·
Org Settings' items · the error-string register sweep.
**The harness is ACCEPTED-PROVISIONAL, NOT OWED** (founder-ruled S14.15) — artifact grep is a complete claim.

**NEXT: the founder sets the order.** EPIC 15 is registered ahead of the beta bundle; server stories are also
queued. **Do not start either unprompted.**

---

**MERGED (2026-08-03): EPIC 14 S14.14 Directory sync (IdP) — PR #62, ff-only, content tip `21537de`.**
⛔ **THIRD USE OF THE POINTER RULE — checkpoint landed inside the PR again, bypass count stays at 8.**

**The slice:** the consuming layer for FIVE endpoints that had ZERO call sites (`putIdpSyncConfig`,
`getIdpSyncHealth`, `triggerIdpSync`, `mapIdpGroup`, `unmapIdpGroup`) — four config arms, two-tier health with
the 30-minute ceiling named, sync-now, group mapping, and a typed-confirm un-map. Plus the fixture (Entra
configured + degraded, Google absent, one mapped group with two real members).

**The finding:** the spec enumerates `provider: [microsoft, google]` on every idp-sync path and the SERVER
refuses Google with `400 provider_not_supported`, deliberately, at config time. **Spec, handler and schema all
read as though Google works — only the served payload disagreed.** Filed in `laws.md`: *the spec describes the
shape of a request, not the existence of a capability.*

**Also:** `AddGroupMember` answers `409 idp_managed_group` and the web read `origin` NOWHERE, so S14.12's
Access screen offered member edits on directory-owned groups that were **guaranteed to fail** — now badged,
withheld, and told where membership CAN be changed.

**⛔ THE VERB CENSUS: ELEVEN BECOMES THREE.** 80 mutating operations, 7 with no call site, 4 of those
correctly absent (CLI auth, agent enrol, device-health report). The three left are TWO workflows —
invitations (`resendInvitation`, `revokeInvitation`) and CLI credentials (`revokeCliCredential`).

⛔⛔ **RANKED #1 IN THE REGISTER — THE INVITATION WORKFLOW IS THE ONLY WRITE-ONLY STATE THAT IS ITSELF AN
ACCESS GRANT.** There is no `GET …/invitations`, and both mutations are keyed by EMAIL rather than an id, so
an invitation cannot be listed and can only be revoked by someone who already knows the address they typed.
The other three write-only items are CONFIGURATION whose effect is visible elsewhere; a pending invitation has
no observable effect until it becomes a member — and by then the grant has happened. **Next server story, all
three verbs together.**

**NEXT: the three candidates are researched in `docs/S14.15-candidates.md` — founder rules the order.**

---

**MERGED (2026-08-03): EPIC 14 S14.13 Org Settings — PR #61, ff-only, content tip `e6e23c2`.**
⛔ **SECOND USE OF THE POINTER RULE, and it landed inside the PR again — the direct-to-`main` bypass count
stays at 8.**

**The slice:** the SSO collapse fix + the fixture that finally gave it a subject (both arms rendering for the
first time) · domain capture · pool-CIDR honesty. **Three findings, none visible from the design:**
**(1)** the wireframe's DNS instruction is wrong in BOTH halves — it says publish `_tunnex-verify.acme.io TXT
"tnx-domain-…"`, the resolver reads the APEX and compares by exact equality to `tunnex-verify=<token>`, so
following the design fails forever with the record visibly present in the zone. **A wireframe diff would MATCH
it — the defect is agreement with the design.** **(2)** `domain_taken` was FALSE 100% of the time on the claim
path (a fresh insert has `verified_at NULL` and so cannot collide with the partial index; only the same-org
constraint was reachable) — the product accused another tenant, at the exact moment an admin was recovering a
lost TXT value, because there is no GET. FIXED, both arms proven. **(3)** an OAuth credential form was being
autofilled with the admin's email and a saved password — **byte-identical markup, caused by POSITION**, so
fixing the visible provider would have moved the bug rather than removed it.

⛔⛔ **S14.13's SECTION IS OPEN.** IdP Sync is **S14.14** (4 verbs, 5 endpoints, no surface) · the machine-
credentials shed is BLOCKED ON A DESTINATION · **VERIFIED-is-not-terminal** (suspend clears verification
org-wide and fires NO audit action) and the **no-delete-verb cross-tenant item** stay registered · the
write-only-state trio stands. ⛔ **The `DomainSection` DOM proof is OWED AND UNCLAIMED — proven by artifact
grep, not DOM assertion, blocked on the `settingswiring` harness story. That is not "untested".**

**NEXT: the harness story or S14.14 IdP Sync — founder rules which. Do not start either unprompted.**

---

**MERGED (2026-08-03): EPIC 14 S14.12 Access Policies — PR #60, ff-only, content tip `7e5a5a1`.**
⛔ **FIRST MERGE UNDER THE NEW POINTER RULE: this names the CONTENT TIP — the last non-pointer commit — NOT
`main`'s head.** A commit cannot contain its own hash, so the post-merge head is unknowable before the merge;
naming the content tip makes the checkpoint knowable while the PR is open, so it lands INSIDE the PR and the
direct-to-`main` bypass does not increment. Count stays at **8**.

⛔⛔ **S14.12's SECTION IS OPEN. THIS MERGE COVERS THE SLICE AS REVIEWED, NOT THE SECTION.** Three items were
extracted at commit-one, never built, and do NOT lapse — see `docs/S14.12-decisions.md` §"STAYS OPEN":
**(1)** the mode toggle as a real switch with the blast-radius confirm (`SetMode` already returns
`[]AffectedDevice`, so unlike the cascade confirm this one CAN name server-owned counts) · **(2)** the
two-column panel layout · **(3)** the `SOURCE · DESTINATION · STATE` table headers.

**Built:** the OPEN-EDITION REVIEW STACK (`make up-open-review` / `seed-open`, :8081, one fixtures.sql two
databases) — it confirmed the predicted gate-order bug AND found an **unpredicted FK ordering defect** a
months-old database had hidden. `accessView` is now **permission-before-edition** (an open-edition MEMBER was
being sold Enterprise for a capability their role forbids — the S14.5 halt, second screen, second instance in
one story). The rule list's **three empty states** (failed / 0-while-enforcing / 0-while-off, the third
asserting a consequence without its precondition). The **access-flow graph** rebuilt from the handoff geometry
with two thresholds — a 24-rule cap and a **coverage floor**, because degree-ranking's usefulness depends on
the degree DISTRIBUTION, not N (same N, opposite verdict). **Group membership** — three endpoints shipped in
S7.5.2 with one consumer. **`src_group_empty`**, admitted by the same test that refused the deactivated-user
badge. **Typed confirms** on both cascading deletes.

> ## **WHAT THIS SLICE ACTUALLY FIXED, AND IT IS NOT THE BADGE: UNTIL NOW, A NEW CUSTOMER'S FIRST TEN MINUTES**
> ## **PRODUCED A RULE THAT SILENTLY GRANTED NOTHING.** Create a group, write a rule against it — it compiled
> ## to nothing while rendering ACTIVE, because `matched = owner[r.SrcGroupID]` matches no device when the
> ## group is empty, **and no surface existed to put anyone in it.**

⛔ **THE MOST DESTRUCTIVE UNGUARDED VERB FOUND IN THIS EPIC:** `src_group_id`, `dst_group_id` AND
`dst_resource_id` are all `ON DELETE CASCADE` — deleting a group or resource **silently deletes every rule
referencing it**; the rows vanish, and the 204 says nothing. Typed confirm ships; a server cascade-preview
endpoint is registered, because a client-computed count would be a second source of truth.

**CARRIED, UNFIXED, EACH REGISTERED:** `CountOwners` counts owner ROWS not owners who can sign in (**a proven,
unrecoverable lockout**) · the Audit Log discards every named `actor_system` · `Kubernetes.tsx:403`'s
placeholder-glyph regression · 51 omitted-and-read mocks · **11 of 12 unreachable mutations** (IdP-sync is five
endpoints with no surface at all) · D1/D1b/D2.

---

**MERGED (2026-08-02): EPIC 14 S14.11 Users & Roles — PR #58, ff-only, main `622f30b`.** Both identifiers carried: the PR number survives rebasing, the sha is what a fresh session needs to know `main` by. **This merge was a TRUE FAST-FORWARD** (`origin/main 832e6b0` was an ancestor of the branch head `9de9406`), so no rebase and **no object rewrite** — the in-PR sha and the post-merge sha are the same for once, and that is a property of this merge, not a new rule.

Section pass on Users & Roles. **The classification was wrong in FOUR of five verdicts, all under-building**, because I grepped the `Member` DTO and reported on the PRODUCT. Not one column was "the product doesn't know" — each was a projection, a permission, an edition, or a missing read. **The DEVICES COLUMN IS ABSENT for anyone without `member:manage`**, never zeroed: `/devices` is audience-scoped at the handler (owner sees 13/2 owners, member sees 6/1), so a client-side group-by would print `0 devices` against a colleague — a positive claim drawn from a response that was never about them. **ACTIONS follows the same rule** (founder review): a header over empty cells is a claim the column has content.

**TWO ORDERING BUGS THE MUTATION SWEEP FOUND, and the survivor was the finding.** A mutation swapping the edition/permission gates SURVIVED; I read it as a thin test and wrote one PINNING MY ORDER. Measured after: `ListGroups` authorizes `PermPolicyView` **then** checks `s.policy == nil`, so an open-edition MEMBER's real answer is `forbidden` — my edition-first version sold Enterprise to someone whose role forbids groups on any edition. **The S14.5 halt, forward, three lines under a comment warning against its reverse.** Same bug twice in one file. **Census: 43 double-gated handlers, 41 permission-first, 2 pre-session by design, 0 leaks — now guarded by `TestEditionGateNeverPrecedesPermissionGate`, a static assertion over handler source, because there is NO shared seam (the pair is hand-written 41 times).**

**⛔ CARRIED OUT OF THIS STORY, UNFIXED, EACH WITH ITS RED WRITTEN — see `docs/DEFERRAL-REGISTER.md`:**
**`CountOwners` counts owner ROWS, not owners who can sign in — a PROVEN, UNRECOVERABLE LOCKOUT** (deactivate both owners: 2 owner rows satisfy the invariant on paper, 0 accounts can sign in and act, recovery needs direct DB access; `docs/probes/lockout_probe_test.go.txt`). **The Audit Log discards every NAMED system actor** (`actor_system` is in the spec, served on 19/78 rows, and read NOWHERE in `apps/web`). **`Kubernetes.tsx:403` re-introduced the banned placeholder em-dash** with a written exemption for the case S14.5 already resolved — the law predicted that reflex verbatim.

**"WRITING A RULE CREATES THE FEELING OF HAVING COMPLIED WITH IT"** — the fourth prose-versus-behaviour instance and the sharpest: I broke my own §2.6 rule (*additions get the same discipline as cuts*) in the story that states it. Which is why the standing question is **"what in this change is asserted only in prose?"** and not "follow your own rules": the first can be asked of yourself; the second is already believed.

---

**MERGED (2026-08-02): EPIC 14 S14.10 Devices — PR #56, rebase-linear, object-rewritten, main `331c96f`.** Both identifiers carried, per the S14.6 correction: the PR number survives rebasing, the sha is what a fresh session needs to know `main` by. (The in-PR checkpoint named `dd7ad2b`; rebase-merge rewrote it, which is the stale-by-construction property that made carrying both necessary.)

Section pass on Devices, plus the fixture bug that hid the product's severest posture state. **`ON CONFLICT (device_id) DO NOTHING` on `device_health` AND `device_status`** meant every time-relative fixture value aged forever while each re-seed reported success: reports drifted past `HealthStaleTTL`, states served `unknown`, the sweep correctly cleared `health_blocked`, and **the device named `blocked-device` was not blocked — `posture blocked` had NEVER rendered on localhost.** `node_peer_status` carried this exact fix three sections earlier with the reason written down; the device tables never did. **A law written in one block does not protect the block below it.**

**`health_blocked = true` is unreachable from SQL** (`SetDeviceHealthBlocked` is called only from `ReportHealth`; the sweep can only set it false), so the seeder **registers it through the product** and counts the server's own verdict. **`TUNNEX_SEED_STRICT` defaults ON** — a missing state is a non-zero exit.

**THIRD SPEC DEFECT THIS STRETCH** (after `listSiteSubnets` and the `policy_degraded_kind` paragraph): `health_state`'s description claimed `unknown` could mean "the fact was reported absent". It cannot — `evaluated_state` is NOT NULL with a two-value CHECK and the evaluator SKIPS an absent fact, so such a device evaluates **compliant**. I built a third UI label for it and **five reds passed against a state production cannot produce**; caught only by asserting on the rendered page. Reverted, spec corrected in place, unreachability pinned. **New law: a test can pin a label production can never produce; only the screen says otherwise.**

**CI FINDING, fix ruled and pending:** `gates` is 8.1 min and is the ENTIRE critical path, spending **78% of it on steps a web-only diff cannot affect**. A UI section pushes 3–6 times ⇒ **20–40 min per section, every section.** Ruled: a fail-closed diff classifier making the six Go steps conditional inside the SAME `gates` job (no required-check rename, no companion no-op). `paths-ignore` DROPPED as redundant once the split lands. Classifier decision table proven 18/18 including the fail-closed arms; **the WIRING is unproven until cited from a real run's step conclusions.**

**NEXT: S14.11 Users & Roles** (REDESIGN; data seeded by S14.9). ⛔ **Shedding is RULED NOT AUTOMATIC:** machine credentials → CLI Credentials and edition → Edition are both BUILD and neither exists, so shedding now would remove a working surface with no destination — deliberately recreating the S11 finding. The surface STAYS until its target lands; ruled in commit-one, never by default.

**MERGED (2026-08-02): EPIC 14 S14.9 Fixtures & Access Policies — PR #54, rebase-linear, tree-identical, object-rewritten, main `0cda482`.** Fixture seeding + Access Policies redesign pass. Seeded `user_groups`, `group_members`, `resources`, `machine_credentials`, `cli_credentials`, soft-deleted `k8s_services`, `policy_rules` (covering all 4 warn-not-refuse states), and `access_events`. Upgraded `/access` header typography & status badges while preserving 100% of RBAC, `policyGate`, and test contracts.

**MERGED (2026-08-02): EPIC 14 S14.8 Kubernetes — PR #53, rebase-linear, tree-identical, object-rewritten, main `2e67902`.** Redesign + control plane fixes: `/kubernetes` screen with 3 stat tiles, D9 reachability status, horizontal DNAT flow, and right-rail panels. Included 2 control-plane bugs found by walking customer path (`node_reconcile` idempotency, failover loop deadlock on `nil` metadata). Overview Kubernetes card reflow registered in `DEFERRAL-REGISTER.md`. Donut reduced-motion path tested & proven to reject on `true`.

**MERGED (2026-08-02): EPIC 14 S14.7 Routed Ranges — PR #52, rebase-linear, tree-identical, object-rewritten, main `fa877ba`.** BUILD, not redesign: `/routed-ranges` has been served since S8.5 and nothing rendered it. Client-side attribution join (the endpoint serves no `site_id`) with a four-armed union so in-flight, could-not-ask and nobody-owns-it are three distinct claims. Address-space map founder-ruled back in with both cut reasons CLOSED, plus a third found by asking what the panel is for: **a dark cell claims the space is free, so the map must draw every class `subnetguard` enforces** (site subnets + pool + K8s VIPs; `reserved` measured DEAD — `WithReserved` has no callers). `nextFreeRange` is interval arithmetic over all classes, withheld when any class failed to load.

**⛔ CI DOES NOT RUN ON `story/*` PUSHES.** `.github/workflows/ci.yml` triggers on `push: [main]`, tags, and `pull_request` — nothing else. Four S14.7 commits were pushed with ZERO runs against them, and the branch looked no different from one that had passed. **Opening the PR is what starts CI**; a green claim before that point is a claim about nothing. (Found while trying to verify S14.7 before merge.)

**⛔ TWO TRIGGERS NAMED S14.7 AND FIRED UNDISCHARGED** — carried, not dropped: (1) `policyHealthBadge` still uses a `switch` + `default` rather than the `Record<NonHealthyPolicyDegradedKind, HealthBadge>` compiler guard; the default is fail-safe but a NEW kind falls through to a generic "degraded" and loses its named remedy — which already happened once (`k8s_endpoints_unavailable`, caught only by the S11 mirror census). (2) Fixture debt: `ovpn_enabled` appears 0 times in `fixtures.sql`, so the OpenVPN panel and demoted-hub badge remain unrenderable locally.

**MERGED (2026-08-02): EPIC 14 S14.6 Gateways — PR #51, rebase-linear, tree-identical, object-rewritten, main `70e4642`.** ⚠ **CORRECTED (Ruling 2):** this line said `544baa5`, which is the PRE-REBASE object of `3d74150` — tree-identical but **not an ancestor of `main`**, and 23 commits behind head. **Disposition (a) — write the pointer inside the PR — has a flaw nobody anticipated: rebase-merge rewrites the sha the pointer just named, so the pointer is STALE BY CONSTRUCTION.** The fix is to carry BOTH: the **PR number**, which survives rebasing, and the **post-merge sha**, which is what a fresh session needs to know `main` by. A PR number alone does not tell you what `main` is; a sha alone does not survive the merge that publishes it.
**FOUNDER RULING 1 (MERGE MECHANISM ADOPTED):** Merges to `main` via GitHub PR auto-merge/rebase-merge are formally adopted as **`rebase-linear, tree-identical, object-rewritten, re-verified by main's own run`**. The claim of "ff-only linear" is stopped across the codebase.
**HUMAN GATE LIMIT LAW FIRST APPLICATION & EXPLICIT ACCEPTANCE:** The Human Gate Limit Law fired on its own first case. Four un-rendered states on localhost (`loadOne: failed-load` top-level red error card, `org.ovpn_enabled: true`, OpenVPN fault kinds, `site_link_note_demoted`) were declared. The Founder explicitly accepted all four states, noting `failed-load` is the only consequential state and its complete alert replacement behavior is described and verified.
**FIXTURE DEBT REGISTERED WITH TRIGGER:** `make seed-fixtures` must reach `ovpn_enabled: true`, at least one OpenVPN fault kind, and a demoted hub note. Trigger: S14.7 Routed Ranges visual review.
**CARRY-OVER DISPOSITIONS:** (1) `max_policy_version` cut trigger: S15 protocol version bump (predictive un-upgradeable warning). (2) `policyHealthBadge` exhaustiveness map typed as `Record<NonHealthyPolicyDegradedKind, HealthBadge>` (compiler-enforced guard) trigger: next health-kind addition or S14.7 pre-flight.

**SHIPPED IN S14.6:** Gateways promoted to dedicated top-level screen (`/gateways`, route `gateways:view`) · grouped table (Degraded → Healthy → Revoked) · 3 filter chips (All / Healthy / Degraded) · single-truth boundary mapping (`healthview.ts` / `gatewaysview.ts`) · 7 `ListItem` primitive invocation call sites hardened under explicit `ListItemProps` (`children`, `aria-label`, `className`) · `isHub` server topology projection preserved (`electSiteHub` filters revoked in API backend).

**MERGED (2026-08-02): EPIC 14 S14.5 Sites — PR #50, rebase-linear, tree-identical, object-rewritten, main `a253e5e`.**
**CHECKPOINT POINTER LESSON & MECHANISM DECISION:**
(1) **Pointer Flaw**: Disposition (a) — writing the re-entry pointer inside the PR branch — produces a checkpoint that is stale on arrival because the PR merge creates a new commit object on `main`. We adopt **Option B**: a 1-line direct push to `main` for `PLAN.md` re-entry pointer updates immediately following a merged PR (strictly bounded: 1 line pointer update in `PLAN.md` only, 0 product code, authorized under `CLAUDE.md` line 42 for immediate process documentation).
(2) **Merge Mechanism**: Merges to `main` via GitHub PR rebase-and-merge/auto-merge are **rebase-linear, tree-identical, object-rewritten, with the merged object verified on `main`**. The claim of "ff-only linear" was inaccurate across PR #44 through #50 and is hereby corrected across all EPIC 14 merge records.

**SHIPPED IN S14.5:** the 8fr/4fr Sites layout from the handoff · `NodeLink` with three link tones, keyboard selection, entry animation, a flowing linked edge and travelling packets (CSS `offset-path`, the handoff's timings, **not GSAP** — ruled out on redistribution licence) · org-wide cross-site DNS with conflict detection · selection-scoped site actions · **a site LIST that scales** (table + one detail panel; a card per row made 10 sites 3,200px of scroll with the same paragraph ten times) · **`make seed-fixtures`**, a populated demo network so screens are reviewed against data instead of empty states · the `AreaChart` primitive.
**FIXED ALONG THE WAY, NONE OF IT SITES-SPECIFIC:** the open edition shown an **UPSELL for an all-editions capability** (client-invented boundary; the server says all-editions core in three places) · **three dead CSS token references**, one (`--tnx-ink-600`) rendering every Donut neutral slice BLACK since S14.3 on a screen already approved · **the primary button unreadable PRODUCT-WIDE** after the mono palette swap (a semantic name survives a palette swap; the contrast it assumed does not) · **`ENTERPRISE_PATHS` missing three genuinely-gated endpoints** because the census matched `(enterprise)` alone · the Overview stat row orphaning its 7th card · **two different network maps** rendering the same data. **NEW INSTRUMENTS:** `tokenrefs` (every `var(--tnx-*)` held to the generated set, proven to reject) · a **CUT REGISTER** (`docs/CUT-REGISTER.md`, one line per cut) · **the six-check PRE-FLIGHT** at the head of the section protocol. **THE NAV AUDIT RE-SCOPED THE EPIC:** not eleven screens to redesign but **CONNECT 2 · REDESIGN 6 · BUILD 5** (nav audit method was testable on 2 screens, wrong on 1 [CLI Credentials vs Machine Credentials] because it matched on component filename rather than checking endpoint calls; corrected in `docs/EPIC-14-ui-redesign.md`).

**MERGED (2026-08-02): EPIC 14 viewport leg — PR #49, rebase-linear, tree-identical, object-rewritten, main `556cfaf`.** A **blocking Playwright `visual` CI job** over a **primitives gallery** at 1440/390, plus **geometric overflow assertions** on Overview at both widths, plus an **exact-count baseline census** (`toEqual`, not a floor — a floor is satisfied by deleting all but one, which is the move it exists to prevent). **IT PAID FOR ITSELF IN PRE-EXISTING `main` DEFECTS, all live since S14.2, on EVERY screen, invisible to `tsc` + 424 component tests + the drift guard + `e2e`:** a **65px horizontal overflow at 390** (shell header flex children defaulting to `min-width:auto`) — FIXED · the drawer **`Menu` button rendering on top of the page `<h1>`** (`absolute left-4 top-4`) — REGISTERED, trigger = the next shell-touching section · the **control-plane health indicator rendering TWICE on Overview** (shell footer since S4.x + S14.4's System Health panel) — REGISTERED as a product decision, founder-ruled *"a visual suite must never be the place a product decision gets made quietly"*, trigger = the next shell-touching section. **SCOPED DOWN ON THE FOUNDER'S RULING after seven rounds:** both Overview **pixel baselines DROPPED** (census 4 → 2) because the surface differed by **621px across runs of BYTE-IDENTICAL app code**, twice defeating a diagnosis. **LAWS MINTED (`docs/laws.md`):** *A VISUAL SUITE'S SUBJECT SHOULD BE THE SURFACE WHOSE OUTPUT IS DETERMINED BY CODE, NOT BY DATA* · *SCOPE THE SUITE TO WHAT HAS PAID, NOT TO WHAT LOOKS COMPREHENSIVE* · *baselines are generated where they will be compared* · *a baseline commit carries `.png` and nothing else*. **COST STATED, NOT GLOSSED:** the `Menu` overlap **had been frozen inside the `overview-390` baseline**; dropping it leaves that defect held in **prose only, with no artifact behind it**. That sentence sits in `e2e/visual/visual.spec.ts-snapshots/README.md`, beside the surviving baselines.

**MERGED (2026-08-01): EPIC 14 = UI REDESIGN through S14.4, five PRs rebase-linear, tree-identical, object-rewritten, main `39c7cad`.** #44 component-test tier → #45 S14.1 design tokens → #46 S14.2 layout shell → #47 S14.3 primitives → #48 S14.4 Overview. **Zero merge commits across the epic.** **SHIPPED:** a **component test tier** (8 wiring slices + screen census + 5 binding query rules) · **design tokens** as ONE authored form, generated + drift-guarded, re-pointed to the **handoff README's** palette (mono default, violet second at `#7C5CFC`; the app's `#7c5cff` was right *by coincidence*) · **layout shell** (228px grouped sidebar with vendored Lucide icons, 56px top bar, ⌘K palette, capability-driven width — `max-w-3xl` removed) · **primitives** (`DataTable`/`Panel`/`Badge`/`EmptyState`/`Loading` semantic-by-construction; command palette; toasts with a MEASURED undo criterion; the motion gate; three hand-rolled viz primitives with `VizSource` as a REQUIRED prop) · **Overview** rebuilt to the design: 12-col bento, six stat cards with icon+value+sub-line, nine panels in three even rows. **THE FOUNDER RULE, BINDING ON EVERY REMAINING SECTION (`docs/EPIC-14-ui-redesign.md`):** 1 READ THE WIREFRAME FIRST (by extraction; the prohibition was lifted) → 2 REMOVE WHAT IS NOT APPLICABLE, recording the reason → 3 DESIGN → 4 CODE → 5 **FOUNDER REVIEWS ON LOCALHOST** → 6 GO-AHEAD. **A slice is NOT complete until the founder has seen it running and said go** — gate green, CI green and mutation proofs are necessary and NOT sufficient. **THE FOUR-WAY PANEL TEST:** endpoint+no data → build with an empty state · **subject supported but the wireframe's RENDERING unsupported → build it in a different form** (Site-Link Throughput → cumulative NUMBERS, never a rate chart) · spec forbids the use → absent with the reason · no endpoint → absent, roadmap. **WHY THE RULE EXISTS: four slices were built from a SUMMARY of the wireframe** because a session-scoped instruction was never lifted — **388 tests, green CI, mutation-proven, and it did not look like the design. NO TEST IN THIS EPIC CAN CATCH THAT.** **LAWS MINTED (docs/laws.md, which now LEADS with the first):** *A CORRECT CAVEAT DOES NOT MAKE AN INADEQUATE CHECK ADEQUATE* (a commissioned click-through reported "nothing is broken", correctly hedged, while `backdrop-filter` had already broken **5 modals across 4 screens** by making `Card` the containing block for `position:fixed`) · *AN ABSENCE FOUND BY ONE ENCODING IS NOT AN ABSENCE* (scanned `#rrggbb`, the accent lives as `rgba()`; nearly cost a full token rewrite) · *⑦ AN UNCHECKED CLAIM* + *⑧ THE SUBJECT AND ITS CHECK VANISHING TOGETHER* (a cherry-pick dropped 400 lines of product code AND its tests; commit counts and exit codes all agreed) · *VERIFYING IS NOT DELIVERING* (three instances in one session, the worst being 401 green tests never pushed) · *EXTENDING A FRAMEWORK'S SCALE WITH ITS OWN KEY NAMES REDEFINES EVERY EXISTING USE* (px-vs-rem silently re-keyed **128 use sites across 17 screens**; a donut rendered at a quarter size; every gate green) · *DURING VISUAL ITERATION, REPORT CI STATE ON EVERY PUSH* (the branch was **RED for four consecutive pushes** under a green local gate) · *adding semantics broke a passing query THREE times — the tests were coupled to incidental structure because the product had none to couple to*. **OWED BEFORE THE EPIC CLOSES: the Playwright viewport leg** — commit-one proposed in `docs/S14-viewport-leg-commit-one.md` (a primitives gallery + Overview, two widths, its own blocking CI job, baselines updated only by their own commit), **awaiting the founder's ruling; NOT BUILT.** **NEXT: S14.5 — NOT STARTED, and it does not start until the viewport leg's commit-one is ruled and §C is reported.** **The twelve remaining screens, in the README's dependency order:** Gateways → Sites → Routed Ranges → Devices → Access Policies → Users/Groups → Access Events → Audit Log → Kubernetes → Operations → Org Settings → Edition/CLI/Auth/Onboarding/Desktop. **Each takes its own section pass, clears its own em-dashes (163 remain across 16 screens), re-checks its cuts against the four-way test, and takes its viewport snapshot last.** **ALSO OPEN:** §C hour-25 checkpoint on `aws-gw-1` due **2026-08-02 ~09:40Z** (S13.1 gateway-recovery, unmerged, branch `story/S13.1-gateway-recovery`) · three security decide-items landing as ONE hardening slice (Pinned-Dependencies · Token-Permissions · **no JS dependency scanning at all**) + the bundle-graph verification · the Makefile `NET :=` defect (one target addressing two stacks).

**MERGED (2026-07-30): EPIC 11 = Production Hardening COMPLETE — slices 2-6 + the box-walk, PR #42, ff-only linear, main `fb99dc6`.** Acceptance was never a story list: *"what breaks when a stranger runs this in production, unattended, for a month?"* **SHIPPED:** Slice 2 observability floor (ONE `tunnex_gateway_policy_health{kind}` gauge derived from the health-kind enum — one truth two renderings · `/metrics`+`/readyz` on a **loopback-bound** port, D3.2 · the single 500 seam logging cause+request_id · WF-OP-3 drift Event) · Slice 3 **leader election** (Postgres session-scoped advisory lock: N replicas serve, exactly ONE ticks; `/readyz` = `ok leader`/`ok follower`, both 200; Helm resources) · Slice 4 backup/restore (separate dump+manifest, **keyed** fingerprint and NO key material, `backupctl verify` refuses **exit 2** naming both fingerprints + agent CA + *orphaned*) · Slice 5 upgrade (forward-only + restore-as-rollback, migration backward-compat guard after a census found TWO historical violations, N/N-1 red, `preflight` that **refuses rather than warns**) · Slice 6 `self-host.md` with ✅/🔶/⚠️ verification marks + honest-limits table + a 14-kind runbook. **BOX-WALK LEGS 0-6 COMPLETE, BOTH OWED DEBTS DISCHARGED ON THE WIRE** (`walk-artifacts/S11/walk-record.md`): **Leg 3 trust-after-restore** — 4 cert serials byte-identical across `pg_restore --clean`, no re-enrolment, counters advanced, **919 packets zero gaps** (the window pulled explicitly, not inferred from a tail) · **Leg 5 HA under a roll** — takeover 2.5s, **an OBSERVED instant with no leader at all** (the advisory lock failing toward nobody-leads, never two), never two across 15 paired samples, returning replica came back a FOLLOWER · Leg 4 wrong-key restore refused exit 2 fleet unmutated · Leg 6 **an N-1 (v6) agent applied an artifact from a v7 CP refusing nothing** — the N/N-1 contract as mechanism, against a real released image (`v0.3.0-rc4`) never built for the test; Leg 0 metrics port **`000` from the host's own LAN address**. **15 FINDINGS (6 HIGH), 1 WITHDRAWN — nine folded WITH GUARDS:** WF-S11-1 `preflight`/`backupctl` never shipped in the api image + two runbooks naming subcommands that NEVER EXISTED (`TestEveryOperatorToolShipsInTheImage`, red-proven at the built-but-never-COPY'd instance) · WF-S11-6(d) the `cert_expired_cannot_reconnect` kind ranked FIRST + 0054/0055 `cert_not_after` as an **upper BOUND that cannot false-positive** · WF-S11-7 `k8s_endpoints_unavailable` reached NEITHER the spec NOR the UI since S10.3 (`TestEveryHealthKindReachesItsMirrorSurfaces`) · WF-S11-8(a) a revoked gateway now FREES ITS NAME (partial unique index + `TestNoAmbiguousNodeNameLookups`, census run BEFORE the migration) · WF-S11-9 gateway revoke existed in the API and NEVER in the UI · WF-S11-10/10b revoked gateways badged, then still counted in fleet health · WF-S11-2/3/4/5 (preflight wording, stdin guidance, a misstated HA limit, verdict-above-evidence). **THE FINDING UNDERNEATH THE FINDINGS: five of six HIGH are ONE class** — a mechanism that works, a procedure around it that does not, docs asserting the procedure — and THREE are one sentence, *"a lost gateway: re-enrol it (one pasted command)"*, which on the walk cost **four hand-run steps, a wrong host, a volume pinned by a container that exited six days earlier, and an undocumented deletion**, for a machine that had merely been SWITCHED OFF. **LAWS MINTED:** *A WITNESS MUST PROVE IT WAS ALIVE ACROSS THE WINDOW IT CERTIFIES* · **COULD THIS CHECK HAVE FAILED? — the censuses need censusing** (PROVE-A-GUARD-REJECTS generalized from guards to EVIDENCE: three checks in one session could not fail — a witness dead nine minutes before the leg it certified still returning clean · a red asserting a tautology that passed with its own fix removed · a provenance census verifying the COMMIT but not the EDITION, so four rebuilds silently swapped open-for-enterprise mid-walk). **NEXT (ruled): GATEWAY RECOVERY as its OWN EPIC, commit-one first, BETA-BLOCKING** — five walls in front of one question ("how does a gateway come back"): WF-S11-6(c) durable re-enrollment · WF-S11-8(b) replace-in-place identity (with the re-key security guard already drafted: re-key ONLY against a node the CP can verify is gone, NEVER one currently reporting) · WF-S11-11 RULED (a) prefer the token when the stored identity is provably unusable, *unusable* being a DETERMINATION not an assumption, failing toward the stored identity when uncertain · WF-S11-14 RULED (c) filter the compiler input AND unbind on revocation · plus the closing cluster (WF-S11-10c the revoked-badge defect in a SECOND component, the site showing "2 gateways" both dead while the live one is orphaned, same-name picker ambiguity). **LEDGER registered with measurements:** no component-test tier for the web app (**4 of 15 findings lived in the UI**, the surface with zero component coverage — same class as `apps/cli` having had no job at all) · the kind-consumer census gap (the census proves a kind REACHES its surfaces, not that each consumer DECIDES correctly about it).

**MERGED (2026-07-29): EPIC 11 SLICE 1 = security-CI tier + debt repayment — PR #41, ff-only linear, main `c278556`.** EPIC 11 (Production Hardening) OPENED: commit-one `docs/S11-decisions.md`, **D1-D5 RULED** (D1 upgrade FORWARD-ONLY with restore-as-rollback, N/N-1 contract + compile red, `tunnex preflight`, never a flag-day · D2 backup/restore where the **trust-after-restore invariant is the point** — backup carries the sealed master key + CAs + agent WG state, restore FAILS LOUD on key mismatch · D3 observability derived from the SHIPPED health kinds · D4 **leader election NOW**, scheduler-loops only · D5 CI security tier, block-what-we-fix / advise-what-we-inherit). **Slice cut:** 1 security-CI+debt (MERGED) → 2 observability → 3 envelope+leader-election → 4 backup/restore → 5 upgrade → 6 docs. **MERGE MODEL = BATCH, with Slice 1 a STATED EXCEPTION** (it carries real security fixes and has no walk-shaped debt; slices 2-6 ride the batch — recorded so the exception isn't read as drift). **SLICE 1 SHIPPED:** `.github/workflows/security.yml` (BLOCKING govulncheck ×5 modules · CodeQL high/critical · gofmt+vet+actionlint+toolchain-pin · SBOM+cosign on tags; ADVISORY Trivy · Scorecard; weekly cron) · **SECURITY.md** (disclosure contact, SLA table, forward-only support, honest in/out-of-scope incl. posture-is-spoofable + no-audit-yet) · `.devcontainer` + `make web-gate` (Node 20 + container-local node_modules — **any host can now run the web gate**; proven by running it: typecheck + 183 tests + build). **THE DEBT REPAID — one escalating class, three instances:** **S11-1** a job configured NOT TO MATTER (e2e was continue-on-error; it let an S10.2 a11y regression merge then excused it → fixed in the PRODUCT not the test, class-swept a 2nd instance in SsoProvider, e2e + e2e-enterprise PROMOTED TO BLOCKING) · **S11-2** a module with NO JOB AT ALL (`apps/cli` was compiled by nothing; an openapi/oapi-codegen name collision had shipped to main → schema renamed, `make test-cli` added, **coverage census over every module** found it was the only hole) · **S11-3** a check that NEVER EXISTED (gofmt ungated, 31 files drifted, fixed in an isolated commit). **THE SCANNER REJECTS, PROVEN BY REALITY:** govulncheck's first honest run exited 3 on `GO-2026-5856` — a reachable `crypto/tls` flaw in the PINNED TOOLCHAIN THAT BUILDS EVERY SHIPPED BINARY. Root: **two toolchain pins that disagreed** (Makefile/Dockerfiles at 1.25.12, `go` directives at 1.25.0, and CI's setup-go resolves go-version-file) → all 11 pin sites aligned + `scripts/check-toolchain-pin.sh` **fails the build on disagreement**. Five more real vulns fixed as **individually-gated bumps** (chi v5.3.0 · pgx v5.9.2 with sqlc output diffed = zero drift · operator x/net v0.55.0, checked first: **no controller-runtime drag**). **govulncheck now exit=0 on all five modules.** **O-1:** an advisory job that fails to START is indistinguishable from one that passes (Trivy 3s no-op reported green) → `continue-on-error` moved to the findings STEP only + produced-results assertions; **the guard then caught the very next instance of its own bug.** **O-2:** CodeQL enumerated FROM THE API — **0 alerts at every severity**, `results_count=0` both languages (`docs/S11-security-baseline.md`, with honest caveats: autobuild per-module coverage unverified → registered; a clean baseline is not an audit). **LAWS MINTED:** NEVER-TRIAGE-FROM-A-TRUNCATED-READ (3rd instance of reading a fragment as the whole — a "pre-existing" attribution must cite a green run at a specific sha) · CENSUS-THE-MIRROR-SURFACE (**S11-6: M1b's "two audit helpers" are FOURTEEN across nine packages** — resized to its OWN STORY post-beta, trigger = the next change to audit behaviour) · PROVE-A-GUARD-REJECTS (a guard that has only ever passed is indistinguishable from one that does nothing). **NEXT: EPIC 11 Slice 2 on branch `story/S11-slice2`** (pushed, 5 commits: commit-one with D3.1-D3.5 ruled · **D3.4+S11-5** the ONE 500-seam that logs cause+request_id — the census found THREE paths, the four unguarded ones on the FLEET'S OWN reporting channel, collapsed to one after verifying the agent never parses a body · S11-6 · **D3.1 part 1** `AllKinds()` + enum-drift census). **Slice 2 resumes at D3.1 part 2** (metrics package + collector over AllKinds()) → D3.2 (separate port, localhost default) → D3.3 (fleet counts, no org/node labels) → D3.5 (typed audit registry + drift red; census confirmed the vocabulary is CLOSED) → WF-OP-3 last. Slices 2-6 ride the batch model.

**MERGED (2026-07-29): EPIC 10 = S10.2 GitOps operator + machine principal — PR #40, ff-only linear, main `932b293`.** A Kubernetes **operator** (`apps/operator`) reconciles `TunnexCluster`/`TunnexExposedService`/`TunnexGrant` CRs against the CP **HTTP API** — THE HARD RULE: an API client, never a DB writer (`TestNoDBImport` census). **Machine principal** (`tnxm_`, owner-only `machine:manage`, one-time-secret mint, `actor_system=operator:<name>` audit); reconcilers with **honest status** (Ready only on CP 2xx; 4xx→verbatim code/message; 5xx→keep-last) + **requeue ordering** + friendly-name→UUID resolution; **finalizer delete through the AUDITED verb with the CR as cause** (`X-Tunnex-Cause`); **drift confirm-by-ID + recreate-from-CR**; `managed_by_operator` **dashboard ownership surface** (badge + withheld destructive control → "edit the CR"); owner-only machine-credential **Settings UI**; `Dockerfile` + `config/deploy.yaml`. **Slice-5 review folded 9 findings** (incl **M1b** — the policy audit path lacked the machine branch the k8s path had → a machine's grant-delete attributed to a zero user-id; `writeAuditAs` fixes it). **LIVE GitOps BOX-WALK DISCHARGED (`walk-artifacts/S10.2/`):** the decisive teeth — **deny (default_drop 0→2) → allow (curl 200) → deny (exit 28), same flow, flipped by `kubectl apply`/`delete` of a TunnexGrant, never the dashboard**, the revoke audited `actor_system=operator:gitops` + `cause=tunnexgrant:...` (M1b live). Legs 0-9 green (provenance census `version=<sha>`, cluster+service from YAML→endpoint DNAT→live pod, cascade audit `services_deleted=1`+CR cause, drift heal, ownership badge). **The walk EARNED ITS KEEP — WF-OP-1 found on the wire + folded (`d3f45a1`):** a user-subject grant reported `Ready`, the CP accepted it, traffic still didn't flow — `RoleOperator` lacked `member:list` so the operator couldn't resolve WHO the grant was for. 3 CI gate-fixes (create-audit NULL-actor FK, both-editions token_hash dup, identical-rule conflict) — go-test cache hid them locally; CI required checks (gates + client macos + windows) GREEN. **7 REGISTERED follow-ups (fold-later, none merge-blocking):** WF-OP-3 drift observability (Event on drift-heal) · R-3b-1 grant idempotency · R-3b-2 poll-vs-watch · L3 cluster name-collision · audit-helper unification (the M1b root, guard-not-mirrored) · hostNetwork deploy note (operator on a full-tunnel-gateway node) · enable/disable audit human-only. Standing probe (3rd instance with C1): **enumerate a principal's role from the CALL GRAPH it traverses, not the feature description.** NEXT = EPIC-10-close / next story, fresh sitting.

**MERGED (2026-07-27): EPIC 10 = S10.3 in-cluster K8s gateway — PR #39, ff-only linear, main `e730d12` (branch `story/S10.3-cluster-gateway` deleted).** Helm charts `tunnex-cp` + `tunnex-gateway`; a privileged hostNetwork node-agent fronts a cluster, exposes in-cluster Services at synthetic VIPs reached by name over the tunnel. **The box-walk's decisive leg (WF-K5) found a DESIGN DEFECT on the wire: a VIP→ClusterIP DNAT CANNOT complete** — netfilter applies one dst-NAT per prerouting pass, so kube-proxy's ClusterIP→pod DNAT is a silent no-op after ours; the packet dies addressed to the ClusterIP. **Rebuilt as ENDPOINT DNAT: VIP→a READY pod endpoint directly** (traffic stays FORWARDED, so the grant chain + S8.7 flush are unchanged), fed by a **raw-REST EndpointSlice+Service watch** (NO client-go — the lean agent ships to every VM gateway; fail-closed on every fault: list/watch/410/parse/zero-ready/local/v6/bad-port; bounded watch; relist-fast + clear-on-failure). **Ruling A amended** (target resolution CoreDNS-ClusterIP → API watch; DNS-answer half intact); **L10 amended** (SA token now mounted for the read-only services+endpointslices ClusterRole — "reads Service endpoints; cannot read Secrets, cannot write, cannot escalate"). **C1 (CRITICAL, caught in re-review not on the wire): forward-chain grant now matches `ct original ip daddr`** — the PRE-DNAT VIP — so enforcement keys the SAME tuple space as the S8.7 flush (the one-truth law); a bare `ip daddr` never matched the post-DNAT pod IP → granted flow dropped + broad-grant bypass. `ct state invalid` drop added. ProtocolVersion 6→7. **WALK GREEN on live k3s (`docs/S10.3-boxwalk.md`):** Leg 1 (Service-by-name→VIP→pod DNAT, 200, internet intact) · WF-K6 enforcing bypass-first (deny counter 0→5 → allow `ct original` grant 200 → revoke 000) · pod-restart (watch re-renders DNAT to the new pod IP, zero-touch). **Review:** 5-finder → 17 findings folded (C1 + H2/H3/H4/M5/M6/M7/M8/M9, L10/L11/L12 fixed/discharged incl an `nft -c` render-check test, L13–L17 registered) → scoped ct-original re-review clean. **Two UI folds (web-only, verified UI-only — model+compiler+API already carried ports):** WF-K-UX-2 K8s expose form gains a required port + tcp/udp (M8/M9 refuse all-ports/ranges); Feature 1 resource form gains optional port scope. **Stale onboarding e2e FIXED** (3 drifted assertions: enroll command compose→`docker run` ×2 branches + `/Pinned to the name/` case) — the prior deferred "e2e onboarding fixture stale" item is now RESOLVED; e2e signal restored. **CI all-green** (gates + client macos + client windows + e2e + e2e-enterprise). REGISTERED/DEFERRED: L13–L17 watcher edges (malformed-DELETE stale-entry, per-slice port-name-mismatch drop, jhash per-client LB granularity, 410 no-backoff, cross-goroutine port-name skew); web-gate LOCAL env-hygiene (Node-20 + cross-platform node_modules — typecheck runs locally, test/build ride CI; fix = devcontainer / container-local node_modules); demo-env DB state left as data (hello port=80, org enforcing). Standing probes added: data-plane red must prove a connection COMPLETES (not just renders); who-reads-this extended to enumerate ALL asserting consumers (unit+e2e+golden) on a render change. NEXT = EPIC-10-close / next story, fresh sitting.

**MERGED (2026-07-25): EPIC 9 = S9.1 OpenVPN — PR #38, ff-only linear, main `cd77a2f` (S9.2/S9.3 absorbed under D-S9.2-SCOPE; WF-OVPN-9 multi-remote HA folded in). Enterprise batch walk 4/4 GREEN (`docs/S9.1-boxwalk.md`): B1 enforcing+grant→flow, revoke→CRL→death, D-S9.5-4 reload-no-restart, WF-OVPN-9 failover. 5 findings ALL UX/observability/timing, ZERO enforcement or security defects — 4 FOLDED (`cd77a2f`: walk-4 profile `connect-timeout 10` + honest re-home note, walk-1 honest-unknown liveness render, walk-2 label, walk-3 Min-OS-Off Save), 3 REGISTERED/DEFERRED: OVPN liveness telemetry (2nd liveness plane, own story), group-member UI (Deck-D 2nd sighting → UI batch), failback readiness gate (walk-5, triggered). NEXT = EPIC-9-close / next epic, fresh sitting. Build record below (decision-first, `docs/S9.1-decisions.md`):** Commit-one + all six D-S9.1-* + D-S9.2-* + D-S9.3-* + D-S9.4-MODEL RULED. **Built + gated (both editions + node), on the branch:** Slice 1 (B1 boundary in code — compiler transport-agnostic + chain address-keyed; WIRE proof OWED, trigger = the S9.1 box-walk) · Slice 2 (`ovpnca` separate client CA + PKI + issuance; migration 0041 `ovpn_client_certs`) · Slice 3 four parts (mesh relaxation: `ip tunnex` interface-SET keying + Docker-USER pool & localSubnets per-interface + route site-link-noted — anti-spoof + zero-config reds green; `ovpnserver.Manager` server-lifecycle+CCD, unit-proven, UNWIRED — the 6 live-wiring preconditions named in the paper) · Slice 4a (`ovpnca.IssueServer` server-auth leaf, role separation) · 4b-core (`ovpn.BuildProfile` .ovpn assembler, one-time-by-construction) · **4b-model** (D-S9.4-MODEL: `devices.transport` tag migration 0042 — FILTER-only, compiler transport-blind, Slice-1 checkpoint re-verified; cap+pool+revocation inherited via the shared Create/Revoke path). **Shas: `9074323`/`f75725c`/`13a8a59` (Slice 3) · `e205223` (ovpnserver) · `c5dc6fd` (4a+4b-core) · `8465a66` (4b-model) · `ef7b8f4`/`8d27cce`/`5e2b1af`/`5c11bbb`/`53fd634` (commit-one+S1+S2).** **4b-wiring SERVICE layer done** (OVPN-create fork at ONE seam `b7a3313` — no WG keypair/peer, pool+/32-in-artifact, migration 0043 keyless-device index; `ExportProfile` orchestration `acd6506` — issue+assemble+serial-fingerprint) · **D-S9.5-OPTIN RULED** (OVPN unlock-then-opt-in, OFF-by-default org-level + per-gateway, binary-unconditional, disable≠revoke full-sweep). **S9.1 through 4d COMPLETE (zero-touch).** Export path + opt-in + Part-2 enrichment + stale surface + WEB ceremony + 4c roster + 4d live wiring + D-S9.6 CERT DELIVERY all built + gated. 4d: precondition guards + refuse-loudly health (ovpn_certs_absent/ovpn_binary_absent, recovery-clears) + TunActive ordering + sweep-on-death + Supervisor + org opt-in toggle (PUT /ovpn-settings) + **D-S9.6 server-cert delivery** (mint-once EnsureServerCert → DesiredState.OVPNServer → agent writes ca/server.crt/server.key 0600 at cfgDir, re-asserted/swept; server key stored SEALED, crosses the existing mTLS channel, no new trust). Node toolchain FIXED (nvm 20). Feature 5 registered (device source kind). **NEXT = (minor) Health()->CP report plumbing** (mirror conntrack_flush_unavailable — PolicyStatus field + reportKeyLoop + CP surface; walk-evidence on the dashboard) **THEN 4e box-walk** — now ZERO-TOUCH (OpenVPN Connect on a device · cross-cloud gateways up/tip · org opt-in flipped via PUT /ovpn-settings · certs auto-delivered · the B1 deliberate-red on the wire: enforcing+zero-grants DROPPED byte-for-byte, grant->flows, pushed routes reach a site subnet — discharges Slice-1's SUBSTITUTE). THEN Slice 5 (revocation full-sweep + CRL reconcile — the last EPIC-9 runtime). Pre-existing bindings intact (ZT-coverage / revocation-parity / S9.3-lock). Slice 5 (revocation full-sweep + CRL reconcile) after Slice 4.

**CURRENT (2026-07-24): EPIC 8 COMPLETE + v0.2.0 · POST-EPIC-8 FIX LANE CLOSED + MERGED to `main` (`e860268`, PR #35, ff-only linear).** Shipped in the fix lane: **WF-A device re-homing** (CP dial channel + client dial tier + helper `set_gateway_peer` peer-swap + D-WFA-4 full-tunnel CP-endpoint kill-switch carve-out — identity minted once/never re-fetched, dial is a volatile network fact) · **WF-B** demoted subordinate badge · **WF-C L1** graceful wg0 teardown · **WF-C L2** `hub_forwarding_not_reconciling` zombie honest state (settle-hardened). **LIVE-WALKED — all 5 legs GREEN** (`walk-artifacts/WF-A-WF-C-boxwalk-record.md`, cross-cloud AWS Sydney↔Azure): split+full-tunnel re-home both directions, carve-out block-all-minus-named + zero-leak (port-scoped), WF-C L1 teardown, WF-C L2 real-zombie true-positive, WF-B badge. The walk **found + fixed + re-verified WF-A-FT-1** live (merge-gating full-tunnel re-home bug: re-home endpoint host-route re-pin re-derived the tunnel next-hop via `gatewayFor` post-tunnel-default → looped; fix `3eaea5b` stores the physical gateway at Up). Two review rounds (peer-model+kill-switch, then the fix batch) — clean; folds: KILL-SWITCH-NO-UNBOUNDED-I/O law, F-Z1 clock-skew clamp, WF-A-obs-1 breadcrumb. **FEATURE 3 (per-rule enable/disable toggle) SHIPPED + MERGED (`e8b1877`, PR #36, ff-only)** — `disabled` boolean; compiler-SKIPS disabled rules (as-if-absent under default-deny, in-hash push, no version bump); two distinct audit actions (`policy.rule_enabled`/`_disabled`); PATCH `/policies/{ruleId}` (`policy:manage`); web row toggle (enable=1-click, disable=confirm naming the rule's subject→destination; disabled dimmed+badged). Two-reviewer round: compiler-skip CLEAN, F-A1 (no-op-toggle audit-lie) folded (`docs/F3-per-rule-toggle-decisions.md`). **NEXT (RULED): EPIC 9 commit-one (OpenVPN)** — the wedge epic, FRESH sitting, decision-first; ledgered bindings (all pre-existing, not to be re-litigated): ZT-coverage guarantee (OVPN devices are policy subjects in the SAME `policyspec.Compiled` artifact — grants transport-agnostic; cert-auth alone ≠ enforcement; S9.1 deliberate-red = enforcing+zero-grants → OVPN DROPPED at forward chain like WireGuard; a parallel non-compiled OVPN path rejected in advance) · identity-binding + full-sweep revocation parity (cert/CRL revoke + address release + status clear — S3.3 rule, transport-agnostic) · S9.3 protocol-selection LOCKED (`.ovpn` export to standard OpenVPN clients; the Tunnex desktop client stays WireGuard-only by construction — native OVPN in the privilege helper is the rejected tier). **Features 2 (port-scoped resources) + 4 (FQDN resources) stay REGISTERED, sequenced AFTER EPIC 9** — either jumps the queue on a named prospect demand. FQDN registered with rationale: cloud-managed endpoints (RDS et al.) resolve to changing IPs, CIDR resources can't express them, NetBird ships it, day-one gap a cloud buyer hits. **DEFERRED-WITH-TRIGGER (no work owed):** WF-C L2 option (c) automatic zombie demotion (trigger = hub-sole-enforcement ZTNA tightening / security-review-beta-blocking / a device seen dialing a zombie in a walk) · **S8.6b-win-carveout** (Windows full-tunnel re-home — currently honestly refused `rehome_full_tunnel_unsupported`; split works; NOT a regression) · devices-on-SPOKES cross-site re-home · PD-3 residual · IPv6 pool · audit-action typed registry · helper-protocol hardening (#4/#6 `docs/POST-EPIC8-feature-requests.md`) · e2e onboarding fixture stale (SPA enroll now `docker run` form, e2e spec expects `docker compose` — opportunistic/non-gating, update the fixture) · env-hygiene (dies at any fresh env) · S8.4b Windows NRPT · SSO-exempt wire proof · MFA break-glass. **ENTITY-GATED:** Gatekeeper/S6.5b signing (xattr+adhoc-codesign is the dev workaround). Prior: EPIC 8 train landed ff-exact (S8.5 `8eabec4` → S8.6 `7083889` → S8.7 `bb05df5`); **v0.2.0 @ `7a7c331`** (node-agent digest `sha256:de8c9cefb614…22f114`); SMOOTH WALK passed on shipped v0.2.0 (`walk-artifacts/S8.6/SMOOTH-WALK-record.md`).**
- **S8.2c MERGED — the zero-touch gateway story, PROVEN on a live cross-cloud re-walk (AWS Sydney↔Azure West US, `walk-artifacts/S8.2c/walk-record.md`).** Commit-one → 3 slices (D1 mesh symmetric forward · D2 CP LocalSubnets + agent src-hint, one-truth law · D3 site_subnet_unreachable kind · D4 emitted single-line docker run · D5 site rules in the Access builder, audited). **First walk FAILED the Zero-Touch Law on WF-4** (Docker `filter FORWARD DROP` swallowed the forward — a manual gateway iptables was needed). Founder dispositioned 8 findings: **6 FOLDED** — WF-4 (agent owns a Routes-scoped **DOCKER-USER accept**, forward `daddr`+return `saddr`, idempotent/full-sweep/comment-marked/Docker-conditional, `ForwardBlocked`→`site_subnet_unreachable`; decision-first) · WF-8 (site rules render by NAME not UUIDv7-prefix) · WF-6 (diagnosed — out-of-hash exclusion holds, no code) · WF-2 (meta-driven digest-pinnable agent image + volume-reuse boot log) · WF-3 (in-UI per-cloud fabric steps) · WF-5 (un-advertise/remove a subnet, audited/org-scoped/full-sweep) — **2 DEFERRED** — WF-1 (positive site-link health → S8.5 L1-metrics rider), WF-7 (site-rule editor → first-request/UX harvest). Targeted re-review of the fold → 5 fold-induced defects fixed at root (/32 daddr churn, transient-list skip, banner, sweep-log). **Leg-2 RE-WALK PASS on live nft:** behind-host forward 0% loss/ttl-63 on agent-managed DOCKER-USER rules **alone** (no manual iptables; fwd+ret counter 3), idempotent handles across a reconcile tick — Zero-Touch Law SATISFIED. Re-walk itself caught + fixed the return-path gap (forward-only accept passed the echo-request, Docker dropped the reply → per-route return accept, `5ab5f04`). Image pinned `sha256:1b39c22e…`. LAWS: Zero-Touch Gateway Law + boundary clause (`docs/laws.md`), one-truth law 5th instance (`meta.public_base_url`). NOTE: the `deeddac`..`07e40c3` fold + `b6ca114` WF-4 + re-review fix all rode to main via the merge. Prior: ALL 3 SLICES COMMITTED (`4ab3b84` D1 mesh symmetric forward, `606c7e9` D2 CP LocalSubnets + agent src-hint, `9371138` D3 site_subnet_unreachable kind, `3a8981f` Slice 2 D4 emitted install command, `ccf0077` Slice 3 D5 site rules in Access builder). REVIEW ARC CLOSED — 3 rounds, all folded: story-end fold `d04092f` (8/9) → re-review fold `f2eab27` (5 findings, budget-rule reduce of the Gateways URL-consumption class) → loop-terminator fold `4fe05e1` (2 findings one root: the in-flight-meta race; reduce COMPLETED by making metaLoaded a first-class state, LOOP HALTED — defects converged 3→2→0-new-root). NEXT = the demo-re-run WALK (Pawan drives; Zero-Touch Law is the gate; `walk-artifacts/S8.2c/walk-record.md`, 5 legs). NOT merged — awaits explicit in-session sign-off.**
- **S8.2c review-FOLD (`d04092f`) — 8 of 9 findings folded, #7 deferred, all gates green:** #1 `Meta.public_base_url` (emitted command derives CP URLs from the CP's OWN configured public base URL, not window.location — tunnel/alias/bare-IP no longer bakes a bad endpoint) · #2 enroll-modal caption points at the co-located doc · #3 endpoint shell-quoted like the name · #4 rule-modal default kind → site when no groups but sites · **#5+#6 the reconcile restructure: host-addr enumeration + src-derivation moved OUT of the wgctrl backend UP into `runOnce` (enumerated ONCE per tick); `WGBackend.ApplyRoutes` takes a reconcile-derived `srcHint string`, the backend threads it verbatim (never guesses); onset warning de-duped; derivation reds moved to a reconcile-level test + a pure `siteRouteSrc` test** · #8 `canEditRuleInModal` comment matches D5 · #9 enum doc + rank for `site_subnet_unreachable`. **#7 (duplicate precedence ladders) DEFERRED.** A feature-sized fold RE-EARNS a review of the folded code → the targeted re-review is running (advisor was disabled this session; the workflow review is the check).
- **S8.2c commit-one RULED (`docs/S8.2c-decisions.md`), Zero-Touch Gateway Law is the acceptance bar (`docs/laws.md` + boundary clause: gateway VM = zero SSH after join; cloud console = ONE guided visit per side).** Slice plan: **Slice 1 (agent: D1✓ D2✓ D3-next) → Slice 2 (emitted install command, D4) → Slice 3 (site rules in the Access builder D5 + GAP-1/GAP-3 D6) → story-end review → the demo-re-run walk (Pawan drives; the cross-cloud demo re-runs clean, only terminal action a pasted join command + one guided cloud-console step per side — the Zero-Touch Law is the gate).** Then S8.4 (DNS) → S8.5 (open-edition routed subnets, shrinks by S8.2c overlap).
- **Cross-cloud demo PROVEN** (`walk-artifacts/cross-cloud-demo/demo-record.md`): AWS Sydney↔Azure West US site-to-site, **138ms un-NAT'd**. Compiler EXONERATED (leg (b)); the 6 gateway findings + 3 UI gaps are S8.2c's scope. **S8.4 prereq still owed:** the two-part verify-item before S8.4's paper.
- **S8.3 (site management UI) MERGED (PR#29, `e3ba76a`)** — the web consuming layer for the S8.1/S8.2 site model. **commit-one 10 decide-items (4 carried + 6 story) → 5 slices → review arc → founder walk 7/8 live.** Slice 0 keepalive on site-link peers (S8.2b rider). Slice 1 backend-truth: health-kind enum (`site_hub_down`/`site_link_down`), CW agent-max-version signal (**absence = below-ceiling**), backend `is_site_hub` **projection of the ONE election** (`electSiteHub` extracted; `siteTopoHasHub == electSiteHub!=nil`), shared `getSiteReferences` (D1 reverse-link ⋂ D4 cascade), wired `deleteSite`. Slice 2 Sites page + top-level nav (member-visible, page owns the upsell) + read-only topology (**CH list-of-one**, backend hub, render-floor law — wire-truth only). Slice 3 mutation surfaces: queue/approve (admin-only), **verbatim `subnet_not_disjoint` refusal** (D3, no JS re-check), bind/unbind, **delete name-typed + present-tense cascade** (ratified advisory copy), the **CW blocking confirm** (`crossesMultiSiteThreshold` the one crossing; `subCeilingGateways` absence-below; ceiling from `meta.protocol_version` — no TS hardcode). Slice 4 Access polish: loud zero-state summary line (`rulesSummary` off `Loaded<T>`, failed≠0-rules) + fieldset panels (rows already rendered S7.5.4 truth, LEFT UNTOUCHED). **Story-end review: 7 findings all CONFIRMED, folded → targeted re-review CLEAN.** #1 correctness: NAT'd-spoke hub-peer perpetual churn (keepalive made a latent S8.2 edge certain) → **three-clause `peersEqual` guard** (compare endpoint only when desired non-empty). #2 correctness (RULED a): member `canView` unkeepable → loosen site READS to `org:view` (member-read precedent, no new perm); mutations/preview/queue stay `site:manage`. #3–#7 cleanups (SiteTopoBatch load-once, dropped dup GetSite, shared auditTarget, Promise.all subnets, shared LoadRetry). **Box-walk 7/8 live** (`walk-artifacts/S8.3/walk-record.md`): topology render-truth · member read-only (#2 fold live) · `site_link_down` badge (enum fold live) · approve+audit · refusal verbatim · delete name-typed+cascade+real-count audit · Access polish. **Leg 6 CW confirm = NAMED SUBSTITUTE, trigger = the EPIC-8-close founder walk after S8.5.** Laws applied: fixture-fidelity contrapositive (keepalive kernel-parsed), render-floor for derived truth (backend hub), reassuring-empty-on-loudest-line (summary failed-state). **Walk-found (pre-existing): stale Add-rule button after group-add → rides S8.5/epic-close fold. Metrics 3-way: L1 card byte-counters→S8.5, L2 site-flows→S7.5.1b, L3 throughput-timeseries→S11.1.**
- **S8.2 (route propagation) MERGED (PR#28, `2df19df`)** — the EPIC's payoff: LAN-to-LAN transit across sites under enforcing ZT. **`Compiled.Routes[]` explicit section** (hash-blind, `RequiredVersion` first customer) + **content-derived version 4→5** (`RequiredVersion(c)` = 5 iff a CIDR-source rule or a non-empty `Routes[]`; no-site orgs stay byte-identical **v4**; multi-site adopters **upgrade-first, all editions** — named limitation, **S8.3 warning + S11.4 docs owed**). **Hub-and-spoke `siteLinkGraph`** (single hub v1, transit grants on the hub per **B1**) + **agent kernel routes** (`proto static` metric 8021, **full-sweep prune**) + **MSS clamp** + **site-link health kinds wired end-to-end (H5)** (`site_hub_down`/`site_link_down`; precedence version-refused > hub > link > apply/desync). **#1 merge-blocker fixed at a single source** — `finalizeArtifact`/`pushedHash` feed BOTH the served `DesiredState` AND the desync baseline (`CompiledHashesForNodes` → `CompiledArtifactsForNodes` route-less), so route-carrying enforcing gateways don't false-`silent_desync` (Version in-hash). **Review arc:** story-end multi-finder → reduce-in-place (B1–B4/H5/M6 cluster) → **budget-rule HALT + terminal reduction** → 4 targeted passes → **model-clean under the four-word model {atomic fetch, fail-static, full-sweep, keep-last-value}** — **DesiredState-atomic law papered (amendment withdrawn** — a topology-load error is the same fail-static class → fail the whole fetch), **fixture-fidelity law minted** (a test double must not out-capability the substrate — the fake stripped `SiteLink` on read), validator-comparison-set applied. F3 terminal: a `-4` route-enum error ALWAYS surfaces (full-sweep wins), `-6` tolerated. **Box-walk 8/8 on a 3-agent topology** (`walk-artifacts/S8.2/box-walk.md`): **Leg-1 transit ping (first cross-site packet, A→B via a hub that is neither endpoint, enforcing)** · routed-but-dropped same-wire contrast · **refuse-half live (S8.1 substitute DISCHARGED** — v4-pinned gateway refused the v5 artifact → `unsupported_policy_version` on the health surface) · full-sweep · `site_link_down` live · desync-quiet. Migrations **0035**. **S8.2b registered:** persistent-keepalive on site-link peers (**trigger = before S8.3's box-walk**) + MSS double-encap contrast (**trigger = client-over-site-link setup**) + hairpin-NAT env clause (single-VM test artifact, not a product issue). **S8.3 commit-one CARRIES:** the add-second-site v5 upgrade warning · the Access-page polish scope (status summary, user-subject + expiry visible, resource-panel layout) · S8.2b keepalive before its walk · the EPIC-8-close founder UI walk after S8.4.
- **S8.1 (site/gateway model) MERGED (PR#27, `e8f6bef`)** — EPIC 8 opener. **Site-as-ENTITY** that owns a gateway node (D6 — replace-node preserves site identity/subnets; single-node v1) with **reservation seams**: link-transport enum (`wireguard` only, day-one modeled), site `link_mtu`, DNS-forwarding-entries (S8.4). **D1 ProtocolVersion fail-closed gate BUILT + wire-proven ACCEPT-half** — retires the safe-by-convention hazard: `Version > MaxSupported → refuse → deny-all + policy_degraded`, surfaced as `unsupported_policy_version` kind on the health surface (S7.4b advisory pattern; refused OUTRANKS apply-error + silent-desync). Refuse-half live proof **DEFERRED → trigger = S8.2 box-walk** (needs an enforcing gateway carrying a compiled v4 artifact; this stack configures none — unit-pinned both editions `TestInterlockOldMaxAgentRefusesSitesBump` + `TestUnsupportedPolicyVersionSurfaces`). **ProtocolVersion 3→4 via the Option-A fork** — sites-as-destination adds NO new AllowEntry wire field; the version BUMP ITSELF is the enforcement-significant change (Version in-hash; A-4 `hash.go` warning discharged); `dst_kind='site'` resolves CP-side to the site's approved subnets at compile (N subnets → N entries; subnetless → no grant). Twin goldens pin identical CanonicalHash both modules. **The ONE org-wide disjointness validator (`subnetguard.Check`) at BOTH seams** — advertisement-approval + pool-resize (S4.5b touch) — incl. the **review-caught #1 duplicate-CIDR bypass** (an `a.Cidr != sub.Cidr` filter exempted the exact-dup collision across sites since uniqueness is per-SITE not per-org; filter DROPPED, fixture-family + **validator-input-filtering law** papered, targeted re-review clean). **Advertisement pending→approved WIRE-PROVEN** (approve → `site.subnet_approved`; cross-site dup approve → **409 `subnet_not_disjoint`** + `site.subnet_approval_refused`; NEGATIVE: refused row **stays `pending`**, re-approvable — the refusal edge first wire-observed). Refusal audit written **outcome-not-error** (outside the failing tx); **swallowed-audit law** minted (in-tx `InsertAuditLog` error must propagate, else mystery commit-rollback). **Absorbed HTTP surface** (6 site ops + 2 subnet ops; every op `authorize(PermSiteManage)` FIRST — 401-walk/RBAC armed; owner+admin). Migrations 0032/0033/0034 (down-discipline; CHECK-widening additive-only). **commit-one D1–D11 → 4 slices → story-end review (4 folded) → bounded box-walk** (`docs/S8.1-decisions.md` + `walk-artifacts/S8.1/box-walk.md`). **STANDING: EPIC-8-close founder UI walk** (folded into the EPIC 8 section below). **S8.2 commit-one CARRIES:** the real new-field D2 classifications, MSS clamp + its walk leg, a routed-but-dropped deliberate red, **the Leg-1 refuse-half old-agent live proof**, and the validator-comparison-set law.
- **S7.5.5 (MFA/TOTP) MERGED (PR#26, `777c6be`)** — in-house RFC-6238 TOTP: self-service enrollment (**D1 OPEN, all editions**) + login second-factor challenge + single-use recovery codes + **org-level MFA enforcement (enterprise; unlock-then-opt-in, default OFF)**. **D6 the MFA-pending state is a challenge TOKEN, never a session** (attempt-capped, burn-on-success). **D8 flip-on = enroll-on-next-login** — Option A: a gated session + **default-deny enrollment-gate middleware** (operationId allowlist; mid-build fork, dispositioned then built). **D5 SSO + bearer EXEMPT by construction** — the review caught the gate was auth-method-blind; fix = an **auth-method principal primitive** stamped immutably at session/credential mint (`Principal.AuthMethod`; local_password gated, sso/bearer skip). Migration 0031. **3 slices → story-end review (10 folded) + targeted re-review.** **WIRE WALK caught a production BRICK:** the enrollment-gate allowlist was keyed in source-yaml **camelCase** while `api.GetSwagger()` carries oapi-codegen **PascalCase** operationIds → the gate denied its own allowlist → grandfather bricked; the self-arming test was **TAUTOLOGICAL** (compared a map to itself) and passed green. Fixed (allowlist re-keyed + de-tautologized with absolute `(method,path)` pins + a permanent full-chain `NewRouter` red). **LAW papered — tautological-guard class:** a guard's test must assert ABSOLUTE behavior, never derive its expectation from the same artifact under test (the first diagnosis was WRONG + approved-for-build; a local full-chain repro caught it before landing — surfaced against the standing disposition, halt-and-surface applies to one's own approved-but-wrong fixes). Wire legs: grandfather / **D5 bearer-exempt contrast** (same subject, local GATED vs bearer EXEMPT) / downgrade-release (both halves) / audited mutations (`mfa.enrolled`/`recovery_code_used`/`admin_reset` + Mailpit). **UI WALK (founder clicks) caught WF-3** (high): forced-enroll page had NO exit — a now-enrolled user was trapped; the `ForcedEnroll` comment claimed a release the code never performed (**reassuring-comment class, 2nd instance under the law** — sibling of review #7). Fixed (symmetric release redirect, extracted to a pure fn + **table-pinned both directions**, `resolveMfaGateRoute`); **WF-5** (high, data-loss): the WF-3 redirect destroyed the one-time recovery-codes modal → fixed (gate clears only on code acknowledgment); **WF-1**: recovery-code Download added; **WF-4** = environment residue, not a defect. `docs/S7.5.5-decisions.md` + `walk-artifacts/S7.5.5/` (grandfather / bearer-exempt / downgrade / audited-mutations / ui-walk-findings). **DEFERRED w/ trigger:** SSO-exempt **wire** proof (box Entra config is a stub → S7.5.2b/SSO-walk window; substitute = unit pin `TestEnrollmentGateAuthMethodExemption` + mint-seam + the bearer-rider shared-mechanism, wire proof OWED). **REGISTERED follow-up:** **WF-2** (sole-owner MFA break-glass — no first-class ops command, raw SQL only; candidate `tunnex-admin mfa-reset` + runbook). step-up deferred as a CLASS; S11.3 global rate-limit still owed.
- **S7.5.4 (per-user + temporary grants) MERGED (PR#25, `17c8c20`)** — USER as a policy subject (`src_kind ∈ {group,user}`, `src_user_id` composite FK cascade-to-wire) + temporary/time-boxed grants (`expires_at`, window-extensible). Identity resolves to /32s CP-side in the clockless compiler → **NO enforcement version bump** (per-user lives at rule-spec level; versioned-artifact obligation discharged by proving the seam doesn't cross). **Option A delete-on-sweep** (story-end review tripwire fired 4/9 in the expiry subsystem → linger REVERSED to stateless delete-on-sweep; 9 findings folded, targeted re-review clean, incl. the [6] fold-induced defect — extend audit read old-after-update → `GetPolicyRuleForUpdate` FOR UPDATE). Migration 0030; v3 `src_device_id` observability (out of hash like `rule_id`). **Box-walk 5 legs + negatives on the two-gateway enterprise wire** (`docs/S7.5.4-boxwalk.md`): per-user grant A+B + F1 org-wide strip; **temporary lapse → the background sweeper's org-wide push reaches gw-b** (a gateway it has no request-context reason to know — the flagged call-site, discharged) + **`grant_expired` system-audit wire-proven** (armed-guard discharge, `actor_system=policy-grants`); downtime-lapse two-mechanism (compiler-filter strip + stateless sweeper delete/audit — audit-gap closed); **per-user semantics** (subject permits / non-subject `default_drop`s, SAME dst); idempotence 1/1 + IP-attribution negatives. **Walk-found fix (D8): extend-no-push** — `ExtendGrant` used `mutate`'s unconditional `pushOrg` → byte-identical org-wide re-apply (nft handle churn on the wire); fixed to `withTx` (expires_at not in the artifact, endpoint extend-only), **red-pinned + re-earned** (handles stable, log-silent). **LEDGER — EPIC-8 ProtocolVersion fail-closed gate is now a BLOCKING S8.1 commit-one item:** `ProtocolVersion` bumped 1→2→3 with NO consumer gate (node applies ANY version, safe-ignoring unknown fields) — safe **by-convention only** (every bump observability-additive + hash-blind + safe-ignore, each unit-pinned); S8.1 MUST build `Version > maxSupported → refuse → deny-all + policy_degraded` before the first enforcement-significant wire field (interim law: every bump owes its own hash-blind pin). **S7.5.4b REGISTERED (deferred): flow-log web VIEWER page + `AccessEvent.src_device_id/src_user_id` — merges with S7.5.1b.** gw-b left standing as the two-gateway enterprise env for S7.5.5.
- **S7.5.3 (device posture checks) MERGED (PR#24, `e7547ee`)** — client-reported OS-version + disk-encryption posture, enterprise-gated. **Per-check org-level config** (`org_health_checks`, no row = off — unlock-then-opt-in); orthogonal `devices.health_blocked` gate AND-in'd into both active-device readers → exclude-then-push (box-proven **69ms** exclusion on the wire). **Three-way report taxonomy** (compliant / blocked / **unknown** — absence is NOT compliance; garbled-positive-report BLOCKS, absence never blocks, stale = absence). **Report-absent tri-state** carried helper→client→server (a fact the client can't read is reported ABSENT, never guessed). Continuous eval + 30-min stale sweep; grandfather 0%-loss flip-on; system-actor audit (`device-health` + cause). Helper read-only `posture_status` verb (FileVault/BitLocker numeric, additive at ProtocolVersion 1); client `posture_blocked` state (a require-mode block is never a silent dead tunnel); web per-check config UI with per-platform coverage indicator + verbatim honesty line (NOT attestation). Migration 0029. **Story-end review (10 verified) folded + targeted-re-review-clean**; **box-walk 5/5 on the wire** (`docs/S7.5.3-boxwalk.md`) incl. **Leg 5 enterprise→open downgrade-release wire-proven** (the highest-sev find). **LEDGER — downgrade-releases-enforcement law:** any enterprise ENFORCEMENT flag must define what CLEARS it on downgrade (mirror of unlock-then-opt-in; sibling of data-retention-on-downgrade) — **binds S7.5.4 grants + S7.5.5 MFA-enforce to state their downgrade-release at commit-one.** **S7.5.3b REGISTERED (deferred): EDR-present + Windows-WSC eval + hardware attestation + posture history + block-on-absence strict mode.** Client `posture_blocked` desktop-UI wire-smoke deferred (packaged-client, SUBSTITUTES≠SATISFIES).
- **S7.5.2 (IdP-group sync) MERGED (PR#23, `e148b93`)** — directory (Entra) groups as Zero-Trust policy SUBJECTS: provider-agnostic `DirectoryProvider` (Entra Graph impl; Google = fast-follow) → reconciler drives `group_members(origin='idp_sync')` to the directory's authoritative membership → compiler puts the members' /32 grants on the gateway forward chain. Poll (10-min jittered) + manual trigger. **Reconciler fail-static BY CONSTRUCTION** (a removal is only ever computed from a successfully-fetched member set); two-tier sync health (freshness clock: ok→degraded→escalated); D1 disjointness app-layer (refuse-unless-empty 409 + no-hand-edit-of-synced 409); **first-class system audit actor** (`audit_logs.actor_system='idp-sync'` + cause, migration 0027 — "revoked by idp-sync because …"); fingerprint-only config read (S4.5). Migrations 0026/0027/0028. **STORY-END REVIEW found a deprovision FAIL-OPEN cluster on the error/edge paths the happy-path walk missed** — folded fail-CLOSED with reds (null accountEnabled→hard-error; continuation-404≠group-gone; committed-removal-always-pushes; one-failing-user-doesn't-strand-siblings; `ResolveUserStatus` wired so a directory-DELETED user is fully swept (1a); per-config poll timeout; unsupported-provider rejected at config; idempotent deactivate no-flood; robust pg-error); **re-earned review tripwire-CLEAR** (no new fail-open). **PROVEN on a live Microsoft Entra tenant + enforcing gateway** (`docs/S7.5.2-box-walk.md`): grant appears → Red 1 group-removal (account stays active) → Red 2 disable→sweep → two-tier health → **post-fold Leg 6 directory-DELETE→full-sweep** (the sharpest fail-open, re-proven closed on the wire). `entra.go` live Graph path (token/pagination/`accountEnabled`/UPN) wire-proven. **S7.5.2b REGISTERED (deferred, not dropped): SCIM push-provisioning + the `deleted_in_directory` audit-cause precision follow + the Google provider.**
- **STANDING CONVENTION — enterprise features are UNLOCK-THEN-OPT-IN, never unlock-and-enforce (founder-directed):** every EPIC 7/7.5+ capability is org-level opt-in and default-OFF (`zero_trust_mode`, `device_approval`, IdP sync's credential+map, flow-log arming all already follow this). **S7.5.3's commit-one MUST state per-check org-level configuration** (e.g. require disk-encryption without EDR) **as a decide-item**; **S7.5.5's per-org MFA-enforce policy likewise.** **S12.1's license-unlock inherits it:** pasting a key makes features AVAILABLE, turns nothing on.
- **EPIC 6 done:** S6.1–S6.6 + S6.7 + S6.8/9/10 (+ S3.7) all MERGED. The mid-epic stories were spun
  up live during full-tunnel hardening and are defined ONLY here (reconciled against git log, so the
  checkpoint never points at ghosts): **S6.8 = quit continuity** (graceful helper Down on app quit +
  fast orphan dead-man — internet no longer dead ~60s after quit); **S6.9/S6.9b = Windows full-tunnel
  guard** (server-side CLEAN refusal of Windows full-tunnel until DNS parity + kill-switch persistence
  landed — LIFTED at S6.7); **S6.10 = Windows full-tunnel DNS parity** (API-verified DNS on the wintun
  adapter, empty-DNS refusal, atomic DNS↔kill-switch coupling). **S6.6 (zero-build deploy) MERGED
  (PR#13) and `v0.1.0` tagged** → multi-arch ghcr images + `install.sh`/`.sha256` release assets published.
  Only **S6.5b** (signing/notarization/auto-update) deferred — named trigger, not a gap. Remaining S6.6
  proof: the clean-VPS acceptance box-proof (`docs/S6.6-acceptance.md`), Pawan's box test.
- **EPIC 7 PULLED AHEAD DELIBERATELY** (chosen over EPIC 8/11 after EPIC 6 closed). Sequential:
  **S7.1 policy model → S7.2 enforcement → S7.3 device posture → S7.4 policy UI.** **S7.1 MERGED
  (PR#14, fe67e28)** — allow-only default-deny model + pure deterministic compiler (`policyspec.Compiled`),
  enterprise-gated CRUD, migration 0018 (incl. the group_members→memberships cascade FK from the F1 fix).
  Enforcement + the on-the-wire default-deny proof are S7.2 (ledgered: AffectedNodeIDs direct test +
  member-removal as the 4th recompile+push trigger). **S7.2 MERGED (PR#16, ac74123)** — enforcement
  box-proven 8/8. **S7.3 MERGED (PR#17, 5e9838a)** — device posture (approval gate + F1-part-3 org-wide
  push + migration reduction arc), box-proven on a live two-gateway wire incl. the 3b cross-gateway
  discriminator (see the re-entry checkpoint). **NEXT: S7.4 (policy UI + differentiated health surface +
  enterprise-e2e stack) decision-first.** See `docs/S7.1-decisions.md`, `docs/S7.3-decisions.md`.
- **LEDGER re-points (recorded at S7.1 sign-off):** triggers formerly anchored to **"EPIC 6 close"**
  (S3.7 decision-review revisit; beta re-decide) are re-pointed to the named trigger **"public-beta
  readiness"** (never calendar clocks). **EPIC 7 is the trigger to build the deferred ENTERPRISE-E2E
  STACK** → unblocks the **S4.5** secret-payload Playwright assertion (GET sso payload carries no
  client_secret material) + the **S4.5b** orphan-render check; both **ledgered into S7.x scope**.
- **DEFERRED CLIENT-WIRE-SMOKE (S7.3 device posture — SUBSTITUTES ≠ SATISFIES, named not dropped):**
  the S7.3 desktop legs are DESKTOP-ONLY and could not run on the headless box-proof VM (no Electron):
  (1) connect a **pending** device on a real mac/win desktop → stable "Awaiting admin approval…" state,
  helper NEVER armed (no admin prompt / no `utun`/WFP adapter), **no spurious "revoked"** across ≥60s;
  (2) trigger a **legacy re-mint** (strip `orgId` from a stored config) → one-time "device replaced" +
  fresh mint; (3) force a migration revoke-fail with OS notifications muted → the new **`migrate_failed`
  legible state** shows in the window/tray ("Couldn't replace device — reconnect to retry"), NOT a bare
  "Disconnected". The **66 client unit tests SUBSTITUTE** (connect-gate, ApprovalMonitor, `migrateLegacyConfig`
  revoke-first, `trayStateFor migrate_failed`) **but do NOT satisfy** the wire proof — same discipline as
  the S4.5 secret-payload + S6.3 packaged-residue deferrals. **Trigger:** the S6.5-class packaged-client
  smoke OR the next real mac/win desktop session, whichever lands first.

**History (EPIC 6 detail):** **S6.5a PACKAGING MERGED (PR#6, 7228d29)** — unsigned macOS `.pkg` (install-time helper via
postinstall, /Applications-pinned, self-uninstall watchdog) + Windows NSIS `.exe` (SCM service, sidtype
unrestricted, Add/Remove uninstall); universal helper; Gatekeeper/SmartScreen install docs; SHA256SUMS;
CI packages the win `.exe` NATIVELY (fixes the cross-built uninstaller). macOS proofs ALL PASS live
(install/connect/ping, residue, tray); Windows install/connect/device-to-device PASS live. Full review
folded (10 findings: 2 security-critical — pf-anchor double-escape defeating the kill-switch + apostrophe
root-shell-injection in the in-app install; + teardown/lifecycle). **NEW GAP LEDGERED → S6.6:** the
Windows WFP full-tunnel kill-switch is **NOT fail-closed on process death** (pcap leaked — wireguard-windows
uses `FWPM_SESSION_FLAG_DYNAMIC`, filters auto-delete on process exit). macOS pf is persistent (proven);
Windows is not. **NEXT: S6.7 (Windows kill-switch persistence)** (the merged S6.5a docs call this "S6.6" — RENAMED to
S6.7 because S6.6 is already Zero-build deploy) — non-dynamic WFP session + fixed provider
GUID + explicit enumerate-and-delete DisableFirewall + reboot/CleanStale recovery, decision-first + box-
proven + reviewed; AND **S3.7 (gateway egress NAT) APPROVED, build after S6.5a merge** (nftables-via-Go-
netlink, probe-every-reconcile, JSONB nodes.capabilities, gateway_no_egress refuse, IPv6 NAT66 best-effort,
device-to-device productized, DoD deletes poc-gateway-nat.sh + compose ip_forward). Full-tunnel usability
needs BOTH S3.7 (egress) + S6.6 (kill-switch). **Prior: EPIC 6: S6.1/S6.2/S6.0b · reconcile-idempotence hotfix
(a8c5344) · S-POC-fixes (copy-button/APP_BASE_URL/invite-rework, PR#3) · **S6.3 TUNNEL CONTROL MERGED
(PR#4, 1b36067)** — root privilege helper (typed protocol, canonicalized caller-auth, version-upgrade
handshake) + macOS **pf** & Windows **WFP** kill-switch backends + **bounded fail-closed** (startup
self-heal + 90s dead-man + graceful Down) + split-default/endpoint-exclusion routing + desktop Connect
UI + dev-install/uninstall (first-class uninstall) + native-lifecycle design. Whole-branch multi-finder
review folded (10 findings, 2 deliberate-reds). macOS kill-switch **PROVEN LIVE** (kill -9 pcap: zero
cleartext + auto-recover). DEFERRED live proofs (ledgered): Windows WFP pcap + windows endpoint paths →
**S6.5a**; packaged residue smoke → Windows **S6.5a** / macOS-SMAppService **S6.5b** (needs signing);
gateway-NAT/full-tunnel egress → **S3.7** (parked, deletes poc-gateway-nat.sh). **S6.4 CONNECTION UX MERGED
(PR#5, 011bb09)** — app-side only (helper/kill-switch untouched): revocation-aware teardown
(`RevocationMonitor` — self-scheduling poll, only-while-up, throw→keep+capped-backoff, fire-once → loud
banner/tray/notification), change-server/sign-out (`DesktopSettings` via existing verb allowlist),
split-tunnel toggle (re-mints on split↔full with full-sweep revoke; `gateway_no_egress` pre-mapped for
S3.7), tray + notifications. High-effort multi-finder folded — ROOT FIX: per-window services → **app-level
singletons, window a detachable null-safe view** (tunnel now SURVIVES window close — the point of a tray;
kills the macOS dock-reopen "second handler" crash + closed-window controller/monitor leak); + #1
`deviceExists` throws on empty-orgs 200 (a replica-lag blip no longer false-revokes a live device). Client
51 tests. **NEXT: S6.5a (UNSIGNED packaging — .dmg/.exe + Gatekeeper/SmartScreen workarounds; needs NO
certs, nothing ops-side blocks it).** First green run went 4/4 (gates + client mac + client
win + e2e) after fixing: `.env` in CI, a Windows path-fixture, `-mod=readonly`, and THE real gates
bug — `.gitignore`'s unanchored `secrets/` had silently kept apps/api/internal/secrets SOURCE out of
git (fine locally, broken on every fresh clone). Remote: github.com/iotunnex/tunnex (public); pushed
as the iotunnex account. Merged in EPIC 6: S6.1 (client shell) + S6.2 (renderer transport — desktop
tenant-functional) + S6.0b (CI). **Distribution: S6.5 SPLIT — S6.5a (unsigned packaging) ships in
EPIC 6; S6.5b (code-signing + notarization + auto-update ON) is DEFERRED, trigger = public beta OR
first outside-circle distribution (NOT a calendar clock). Windows EV needs a legal entity that does
not yet exist → entity formation is additive lead time; interim = individual Apple Developer ID.**
**Ops (Pawan): domain purchase tunnex.io PENDING — blocks real-deployment APP_BASE_URL / SSO
redirect URIs / outbound email, and the B2 domain-capture walk item.** S3.7 parked at paper. Beta
deferred — re-decide at EPIC 6 close.
Ledgered: CLI-code GC → S11, rate limits → S11.3, user-scoped credential surface → security review /
CLI-sessions panel; S3.7 gateway-NAT parked (trigger = EPIC 6 close or beta).
**External DB/Redis support (DECIDE-BEFORE-CODE, parked; see docs/S6.6-decisions.md):** install.sh
accepts `TUNNEX_DATABASE_URL`/`TUNNEX_REDIS_URL` (URL-wins; bundled compose stores move behind a
profile), bootstrap skips credential-gen + validates/migrates/fails-loud when externally set. **Decide-
item = master-key externalization** (env override vs volume) — the master key NOT being in the DB is the
durability trap an RDS customer hits (lose the volume → lose the key → DB-encrypted data undecryptable).
The env seam MUST be SHARED with the **S10.1 Helm values** (compose + K8s must not diverge). Full polish
(TLS/sslmode docs, profiles, RDS runbook) parked, **trigger = first customer request OR S10.1**.
**POC FRICTION LEDGER (WS2, triaged 2026-07-09):** item 1 → **S6.6 zero-build deploy** (SB.1/SB.2
shrink); items 2+3 → **S-POC-fixes** (started next); item 4 → **S6.4** (in-app change-server/sign-out);
item 5 (**dev-install: codesign-after-cp on Apple Silicon fixing Killed:9 + auto-detect the Electron
path for `TUNNEX_INSTALL_DIR`**) → fold into `scripts/macos-dev-install.sh` (not customer-facing);
item 6 (**join-token env-vars-must-be-inline gotcha**) → the gateway ceremony shows the COMPLETE
runnable command incl. `docker compose up -d --force-recreate node-agent`, not just the vars; item 7
(**client Node >=20 engine warning**) → pin/enforce or fix compat. ALSO surfaced + already fixed:
the `.env` `cat >>` duplicate-key trap (compose used the first value) — the S6.6 install.sh writes a
clean `.env` (no append). **Item 8 (NEW, FIXED in S-POC-fixes): invite accept was broken end-to-end —
the web had no `/accept-invite` route, so the email link dropped the token and the invited user was
sent to create-org instead of joining the inviting org.** Fixed: web AcceptInvite page + public route.
**Delivery + auth decisions (superseding an initial auto-login attempt):** CreateInvitation returns the
raw token so the dashboard shows a COPYABLE accept link (shared OneTimeSecretModal) — the SMTP-less
delivery path (POC hit "no email": dev mailer only tees to logs/Mailpit); email stays best-effort. The
accept does **NOT auto-login** — because the link is now admin-visible, minting a session from it would
let a link-holder land in an existing invitee's account (impersonation). Invitee sets a password (new
user) / keeps existing (never reset), then **signs in explicitly** and lands in the org. Item 3's
APP_BASE_URL fix still matters for the emailed link; the UI link uses the browser origin.
**REPO VISIBILITY — DECIDED: stays PRIVATE until the beta milestone.** Rationale: pre-beta there is
no external audience, and private keeps the unfinished/unsigned client + evolving security surface out
of public view; the cost is Actions runner QUEUING (private repos share a small pool + a 2000-min/mo
budget, macOS 10×/Windows 2×) — accepted for now. History is already secret-clean + Entra IDs scrubbed,
so flipping public is safe whenever the beta trigger (same as S6.5b) fires. TRIGGER to go public =
public beta.
**RESOLVED DECISIONS:** (a) **LICENSE — LANDED on `main`:** root **Apache-2.0** (Copyright 2026
Tunnex) + `NOTICE`; `apps/api/internal/enterprise/LICENSE` = proprietary **source-available**
(reference-visible, commercial agreement for production, NO redistribution); README **Licensing**
section citing the `test-editions` build-tag guard; `CONTRIBUTING.md` (external PRs paused pending
CLA/DCO). **Copyright held under the pre-entity project name "Tunnex" — on entity formation, execute
a written assignment from the individual authors to the entity and reaffirm the notices; TRIGGER =
entity formation (the SAME event S6.5b already requires for the Windows EV cert). One event now
closes BOTH the EV blocker and the copyright cleanup.** (b)
**Go module path — DECIDED: defer to the VANITY path (`tunnex.io/…`) on domain purchase**; interim
keep-as-is, now GUARDED by a `-mod=readonly` note in each go.mod + the Makefile so the flag can't be
innocently dropped pre-rename.
**SECURITY LIMITATION (S6.3, named):** the privilege helper's INTERIM caller-check on unsigned builds
is executable-path-inside-install-dir verification — WEAKER than code-signing identity pinning. Blocks
a non-admin local process from driving the root helper; does NOT stop an already-admin attacker or a
path-spoofing race. Wire protocol carries `auth_mode` so this upgrades to `code_signing` at S6.5b
without a break. TRIGGER to retire = S6.5b (signing + notarization).

**AVAILABILITY LIMITATION (S7.2, named — gateway cold-start deny-until-first-fetch):** a gateway that
starts (crash / upgrade / reboot) BEFORE its first successful desired-state fetch renders a deny-all
forward chain regardless of the org's Zero Trust mode — including for OFF / open-build orgs. This is
INHERENT to the boundary, not a bug: the gateway cannot learn its mode without reaching the control
plane, so the only safe default before it knows is fail-closed. The alternative (serve blanket mesh on
cold start) would let a reboot-during-CP-outage turn an ENFORCING org into an open mesh — a breach, not
an outage. **Exposure:** a gateway reboot that COINCIDES with a control-plane outage → an off-mode org's
forwarded traffic is denied until the CP returns. **Bounded + self-healing:** the very first successful
fetch flips the state (`policyReceived`) and restores mesh/grants; no manual step. NB this is scoped to
the NODE cold-start only — the control-plane policy-error path IS scoped by mode (finding #2: off orgs
served mesh), so a CP/DB blip does not blackhole off-mode orgs while their gateway is already running.

**NAMED LIMITATION (S7.3, migration compound-edge — [0] recorded-as-CLOSED):** the client's legacy-config
migration (a pre-`orgId` v0.1.0 profile → one-time re-mint) can, on the compound edge
`legacy × persistent-revoke-failure × OS-notifications-muted`, leave the user on a repeating soft
`migrate_failed` state ("Couldn't replace device — reconnect to retry") rather than auto-completing. This is
BOUNDED by construction (config kept, terminal-per-connect, no raw reject, no unbounded loop) and now
LEGIBLE in the window/tray (the fifth-touch emit CLOSED the silent-"Disconnected" residual [0]); a working
revoke on any later connect self-heals it. The smallest population this product will ever have (a capped
legacy upgrader whose self-revoke persistently fails with notifications off); the four-reduction ceiling was
deliberately not spent chasing it further. Wire-observation of the desktop states themselves is the ledgered
client-wire-smoke (SUBSTITUTES≠SATISFIES). Recorded per the escalation doctrine: name the edge, don't keep
touching working-enough code.

Done through (merged to `main`): **EPIC 0–2, EPIC 3 (S3.1–S3.6), EPIC 4 COMPLETE — S4.1 (shell) ·
S4.2 (auth) · S4.3 (dashboard) · S4.4 (users & roles) · S4.5 (org settings + SSO) · S4.5b (CIDR
resize) · S4.6 (audit viewer) · S4.7 (onboarding funnel) · S4.8 (Round-2 walk fixes) · EPIC 5 / S5.1
(tunnex CLI) · EPIC 6 S6.1 (client shell) + S6.2 (renderer transport — tenant-functional).**
**RE-ENTRY CHECKPOINT — S7.3 MERGED (PR#17, merge sha 5e9838a)** — device posture: an org-level
approval gate (org setting `device_approval` default-off, enterprise-gated; `device:approve` owner+admin;
self-approve DISTINCTLY audited `device.self_approved`) + **F1-part-3 org-wide push** (device Create /
Revoke / Approve / Reject ALL push org-wide, not own-node — Revoke→org-wide is the SECURITY fix for the
address-reuse privilege leak) + the migration-surface **reduction arc** (4 reductions + 1 legibility emit:
scan deletion → one-time reconnect → revoke-first → outcome-degrade → `migrate_failed` legible state).
**BOX-PROVEN ON A LIVE TWO-GATEWAY WIRE (2026-07-14):** Legs 1/2/3/4 green (pending=no-peer/no-ping/no-rule;
approve push Δ0.21s<5s; reject→IP-freed→reused; flip-ON grandfathers 0% loss) + **Leg 3b F1-part-3
cross-gateway discriminator** — revoking a device homed on G2 stripped its stale `saddr S daddr T` grant
from the NON-hosting gateway G1 in **0.236s** (own-node push would leave it → the loop would hang) + reused
IP → `default_drop`, leak closed. G2 (2nd node-agent) LEFT STANDING as a live two-gateway env for S7.4 +
the deferred client-wire-smoke + dogfooding. Client legs (connect-gate / re-mint / `migrate_failed`)
ledgered SUBSTITUTES≠SATISFIES (66 client unit tests substitute; wire proof deferred → packaged-client
smoke OR next desktop session). 5 review/confirm passes total; the collapse-arc's terminal form
(degrade-on-outcome-not-error-type) recorded as the S7.4 first-reach heuristic. EPICs 0–6 COMPLETE + EPIC 7:
S7.1 + S7.2 + S7.3 MERGED. **S7.4a (Zero Trust admin UI) MERGED (PR#18, merge sha 7402e5b)** — the Access
page (rules builder + mode toggle w/ count-confirm + FOLDED-IN device-approval queue), web-only consumption
of the S7.1–S7.3 backend; box-walked on the live two-gateway enterprise env (mode+count · post-hoc affected ·
create · approve · delete · **D-a5 edit gap-free — WIRE-PROVEN `1→2→1` on the nft ruleset** (create-before-
delete; never `1→0→1`) · notices legibility [Amendment-A unit-covered via the `sectionRender` [291] red;
live-force optional] · failure leg [E is client-side `loadOne`, unchanged by the hotfix] · member gating). Review
arc = story-end → fold-1 (loadOne legible-loads) → fold-2 (pure `accessView` gating + compose-not-compete) →
round-3 (Esc drop) → budget-escalation → **notices reduction (single-source-of-truth `staleRuleIds`)** →
clean. **HOTFIX MERGED — `fix/audit-nil-metadata` (PR#19, 28a388e):** audited DELETE 500 (audit_logs.metadata
nil→NULL 23502) fixed; surfaced by S7.4a's walk (first wire-delete of an audited entity). **S7.4b
(differentiated health surface) MERGED (PR#20, merge sha 6aa0fad)** — Option X built: `policy_degraded_kind`
advisory over the authoritative `policy_degraded` bool, from ONE compute (`PolicyHealthForNodes`); the
CP-owned `policy_desync_since` (0021) stamped at report-ingest (single-writer `trackDesync`, CP clock) +
`policy_reported_at` (0022) as the REPORT-freshness clock; `desync_unknown` a first-class honest state;
T=F=2R=60s. Box-walked on the two-gateway wire (boot-log · converging no-false-alarm · desync_unknown via
`docker stop g2`+forced-mismatch · matched-silent→healthy · bool/kind flip together = the collapse live).
Review arc: story-end (9, incl. the kind-less-alarmed-than-bool class) → fold (collapse + real freshness clock
+ log-not-swallow) → confirm (4, all hygiene/accept) → clean. **S7.4c (enterprise-e2e enabler, UN-DEFERRABLE)
MERGED (PR#21, sha 8ad71cd) → EPIC 7 COMPLETE.** Delivered: `cmd/seed-enterprise` + `make seed-enterprise`
(sealed SSO config + gateway node row + device holding a pool IP, composed ON TOP of `seed`), the BLOCKING
`TestGetSsoConfigPayloadCarriesNoSecret` (real audited `Set` write + payload-secret-free + AUDIT-metadata-
secret-free asserts, cleanup via `session_replication_role=replica` bypass), `settings.enterprise.spec.ts`
(real S4.5 payload + live-shrink S4.5b 409, edition self-detected via `/meta`), the `e2e-enterprise` CI job.
D-c4 VERIFIED (orphan check is a pure DB read → no CI agent). Review arc: high-effort story-end (18/18, 0 err,
8 findings) → 7 folded + [3] accept-by-design → [audit-cascade] REWORKED as a decide-item (pick (a): restore
the audited write, trigger-bypass cleanup) → CI all-green on a91e5cd incl. `e2e-enterprise` IN CI → box-walk
stands. **S4.5 + S4.5b ledgers flipped SUBSTITUTE→SATISFIED (PR#21, sha 8ad71cd).** **EPIC-7-CLOSE PLANNING
SESSION HELD (2026-07-14) — build order LOCKED: 7.5 → M → BETA BUNDLE → PUBLIC BETA (joint w/ site) → 8 → 9 →
10 → 11 → 12-remainder.** ~~Beta = full scope (7.5 + M + bundle).~~ **AMENDED 2026-07-15: EPIC M parked (founder
trigger); beta gates on 7.5+8+9+10+11+bundle; mobile-at-beta via official WG apps. New order: 7.5 → 8 → 9 →
10 → 11 → bundle → beta → M-parked (see Build Order — LOCKED).** S12.1/S12.2 pulled into the bundle; EPIC 12
trigger = first paying-customer intent. Batches 1–3 dispositioned (see the ledger + `docs/` decisions).
**S7.5.1 (flow/access logs) MERGED — the VISIBILITY half of Zero Trust, PG-only.** Ships: kernel nflog →
kernel-stamped `rule_id` on the wire → allow/deny/deny_aggregate/gap/terminated access events (box-proven
LIVE on the two-gateway box) + PG hot-window (retention sweep + `retention_failed`) + org-scoped keyset
query API + deny-aggregation. Box-walk caught+fixed 3 real gateway/ingest bugs (deny-tail nft syntax,
JSONL-durability class, flowlog volume/ownership); the review arc caught+fixed the concurrent-ingest class
(RED-proven). **S7.5.1b REGISTERED-DEFERRED (EPIC 7.5, after S7.5.5 or first SIEM/compliance prospect):** the
on-disk JSONL source-of-truth + byte-verbatim SIEM export + tamper-evidence (D4) + beyond-hot-window retention
— the writer took six review rounds without converging and was DEFERRED rather than shipped with defects
(the D4 obligation moved to S7.5.1b; the `seq` column + box-walk JSONL/export evidence carry over as its spec).
**Metrics L2 (added at S8.3 walk close, founder-directed — no new scope):** site-to-site FLOWS are a first-class consumer of the flow-log viewer — the per-rule counters already capture site grants; this story surfaces them.
**NEXT: S7.5.2 (IdP sync + SCIM) commit-one — its own fresh sitting.** If this pointer disagrees with the git
log, TRUST GIT (`git log --oneline -20`) and update it.

## Armed Guards (living inventory — "what protects us")
Each has been demonstrated to *fail* on a real violation during its story's DoD.
Seed for the eventual SECURITY.md.
- **Query-lint / org_id** (`db/querylint_test.go`) — tenant-owned-by-default (tables derived from migrations, `globalTables` allowlist); every tenant table query must scope by `org_id`.
- **Query-lint / deleted_at** — soft-delete tables must filter `deleted_at IS NULL`.
- **Trigger schema check** (`db/schema_test.go`) — every `updated_at` table has the `set_updated_at` trigger.
- **audit_logs append-only** — DB triggers reject UPDATE/DELETE/TRUNCATE; actor FK to `users` enforces attribution.
- **audit metadata never-NULL** (hotfix `fix/audit-nil-metadata`; `TestAuditedDeletesPersistMetadata`, red-on-main) — `audit_logs.metadata` is `NOT NULL`; the policy `writeAudit` helper must default a nil meta to `[]byte("{}")`, never a nil `[]byte` (pgx sends nil as SQL NULL → 23502). Demonstrated-red: it used `var raw []byte`, so EVERY audited DELETE (`group.deleted`/`resource.deleted`/`policy.rule_deleted`) 500'd + rolled back — undeletable rules/groups/resources — surfaced only when S7.4a's UI first deleted an audited entity on the wire. **BOX-PROOF CONVENTION (new):** every audited MUTATION CLASS (not just create) gets one wire execution in its story's box proof — a create-only proof let this live across S7.1/S7.2/S7.3. **UNIT-TEST GAP:** the policy integration suite tested create/mode/push but never an audited delete; the red test closes it. **LEDGER (S11-class, swallowed-500 logging gap):** the handler wrapper maps a raw error → `500 internal_error` WITHOUT logging the wrapped cause — the http_request line showed only `status:500`, so the DB error (23502) was invisible until reproduced via the DB directly. The `internal_error` path MUST log the wrapped cause WITH the `request_id` (diagnosis-from-logs, not from a repro). → S11 (production hardening / observability). **REVIEW-PASS WAIVER (recorded, NON-PRECEDENT):** merged `fix/audit-nil-metadata` (PR#19) on CI-green without a multi-finder review pass — scoped to THIS hotfix only (1-line change, red-proven on the real schema, wire-confirmed 23502, sweep-complete). Not a precedent for feature work.
- **audit-append-only blocks org hard-delete (S7.4c armed guard).** A pool-based test that creates an org + an AUDITED write (e.g. `ConfigService.Set`) can NOT clean up by deleting the org: the `audit_logs` org FK is `SET NULL`, which the append-only trigger REFUSES, so the org-delete errors and the org LEAKS into the shared compose DB. Fix pattern (used by `TestGetSsoConfigPayloadCarriesNoSecret`): clean up under a test-only `session_replication_role = replica` trigger bypass on its OWN acquired conn, deleting children (`audit_logs`, `sso_configs`) + org + actor explicitly, then restore. Do NOT drop the audited write to dodge this (that removes secret-in-audit-metadata coverage). **LEDGER (S11-class / next test story): shared-DB test-leakage audit.** S7.4c surfaced `real_orgs=29` after one `test-editions` run — [0]'s dead-cleanup class exists in OTHER pool-based tests (bearer/session/etc. commit orgs to the shared DB), inflating `countRealOrgs` and tripping the seed guard on a persistent volume. Sweep pool-based tests for full cleanup (or a dedicated test-slug prefix `countRealOrgs` excludes). → S11 or rides the next test-focused story.
- **Codegen drift guard** (`make generate-check`) — spec/generated code can't diverge.
- **Edition build+test** (`make build-editions` / `test-editions`) — open and enterprise builds both compiled & tested; neither rots.
- **e2e correlation** (Playwright) — SPA→API `X-Request-Id` chain asserted end-to-end.
- **RBAC matrix** (`rbac_test.go`) — executable privilege-escalation spec.
- **Restart-persistence + fail-loud secrets** (S0.3) — master key never silently regenerates.
- **Reconcile idempotence** (`reconcile_test.go` `TestReconcileIgnoresRoamedEndpoint` + `wg_dataplane_e2e.sh`
  stability sample across ≥2 intervals) — the node-agent dirty-check keys on stable identity (pubkey +
  allowed-ips), NOT the roaming endpoint, so steady-state reconcile is a byte-stable no-op; and
  `wg syncconf` echoes the key + port so it can never wipe the interface. Demonstrated-red: the POC
  itself (wg0 key→`(none)`, port randomized every cycle) was the failing case. Gated in CI via
  `make test-node`.
- **Edition build-constraint isolation** (S7.1; `go list -deps ./apps/api/cmd/server | grep -c
  enterprise/policy` == 0, asserted in CI) — the open build's server binary must NEVER link the
  `//go:build enterprise`-tagged policy engine. Demonstrated-red: the enterprise policy package linking
  into the open `cmd/server` (neutral DTOs live in `internal/policyspec`; the boundary is the guard).
- **Policy schema cascade FK** (S7.1) — deleting a group / resource / membership cleans its dependent
  policy rules + group memberships via `ON DELETE CASCADE`, so no rule can reference a vanished subject
  or destination (no dangling grant). Demonstrated-red in the S7.1 policy-model tests.
- **Canonical-hash twin goldens** (S7.2; `policyspec` hash_test.go ≡ `nodepolicy` nodepolicy_test.go,
  identical fixtures + expected hex in BOTH modules — the cross-module drift guard) — the compiled-policy
  hash the control plane computes must byte-match what the agent computes. Demonstrated-red: the first
  impl hashed the RULESET TEXT (node-local masquerade subnet the control plane can't reproduce) →
  permanent false staleness.
- **Multi-node push-target** (S7.2; `TestDeactivatePushesOrgWideNotJustUserNodes`) — a member
  deactivation must push EVERY active org gateway, not just the ex-member's own device-nodes.
  Demonstrated-red (F1-part-2): the /32-sweep was proven at the model layer but the push TARGETING was
  not — on a multi-gateway org a node hosting another user's device that referenced the ex-member as a
  policy destination wouldn't be pushed <5s.
- **Fail-closed cold-start** (S7.2; `TestNeverReceivedIsDenyAllNotMesh`) — a gateway that has never
  received a policy renders DENY-ALL regardless of mode, never the blanket mesh. Demonstrated-red: a
  restart re-armed the blanket mesh under enforcing (fail-OPEN) until the first fetch.
- **Refuse unknown / half-spec, never widen** (S7.2; `TestRenderAllowHalfSetPortRangeFailsClosed` +
  `TestRenderAllowUnknownProtocolFailsClosed` + `TestValidateResourcePortsBothOrNeither`) — the
  compiler/renderer skip a malformed AllowEntry (→ default-deny), never widen on it; validation rejects
  it at the API. Demonstrated-red TWICE: a half-set port range widened to all-ports; an unknown protocol
  widened to all-protocols. (Checklist line for every new AllowEntry field.)
- **ProtocolVersion equality** (S7.2; `TestProtocolVersionConstantsAgree`) — `nodes.ProtocolVersion` ==
  `policyspec.ProtocolVersion`, so a fail-closed fallback artifact's canonical hash can't fork from the
  compiler's. Demonstrated-red: the two independent constants (both 1) diverging would false-alarm every
  enforcing gateway on the fallback path.
- **policy_degraded gap-state red** (S7.2; `TestPolicyDegraded` stuck-enforcing case) — a gateway that
  failed to apply an off/mesh ruleset and is still enforcing a DISABLED policy (applyErr set,
  failingSince empty, synced-would-be-true) MUST read `policy_degraded=true`. Demonstrated-red: this
  exact green-while-blackholing state survived review passes 2, 3 AND 4 across the 3→2-field staleness
  surface before the collapse to one conservative field closed it.
- **Device active+pending accounting convention** (S7.3; `CountDevicesForUserCap` + its pin test) — a
  `pending` device is EXCLUDED from enforcement (peer + compiler filters key on `status='active'`) but
  INCLUDED in resource accounting: the per-user cap, the IP pool, and node-sweeps all count active+pending.
  Demonstrated-red: cap counting active-only let a user enroll past the cap by stacking pendings (a free
  DoS on the address pool); the fix counts both. The taxonomy: **exclude from what grants access, include
  in what consumes resources.**
- **Partial-unique-index ⊇ allocator domain** (S7.3; migration 0020 widened `devices_org_ip_key` to
  `status IN ('active','pending')`) — the partial unique index on `(org_id, assigned_ip)` must cover EVERY
  status the allocator can hand a live IP to. Hazard: an index narrower than the allocator's domain (index
  on `active` only, allocator also assigns to `pending`) lets two pending devices collide on one IP with no
  DB guard. Checklist line for any new status that can hold an `assigned_ip`.
- **F1-part-3 org-wide push on every membership-changing lifecycle event** (S7.3; device
  Create/Revoke/Approve/Reject → `PushOrgNodes`, wire-proven Leg 3b) — any device event that changes
  compiled policy membership pushes EVERY active org gateway, not the device's own node. Demonstrated-red
  ON THE WIRE: revoking a device homed on G2 left its stale `saddr S daddr T` grant on the non-hosting
  gateway G1 under own-node push; org-wide push strips it (0.236s box-measured). Revoke→org-wide is the
  SECURITY fix (address-reuse privilege leak: a reused IP would inherit the revoked device's grants).
  Generalizes the S7.2 multi-node push-target guard to the device-lifecycle surface.
- **Two-layer pending exclusion** (S7.3) — a `pending` device must be dropped from BOTH the peer set
  (`ListActivePeersForNode` → no wg peer/tunnel) AND the compiler input (no grants) by the same
  `status='active'` filter. Box-proven Leg 1: pending = no wg peer + no ping + no allow rule. Single-layer
  exclusion (peer-only) would arm a tunnel with no policy (or vice versa).
- **openapi-fetch no-throw legibility — `loadOne` (S7.4a; `apps/web/src/lib/api.ts`, class-guard tests
  in `policyview.test.ts`)** — openapi-fetch is a STANDING FOOTGUN: it returns `{data:undefined, error}`
  on a non-2xx (does NOT throw) and REJECTS on a network failure, so a component that reads only `data`
  renders a REASSURING EMPTY state for a real failure (a failed rules load → "No rules"; a failed members
  load → a false "not an admin" lockout). **SANCTIONED CALL PATTERN:** a raw `api.GET` in a component whose
  emptiness is user-meaningful (a list, a role, a count gating a destructive action) is **review-refused** —
  route it through `loadOne`, which collapses both failure paths into a discriminated `Loaded<T>` so the
  caller renders a legible "failed — retry", never absence. Demonstrated-red: the S7.4a story-end review's
  dominant cluster — 6 sections each swallowing their fetch error into a reassuring default (the exact
  failure-must-be-legible invariant, applied to referents but not the loads themselves). **Carry into S7.4b
  (the health-badge fetch) and every later web surface.**
- **Terminal-migration outcome-degradation** (S7.3; client `migrateLegacyConfig` revoke-first + the
  ipc bare-catch degrade + `migrate_failed` synth state; reds in `deviceconfig.test.ts` + `uxwiring.test.ts`)
  — a legacy-config migration has EXACTLY TWO bounded outcomes, degraded on OUTCOME not error type: completed
  → `migrated`; failed-for-any-reason → config KEPT + the legible `migrate_failed` down-state. Structurally
  NO path from a failed migration to a raw renderer reject or an unbounded loop. Demonstrated-red across the
  reduction arc: revoke-first fixed a cap-lockout; the bare-catch removed the raw-reject; the `migrate_failed`
  emit removed the silent-"Disconnected" on notif-muted machines. The doctrine (collapse N error paths to one
  outcome-degraded down-state) is the S7.4 first-reach heuristic.
- **main branch protection is itself a guard that can silently vanish** (S7.5.3; found ABSENT — `gh api
  .../branches/main/protection` returned **404**, not permissive — at PR#24 merge, cause unknown). The
  mechanized safety layer documented at S6.0b (required checks + linear history + no force-push) had
  silently dropped at some earlier point; nothing was watching it, and green CI + convention-held sign-offs
  MASKED the gap — the reassuring-green class applied to the PROCESS itself: everything looked fine while a
  load-bearing guard was gone, so for an unknown window every merge relied entirely on human discipline with
  no backstop (it held — luck + habit, not a guarantee). Restored 2026-07-16 belt-and-braces: repo
  `allow_merge_commit=false` (squash+rebase only, so `--merge` can't produce a merge commit regardless of
  flag) + branch protection `required_linear_history=true` + required checks strict (`gates` + `client
  (macos-latest)` + `client (windows-latest)`) + `allow_force_pushes=false` + `enforce_admins=false`. Either
  layer alone blocks the deviation; both make it structurally impossible. **STANDING CHECK (pre-merge
  assertion):** verify protection is PRESENT (`gh api repos/iotunnex/tunnex/branches/main/protection` ≠ 404,
  `required_linear_history.enabled=true`) at each story merge — a one-line check so an absent guard can never
  again hide behind green CI. The guard that protects the merges must itself be verified, not assumed.

## Edition Model — Open-core (resolved)

> **⚠️ SUPERSEDED (pending EPIC 12 / S12.1 decision review):** the build-tag edition split
> below is **superseded IF the commercial-upgrade flow (EPIC 12) is built.** Requirement: an
> open-build customer pastes a license key into the RUNNING deployment and enterprise features
> unlock — **no rebuild, no redeploy.** That is impossible with the build-tag split (enterprise
> code isn't compiled into the open binary), so **EPIC 12/S12.1 refactors to a single binary,
> runtime license-gated** (GitLab-EE model). **CONSEQUENCE, accepted knowingly:** enterprise
> source then ships inside the open binary — readable, and the license check is patchable (it's
> open source). Piracy isn't prevented; honest commercial compliance is made easy, backed by
> license law. This **invalidates the test-editions "enterprise-not-in-open-binary" property** —
> S12.1 replaces that guard with a runtime-gating guard. **PARKED:** not built until after the
> public beta; decide-before-code review required at S12.1. Until then the build-tag model below
> stands as-is.

- **Schema is multi-tenant in core.** Everything carries `org_id`; the open edition simply **does not expose creating a second org** — an API/UI limit, not a schema fork. No migration or code move later.
- **Enterprise features** (gated behind an `internal/enterprise/**` package + build tag): SSO (Google/Microsoft), Zero Trust policies, Kubernetes operator, and the multi-org limit-lift.
- **The enterprise boundary is established in S1.1**, because the first gated decision (org-creation limit) lives there — not at SSO. SSO/policies/operator plug into the same boundary as they arrive.

---

## EPIC 0 — Foundation & Scaffolding

- **S0.1 Monorepo scaffold** — layout, `pnpm` workspace, `go.mod`, Make/Turbo targets, linting, README. **DoD: structured logging (slog) + request-ID middleware + `/healthz` that logs with correlation IDs.**
- **S0.2 Docker Compose one-command boot** — postgres + redis + api + web + nginx + node-agent + Mailpit; `.env.example`; **healthchecks on every service**; `make up`/`make down`. **Non-web bits:** node-agent needs `cap_add: NET_ADMIN` and the **WG UDP port published**. **Non-root:** api (uid 10001) + web/nginx (nginx-unprivileged, uid 101) run non-root; only node-agent stays privileged for WireGuard.
- **S0.3 First-boot bootstrap, secrets & mailer** — entrypoint auto-generates JWT/session secrets, DB creds, WG server keys, and a **master encryption key** if absent; persists to a volume; idempotent. Sensitive per-org data (IdP secrets) stored **DB-encrypted (AES-GCM) under the master key**. **Pluggable mailer:** SMTP env vars for prod; **dev fallback = Mailpit** (compose) + log the link. **DoD: restart-persistence test** — `up → down (no -v) → up` reuses volumes, secrets are stable across restarts, and all services return healthy (foundation already proven for volumes in S0.2; extend to secrets here).
- **S0.4 DB migrations & tooling** — `golang-migrate`, `sqlc`, `make migrate`.
- **S0.5 OpenAPI contract + codegen** — author the OpenAPI spec; generate the TS client into `packages/shared`; wire request/response validation on the Go side. Source of truth for all later endpoints. **Cleanup:** the S0.1 placeholder `/api/v1/ping` and the hand-written `HealthResponse` in `packages/shared/src/index.ts` must be folded into the spec (as `/healthz`) or removed — no hand-maintained types survive S0.5 (avoid spec drift).
- **S0.6 Seed data + e2e test harness** — `make seed` (demo org/user); Playwright (web) + `httptest` (API) skeletons so every later story's "verify end-to-end" has rails. **DoD: seed + e2e run green on the open build using local auth only** (no enterprise/SSO dependency), so the open edition is fully testable end-to-end. **Schema guard:** add a CI check that every table with an `updated_at` column has the `set_updated_at` trigger bound (one query joining `information_schema.columns` + `pg_trigger`) — enforces the convention that policy alone can't.

## EPIC 1 — Multi-Tenancy Core

- **S1.1 Data model + enterprise boundary** — `organizations`, `users`, `memberships`, `invitations`, `audit_logs`; org-id row scoping. **Establish `internal/enterprise/**` + build tag here; open build enforces the single-org-creation limit.**
- **S1.2 Org lifecycle** — create org, settings, slug/domain, soft-delete.
- **S1.3 Tenant context middleware** — resolve current org from session membership; enforce isolation on every query.
- **S1.4 RBAC** — roles (owner, admin, member) + permission-check middleware.

## EPIC 2 — Authentication (Google + Microsoft + Local)

- **S2.1 Local auth** — signup/login, argon2id, **email verification + password reset (uses S0.3 mailer)**. DONE. **Decisions:** unverified users MAY log in; email-verification gates org-*mutating* actions (enforce once the principal carries verified state, S2.2). No account enumeration (generic signup/reset responses; generic login error + dummy-verify timing). Tokens hashed/purpose-bound/single-use/expiring.
- **S2.2 Session management** — Redis-backed cookie sessions, CSRF, logout, refresh. **Carries the S1.3 + S2.1 handoffs:** supply the real session-backed `AuthFunc` (resolves session → `authctx.Principal` with memberships + verified state); spec-driven test asserting every mutation endpoint returns 401 without a session (walks the OpenAPI paths); populate `audit_logs.actor_user_id` for authenticated mutations (NULL = system only); gate the org collection/create endpoints; **wire login to establish a session cookie**; **password reset must revoke all of the user's existing sessions**; enforce verified-gating on org-mutating actions.
- **S2.3 Google OIDC** *(enterprise)* — login + account linking; per-org SSO config (secret encrypted at rest).
- **S2.4 Microsoft Entra OIDC** *(enterprise)* — login + account linking; multi-tenant Azure app; secret encrypted.
- **S2.5 SSO provisioning & domain capture** *(enterprise, security-sensitive — extra review)* — JIT user creation + role mapping. Require **DNS-TXT-verified domain ownership**; **block public domains** (gmail.com, etc.); **domain capture is globally unique** (two orgs cannot capture the same domain); never auto-join on unverified email.
- **S2.6 Manual user management** — admin invites/creates users, resend/revoke invites, deactivate.

## EPIC 3 — WireGuard Core Loop (proves the product — before full dashboard)

- **S3.1 Node agent + control-plane protocol** — define `tunnex-node`: registration, mTLS/gRPC between API and agent, desired-state push + **reconcile loop** (agent compares desired vs. actual `wgctrl` state on an interval; heals drift). **Agent enrollment:** a one-time **join token** (generated in dashboard / compose bootstrap) is exchanged for the agent's mTLS client cert on first connect. **Revocation latency spec:** control plane **pushes** revocations (agent applies in **<5s**); interval reconcile is the safety net, not the primary path.
- **S3.2 WG server lifecycle** — interface up/down via agent, key mgmt, listen port, address pool (CIDR) per org. **DELIVERED** (node-generates key, real wgctrl adapter dirty-checked, reconciled interface, `wg show` e2e). **Deferred limitation (no owning story — noted here):** node re-key currently requires an agent restart (the WG key file is read once at boot); a running agent won't pick up a deleted/rotated key file. Acceptable for now (re-key is an operator action); revisit as a hardening item (live key-file watch / re-report without restart) if/when key rotation becomes routine.
- **S3.3 Peer/device management** — issue peer config, QR/download, per-user device list, revoke. **Acceptance (identity binding):** a peer config cannot be created/activated except via the owning user's authenticated session; admin-created peers are bound to a named user; revocation immediate per S3.1 latency spec. **Also owns:** peer traffic routing (`ip route` for peer AllowedIPs — S3.2 configures the interface but installs no peer routes; a /32 interface addr has no subnet route, so tunneled traffic won't flow until this lands).
- **S3.4 Client config generation + bare UI page** — `.conf` output (DNS, allowed IPs, keepalive) + minimal download page. **← "Tunnex is real" milestone.**
- **S3.5 IP allocation service** — deterministic, collision-free assignment from org pool. **Acceptance (edge cases):** address **release/reuse** on revocation; safe on **org CIDR resize**; no reassignment of an in-flight address.
- **S3.6 Live connection status** — handshake/last-seen, bytes tx/rx, online peers (data from agent).
- **S3.7 Gateway NAT + forwarding (full-tunnel egress)** — make `--full-tunnel` (`AllowedIPs=0.0.0.0/0`)
  actually reach the internet: the agent enables IP forwarding + source-NAT on the gateway so client
  traffic egresses via the gateway host. Today the config connects but egress dies at the gateway
  (split-tunnel only).
  **DoD — REMOVE THE CRUTCH: S3.7 replaces and DELETES `scripts/poc-gateway-nat.sh`** (the throwaway
  POC NAT) and folds the `sysctls: net.ipv4.ip_forward=1` POC line in `docker-compose.yml` into the
  agent's own probed setup. The hand-hacked POC egress must not outlive the real feature.
  **PARKED at paper (2026-07-08).** The paper decision below stands, unreviewed-for-build; EPIC 6 was
  chosen over pulling this forward. **Ledger trigger: EPIC 6 close OR the beta milestone, whichever
  comes first** — resume with a decision review, then build. Beta was DEFERRED, not rejected.

### S3.7 paper decision (PARKED — decided on paper; review + build deferred to the trigger above)

Grounded in code: the agent drives WG via `wgctrl` (netlink), holds `NET_ADMIN` + `/dev/net/tun`,
and reports endpoint/wg-key to the control plane (`reportKeyLoop`). Device configs already emit
`0.0.0.0/0` for full-tunnel (`devices/config.go`); nothing sets up forwarding/NAT anywhere in
`apps/node/` — that is the whole gap.

**(1) Privilege posture — NET_ADMIN is enough; the real dependency is the HOST kernel, so DETECT it.**
No `privileged: true`. The agent already has `CAP_NET_ADMIN` in its own netns; `net.ipv4.ip_forward`
is a per-netns sysctl writable with NET_ADMIN, and a source-NAT rule on the container's egress
interface needs NET_ADMIN + the host's `nf_nat`/`nf_conntrack` (and masquerade support) loaded in the
kernel — a capability caps can't grant. So S3.7 does NOT add privileges; it PROBES at boot whether
egress NAT is achievable (ip_forward writable AND a masquerade rule can be added AND conntrack is
present) and degrades gracefully when it isn't (locked-down host).

**(2) iptables vs nftables — nftables, native.** The agent already speaks netlink for WG; it manages
the NAT ruleset the same way (nftables netlink API, or the `nft` binary as a fallback) in its OWN
named table/chain (e.g. `tunnex` table, a `postrouting` masquerade chain scoped to the pool CIDR →
egress iface). Rationale: iptables-legacy is deprecated, iptables-nft is a shim over exactly this,
and a dedicated nft table is atomically replaceable and won't collide with host rules. NO shelling to
`wg-quick` PostUp (the agent owns the interface, not wg-quick). Masquerade is scoped to the org pool
source CIDR — never a blanket rule.

**(3) Per-gateway capability flag + `--full-tunnel` REFUSE (not warn).** The agent reports an
`egress_nat` capability bit (from the probe) up the existing report channel; stored on the `nodes`
row. Creating a device with `full_tunnel=true` against a gateway whose `egress_nat` is false is
REFUSED server-side (typed `gateway_no_egress`) — a full-tunnel config that silently blackholes all
internet is worse than a clear refusal; the UI mirrors it (disable/explain the full-tunnel toggle
for incapable gateways). Split-tunnel is always allowed.

**(4) Desired-state + full-sweep (reuse the cross-cutting principles).** NAT rules are data-plane
state → RECONCILED on the S3.1 interval (the agent re-asserts ip_forward + the masquerade ruleset,
heals a flushed table), never assumed. And revocation is a full sweep: when the gateway is revoked
(or its last full-tunnel peer is gone) the NAT table is torn down — no dangling masquerade.

**(5) Egress e2e (the proof obligation).** A compose "internet" target reachable by the gateway but
NOT directly by the client; a client container with a full-tunnel `.conf` reaches it ONLY through the
tunnel (real WG + real NAT, like the S4.5b race harness is real). Deliberate-red: flush the
masquerade rule → egress fails (proves the rule carries it, not a leak). Negative: a device create
with `full_tunnel=true` against a no-capability gateway → `gateway_no_egress`.

Open sub-questions to settle IN the decision review (not assumed): whether `egress_nat` is a boolean
column or a capabilities JSONB on `nodes` (forward-compat for future gateway caps); whether the probe
runs once at enroll or every reconcile (host state can change); and the exact typed error + whether
the open edition gates full-tunnel at all (it is core/edition-neutral like the allocator — lean
neutral, confirm).

## EPIC 4 — Full Web Dashboard

- **S4.1 App shell & design system** — Tunnex brand (logo assets from user), Tailwind theme, layout, nav, auth-gated routing.
- **S4.2 Login / signup / SSO screens** — all three auth paths.
- **S4.3 Dashboard home** — org overview, members, activity, live connection stats. **Delivered:** single `GET /api/v1/organizations/{orgId}/overview` (counts + audit-log activity slice, LIMIT 10; `/organizations` matches every existing route — `/orgs` was only shorthand). Online tile inherits S3.6 honesty ("Seen in last N min", active-owner filter); `tenancy.OnlineWindow` is the single source of truth for the window; future-handshake upper bound is a data invariant at ingestion, not a per-read predicate.
- **S4.4 Users & roles UI** — list, invite, edit role, deactivate.
- **S4.5 Org settings & SSO config UI** — connect Google/Microsoft, domain-capture rules. **Delivered (org settings + SSO config only; CIDR resize split to its own story):** SSO secret is WRITE-ONLY (GET returns a keyed HMAC fingerprint, never the secret — no `client_secret` field in the response type); config writes are audited (`sso.config_updated`, actor-attributed, secret-free metadata); open builds refuse SSO-config endpoints with 403 `edition_required` (the established precedent, not 404); the client RBAC mirror is now GENERATED from the Go grant table (drift = red build). **Deferred tests — SATISFIED (S7.4c, PR#21, sha 8ad71cd):** the payload-level "GET has no secret" assertion now runs BOTH as a BLOCKING enterprise Go httptest (`TestGetSsoConfigPayloadCarriesNoSecret` in `make test-editions` — a security assert must gate, not sit behind continue-on-error) AND as an opportunistic enterprise Playwright leg (`settings.enterprise.spec.ts`, E2E_EDITION=enterprise, seeded SSO config → real 200 payload: fingerprint present, no `client_secret`). The old open-edition 403-gate check (settings.spec.ts:25) is retained + demoted-with-pointer as the OPEN substitute.
- **S4.5b CIDR resize** (split from S4.5) — resize the org WG pool. **Delivered:** `PUT /organizations/{orgId}/pool-cidr` (edition-neutral — allocator is core/open); grow-superset / shrink-subset only (else `illegal_resize`), identical CIDR = idempotent 200, `< /30` = `cidr_too_small`; canonical (masked) CIDR stored/audited. Shrink that would strand allocations → structured 409 `{orphan_count, orphans[≤20]{device_id,name,assigned_ip,reason}}`, reason = `out_of_range | reserved_collision` (ipalloc.Orphans, reserved-collision-aware, single-read so check == 409 objects). Check runs UNCONDITIONALLY (check-anyway) — provably empty on a valid grow, a backstop if a non-Allocate writer breaks the invariant. Atomic + audited (`org.cidr_resized`, no row on no-op) under the shared per-org `LockDeviceKey`; `TestResizeAllocationRace` proves the lock excludes a concurrent allocation (red-without-lock demonstrated). **Deferred test — SATISFIED (S7.4c, PR#21, sha 8ad71cd):** the 409 orphan-list UI render now runs UN-MOCKED against a live shrink in `settings.enterprise.spec.ts` — `seed-enterprise` seeds a device holding `10.99.0.200`, a shrink to `/25` strands it, and the REAL 409 body renders (device name + `out_of_range`). Verified D-c4: the orphan check is a pure DB read (`ListActiveDeviceAllocations`), so a plain seeded node ROW satisfies the device's `node_id` FK — NO enrolled agent needed. The MOCKED render (settings.spec.ts) is retained + demoted-with-pointer as the OPEN substitute.
- **S4.6 Audit log viewer** — filterable event stream.
- **S4.7 Fresh-user onboarding** — close the empty-funnel gap: a freshly-verified local user with
  zero orgs currently lands on a dead-end dashboard (no create-org / no gateway-enroll affordance).
  Ship the post-verify router + explicit create-org step + gateway-enroll empty state.

### S4.7 onboarding state machine (COMMIT ONE — decided on paper, before code)
Grounded in code: `auth.Signup` makes user + verify token, **no org / no membership**;
`CreateOrganization` (`handlers.go`) is `requireVerifiedUser`-gated; open-build org cap is
`enterprise.Unlimited{MaxOrganizations:1}` → `org_limit_reached` 403 (`tenancy/service.go`); SSO JIT
`ensureMembership` adds a member-role membership + `member.jit_joined` audit and **never** touches
create-org.

Post-verify, a router branches on the caller's **membership count** (not auth-path):

1. **≥1 membership** → straight to dashboard (skip the funnel entirely).
2. **0 memberships, org-create allowed** → **explicit "Create your organization" step**
   (user names the org; slug auto-derived) → on success, owner membership + dashboard.
3. **0 memberships, cap reached** (open build, second tenant) → **invitation-only dead-end card**,
   NO create control. Server is the truth (`org_limit_reached` 403); the UI only mirrors it.
   **Reached REACTIVELY, not pre-empted** — see the amendment below.

Path carve-outs (must NOT hit the create-org step — they already produce membership):
- **Invite accept** → membership added → dashboard.
- **SSO JIT login** → `ensureMembership` → dashboard.

Decisions locked (the three decide-before-code items):
- **(1) Signup→org shape = EXPLICIT create-org step** (not silent auto-create). One funnel; the
  JIT + invite paths bypass it because they already yield membership; auto-create would fork
  behavior by auth-path and inject a phantom "My Organization". User names their own org.
- **(2) Open-edition second-signup = invitation-only.** The single-org cap is already
  server-enforced; the UI mirrors with the dead-end card, never invents permission. A legal second
  local signup with no org lands on the same card.
- **(3) Verified-email gate = structural, upstream of create-org.** `requireVerifiedUser` already
  refuses unverified create-org; the funnel routes signup→verify BEFORE the create-org step, so the
  refusal is by construction, not a surprise 403. TRACE it in a test (unverified → refusal shown).

**AMENDMENT (build) — cap-reached is REACTIVE-403, not pre-empted.** The paper spec put a
verified/0-membership/cap-reached user straight onto the dead-end card (never seeing a create form).
Amended to: show the create step, and on the server's `org_limit_reached` swap to the invitation
card (create form + all create controls removed). **Rationale:** the cap is GLOBAL and deployment-wide
(`tenancy.CreateOrganization` → `CountOrganizations()` ≥ `MaxOrganizations`, i.e. one live org total).
A verified 0-membership user cannot know the single slot is taken without asking the server, and the
only way to pre-empt client-side would be to reveal that *some org they are not a member of exists* —
a tenant-isolation leak. So the server is the sole authority and the UI reacts to its 403. The end
state still satisfies the spec's intent: the user lands on the invitation card with **no usable
create affordance**. **On the 403 the UI re-checks membership first** (`GET /organizations`): if the
user gained a membership between routing and refusal (invite accepted elsewhere, JIT-join, admin add)
they go to the dashboard; only a still-0-membership user sees the card. Proven end-to-end against the
REAL open build (seed `DemoNoOrgUser`, no mock) in `onboarding.spec.ts`.

Edge-case decisions (one line each, for the record):
- **Soft-deleted-org membership counting:** the funnel counts memberships via the `GET /organizations`
  handler → **`ListOrganizationsForUser`** (`organizations.sql`), which filters `o.deleted_at IS NULL`
  (query-lint deleted_at guard enforces it) — so a user whose only org was soft-deleted counts as 0
  and is routed to create-org, never trapped pointing at a dead org.
- **Deactivated-user routing:** a deactivated user is blocked at login (`account_deactivated` 403,
  `auth/service.go`) → no session → never reaches the funnel; no funnel special-case needed.
- **Invite-accept vs email-verification ordering:** `invites.Accept` **marks the email verified THEN
  upserts the membership in one tx** (token proves inbox control) — so an invitee lands in the shell
  already verified and with ≥1 membership (has-org branch); they never hit create-org or
  verify-pending.
  **Clarification (existing behavior, NOT new in S4.7):** this verify-then-membership ordering
  predates S4.7 (`invites.go` Accept, shipped in S2.6) — S4.7 adds **no** new Go for invite-accept, it
  only relies on the existing flow so the funnel is correct. Audit coverage is likewise pre-existing:
  Accept writes an `invite.accepted` audit row (actor = the invitee) in the same tx. S4.7 introduced
  no new server behavior or audit action here; the only new backend code in the story is the
  `DemoNoOrgUser` seed fixture (commit `6ac1a6b`).

Conventions named: gateway **join token = one-time secret** (S4.5 config-download ceremony — amber
callout, "I've saved it" gate, no route back, keyed fingerprint in logs/audit, never the raw token);
audit rows same-tx, actor-attributed, secret-free; guards auto-arm (401-walk picks up any new gated
op, RBAC matrix, deliberate-red one-line per new guard).

Prove: fresh-org empty-state render set (Playwright, all three router branches); enrollment e2e
(join-token → agent joins → node appears — real compose agent if the harness allows, else mocked
ceremony + a deferred-ledger entry).

- **S4.8 Round-2 walk fixes** — the Part A walk's bug + top frictions (see ROUND2-REPORT.md):
  B1 CSRF stale-cookie login lockout (client-wide header in createTunnexClient); F1+F2 name-pinned
  join-token ceremony line + compose plumb; F3 token fingerprint in issuance/enrollment audit;
  F4 visit-time /create-org re-route; commit the ROUND2-gated walk spec + report.

**UX-backlog (from the Round-2 walk — recorded, NO code scheduled):**
- F5: org-name slugging drops non-ASCII (`Ä` → dropped, not transliterated to `a`); emoji-only
  names produce an empty slug requiring a manual one. Cosmetic.
- F6: the verify-email success page could point to sign-in more loudly (the link does not and
  should not establish a session; the page just under-sells the next step).
- B6 (CONFIRMED in the Part B walk): the member-role dashboard shows "Enroll a gateway →" but
  IssueJoinToken requires org:update — the affordance leads to a guaranteed 403. Role-aware
  empty-state copy needed (same class as the S4.3 role-aware empty-state watch-item).
- Domain-capture has API endpoints but NO Settings UI (found in Part B) — surfacing claim/TXT/verify
  states in the UI is an open story candidate (S4.5 watch-item d was never built). Trigger = the
  capture-UI story; the B2 DNS-TXT manual leg rides it.
- B4 negative leg (optional): live-exercise `sso_link_required` 409 (SSO login vs an UNVERIFIED
  local account) — server code confirmed present; needs a third Entra test user.

## EPIC 5 — CLI Client (dogfood & de-risk before Electron)

- **S5.1 `tunnex` CLI** — walk-derived scope (Round-2, D1/D2/D3 resolved; supersedes the original
  "fetch config" sketch):
  **Auth (D1+D3):** `tunnex login` opens the SYSTEM BROWSER to Tunnex; authentication (local or
  SSO — MFA and all) completes in-browser against Tunnex; Tunnex then redirects to the CLI's
  `http://127.0.0.1:<port>/callback` with a ONE-TIME authorization code; the CLI exchanges the code
  for a **dedicated CLI credential** — a NEW server-side model: hashed at rest, identity-bound
  (identity↔credential principle), keyed-fingerprint audit rows written same-tx (proof-of-secret
  convention), header-borne (no cookie → csrfGuard is already inert for it — VERIFY with a test),
  revocable. **Entra never sees the loopback** — the CLI callback is Tunnex's own redirect; the
  server needs a loopback-redirect allowlist (127.0.0.1 only, any port). **D1 caveat (recorded):**
  verified on an MFA-less Free tenant; the MFA claim rides the in-browser-completion ARGUMENT
  (challenges finish before the final redirect), not observation. **Device-code fallback for
  browserless hosts stays in scope.**
  **Config (D2):** the CLI OWNS device creation — the config is captured exactly once at creation
  and written atomically, `0600`, under `~/.config/tunnex/`; then the `wg-quick up/down` wrapper.
  Guards auto-arm: new endpoints picked up by the 401-walk + RBAC matrix; one deliberate-red per
  new guard.

### S5.1 decide-before-code (COMMIT ONE — decided on paper, for review before code)

**(1) CLI credential lifetime + revocation semantics.**
- **Password reset SWEEPS CLI credentials — YES** (the default stands, no argument against it):
  a reset signals identity compromise; S2.2 already sweeps sessions on exactly that signal, and a
  surviving CLI credential would be a back door around the sweep. Same tx, same trigger.
- **Deactivation sweeps too** (S2.6 parity — a deactivated user's CLI must die with their sessions).
- **Lifetime: 90-day absolute expiry**, no sliding refresh in S5.1 (`tunnex login` again is cheap;
  refresh-token machinery is not — defer until dogfooding demands it). Expiry stored server-side
  next to the hash.
- **Listable/revocable: API now, dashboard UI deferred.** The model ships with list + revoke
  endpoints (name, created_at, last_used_at, fingerprint — never the token), because the endpoints
  arm the 401-walk/RBAC guards and `tunnex logout` needs revoke anyway. The dashboard "CLI
  sessions" panel is a LEDGERED follow-up (rides a later dashboard story), not S5.1.

**(2) Header format + OpenAPI representation.**
- **`Authorization: Bearer <token>`** — the standard every CLI/tool ecosystem expects; no custom
  header. Token format: opaque random (32B, base64url), prefixed `tnx_` so leaked-secret scanners
  can pattern-match it; NEVER a JWT (server-side revocation must be instant, not TTL-bound).
- **OpenAPI: a second securityScheme** (`http`/`bearer`) alongside the cookie scheme; gated ops
  accept either. The 401-walk keeps walking sessionless ops; a new deliberate-red proves a
  REVOKED bearer token is refused (not just a missing one).
- csrfGuard stays cookie-keyed and is therefore inert for bearer requests — one test PROVES a
  bearer mutation with no cookie and no X-Tunnex-CSRF header succeeds (the CLI never does the
  CSRF dance; that was D3's point).

**(3) Loopback callback discipline (join-token-class hygiene).**
- **Port: OS-assigned ephemeral** — the CLI listens on `127.0.0.1:0` and puts the actual port in
  the redirect it requests; the server's allowlist validates host `127.0.0.1` (or `[::1]`)
  EXACTLY, any port, fixed path `/callback` — nothing else, ever (no `localhost` — DNS-spoofable).
- **Code: single-use, 60s TTL, PKCE-bound.** The CLI mints a code_verifier, sends the S256
  challenge on the authorize leg; the exchange requires the matching verifier — a stolen code
  alone is useless (same discipline as join tokens: hashed at rest, consumed atomically).
- **Exact-match binding:** the code is bound at mint to the EXACT redirect (host+port+path) it was
  issued for; the exchange re-presents it and must match. State parameter carried end-to-end for
  the CLI's own request correlation.

**Approved (sign-off) with recorded ADDITIONS:**
- **(a) Minting is verified-gated** (`requireVerifiedUser` on the authorize + device-approve legs).
  No exception argued: an unverified account must not mint a long-lived credential when the same
  account can't perform org mutations — the credential would outlive/outrank its owner's standing.
- **(b) bearer ≡ cookie on ALL authenticated endpoints.** Any exception is ARGUED IN THE SPEC on
  the op itself. Two exceptions argued: `cliAuthorize` and `cliDeviceApprove` are cookie-session
  ONLY — minting a new credential from an existing bearer credential is self-replication (a stolen
  token could outlive its expiry by re-minting); the browser leg is the human checkpoint.
- **(c) `state` carried on the loopback callback alongside PKCE** (CLI-side request correlation +
  CSRF on the loopback listener); the device-code fallback inherits the SAME code-hygiene class
  (hashed at rest, single-use, short TTL, atomic consume).
- **SHA256SUMS for website distribution:** every released CLI artifact set ships a SHA256SUMS file
  (and its URL is printed in install docs); signing rides the EPIC 5 ops item (Apple ID + EV cert).
- **Expired-credential UX:** on any 401 `credential_expired`, the CLI prints exactly one actionable
  line — `credential expired — run 'tunnex login'` — never a raw error dump.

**S5.1 ACCEPTANCE CRITERION (spec sign-off flag 1) — the consent page is a real checkpoint:**
the browser leg renders an explicit consent page that (i) requires a DELIBERATE CLICK to mint —
never auto-approves on load (an instant redirect would reduce the "human checkpoint" argument for
the cookie-only exception to theater); (ii) DISPLAYS the loopback redirect it will send the code
to, INCLUDING THE PORT (the user can see which local process is asking); (iii) the device-approve
page displays the user_code it is approving. **Playwright proof of the no-click-no-mint property**
(landing on the consent page mints nothing; only the click calls cliAuthorize).

Ledgered at spec sign-off (flags 2+3):
- **Rate-limit targets for the public CLI endpoints** (cliToken, cliDeviceStart, cliDeviceToken —
  brute-force surface: code guessing, device-code polling) → S11.3 (rate limiting & security
  headers); interval/slow_down semantics are already in the device contract.

Ledgered at story-end review (S5.1 5/n+):
- **Expired-credential 401 oracle — REMOVED (not accepted).** The distinct `credential_expired`
  code was dropped: the server now returns a generic 401 for expired, BYTE-IDENTICAL to
  revoked/unknown (extended no-oracle test asserts all three identical). The CLI disambiguates
  expiry from its LOCALLY stored `expires_at` and prints the exact "run 'tunnex login'" line, so the
  UX is preserved with no server-side oracle. Closed at Pawan's direction pre-merge.
- **Expired/consumed CLI-code GC**: `cli_auth_codes` (60s) and `cli_device_codes` (15m) rows are
  never deleted after expiry/consumption → unbounded growth. Add a periodic
  `DELETE … WHERE expires_at < now() OR consumed_at IS NOT NULL` sweep (a cron/boot job). → S11 hardening.
  **S7.5.5 adds `mfa_challenges` to this SAME class** — burned-on-resolution but expired-and-abandoned rows
  accumulate; rides the same GC fix (`DeleteExpiredMfaChallenges` query already exists). No sweeper built now.
- **Rate limits for the public CLI endpoints** (cliToken code-guessing; cliDeviceStart/cliDeviceToken
  device-code brute-force + phishing amplification) → S11.3. The device-flow phishing surface is
  inherent to device-code flows; mitigated now by the anti-phishing warning on /cli-device, fully
  addressed by the rate limit. **LAW (S7.5.5-found): a rate-limit/attempt counter must NOT share a tx
  with the refused request's failure path — a counter that rolls back with the refusal is no limit
  (the MFA cap bug). Commit the counter; map the refusal to an error AFTER commit (outcome-not-error).**

Ledgered at implementation sign-off (MERGED item):
- **User-scoped credential surface** = admin revoke of another user's CLI credential + the
  CLI-credential audit slice (cli.credential_issued/_revoked rows are written org-NULL and are
  therefore invisible to the org-filtered audit viewer — the rows exist, the surface doesn't).
  **Trigger: the security-review pass or the dashboard CLI-sessions panel story, whichever lands
  first.** Until then: revocation is self-serve (`tunnex logout`, DELETE endpoint) + the
  reset/deactivation sweeps; the audit slice is queryable in the DB.
- **(Ops, when EPIC 5 begins)** Begin **code-signing cert procurement** — Apple Developer ID + Windows EV cert (weeks of lead time).

## EPIC 6 — Electron Desktop Client (Windows + macOS)

- **S6.0b CI pipeline (verification gates + client build matrix)** — IN PROGRESS. The repo's gates
  ran only via manual `make`/`turbo` (no `.github/workflows`); the Electron client adds a macOS +
  Windows surface a human can't reliably cover. **Scope:** GitHub Actions on push/PR —
  (i) a **Linux `gates` job** running the existing make gates (codegen drift, both-edition tests,
  web typecheck+build); RED BLOCKS MERGE. (ii) a **`client` matrix** (macOS + Windows runners):
  `pnpm install` (electron provisioned via the onlyBuiltDependencies allowlist), client
  typecheck + unit tests + build — none LAUNCH Electron (no display needed), so the matrix is
  display-free; RED BLOCKS MERGE. (iii) **full e2e in CI is OPPORTUNISTIC** — included as a job, but
  if it resists (runner resources / flakiness) it drops to nightly/non-blocking (ledger). (iv)
  **playwright-electron** is NOT in scope now — launching Electron needs xvfb + the built app + the
  stack, not "trivially cheap"; ledgered for later. Must land before S6.5; recommended before S6.3.

**S6.0b LEDGER — CI first-run fixes (root-caused).** The blocking jobs (gates + client) were red on
first runs; all three causes fixed: (1) `.env` absent → `cp .env.example .env` before DB steps;
(2) a Windows-only path fixture in the client test (resolve the root per-platform); (3) THE big one —
`GOFLAGS=-mod=mod` made `go build`/`go test` RE-RESOLVE the module graph on the cold CI cache and,
because the module path (`github.com/tunnexio/tunnex/...`) is NOT the real repo
(`github.com/iotunnex/tunnex`), it ran `git ls-remote https://github.com/tunnexio/tunnex` → exit 128.
It surfaced only after the repo went public (the mismatched path suddenly looked resolvable) and did
NOT reproduce locally (populated cache). Fix: `-mod=readonly` (go.sum is committed + complete) on the
apps/api build/test/seed commands + the api/migrate/node Dockerfiles — go then trusts go.mod/go.sum
and never remote-resolves. **`e2e` stays non-blocking `continue-on-error` by design** (full-stack,
heavier/flakier; opportunistic per mandate), not because it's broken — with the readonly fix it is
expected to pass. Gates + client are the blocking gates.

### S6.0b decide-before-code (COMMIT ONE, for review): deliberate-red representation in CI
The story-protocol proves each new guard by a DELIBERATE RED — comment out the guard, watch its test
fail, record the one-line failure in the commit — then restore green. **Decision: CI runs the GREEN
suite only; deliberate-reds stay MANUAL, dev-time, recorded in commit messages.** A red is produced
by committing *broken* code (a removed guard); CI cannot host that without a permanently-failing job,
and a "red on a branch that removes the guard" is exactly what a human does locally, not a committed
artifact. What CI guarantees instead: the GREEN test each red proves (401-walk, RBAC matrix, the
sweep tests, the no-oracle byte-identical test, CORS no-credentials, bearer session_required, …) runs
on every push and RED BLOCKS MERGE — so a regression that would re-open the hole fails CI even though
the *red demonstration* isn't itself a CI job. The deliberate-red remains the AUTHOR's proof the test
detects the violation; CI is the CONTINUOUS proof the invariant still holds. (Argue if a subset of
reds should be encoded as committed "guard-present" assertions — none proposed; the green tests
already assert the positive invariant.)

### S6.3 Tunnel control — DECIDE-BEFORE-CODE (privilege helper gets a FULL review round)
Scope: start/stop a WireGuard tunnel from the desktop app — embed a userspace WireGuard
(`wireguard-go` on macOS, `wintun`/`wireguard-nt` on Windows) and configure the interface, which
needs elevated privilege. The **privilege helper is the heavyweight, security-critical item** and
its architecture must be reported for review BEFORE any code, covering FOUR decide-items:
1. **Minimum surface** — exactly what the helper does (bring an interface up/down with a specific
   config; set routes/DNS) and, more importantly, what it REFUSES. No arbitrary config path, no
   shell, no generic "run as root" — a typed, minimal verb set mirroring the preload allowlist
   posture (S6.1). The helper is the privileged trust boundary; its surface IS the attack surface.
2. **Caller authentication** — how the helper knows it is talking to the REAL Tunnex app and not
   another local process (code-signing identity / audited client requirements on macOS XPC; a
   signed-peer check on the Windows service pipe). A root helper that trusts any local caller is a
   local-privilege-escalation primitive.
3. **Install/uninstall lifecycle per platform** — macOS `SMAppService` (or a LaunchDaemon) register/
   unregister; Windows service install/remove — idempotent, clean uninstall (no orphaned root
   daemon), and how it is signed/notarized (ties to S6.5).
4. **Why NOT wireguard-tools-as-root** — argue the baseline explicitly: why the app does not simply
   shell out to `wg-quick`/`wg` under sudo/elevation (auditability, surface, credential prompts,
   packaging), justifying the dedicated minimal helper instead.
Standard protocol otherwise: decide-items reported for review → build → multi-finder + the security
review → e2e where the harness allows + human smoke for tunnel-up/down.

#### S6.3 COMMIT ONE — privilege-helper architecture (PROPOSED, for review before any code)

**HEADLINE TENSION (decide first):** robust caller-authentication (item 2) and a trusted
daemon/service (item 3) BOTH rest on code-signing, which is now DEFERRED to S6.5b. So a *cryptographically*
authenticated helper cannot be fully realized on unsigned builds. Two paths — pick one:
- **(A) Build now, auth hardens later.** Ship the helper + its typed protocol on unsigned dev/S6.5a
  builds with an INTERIM caller check (install-time admin consent + client-path/bundle check), and land
  the crypto identity-pinning when S6.5b signs. Tunnel works early; the helper is only *fully* trusted
  once signed. RECOMMENDED — keeps EPIC 6 moving; the interim helper is not internet-exposed and is
  installed only by explicit admin action.
- **(B) Pull macOS signing early.** Use the individual Apple Developer ID (no legal entity needed) to
  sign the macOS app+daemon NOW so the macOS helper gets real XPC code-requirement pinning immediately;
  Windows helper still waits on the entity/EV. Splits the platforms but maximizes macOS security first.

**(1) Minimum surface.** The helper is a SEPARATE privileged process (native Go/Swift/C — NOT Electron,
NOT Node), exposing a TYPED verb set only: `TunnelUp(cfg)` · `TunnelDown()` · `Status()`. `cfg` is a
STRUCTURED, VALIDATED WireGuard config passed over IPC (never a file PATH — dodges TOCTOU/arbitrary-read):
own private key, peer pubkey, endpoint host:port, allowed-IPs, address/CIDR, DNS, MTU — each field parsed
+ rejected if malformed (valid base64-32 keys, parseable CIDRs, well-formed endpoint). REFUSES: arbitrary
interface name (one app-owned name, e.g. `utun-tunnex` / a fixed wintun adapter), arbitrary routes/DNS
beyond what the validated cfg implies, any exec/shell/file-path/"run binary", more than one concurrent
tunnel. The verb set IS the attack surface — same allowlist posture as the S6.1 preload.

**(2) Caller authentication.** macOS: helper = a LaunchDaemon exposing an XPC service; pin the peer with
`xpc_connection_set_peer_code_signing_requirement` (audit-token → SecCode → Tunnex Team ID + designated
requirement). Windows: helper = a Windows service; IPC over a named pipe with a tight ACL; resolve the
client PID (`GetNamedPipeClientProcessId`) → verify the client image is the signed Tunnex exe
(`WinVerifyTrust` + path). BOTH depend on signing (see the headline tension) — on unsigned builds the
interim is bundle-path + explicit-install consent, upgraded to crypto pinning at S6.5b. A root helper
that trusts ANY local caller is a local-EoP primitive; that is the failure mode we design against.

**(3) Install / uninstall lifecycle.** macOS: `SMAppService.daemon` (macOS 13+) registers a LaunchDaemon
bundled at `Contents/Library/LaunchDaemons/` — one admin auth on first tunnel use; `unregister()` on app
removal; idempotent; NO deprecated `SMJobBless`. Windows: register the service via the SCM through a
ONE-TIME elevated install action (runs as LocalSystem); uninstaller STOPS + DELETES the service (no
orphaned LocalSystem daemon); idempotent check-then-create. Both binaries must be signed/notarized for the
OS to load them (→ S6.5b).

**(4) Why NOT wireguard-tools-as-root (the rejected baseline).** Not `sudo wg-quick up <file>` because:
(a) surface — `wg-quick` is a root shell script invoking `ip`/`route`/`resolvconf`; a config file handed
to root is a fuzzy, injectable surface vs. a fixed typed verb set; (b) UX/security — `sudo` either
password-prompts every connect (bad) or needs a NOPASSWD sudoers entry (a standing root hole any local
process can abuse); the helper authenticates the CALLER once at install instead; (c) cross-platform —
`wg-quick` is unix-only; Windows needs the service/wireguard-nt model regardless, so a unified helper
abstraction is required anyway; (d) versioning — embedding `wireguard-go`/`wireguard-nt` pins a known-good
implementation rather than depending on a possibly-absent/old system `wireguard-tools`; (e) TOCTOU — a
file-path arg to root invites time-of-check/use races; structured IPC config avoids it.

Report: decisions above for review (esp. the A/B signing-tension call) BEFORE any code.

**COMMIT-ONE AMENDMENTS — PATH A APPROVED (build now, harden at S6.5b), with:**
- **Interim caller-check (unsigned builds) = executable-path-inside-install-dir verification.** The
  helper resolves the connecting client's executable path (macOS: audit-token → PID → path; Windows:
  `GetNamedPipeClientProcessId` → image path) and requires it to live INSIDE the app's install dir
  (`/Applications/Tunnex.app/…`, `C:\Program Files\Tunnex\…`). RECORDED AS WEAKER-THAN-PINNING —
  THREAT MODEL: it stops an unrelated local process from driving the helper, but does NOT stop a
  process that can write into / replace a binary in the install dir (needs admin already) or a
  path-spoofing race; a non-admin local attacker is blocked, an admin-level one is not. Real crypto
  identity pinning lands at S6.5b (mode upgrade, below).
- **Wire protocol carries `version` + `auth_mode` from day one.** Every request/response header
  includes a protocol version and the auth mode in force (`path_check` now, `code_signing` at S6.5b).
  So S6.5b hardening is a MODE UPGRADE negotiated on the existing protocol, NOT a breaking change —
  the app and helper agree on the strongest mutually-supported mode; the helper REFUSES to downgrade
  below its configured minimum once signed.
- **Fail-CLOSED on helper death (CONFIRMED, no deviation).** If the helper dies / the IPC channel
  drops while a tunnel is up, tunnel traffic FAILS CLOSED — the tun interface + its routes are torn
  down (or a kill-switch route/deny stays installed) so NO traffic silently falls back to the
  cleartext default route (no leak). The UI surfaces the drop LOUDLY (disconnected + reason), never
  a silent degrade. Rationale: a VPN client that fails OPEN leaks the exact traffic the user meant to
  protect; closed-on-failure is the only defensible default. (Any future opt-in "allow fallback" would
  be an explicit, off-by-default user choice — not in scope here.)
- **PLAN ledger:** the interim path-check posture is a NAMED SECURITY LIMITATION (below), trigger to
  retire = S6.5b crypto pinning.

**S6.3 ConfigProvider — DECIDE-BEFORE-CODE (D2-honoring; report for review before the config commit).**
The `TunnelController` needs a `ConfigProvider` that yields the device's WireGuard `TunnelConfig` in
MAIN. It MUST honor Round-2 walk decision **D2**: the config is served EXACTLY ONCE at device creation
and is NEVER re-fetchable, so the client must OWN device creation (as the CLI does) — it cannot "fetch
the config for a device." Proposed decisions:
1. **Own creation, once.** First tunnel-up with no stored device → the desktop CREATES a device via
   the API (bearer, in MAIN — reusing the S5.1/S3.4 device-create-returns-config flow) and captures
   the config at that moment. It NEVER attempts to re-fetch an existing device's config (the API
   forbids it). Subsequent ups reuse the stored config.
2. **Secure storage, key-never-in-renderer.** The WG PRIVATE KEY + config persist via Electron
   `safeStorage` (macOS Keychain / Windows DPAPI) — the SAME refuse-by-default posture as the S6.1
   credential (no plaintext-on-disk unless an explicit `--allow-insecure-credential-storage`). The key
   flows API → MAIN (safeStorage) → helper (IPC); it NEVER enters the renderer. This deliberately
   AVOIDS the browser flow's mistake (a plaintext key in ~/Downloads) that D2 called out.
3. **One device per install**, named from the hostname (with a disambiguating suffix); the device id is
   persisted alongside the config.
4. **Lifecycle on logout — CONFIRMED DELIBERATE (logout revokes the device).** Clearing the
   credential (auth:logout) ALSO clears the stored tunnel config and BEST-EFFORT revokes the device
   server-side. ARGUMENT (one line): the local WG config is cleared on logout exactly like the bearer,
   so leaving the server-side peer alive would ORPHAN it (dangling peer + stale telemetry) — logout
   revokes to complete the full-sweep; re-login creates a fresh device (D2: no re-fetch).
5. **Loss = recreate, never re-fetch.** If safeStorage is cleared/unavailable, a NEW device is created
   (old one is orphaned → the logout/GC sweep or an admin reap handles it); consistent with D2.
6. **Server-URL change — RESOLVED: NO auto-revoke.** The stored config is ORIGIN-KEYED (like the
   bearer) and NEVER used cross-origin — a URL change simply means the new origin has no config yet
   (a fresh device is created on next connect there). The old-origin device is NOT auto-revoked
   (avoids destroying a working config on a fat-finger URL edit / temporary switch); instead the UI
   SURFACES the orphaned old-origin device with a "remove or switch back" affordance, and remove does
   a best-effort revoke against the OLD ORIGIN ONLY (never the current one). This is the deliberate
   divergence from S6.2's force-relogin-on-URL-change: the credential is discarded, but a device
   (server-side state + a stored config) is worth preserving/surfacing, not silently reaping.

**S6.3 KILL-SWITCH DESIGN — BEFORE-CODE (review item at story end; pcap-verified smoke step).**
THE INVARIANT: fail-closed must require NO LIVE CODE to act. The app is unprivileged (can't fix
routing); the helper can be `kill -9`'d, which runs NO cleanup handlers. So fail-closed CANNOT be a
`FailClosed()` method that runs on death — it must be KERNEL-RESIDENT STATE the helper ARRANGES AT
`Up` that BLOCKS cleartext egress and PERSISTS however the process exits. **Death itself is the
enforcement.** Only a graceful `Down` removes it. This corrects the current Supervisor: `Up` installs
the persistent block; `Down` removes it; the live `FailClosed()`/`OnPeerLost()` path is a fast-teardown
CONVENIENCE for the alive-process case, NOT the guarantee. On next helper start a STALE block from a
prior crash is reconciled (adopt on reconnect, or an explicit user-driven clear so a crash can't
permanently black-hole the internet — but the DEFAULT post-crash state is blocked).
- **macOS:** a `pf` (packet filter) anchor installed via `pfctl` at `Up` — rules that block all
  outbound except to the WG endpoint + via the utun. `pf` rules are kernel-resident and survive helper
  death; graceful `Down` flushes the anchor. (Route-only blackholing is fragile across utun teardown;
  pf is the durable mechanism.) RULESET REQUIREMENTS (folded, S6.3-17): (1) pf enabled via
  reference-counted `pfctl -E`, token RELEASED with `pfctl -X` on Down (never a global `pfctl -d`) —
  smoke asserts ENFORCEMENT (a blocked ping), not rule presence; (2) `set skip on lo0` (loopback
  exempt — also protects the app's own 127.0.0.1 callback); (3) DHCP + NDP pass (UDP 67/68, DHCPv6
  546/547, ICMPv6/NDP) — a DELIBERATE, threat-model-argued exception so a long session doesn't lose
  its lease/neighbor state (exposure = a local-segment attacker spoofing DHCP/RA, out of scope for an
  egress kill-switch and a pre-VPN risk anyway); (4) `block drop out all` covers inet AND inet6 (NDP
  explicitly passed) — the smoke kill-switch pcap includes a v6 probe. The named anchor must be
  REFERENCED from pf.conf to be evaluated — the SMAppService/installer adds `anchor "tunnex"` (removed
  on uninstall); the enforcement-based smoke catches a non-referenced anchor.
- **Windows:** WFP (Windows Filtering Platform) filters in a PERSISTENT sublayer at `Up` — the same
  mechanism the official WireGuard Windows client uses for its kill-switch ("block untunneled
  traffic"). WFP filters are kernel-resident and persist past process death; graceful `Down` removes
  the provider/sublayer.
Backend contract (corrected): `Up(cfg)` = tun + routes + ARRANGE the persistent pf/WFP block;
`Down()` = remove tun + REMOVE the block (restore routing); `FailClosed()` = alive-process fast path
that tears the tun and ASSERTS the block is present (it already is from Up). SMOKE (both platforms):
`kill -9` the helper mid-tunnel; a pcap on the physical NIC proves ZERO cleartext to a tunneled dest
AFTER the kill — with the helper process GONE, so nothing but pre-arranged state can be enforcing it.

**RECOVERY MODEL — BOUNDED FAIL-CLOSED (mini-smoke-surfaced; implemented + tested).** The design above
("death = enforcement, only graceful Down removes it") is correct for BLOCKING but originally had NO
RECOVERY PATH: an abnormal exit (kill -9 / crash) left the kernel-resident block with nothing to release
it, so a FULL-TUNNEL helper death STRANDED THE HOST (reboot required — the first mini-smoke did exactly
this, against the no-egress parked-S3.7 gateway). Fail-closed is now **"death = enforcement, BOUNDED by
the dead-man interval."** Three recovery mechanisms, all landed with tests (`TestSupervisorSelfHeal`,
`TestSupervisorDeadMan`): (1) **STARTUP SELF-HEAL** — the helper flushes a stale `tunnex` anchor +
releases a PERSISTED (root-only `/var/run/tunnex/pf.token`) `pfctl -E` reference BEFORE serving, so a
KeepAlive restart un-strands; (2) **DEAD-MAN TIMEOUT** (`DeadManDefault` = 90s) — if the owning app
stops heartbeating past the window (crashed/wedged), the LIVE helper auto-releases the block; (3)
graceful `Down` (unchanged). **MAX CLEARTEXT-LEAK WINDOW after an un-recovered crash = the dead-man
interval (~90s) — a DELIBERATE trade: an UNBOUNDED block bricks the host, worse than a bounded post-crash
leak window on a machine whose VPN is already down.** ROUTES (RC2): full-tunnel now installs the
WG-standard SPLIT-DEFAULT (`0.0.0.0/1`+`128.0.0.0/1`, `::/1`+`8000::/1`) — more specific than the
physical default so it takes precedence WITHOUT destroying it; on teardown/crash the halves vanish with
the utun and the physical default resurfaces automatically (no capture/restore, no stranding). **WINDOWS
WFP MUST INHERIT THIS BOUNDED MODEL** — WFP filters have the IDENTICAL latent persist-with-no-releaser
bug. The WFP backend must implement the same `CleanStale` (startup sweep of stale filters by a well-known
provider/sublayer GUID) and be driven by the same dead-man, or it will strand Windows hosts identically.
Build it bounded from day one — do not port only the arming half.

**KILL-SWITCH VALIDATION STATE (2026-07-09, after the POC mini-smoke sessions):**
- **PROVEN LIVE (real macOS hardware):** (a) full-tunnel routing loop FIXED — endpoint host-route
  via the physical gateway, `tx` steady not runaway; (b) HOST-STRANDING RECOVERY confirmed live via
  Ctrl-C graceful Down (network returns, no reboot) — RC1/RC2 work on real hardware, not just in unit
  tests; (c) generator emits both AFs; (d) dev-install one-shot (codesign + Electron-path auto-detect
  + stale-config self-heal).
- **PROVEN (unit):** self-heal + dead-man release, both paths independently (`TestSupervisorSelfHeal`,
  `TestSupervisorDeadMan`); split-default mapping (`TestRouteTargets`).
- **PROVEN LIVE (2026-07-09, on real macOS) — GATE CLEARED:** the `kill -9` pcap PASSED. Full-tunnel
  up, `kill -9` the helper, `en0` capture over the dead window: BOTH pcaps (v4 `1.1.1.1` + v6
  `2606:4700:4700::1111`) showed **0 packets** while ~30 ping attempts fired — the kernel-resident pf
  anchor blocked every one with the helper PROCESS GONE ("death = enforcement"). BONUS: the manual
  recovery command errored (zsh inline-comment), yet the host STILL recovered — the KeepAlive restart +
  startup `CleanStale` self-healed AUTOMATICALLY (RC1 self-heal now live-proven, not just unit-tested).
  No strand, no reboot. **WFP is UNBLOCKED.** (Windows WFP still needs its OWN Windows-side proof at its
  story-end — a macOS proof validates the PATTERN, not WFP's kernel mechanism — but the bounded model
  is now confirmed sound on real hardware, so WFP is built against a proven pattern.)
- **PARKED AS ITS OWN STORY:** gateway NAT / full-tunnel real internet egress (the `rx=92` container
  double-NAT issue) is **S3.7** — do NOT hand-hack it live; the POC's manual iptables was a throwaway.

**S6.3 native deps (pinned; license check):** macOS tun/device = `golang.zx2c4.com/wireguard`
(wireguard-go) — **MIT**, compatible under our Apache-2.0 open edition (permissive → permissive, OK).
Windows = `golang.zx2c4.com/wireguard/windows` / `wireguard-nt` + `wintun` — WireGuard-NT/Wintun are
**MIT**-ish (WireGuard) with the Wintun redistribution note; wintun.dll is bundled per its license.
Exact commit/tag pins recorded in `apps/helper/go.mod` when the backends land; the license check
(MIT-under-Apache = fine; note Wintun's redistribution terms in NOTICE) is a story-end review item.

**S6.3 NATIVE LIFECYCLE — DESIGN (install/UPGRADE/UNINSTALL; uninstall is first-class).**
- **Mechanism per platform.** macOS: **SMAppService** — the app bundle ships
  `Contents/Library/LaunchDaemons/io.tunnex.helper.plist`; the Electron main calls
  `SMAppService.daemon(...).register()` (install/upgrade) and `.unregister()` (uninstall). Windows: the
  helper is a **Windows service** (SCM) — the packaged installer registers/starts it; uninstall stops +
  `sc delete`s it. Both REQUIRE the packaged app (signed `.app` / installer) — see substitutes below.
- **UNINSTALL IS A FIRST-CLASS, VERIFIED DELIVERABLE (steer).** The dev-install left `/etc/pf.conf`
  modified with no restorer — the production lifecycle must NOT repeat that class. Uninstall removes,
  per platform, ALL of: the daemon/service registration; the helper binaries; the socket/pipe; on
  macOS the `pf.conf` anchor reference **RESTORED FROM THE INSTALL BACKUP** (`/etc/pf.conf.tunnex-bak`)
  + the pf token file; on Windows **all WFP objects by our provider GUID** (`firewall.DisableFirewall`);
  and leaves **zero routes/rules**. The **story-end smoke's uninstall-residue checks are the acceptance
  test** — the lifecycle is built to pass them. Dev path already updated: `macos-dev-uninstall.sh`
  restores the pf.conf backup + cleans the token + checks split-default-route residue.
- **VERSION UPGRADE PATH (steer).** The helper is the long-lived root daemon; the app upgrades it (a new
  app version registers its bundled helper). `NegotiateVersion` (protocol.go, tested) makes the handshake
  actionable: **app newer than helper → `helper_outdated`** (app re-registers/upgrades the helper via
  the lifecycle, then retries — the normal path); **app older than helper → `client_outdated`** (REFUSE;
  a stale app must not drive a newer helper — a downgrade-refused ratchet mirroring the auth-mode one).
- **SUBSTITUTES vs SATISFIES (steer — honest split).** PROVABLE NOW (pre-packaging, this story):
  uninstall COMPLETENESS + residue logic (pf.conf restore, WFP `DisableFirewall`-by-GUID, socket/token
  removal); the version-handshake upgrade errors (unit-tested); the backend `CleanStale`/`Down` removal
  ops the uninstall relies on. DEFERS TO S6.5a (needs the packaged `.app`/installer): SMAppService
  `register`/`unregister` and the Windows-service install exercised END-TO-END, and the packaged
  install→run→UNINSTALL residue smoke. **The dev-install scripts remain the unpackaged-dev mechanism
  ALONGSIDE the production lifecycle.** **TRIGGER SPLIT (resolved at S6.3 sign-off — a proof's trigger
  must be a milestone that can actually RUN it):** the **Windows** service install→run→uninstall residue
  smoke runs on the UNSIGNED S6.5a package (a user-mode service installs without code-signing; SmartScreen
  click-through) → **trigger = S6.5a**. **macOS SMAppService** register/unregister REQUIRES a code-signed
  app bundle (SMAppService validates the signature) → it cannot run on the unsigned S6.5a package →
  **trigger = S6.5b** (signing). The uninstall REMOVAL/residue LOGIC (pf.conf restore, WFP
  DisableFirewall-by-GUID, socket/token removal, zero routes) is already dev-proven and rides S6.5a on
  both platforms; only the macOS SMAppService *registration* e2e waits for S6.5b.
Deps landed so far: `golang.org/x/sys` (caller-path), `github.com/Microsoft/go-winio` v0.6.2 (MIT —
Windows SDDL pipe).

**S6.3 Windows pipe — TWO-LAYER intent (endorsed):** the pipe SDDL gates CONNECTION (who may open
the pipe: SYSTEM/Admins full, Authenticated Users connect+rw so the unprivileged app can reach it);
the caller-path check gates TRUST (which PROCESS may drive the helper: image inside the install dir).
Access ≠ authorization — both layers required. EDGE (refuse-path): if the client process dies between
connect and resolution, `OpenProcess`/`QueryFullProcessImageName` error → the resolver returns an
error → the Server refuses the caller (fail-closed, correct). Add an explicit test when Windows tests
are runnable.

- **S6.1 Client shell** — Electron app, reuse React renderer, secure IPC, auto-update scaffold.
  **MERGED** (7 commits; smoke-verified on macOS). Delivered: `apps/client` Electron main+preload;
  `app://` (standard+secure, strict escape+symlink+realpath, CSP) serving the `apps/web` bundle;
  hardened window (contextIsolation/sandbox on, nodeIntegration off, navigation locked); preload
  verb-specific allowlist (`auth.*`/`config.*`/reserved `tunnel.*`, no generic invoke, main
  validates inputs); S5.1 login reused in main (system browser + single-shot loopback →
  `safeStorage` keychain, refuse-by-default + `--allow-insecure-credential-storage`); bearer
  attach-on-request on the exact minting origin only; `/healthz`-validated main-process server
  config with force-relogin-on-change; first-run setup screen; `electron-updater` scaffolded inert
  (`AUTOUPDATE_ENABLED=false`). 17 unit tests over the pure security core.

### S6.1 paper decisions (COMMIT ONE — decided on paper, for review before any code)

New surface (`apps/client`, Electron main + preload + the reused SPA renderer). Nothing exists yet;
this commit is the contract, not code. Grounded in S5.1: the CLI credential flow (system browser →
`127.0.0.1:<port>/callback` → PKCE code → `tnx_` bearer, header-borne, no cookies) already exists and
the desktop client REUSES it wholesale.

**(a) Auth = reuse the S5.1 credential flow via the SYSTEM browser + loopback.** The Electron MAIN
process runs the same single-shot loopback listener the CLI does, opens the user's DEFAULT browser to
`/cli-auth` (never an embedded `BrowserWindow`/webview), receives the one-time code, exchanges it for a
`tnx_` bearer credential. **No embedded-webview login, no cookies in the client.** Rationale: an
embedded webview can capture credentials and is refused by Google/Microsoft for OAuth; the system
browser + loopback is the audited S5.1 path and gives SSO/MFA for free. Deviation would have to be
argued — none proposed.

**(b) Renderer reuse = the built SPA bundle, pointed at a CONFIGURED server, authed by BEARER.** The
existing `apps/web` build (locked: "same bundle reused by the Electron renderer") is loaded in the
renderer via a custom `app://` protocol (not `file://` — file URLs break same-origin/fetch
assumptions and are a security footgun). What DIFFERS from the browser SPA: (i) no nginx same-origin —
the API base URL is configured (a server field, persisted), so `createTunnexClient("/")` becomes
`createTunnexClient(serverURL)`; (ii) auth is the bearer credential injected from main via the preload
bridge (the SPA's client attaches `Authorization: Bearer`), NOT the cookie session. The SPA's
existing client-layer header hook (from S4.8) is the natural seam. Confirm in review: whether the SPA
needs a small "transport mode" switch (cookie for web, bearer for desktop) or the client factory just
takes an optional token.

**(c) IPC security posture = locked-down by default; the preload bridge is the ONLY privileged
surface.** `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`; the renderer gets
node/OS access through NOTHING except a minimal `contextBridge.exposeInMainWorld` allowlist (get the
configured server, get/refresh the bearer, trigger login/logout — and later the S6.3 tunnel
up/down/status calls). No remote module. This allowlist IS the S6.3 tunnel-control precursor: privileged
WireGuard actions will be added as explicit IPC channels, never direct renderer access.

**(d) Auto-update = electron-updater SCAFFOLDED but INERT until S6.5b — inertness now INDEFINITE by
design.** Wire `electron-updater` (config + a placeholder feed URL) so the plumbing exists, but do
NOT call `checkForUpdates` / enable it: macOS auto-update (Squirrel.Mac) requires a signed + notarized
app and simply cannot function unsigned, and shipping an unsigned auto-updater is a security
anti-pattern. Scaffold-don't-enable. Because signing moved to the DEFERRED S6.5b (trigger = public
beta / first outside distribution), the updater — and macOS auto-update specifically — stays inert
INDEFINITELY until that trigger fires; S6.5a ships unsigned with NO auto-update. This is deliberate,
not an oversight.

**(e) Credential storage = OS keychain via Electron `safeStorage`, NOT the CLI's 0600 file.** The
desktop client stores the `tnx_` credential encrypted through `safeStorage.encryptString`
(Keychain / DPAPI / libsecret), never a plaintext-ish file — a desktop is a shared, GUI environment
where a `0600` file is weaker than the OS keychain. Argue in review: the CLI's
`~/.config/tunnex/credential.json` convention stays correct for headless/CLI; the desktop client and
CLI hold SEPARATE credentials (both independently revocable) — no shared store, no interop
requirement. Caveat to handle: `safeStorage` on Linux can fall back to plaintext when no keyring is
present — detect and warn/refuse rather than silently downgrade.

**RESOLVED (review, approved) — the four sub-questions + two additions:**
- **`app://` protocol:** standard + secure registration (`registerSchemesAsPrivileged`
  `{standard:true, secure:true}`) serving the in-bundle SPA; STRICT in-bundle path resolution — any
  path escaping the bundle dir is rejected (escape-rejection is a tested unit, not a comment).
- **SPA auth:** a token-taking client factory extending the S4.8 middleware seam, but the **raw token
  NEVER crosses into the renderer** — an attach-on-request bridge (main injects `Authorization: Bearer`
  on requests to the configured API origin), NOT a `getToken`. The token lives only in main + the
  keychain.
- **Server URL:** persisted in a **MAIN-PROCESS config file** (electron-store or equiv.), never
  renderer storage — it's where the auth flow + updater point, so it's main's concern; the renderer
  consumes it via `config.getServerUrl` over the bridge. First run shows a server-URL prompt screen;
  the URL is validated by hitting **`/healthz` before it is accepted**. **Changing the server URL when
  a credential exists FORCES re-login** (revoke local + clear the keychain entry) — a stored
  credential must never be sent to a server it was not minted against (the desktop cousin of the
  loopback exact-binding discipline).
- **Preload API = verb-specific, promise-based, minimal allowlist** — `auth.{login, logout, status}`,
  `config.{getServerUrl, setServerUrl}`, and a **reserved-but-empty `tunnel.*`** namespace for S6.3.
  **NO generic `invoke(channel, args)`** (that makes the allowlist decorative). Main **validates every
  method's inputs** (never trust the renderer, same posture as never trusting the browser). This list
  IS the (c) allowlist and doubles as the audit surface.
- **Linux `safeStorage` no-keyring fallback = REFUSE by default**, with an explicit
  `--allow-insecure-credential-storage` opt-out (a flag + a VISIBLE UI state, never a config default —
  "warn" gets clicked through, and a plaintext `tnx_` on disk without even the CLI's 0600 discipline is
  strictly worse). Acceptable alternative offered: refuse keychain-less persistence but allow
  **device-code login per session** (credential in memory only) — slower but honest.

- **S6.2 Client auth / renderer transport switch** — make the desktop app FUNCTIONAL against a
  tenant: the SPA (still "control plane unreachable" after S6.1 because it targets same-origin
  `app://`) must call the CONFIGURED server with the bearer, and the desktop must expose login/logout
  in the UI (no more devtools-console-only). **DECIDE-BEFORE-CODE (commit one, for review):**
  - **(1) How the SPA learns it is in desktop mode + its server base URL.** The web SPA uses
    `createTunnexClient("/")` (same-origin cookie). In Electron there is no same-origin server. Options
    to decide: (a) the preload exposes `config.getServerUrl()` (already built) and a tiny bootstrap in
    the SPA switches the client's base URL to it when `window.tunnex` exists; (b) main rewrites a
    build-time base-URL constant. Lean (a) — runtime, no bundle fork, reuses the existing bridge; argue
    if (b).
  - **(2) Transport = bearer, not cookie — where the switch lives.** The S4.8 client-header seam +
    the main-process `attachBearer` injector (S6.1) already add `Authorization: Bearer` on requests to
    the server origin. So the SPA in desktop mode must (i) point its base URL at the server origin and
    (ii) NOT rely on cookies. Decide: does the SPA client factory take an explicit "desktop transport"
    (base URL + no credentials:'include'), or does main's injector + a base-URL swap suffice with the
    SPA unchanged? The token must STILL never enter the renderer (S6.1 invariant) — the injector stays
    the only thing that sees it.
  - **(3) Login/logout UI + auth state in the renderer.** The SPA needs a desktop-aware entry: when
    `window.tunnex` exists, the Sign-in screen offers "Sign in with your browser" (calls
    `auth.login()`), and the app reflects `auth.status()` (logged-in/expired/secureStorage). Decide the
    minimal SPA change vs a desktop-only shell around it, and how an expired credential (local, no
    server oracle) surfaces (a re-login prompt).
  - **(4) SSO parity.** S6.2's title includes SSO. Confirm SSO needs NOTHING desktop-specific — the
    `/cli-auth` browser leg already completes any local-or-SSO login in the system browser before the
    loopback code is minted (the S5.1/Part-B proof), so desktop SSO is free. State it, or surface the
    gap.
  - Guards: any new endpoint auto-armed by the 401-walk + RBAC; the token-never-in-renderer invariant
    gets an explicit assertion.

**COMMIT ONE — decisions confirmed (pre-positions folded, no deviation; build proceeds directly):**
- **(1) Desktop detection + one-bundle runtime branching.** `window.tunnex` presence IS the desktop
  signal — one SPA bundle, runtime branch (no build fork). A bootstrap in `main.tsx` awaits
  `config.getServerUrl()` and calls `setApiOrigin(origin)` in `@tunnex/shared` BEFORE React renders,
  so every request (incl. the first `/auth/me`) targets the configured server. Web path unchanged
  (origin unset → same-origin `/`).
- **(2) Main-process exact-origin bearer injection; residual acknowledged.** The S6.1 `attachBearer`
  (bearer only when request-origin === configured-origin === `cred.server`, unexpired) stays the ONLY
  thing that sees the token. The client middleware only rewrites the ORIGIN of the request URL; it
  never touches auth. RESIDUAL (acknowledged): the renderer still *initiates* authenticated calls and
  *reads* their response bodies — unavoidable (it is the UI) and not a token exposure; the invariant
  is "token never enters renderer JS", which holds.
- **(3) No web login FORM in desktop; bridge-driven auth state; unverified consent messaging.** In
  desktop mode the SPA's Sign-in screen replaces email/password with "Sign in with your browser"
  (`auth.login()`); on success main reloads → `/auth/me` (bearer) → authed. Logout in desktop routes
  through `auth.logout()` (revoke + clear keychain + reload). The `/cli-auth` consent page (runs in
  the system browser, cookie session) messages an UNVERIFIED user clearly on `email_not_verified`
  instead of a generic error.
- **(4) SSO parity = verify-only, zero build.** The `/cli-auth` browser leg already completes any
  local-or-SSO login in the system browser before the loopback code is minted (S5.1 + Part-B proof),
  so desktop SSO needs no desktop-specific code. Confirmed, no build.
- **S6.3 Tunnel control** — start/stop WireGuard, embed `wireguard-go`/wintun (mac/win), privilege helper.
- **S6.4 Connection UX** — status, server picker, split-tunnel toggle, tray icon, notifications.
  **SCOPE NOTE (captures the revocation-POC findings so nothing is re-discovered):**
  - **Base:** connection status, server picker, split-tunnel toggle, tray icon, notifications.
  - **(item 4) change-server / sign-out UI** — the client silently reused a stale `localhost` server +
    credential; the only recovery was deleting userData files by hand (never a customer action). The
    origin-keyed config already anticipates it; S6.4 adds the UI (surface the current server + a
    switch/sign-out affordance; `config.setServerUrl` already forces re-login).
  - **Revocation-aware teardown (NEW, from the revocation POC — the real S6.4 work):** when an admin
    revokes the device, the gateway drops the peer (traffic stops, ↓0 B), but the client keeps its
    interface up and retries handshakes forever. The client must DETECT peer-gone — persistent
    handshake failure past a threshold, and/or polling its own device status — then **auto-disconnect +
    clear the now-dead config** (the config is client-owned per D2, so nothing else tells it). Has its
    own tests (revoke → client tears down within N s; config cleared; no stale "Connected").
  - **ALREADY DOWN-PAID on `story/S6.3` (commit 7e99631) — do NOT rebuild:** (a) connection status is
    derived from HANDSHAKE liveness (no green "Connected" when the last handshake is stale >180s — kills
    the "Connected — handshaking…" contradiction); (b) the assigned tunnel IP is shown ("Your IP:
    10.99.0.x") — main caches the config address and attaches it to forwarded status. These two shipped
    early because a green-but-dead status is misleading even in a demo; S6.4 builds the rest on top.
- **S6.5a Packaging (unsigned)** — `electron-builder` `.dmg` + `.exe`, `SHA256SUMS`, an install
  script, and DOCUMENTED Gatekeeper (macOS) / SmartScreen (Windows) workarounds for unsigned
  artifacts. Ships in EPIC 6. Auto-update stays OFF (see S6.5b). This is the "friends & self can
  install it" milestone.
- **S6.5b Code-signing + notarization + auto-update — DEFERRED.** Apple notarization + Windows
  Authenticode, then flip `electron-updater` ON (the scaffold is inert until here — see S6.1 (d)).
  **Trigger = public beta OR first outside-the-inner-circle distribution** (not a calendar clock).
  **Windows EV blocker:** an EV cert requires a LEGAL ENTITY that does not yet exist — entity
  formation is additive lead time on top of the 1–3 wk EV validation, so start it when the trigger
  approaches. **Interim recorded:** an INDIVIDUAL Apple Developer ID (no entity needed) can sign +
  notarize macOS early if only macOS distribution is wanted first; Windows waits on the entity.
- **S6.6 Zero-build deploy (EPIC-6 epic-end) — from the POC's #1 friction.** PRINCIPLE: a customer
  must NEVER clone the repo, build from source, edit files, or run diagnostics to get a working
  tunnel. The POC required building on BOTH server and VM. Minimum-customer-effort =
  **published prebuilt images (ghcr.io)** + a **hosted compose file** + an **`install.sh` that asks
  for exactly two things** (public address; SMTP-or-skip) and writes a clean `.env`. This pulls most
  of **SB.1/SB.2 forward into reality** — those stories **shrink accordingly** (SB.1 Helm / SB.2
  hardening keep only what S6.6 doesn't cover). Depends on the CI publishing images (extend S6.0b) +
  S6.5a for the client side. **Pipe-safe from day one** (marketing's landing-page hero is
  `curl -fsSL https://get.tunnex.io | sh` serving THIS script): `install.sh` is safe to pipe blind
  into a root shell — idempotent (re-run reuses the DB password), write-then-move `.env` (never
  half-written), non-TTY env-var overrides (`TUNNEX_PUBLIC_ADDR` / `TUNNEX_SMTP`), loopback refused at
  the source, and a **SHA256 shipped alongside the release assets** so the docs offer a
  download-verify-inspect-run path (the security-conscious default) beside the one-liner.
  **OWNERSHIP (must not drift): there is exactly ONE `install.sh` — it lives in THIS repo (produced by
  S6.6). The marketing site only SERVES it (release asset / static file); it must NEVER fork or
  hand-maintain its own copy.** `get.tunnex.io` waits on the pending domain purchase — S6.6 does not
  block on it; the script just gets a URL later.
- **S6.7 Windows kill-switch persistence (from S6.5a's live-found gap)** — the Windows WFP full-tunnel
  kill-switch is NOT fail-closed on process death: wireguard-windows opens its WFP engine with
  `FWPM_SESSION_FLAG_DYNAMIC`, so filters auto-delete when the process exits → a hard-killed helper
  releases the block → traffic leaks (pcap-confirmed on the box 2026-07-10). macOS pf is persistent
  (proven); Windows is not. **Fix:** a NON-DYNAMIC WFP session (persistent filters) + a FIXED provider
  GUID + an explicit enumerate-and-delete `DisableFirewall` (the dynamic session did all cleanup for
  free — remove it and nothing does), reusing wireguard's proven filter set. **Recovery safety net**
  (bounds the blind-implementation risk): startup `CleanStale` removes any stuck block before re-arming,
  the dead-man still bounds it, service auto-start makes reboot a recovery, + a documented `netsh wfp`
  manual escape. **Decision-first, box-proven (pcap), reviewed** — a root kill-switch primitive, treated
  like S6.3. **Trigger: before Windows full-tunnel is offered to real users** (pairs with S3.7, since
  full-tunnel usability needs BOTH gateway egress + a real kill-switch). Until then the client gates/
  caveats Windows full-tunnel.
- **S-POC-fixes (hotfix story — STARTED NEXT, before resuming S6.3 remaining).** POC friction items
  2 + 3: **(2) ceremony one-time-secret COPY BUTTON didn't work** (manual copy needed) — a real UX
  failure; **(3) verify-email link emitted `localhost` on a REMOTE deploy** (`APP_BASE_URL` left at
  its default) — bootstrap must FAIL LOUD or warn when `APP_BASE_URL` is the localhost default while
  the process is clearly non-local. Both are immediate customer-facing bugs.

## EPIC 7 — Zero Trust Access *(enterprise)* — ✅ COMPLETE

- **S7.1 Policy model** ✅ (PR#14) — resources, groups, access rules (who → what), default-deny.
- **S7.2 Policy enforcement** ✅ (PR#16) — evaluate on connection + per-peer route filtering (via agent);
  conservative `policy_degraded` bool + org-wide push law.
- **S7.3 Device posture (basic)** ✅ (PR#17) — require known device, block untrusted.
- **S7.4 Policy UI + differentiated health + enterprise-e2e** ✅ — shipped as three PRs:
  - **S7.4a** Zero Trust admin UI (`/access`) ✅ (PR#18) + audit-nil-metadata hotfix (PR#19).
  - **S7.4b** differentiated health surface (advisory `policy_degraded_kind` OVER the bool, Option X) ✅ (PR#20).
  - **S7.4c** enterprise-e2e enabler ✅ (PR#21, sha `8ad71cd`) — SATISFIED the twice-deferred S4.5
    secret-payload + S4.5b orphan-render (blocking Go httptest + enterprise Playwright leg + `seed-enterprise`).

## EPIC 7.5 — ZTNA Competitiveness *(enterprise)* — NEXT (order LOCKED 2026-07-14)

Target segment = self-hosted / WireGuard ZTNA (Tailscale · Twingate · NetBird · Headscale), NOT the Zscaler
tier. Win = match-or-beat on ZTNA DEPTH while holding the differentiator (fully self-hosted, zero SaaS in the
trust path, air-gappable). L7/app-aware proxying · risk scoring · continuous re-auth = Tier-3 NAMES, NOT built.
Every story is decision-first (commit-one paper before code). Batch-1 items 1–4 are superseded-by-inclusion here.

- **S7.5.1 Flow / access logs** — **STARTS FIRST under every path.** Per-connection / per-grant access events,
  org-scoped, queryable + **exportable in a SIEM-ingestable shape (SIEM export is in the DoD, batch-3 #2)**.
  Builds on the S7.2 per-rule `counter` seam. Decide-before-code: event granularity · retention/rotation
  (customer disk) · append-only / audit-class storage posture · SIEM export shape · schema seam from counters.
- **S7.5.2 IdP-group sync + SCIM** — Entra/Google groups as policy SUBJECTS (sync, not mirror); SCIM rides or
  splits at paper. Enterprise-gated. Decide: IdP-authoritative vs merge-conflict rules; a deprovisioned user
  gets the full S2.6/S7.2 sweep.
- **S7.5.3 Posture checks v1** — extends S7.3's gate: OS version · disk-encryption · EDR-present; block-or-warn
  per org. Decide: client-reported attestation limits named HONESTLY (spoofable by a compromised device).
- **S7.5.4 Per-user + temporary grants** — USER as a subject kind in `policyspec.Compiled` (versioned-artifact
  bump per the S8 seam discipline) + grant EXPIRY that is **WINDOW-EXTENSIBLE** (extend before lapse, not
  delete+recreate; recompile+push on lapse, org-wide push law). **Decide before the S7.4a UI hardens the
  group-only habit.**
- **S7.5.5 MFA / TOTP** *(batch-3 #1, STORY-REQUIRED before outside-circle distribution)* — second factor for
  local auth. Decide-before-code: TOTP enrollment · recovery codes · per-org enforce policy · SSO-vs-local
  interplay.

## EPIC M — Mobile Clients (iOS + Android) — PARKED (RESTRUCTURED 2026-07-15; founder trigger)

**PARKED at the strongest tier with a NAMED TRIGGER: founder decision — revisit at BETA-BUNDLE PLANNING OR on a
demand signal (a design partner / prospect requiring native mobile), whichever first.** Native iOS + Android
Tunnex clients (login local+SSO + tunnel control, at the EPIC-6 desktop discipline). The one open decide-item —
**stage-1 (QR/config export into the official WireGuard apps) vs FULL native apps** — PARKS WITH the epic,
resolved at M's commit-one when it unparks (calendar costs per option, then).

**MOBILE-AT-BETA (the fact that softens the amendment):** mobile connectivity SHIPS at beta WITHOUT EPIC M —
the existing **S3.3/S3.4 QR / config export**, consumed by the **official WireGuard iOS/Android apps**, gives
mobile users a working tunnel; **gateway-side Zero Trust enforcement applies (transport-agnostic).** Pinned
POSITIONING LINE for site copy: *"Mobile via the official WireGuard apps; native Tunnex apps on the roadmap."*
Honest caveats (all = EPIC M's scope when it unparks): **no in-app SSO device creation** (config is minted from
the dashboard) · **no mobile posture reporting** · **no client-side mobile kill-switch.** **VERIFY-AND-RECORD
(small, rides an existing walk): the dashboard QR flow works end-to-end on the official WG mobile apps — one
leg; if a gap surfaces it is a small story, NOT EPIC M.**

## REGISTERED — UI REDESIGN + DESKTOP-CLIENT SPLIT (2026-08-01, founder-directed; PAPER ONLY, NOT STARTED)

**Full registration: `docs/UI-REDESIGN-registration.md`.** Source artifact = the Claude Design wireframe (12
dashboard screens + a desktop-client section), held by the founder, not in this repo.

- **ITEM A — the desktop client as a SEPARATE UI. REVERSES A LOCKED DECISION** (the "same bundle reused by the
  Electron renderer" lock below in EPIC 6). Recorded as a **decide-item, not a ruling.** The case: a desktop VPN
  client and a multi-tenant admin console are different products, and today a user installs a VPN app and gets
  an admin console with a Connect button in it. The wireframe already specifies the client in full (10-state
  taxonomy, tray vocabulary, handshake-derived status, MFA-by-browser-only). **Three open questions and a real
  refactor cost (`packages/shared` is generated types only) are listed in the paper.** **MUST BE RULED BEFORE
  the redesign's screen list is fixed** — else screens get designed twice.
- **ITEM B — the dashboard redesign, its own epic, arc-sized.** Faithful to the plan (it renders shipped laws as
  UI) and **closes four registered gaps**: domain capture · CLI-sessions panel · flow-log viewer (S7.5.1b) ·
  group-member surface (Deck-D). **Six commit-one decide-items in constraining order** — re-skin vs
  re-architecture · **component test tier lands FIRST or same-story, never after** (S11: zero component coverage,
  4 of 15 walk findings there) · per-screen render-floor audit (**two known violations already: "Fleet risk" is
  an unbuilt Tier-3 name; "Site-Link Throughput" is a rate time-series where S8.3 ruled L1 cumulative-only**) ·
  bulk destructive verbs · theme×palette×density · **edition gating behind ONE seam** so S12.1 rewrites a hook
  and nothing else.
- **ONE COPY FIX recorded now:** the wireframe's `'Free plan · cloud-hosted'` is wrong — **both editions are
  self-hosted**, the difference is features. It contradicts the wedge and would reach a launch screenshot.
- **SEQUENCING (founder-ruled):** EPIC 13 merge → **Item A ruling** → UI redesign → EPIC 11 remainder / BETA
  BUNDLE → S12.1 → beta. The redesign does NOT wait for S12.1. **Content-freeze interaction:** site screenshots
  come from this UI, so redesigning BEFORE the joint launch beats after.

## BETA BUNDLE — the pre-public-beta gate (a workstream bundle, joint launch with the site)

The set that must all land before PUBLIC BETA; the site goes live ONCE, synchronized (single complete launch).
**INTERNAL ORDER (approved 2026-07-14): S12.1 → S12.2 → S6.5b → rest** — the load-bearing runtime license-gate
goes FIRST (everything packaged/signed depends on the final edition-gating shape).
- **S12.1 — runtime license-gate refactor** *(FIRST; PULLED INTO THE BUNDLE — site-launch consequence)*:
  build-tag → runtime `LicenseManager`, **DECIDE-BEFORE-CODE, load-bearing — supersedes the S1.1 edition
  model.** Everything else in the bundle assumes the final edition-gating shape, so it leads.
- **S12.2 — Ed25519 offline issuance** *(PULLED INTO THE BUNDLE)* — the site's trial funnel delivers REAL keys
  at its only launch. Payments (**S12.5) stay PARKED.**
- **S6.5b** signing + notarization + auto-update ON *(named trigger now FIRED = public beta; Windows EV still
  waits on entity formation)*.
- *(S11.3 rate limits + security headers REMOVED 2026-07-15 — rejoins EPIC 11, which now runs FULL before the
  bundle.)*
- **SECURITY.md + vulnerability disclosure** *(batch-3 #5; seeded from the Armed Guards inventory)*.
- **S6.6 clean-VPS acceptance + client-wire-smoke** *(the pending EPIC-6 box-proof + the ledgered wire-smoke)* —
  **but its PROOF-run re-triggers to the "next available desktop/VPS session" (founder-schedulable NOW), NOT
  the now-distant bundle** (else several epics stack on unproven legs; the configured test-relay customer-path check rides it).
- **Go-module vanity rename** `tunnexio/tunnex` → `tunnex.io/…` *(trigger FIRED — domain purchased)*.
- **Site-sync joint cutover** — the platform emits SYNC EMIT-POINTS the site consumes (re-anchored 2026-07-15):
  **(a)** 7.5 close → compare/feature DRAFTS (not final); **(b) NEW:** 11 close → CONTENT FREEZE (the honest
  feature list now includes site-to-site, DNS, OpenVPN, K8s); **(c)** bundle done → joint cutover. The mobile
  claim uses the EPIC-M positioning line (*"Mobile via the official WireGuard apps; native on the roadmap"*),
  NOT an M-close point (M is parked).

## EPIC 8 — Site-to-Site Networking — opens next AFTER S7.5.2–S7.5.5 (RESTRUCTURED 2026-07-15)

**EPIC 8 is now EIGHT stories** (founder-directed 2026-07-18, +S8.6/+S8.7 2026-07-19): S8.1 model · S8.2 route propagation · S8.3 site UI · **S8.2c gateway zero-touch (inserted ahead of S8.4)** · S8.4 DNS · **S8.5 open-edition routed subnets** · **S8.6 hub HA** · **S8.7 CIDR-scoped rule sources (registered 2026-07-19, sequenced AFTER S8.6)**. The epic-close founder UI walk lands after S8.7 (covers the COMPLETE story: open edition + hub redundancy + CIDR-source policy).

**HUB BEHIND-HOST FORWARDING GAP — CLOSED verified-no-agent-fix-needed (2026-07-19, `walk-artifacts/hub-forwarding-verify/verify-record.md`).** The verify EXONERATED the forward chain: WF-4's `tunnex-site-fwd` DOCKER-USER accepts are present + firing (30 pkts), the hub's `Routes` correctly contain the spoke subnet (the daddr-scoped accept covers behind-hub→spoke), and there was NO manual iptables rule on the box (the "load-bearing manual rule" had been swept — likely a reboot). NOT a chain gap; the enforcing-mode denial of a behind-hub host is ZT working. **Live-proven the fixture-fidelity LAST quadrant** (genuinely-separate behind-hub `172.31.17.64` → behind-spoke `10.0.0.4`, cross-cloud): 0 grants → 100% loss; add a **site→site grant** (Source type = Site, live in the modal — `Access.tsx:636-640`) → renders `ip saddr 172.31.0.0/16 ip daddr 10.0.0.0/16 accept` → 0% loss, ttl 62 (two forwarded hops). MESH stance recorded: mesh = grant-free by design; enforcing = grant-required by design. The enforcing-granularity remainder folds into S8.7 (below). **This behind-hub-originated leg REGISTERS into the S8.5/S8.7 walk inheritance so the last quadrant stays covered in every future walk.** _(Original registration, now discharged:)_

**HUB BEHIND-HOST FORWARDING GAP — VERIFY-THEN-FIX (founder-directed 2026-07-19, URGENT — rides S8.4's close or a fast follow; does NOT interrupt the S8.4 walk).** At the cross-cloud demo the founder needed a MANUAL `iptables -A FORWARD -i ens5 -o wg0 -j ACCEPT` (+ reverse) on the AWS HUB before behind-hub instances could reach spokes — those rules are load-bearing NOW and won't survive a reboot (the urgency). **STEP 1 — VERIFY (read-only, cited):** do the D1/S8.2c forward accepts cover a behind-HUB host initiating OUTWARD to a spoke — which chain, what scoping, and does the hub's OWN local subnet appear in its accepts at all? (It is NOT in its own `Routes` by construction — Routes are OTHER sites' subnets.) Characterize the failure: agent-rule scoping hole vs chain-ordering vs genuine gap. **STEP 2 — IF a gap:** it is a ZERO-TOUCH LAW violation on the hub. Fix = **agent-owned symmetric accepts covering the hub's local-LAN↔tunnel case, `Routes`+`LocalSubnets`-scoped, marked/swept per the shared-territory ownership law** (`docs/laws.md`). **REFUSED IN ADVANCE:** any UI-pushes-raw-iptables surface — arbitrary rule push CP→gateway is a remote-execution surface in a convenience costume; the AGENT owns its rules, the CP owns INTENT. The founder's manual rules get REMOVED in the fix's re-walk. **This is the fixture-fidelity law's LAST uncovered quadrant** — no walk ever originated from a genuinely-separate host behind the HUB; the fix's red + walk leg close it. **Walk deck note (S8.4 + the fix walks):** behind-host legs must NOTE any manual iptables currently present on the hub.

**S8.6 — HUB HA (multi-hub) — REGISTERED (founder-directed 2026-07-19; the multi-hub seam UNPARKS — founder is the first named demand, the trigger fired). Sequenced AFTER S8.5. Honest sizing: an S8.2-class arc.** Commit-one decide-item SKETCH: hub-set election (N hubs, priority) · spoke multi-hub WARM tunnels · **failover detection + decision RIDING existing PROVEN staleness clocks (hard design constraint from the budget-rule history — NO clever per-tick logic; the dormant-machinery + ride-a-decision laws bind here)** · flap damping · split-brain stance stated HONESTLY · route-flip under the four-word reconcile model · **walk = a LIVE hub-kill with traffic re-routing via hub-2, behind-hosts on BOTH ends, a THIRD VM required.** The parked **HA-posture ledger items (batch-3 #4, site-gateway-redundancy)** FOLD into this story's paper.

**S8.7 — CIDR-scoped rule sources — REGISTERED (founder-directed, live-walked 2026-07-19; SECOND same-day founder demand). Sequenced AFTER S8.6. RE-SHARPENED post-verify: this is CIDR-source for /32-HOST PRECISION, NOT "add site-source" (site-source ALREADY EXISTS + is live-proven).** **The gap (founder hit it live):** the Access modal cannot express a specific-source-IP `172.31.17.64/32 → 10.0.0.4/32` for a SINGLE behind-gateway host. **Correction to the original read:** the modal DOES offer **Site (a LAN behind a gateway)** as a Source type (`Access.tsx:636-640`, `src_kind='site'` from S8.2, migration 0035) — the walk-read of "Group/User only" was incomplete. Site-source covers the COARSE case (whole `172.31.0.0/16` → whole `10.0.0.0/16`) and is **live-proven** (hub-forwarding verify leg). S8.7 adds the missing PRECISION: a `src_kind='cidr'` for a specific host/subnet source, so `172.31.17.64/32` (not the whole LAN) can be named. **PLACEMENT (argued):** standalone S8.7 IN EPIC 8, not folded into a future generic policy-granularity story — the demand is behind-gateway-host↔behind-gateway-host, intrinsically a site-networking scenario, and `src_kind='cidr'` rides the **site-src `saddr` compiler path proven in S8.2**; folding it out would divorce it from the exact machinery it mirrors + defer a founder-hit gap. **Commit-one sketch:** `src_kind='cidr'` on the existing enum seam (`policy_rules.src_kind`) · compiler **`saddr` emission mirroring the site-src path** (S8.2 already proved the saddr class) · **version/hash classification argued per the D2-checklist row — enforcement-significant, LIKELY rides the existing v5 since site-src already proved the saddr class, but VERIFY don't assume** (a new saddr-source that changes no wire field but changes the match set) · modal **Source dropdown gains Resource/CIDR, symmetric with the destination** side · **one validator + typed refusals** per convention (the CIDR validated once, no JS re-check). **Sequencing stays honest:** after S8.6 — S8.4's merge, the hub-forwarding fix, S8.5, and HA do NOT move; this registers now so it can't be lost and builds in its slot.
- **S8.7 ALSO carries — EXPIRED/REVOKED GRANTS MUST TERMINATE ESTABLISHED FLOWS (founder-walked 2026-07-19, verified read-only).** **Finding:** an expired/deleted grant removes the ACCEPT rule but does NOT kill in-flight flows — the forward chain's `ct established,related accept` honors an already-open flow indefinitely (a chatty sender refreshes its own conntrack entry); only re-establishment is denied. Founder verified LIVE: a ping survived the grant's expiry timestamp; a re-started ping was correctly refused. **Verify, cited:** (a) **S7.5.4's paper is SILENT** on established-flow semantics — D2 (`docs/S7.5.4-decisions.md:101-116`) addresses the /32 leaving the ACCEPT set, never conntrack. (b) **Device revocation = PEER REMOVAL** (`devices/service.go:496`) = a crypto-layer stop, EFFECTIVE, NOT the same class; the vulnerable class is **grant-expiry / rule-deletion where the peer STAYS** (device-grant removed but device connected; site-grant removed but sites peered). The **conntrack-kill seam is already RESERVED** (`flowlog/event.go:22-23`, `accesslog/event.go:24` `DecisionTerminated` + RuleID binding) but **NEVER built** (grep: no `conntrack -D` anywhere). **Fix:** the grant-expiry sweeper AND the rule-deletion path gain a **SCOPED conntrack flush keyed on the removed rule's tuple** (src/dst/proto) — **NEVER a blanket flush** (which would kill every innocent flow on the box). Red: a live flow crossing expiry dies within the sweep interval; an unrelated flow survives the flush. **Walk leg:** the founder's exact scenario — ping running, grant expires, ping stops.

**FOUNDER-DIRECTED REGISTRATIONS (2026-07-19, product-improvement review — none jump the queue):**
- **CONNECTIVITY CHECKER / PATH EXPLAINER — flagship POST-EPIC-8 story (first named demand: founder, 2026-07-19).** A site-card **"test path to <site>"** that walks the layers and names the likely fix (handshake ✓ / route ✓ / fabric ✗ → "your Azure UDR / AWS route-table is missing X"), PLUS an Access-page **path-explainer** ("would A reach B? → **denied: no matching grant**" / "allowed via rule R"). **Spec source = the demo/verify tcpdump archaeology** — every layer we debugged by hand this epic (bind-scope, forward chain, grant render, fabric route, conntrack) becomes a check the PRODUCT runs. This is the "stop SSHing the box to debug" story. Sized post-EPIC-8.
- **SUBNET-CONFLICT GUIDANCE — rides S8.5's scope (one message edit).** The disjointness refusal for a range-collision gains TEACHING text: *"both sites use `X` — options: renumber one, or subnet-mapping [roadmap]"* (not just `subnet_not_disjoint`). The FULL **NAT-mapped-subnets** feature (the `192.168.1.0/24` branch-twins problem — map colliding LANs to non-overlapping virtual ranges) registers as a LEDGER item, **trigger = first prospect with colliding branch LANs**. S8.5 ships only the teaching text.
- **"CONNECT TWO SITES" GUIDED FLOW — EPIC-CLOSE CANDIDATE, decided AFTER the founder's epic-close walk.** A guided "connect site A to site B" wizard. **Deliberately NOT built before the walk** — the founder's stumbles ON the walk are the spec; building it first guesses at them. Decide at epic-close.

**S8.2c — "site-to-site end-to-end via UI" (gateway zero-touch) — REGISTERED NEXT (founder-directed 2026-07-18, ahead of S8.4).** Born from the cross-cloud demo (AWS Sydney↔Azure West US PROVEN at 138ms, but only after 6 manual gateway touches + 3 UI gaps — see `walk-artifacts/cross-cloud-demo/demo-record.md`). **The ZERO-TOUCH GATEWAY LAW (`docs/laws.md`) is the paper's first line + the acceptance bar:** the demo re-runs clean — fresh org, two cloud VMs, the ONLY terminal action a pasted join command; sites/subnets/enforcing/grant/behind-gateway-host-reaching-far-site all CLICKED. **That re-run IS the story's box-walk.**
- **Decide-items (commit-one, proposed dispositions held for founder ruling):**
  - **#5 behind-host reach — RE-CHARACTERIZED by (b): the S8.2 COMPILER IS EXONERATED** (enforcing+grant emits the correct symmetric iifname-agnostic `saddr/daddr accept`; not a data-plane defect). The blockers are **deploy-class**: (a) **cloud-fabric routing** — Azure UDR / AWS route-table + source-dest-check for a behind-host to reach the gateway (the CP's packet was dropped by Azure SDN *before* the gateway, no UDR); (b) **mesh mode emits no LAN→tunnel forward rule** (only enforcing+grant does — a mode gap, likely by-design). So NOT a forced Slice-1 compiler fix — folds into #3 (host/cloud-networking) + a mesh-mode-forwarding decide-item. Red still owed: a genuinely-separate behind-gateway host initiates cross-site end-to-end (the fixture class whose absence hid this — the fixture-fidelity TOPOLOGY-SIBLING law) — WITH the cloud UDR/route-table as an emitted/documented step.
  - **#4b src-hint in `ApplyRoutes`** — the agent programs site routes with the correct source; red: **survives reconcile** (today it clobbers a manual fix).
  - **#3 host-networking stance** — decide (host-mode required+emitted vs bridge+forwarding); the agent must **refuse-loudly when it can't reach what it advertises**.
  - **#1/#2 emitted install command** — the join-token screen produces the ONE true `docker run` for a remote gateway (wgctrl, host networking, all envs, endpoint param); compose remains for co-located.
  - **GAP-2 site rules in the Access builder** — src/dst site options in the modal (S8.3 built display, not create; this completes it), disjointness/validation riding the EXISTING API path (no new bypass).
  - **GAP-1 org creation + GAP-3 add-rule-with-zero-groups** — small UI items, same slice as #5.
- **Protocol UNCHANGED:** commit-one (dispositions held) → slices → gates → story-end review → the demo-re-run walk (Pawan drives). **NO scattered hotfixes** — the S8.2 four-round arc is the standing proof that "just fix it" on this component breeds defects.
- **Sequencing:** S8.2c → S8.4 → S8.5. **S8.5's scope SHRINKS by whatever S8.2c absorbs** (the container→host routing/NAT honesty + emitted-command shape overlap) — noted in the S8.5 registration.

**S8.5 — open-edition routed subnets (split-tunnel push routes) — REGISTERED (founder-directed 2026-07-18). SCOPE-SHRINKS by whatever S8.2c absorbs** (the container→host-LAN routing/NAT + emitted-install-command shape overlap the S8.2c gateway-zero-touch work; S8.2c lands first, so S8.5 inherits a gateway that already reaches its host LAN correctly).
Per-gateway admin-declared LAN CIDRs → compiled into device `AllowedIPs` + gateway forward rules → those ranges route via the gateway, the rest direct. **Open edition, no policy engine**; enterprise INHERITS the ranges as policy destinations (ONE mechanism, edition-gated depth). Founder rationale: **Pritunl push-routes parity — the migration wedge's table-stakes config.**
- **Sequencing:** after S8.4, BEFORE the epic-close founder UI walk.
- **S8.4 COUPLING (binds S8.4's commit-one):** S8.4 DNS design must treat routed-LAN ranges as a KNOWN SIBLING of site subnets — DNS decided blind to S8.5 would bake in a redo. **S8.4's paper MUST state this coupling.**
- **Known bindings for S8.5's commit-one:** the disjointness validator gains a THIRD input class (routed-LAN ranges alongside site subnets + pool) · **NAT/return-path stated explicitly** (SNAT vs documented static-route) · fleet-wide **device-config blast radius = full protocol** (a routed range changes every device's `AllowedIPs`) · **D2 enforcement-vs-observability classification answered, not assumed.**
- **S8.5 ALSO carries (from the S8.3 walk close, founder-directed):**
  - **S8.4b — Windows NRPT domain-scoped resolvers (parity for S8.4's macOS `/etc/resolver`) — REGISTERED (founder-directed 2026-07-19).** S8.4 STAGES the client-side resolver mechanism macOS-first (`/etc/resolver`, file-drop simple, S6-trodden); Windows is deferred here, NOT dropped — parity is scheduled. **Trigger = S8.5's device-routes slice going green** (device→site DNS is S8.5-gated/inert until then; NRPT is the first-ever helper touch on a novel Windows subsystem — the WFP proofs don't transfer, so it must be REVIEWED + WALK-PROVEN in the story where a Windows machine can actually resolve a cross-site name, per the S8.2 #5 lesson: the un-exercisable path is where the defect lives). **Terms:** own helper verb (mirror `VerbSetResolvers`; the protocol field + validation already exist, added in S8.4) + its own red + **the kill-switch/revocation-untouched probe (pre-registered NOW, inherited THEN)** + owned-marker/full-sweep discipline mirroring the macOS `/etc/resolver` reconcile. **The S8.5 walk gains the Windows name-resolution leg.** (S8.4 helper stub already returns `resolvers_unsupported` on Windows → client fail-STATIC today.)
  - **S8.4b/S8.5 ALSO carries — the CRASH/OWNER-LOSS resolver sweep (deferred from S8.4's round-3 reduce-by-removal, founder-directed 2026-07-19).** S8.4 keeps ONLY startup `CleanStaleResolvers`; the crash/owner-loss sweep was built twice (eager per-exit, then a kill-switch release-rider) and generated three defect rounds on DORMANT machinery — the client installs NO resolver files until S8.5, so there is no crash residue to sweep in S8.4. **NAMED ORDERING PRECONDITION (so it can't be forgotten and can't ship late):** when the client resolver path goes live (S8.5/S8.4b), the crash/owner-loss sweep MUST land BEFORE the first `set_resolvers` install path activates — a resolver file must never be able to exist without its teardown mechanism already present. Design it exercisable + red-able + walk-provable (a crash-mid-session leg on the S8.5 walk), NOT as dormant lifecycle code. See `docs/laws.md` shared-territory instance #4 + the dormant-machinery addendum.
  - **Metrics L1 — site-link byte counters (tx/rx) + handshake age on the S8.3 topology cards.** SIZE IT here (same report-plumbing neighborhood; the agent already parses `wg show dump`, S3.6). A report-path extension + a UI join. **Render-floor:** cumulative-since-handshake totals labeled as EXACTLY that — NO rate graphs, NO sampling implied (that is S11.1's job).
  - **Walk-found UX fix — stale Add-rule button after group-add** (pre-existing cross-section staleness on the Access page; founder-found at the S8.3 walk). Rides **S8.5 or the epic-close fold, whichever lands first**. Lift `groups` to the parent / reload RulesSection on group-add.
- **PREREQUISITE — run BEFORE S8.4's paper (read-only, cited answers; feeds BOTH S8.4 and S8.5 papers):** the two-part verify-item — **(a) enterprise:** do granted resource-CIDRs already flow into device `AllowedIPs` today? **(b) open:** what surface exists today for gateway-reachable LAN routes — configured / partial / missing? Answer with citations before S8.4 commit-one.

**INHERITS the S7.5.1 versioned-artifact discipline** (sites-as-destination-kind bumps `policyspec.Compiled`):
(1) the **newer-Version FAIL-CLOSED decide-item** — an agent receiving a Version it doesn't speak must refuse →
deny-all + `policy_degraded` (today it silently accepts; S7.5.1 ledger, decide-before-code AT this bump since
sites is a SEMANTIC change) · (2) the **enforcement-vs-observability PROJECTION checklist** — every new
`Compiled`/`AllowEntry` field is classified; enforcement → into `CanonicalHash`'s projection, observability →
out (S7.5.1 A-1). See docs/S7.5.1-decisions.md.

**HARDENED at S7.5.4 box-walk (2026-07-16) — the newer-Version gate is now a BLOCKING S8.1 item, not a
discretionary one.** The walk confirmed `ProtocolVersion` has already bumped **1→2→3** (S7.1 v1 · S7.5.1 v2
`rule_id` · S7.5.4 v3 `src_device_id`) with **NO consumer-side gate** — the node applies ANY Version,
safe-ignoring unknown JSON fields (proven: reconcile `policy_test.go` applies v5/v6). This has been safe ONLY
because every bump so far is **observability-additive + hash-blind + safe-ignore, each unit-pinned** (v3:
`TestCanonicalHashSrcDeviceIDIsObservabilityOnly`). Bindings inherited by S8:
- **S8.1 commit-one MUST build the fail-closed gate** (`Version > maxSupported → refuse → deny-all +
  policy_degraded`) BEFORE the first enforcement-significant wire field (sites-as-destination IS that field).
  Blocking decide-item, not optional.
- **Interim law (until the gate lands):** every `ProtocolVersion` bump owes its OWN hash-blindness +
  safe-ignore unit pin (the v3 pattern) — this is what keeps the unguarded window safe if anything bumps
  before S8.
- **Honesty:** the model is **safe-by-CONVENTION, not safe-by-construction** — "nobody ships an
  enforcement-significant field without the gate" is mechanized by NOTHING until S8 (the branch-protection
  lesson class: a convention holding is not a guarantee). See docs/S7.5.4-decisions.md §D5-reaffirmed.

**LEDGERED at S7.2 (decide-before-code for S8.1/S8.2): Zero Trust policy MUST govern site-to-site
traffic.** Sites/subnets become a policy DESTINATION KIND — extending the S7.1 model through the
VERSIONED `policyspec.Compiled` artifact (bump the version; agents gate on it), not a side channel.
**S8.2's propagated routes are compiled-policy OUTPUT, never a parallel enforcement path:** under
`enforcing`, a site subnet is reachable ONLY via an explicit grant; under `off`, the legacy mesh —
the same mode-as-compiler-input principle S7.1 locked (one code path, one artifact, mode selects
what's compiled). **Deliberate-red at S8.2:** enforcing + zero grants → a propagated site subnet is
ROUTED but DROPPED at the gateway forward chain (routing ≠ permission). Note **S10.3 already
presumes this seam** ("expose in-cluster services via Zero Trust policies") — it is load-bearing for
EPIC 10 too; do not build S8 routing without it.

**LEDGERED at S7.2 (more S8.1/S8.2 decide-before-code + a promoted story):**
- **Site-link TRANSPORT is a modeled enum field from day one** (S8.1 schema), with **wireguard the
  only implemented value**. This RESERVES the parked IPsec-interop seam (for agent-impossible
  endpoints: managed cloud VPN gateways — AWS TGW / Azure VPN GW — hardware appliances, partner
  networks) without a later migration. **IPsec itself stays PARKED** — trigger = a real
  customer/prospect with an agent-impossible endpoint AND **after EPIC 9 ships** (no third protocol
  before the second is proven). If ever built: **strongSwan managed by the node agent per the S9.1
  pattern, site-to-site ONLY** (no IPsec end-user clients), and the **tested-interop matrix is bounded
  at story-open** (strongSwan↔strongSwan + AWS/Azure managed endpoints; arbitrary-appliance interop
  explicitly best-effort — an unbounded vendor matrix is REJECTED in advance). **Routing + Zero Trust
  enforcement are transport-agnostic by design — state this in S8.1.**
- **Subnet-advertisement decisions (S8.1/S8.2):** (a) **overlapping advertisements across sites →
  REFUSE the second** (typed clean error, `gateway_no_egress`-style) in v1; precedence/longest-prefix
  semantics DEFERRED (trigger = first real customer need). **Silent ambiguity is the one forbidden
  outcome.** (b) **Advertisements require control-plane/admin APPROVAL before propagation** — a
  compromised site gateway must not hijack routes by advertising subnets it doesn't own; **approved ≠
  reachable** (Zero Trust grants still gate reachability, per the ledger above / d21cf19). (c) Manual
  route pinning DEFERRED alongside (a).
- **S8.4 Cross-site DNS — PROMOTED to an in-scope story** (below). Rationale: subnet reachability
  without name resolution is half a feature for real users, and it is the #1 competitor-comparison
  line. The device config's DNS field (S3.4) is the client-side seam; **S8.1's schema RESERVES the
  site-carries-DNS-forwarding-entries seam** as S8.4's foundation.

- **S8.1 Gateway/site model** — register site gateways (each a `tunnex-node` agent), subnet routing.
  **Reserves: link transport enum (wireguard only), site DNS-forwarding entries (S8.4). Routing + ZT
  enforcement transport-agnostic.**
- **S8.2 Route propagation** — advertise/accept routes between sites via WireGuard, reconciled by agents.
  **Advertisements need admin approval; overlaps refused (typed); approved ≠ reachable (ZT gates).**
- **S8.3 Site management UI** — add site, topology view, health.
- **S8.4 Cross-site DNS** *(promoted from candidate, S7.2 review)* — mesh name resolution (devices +
  site hosts resolvable by name across the mesh) + **split-horizon per-site forwarding** (a domain →
  that site's existing internal resolver, queries routed over that site's tunnel). Decision-first,
  **sequenced after S8.2**. Reference design: MagicDNS + split-DNS.

**STANDING INSTRUCTION — EPIC-8-CLOSE FOUNDER UI WALK (folded from S8.1, ruled 2026-07-17):** after
S8.4 merges (the epic's LAST merge), a founder-driven full-surface click-through of the INTEGRATED
site-to-site whole — rules → sites → topology → health in one journey (S7.5.5 protocol: founder clicks,
findings HELD for disposition). S8.3 (the dedicated UI story) carries its OWN UI-heavy walk; this
epic-close walk covers the integrated surface end-to-end. Plan S8.3's walk with that division in mind.

## EPIC 9 — OpenVPN Support (port from existing Bolster stack, not greenfield)

- **S9.1 OpenVPN server mgmt in node agent** — port `openvpn-auth-oauth2` patterns + `genclient`-style PKI into the agent; managed process, cert/PKI, config gen. Reference the Bolster handover doc as the spec.
- **S9.2 OpenVPN profiles** — `.ovpn` export, per-user certs, revocation (CRL) — same identity-binding rule as S3.3. **The `.ovpn` export is the OpenVPN client story (made first-class here + S9.3): per-OS import instructions + a QR on the download page, consumed by the OFFICIAL OpenVPN clients (OpenVPN Connect / Tunnelblick / mobile). Revocation guarantees hold FULLY (CRL + the full-sweep of §Cross-Cutting: cert/CRL revoke + address release + status clear).**
- **S9.3 Protocol selection** — org/server chooses WireGuard or OpenVPN. **"Clients support both" — DECIDED (not open), so it isn't re-litigated:**
  - **Path (a), delivered:** OpenVPN is consumed via the `.ovpn` export (S9.2) by the standard OpenVPN clients. The **Tunnex desktop client stays WireGuard-ONLY** — it is WireGuard-only BY CONSTRUCTION (embedded wireguard-go/nt, WG-typed helper verbs, pf/WFP kill-switches, WG ConfigProvider, handshake-based revocation detection); nothing in EPIC 6 or 9 builds an OpenVPN engine into it.
  - **Optional S9.x (decide-at-open):** the `tunnex` CLI wraps `openvpn` as it already wraps `wg-quick`. Small, sandboxed, no privilege-helper blast radius.
  - **Positioning line (pinned):** "both protocols" = both **server-managed with full revocation**; **WireGuard gets the native Tunnex client, OpenVPN uses standard OpenVPN clients.** NEVER "our desktop app runs OpenVPN."
  - **REJECTED (strongest deferral tier — the rejected-call-home-licensing class, NOT parked-with-trigger): native OpenVPN INSIDE the Tunnex desktop client,** unless a paying customer makes it a hard deal condition. Rationale (recorded so it isn't re-argued): a second data-plane engine inside the privilege helper — the most security-critical, most expensively-verified component (S6.3 decide-before-code + live-pcap kill-switch proofs ×2 platforms + S6.7) — would need a managed-process `TunnelUp` path (exactly the injectable-surface class S6.3 rejected), OVPN-specific kill-switch semantics, cert-based config storage, CRL revocation detection, and a permanent **2× proof burden on every future helper change** — all for a population whose migration endgame is the WireGuard client we already ship. Reference competitor (Tailscale) ships ZERO OpenVPN and wins those migrations anyway.

## EPIC 10 — Kubernetes Integration

- **S10.1 Helm chart** — deploy full tunnex stack to a cluster; values for secrets, ingress, storage.
  **Shared seam obligation:** the external DB/Redis + master-key env contract
  (`TUNNEX_DATABASE_URL`/`TUNNEX_REDIS_URL`/master-key source) is the SAME one install.sh uses — do not
  diverge from the S6.6 ledger (see docs/S6.6-decisions.md "external DB/Redis"); the master-key
  externalization decide-item is load-bearing here (external DB customers).
- **S10.2 Operator + CRDs** *(enterprise)* — `TunnexPeer`, `TunnexRoute`; reconcile WG peers/routes as k8s resources — **reuses the S3.1 reconcile loop design**.
- **S10.3 Cluster gateway** — expose in-cluster services to tunnex clients via Zero Trust policies (agent as in-cluster gateway). **Depends on the EPIC 8 ledger seam** (sites/subnets as a policy destination kind in the versioned `Compiled` artifact) — in-cluster service exposure is the same "subnet reachable only via grant" mechanism.

## EPIC 11 — Production Hardening — runs FULL before the BETA BUNDLE (RESTRUCTURED 2026-07-15)

*(S11.3 rate limits + security headers REJOINS here — it was pulled into the bundle under the old order; the
new order runs EPIC 11 complete before the bundle, so the bundle sheds it.)*

- **S11.1 Metrics** — Prometheus metrics, health/readiness (logging already in EPIC 0). **Metrics L3 (added at S8.3 walk close, founder-directed):** site-link throughput TIME-SERIES joins the Prometheus metric set when S11.1 opens — NOT pulled forward (S8.3's card counters are cumulative-since-handshake only; rate/time-series is S11.1's job).
- **S11.2 Backup/restore** — DB + master key **+ node-agent state (WG private keys on each gateway)**; documented restore.
- **S11.3 Rate limiting & security headers** — API abuse protection, TLS via nginx, secrets hygiene.
- **S11.4 Docs & install guide** — self-host quickstart, upgrade path.

**LEDGERED (S7.2 box-proof finding #2, DEFERRED): targeted conntrack-kill on Zero Trust grant change.**
Today `ct established,related accept` (the return-path guard) lets flows ESTABLISHED under a prior
policy DRAIN until idle when a restriction takes effect — covers BOTH enabling `enforcing` AND deleting
an existing grant; NEW flows are blocked immediately, and revocation/offboarding is unaffected (wg peer
removal kills the tunnel). To terminate in-flight flows the instant a grant is removed, the agent would
delete the conntrack entries matching the removed allow. **Trigger = first customer/compliance need for
immediate flow termination on grant change.** Pairs naturally with the flow-logs candidate (S7.2 already
emits per-rule `counter`s) — the same per-rule identity drives both. Documented in docs/S7.2-decisions.md.

## ZTNA COVERAGE + GAP LEDGER (batch-1, recorded during S7.4b) — DISPOSITIONED 2026-07-14 (items 1–4 superseded-by-inclusion into EPIC 7.5 / batch-3; items 6–8 carry into EPIC 9/10 unchanged; historical record below)
1. **Flow / access logs — PROMOTION CANDIDATE.** Argue at EPIC-7 close for EPIC-7-ADJACENT, *ahead of
   site-to-site* if needed. Seam exists: the S7.2 per-rule `counter`s. Buyer-facing property = "who accessed
   WHAT, WHEN" — compliance/sovereignty buyers treat this as the *reason to buy ZTNA*; "ZTNA without access
   logs" is the competitor's line against us. (Pairs with the conntrack-kill item above — same per-rule identity.)
2. **IdP-group sync (Entra/Google groups → policy subjects) — enterprise-gated.** Without it, policy groups
   must manually mirror the directory and decay immediately. Candidate: EPIC 7.x / EPIC 8 era.
3. **Posture DEPTH (OS version · disk-encryption · EDR-present).** S7.3 is KNOWN-device, not HEALTHY-device.
   Needs a story number + named trigger = **first compliance-driven prospect**.
4. **Per-USER grants.** Rules are group→resource only; "give Alice temporary access" has NO path. DECIDE
   (user-as-a-subject-kind vs a blessed one-user-group UX) **before the policy UI hardens the habit** (S7.4a
   shipped group-only; revisit before it ossifies).
5. **S7.4b scope note.** The differentiated-health BADGE is *enforcer-health*, NOT *access-visibility* — the
   larger visibility half is item 1 (flow/access logs). Don't let the badge read as "we have visibility."
6. **ZT-coverage: OpenVPN (S9.1 DECIDE-BEFORE-CODE — REQUIRED).** OVPN devices MUST be policy subjects in the
   SAME `policyspec.Compiled` artifact (grants are transport-agnostic); **cert-auth alone is NOT enforcement**.
   Deliberate-red at S9.1: `enforcing` + zero grants → OVPN client traffic DROPPED at the forward chain, same
   as WG. A parallel non-compiled OVPN path = a two-door breach — **rejected in advance**.
7. **ZT-coverage: DNS under enforcing (S8.4 PAPER ITEM).** Split-horizon DNS needs port-53-to-site-resolver
   reachability MODELED (a grant, or an explicit modeled exception) — else name resolution breaks silently
   under `enforcing`.
8. **ZT-coverage: full-tunnel egress under enforcing (S3.7 DECISION-REVIEW ITEM).** Decide whether internet
   egress is a policy DESTINATION KIND (an "internet" resource) or explicitly OUT-OF-ZT-SCOPE; currently
   UNDEFINED under `enforcing` (a full-tunnel device under enforcing with no egress grant = undefined behavior).

## ZTNA COMPETITIVE SCOPE — LEDGER BATCH 2 (user-directed strategic intent, 2026-07-14; PAPER only, no epic reorder executed — DISPOSITION AT EPIC-7-CLOSE PLANNING). Extends batch-1 items 1–4 from "gaps" → COMMITTED competitive scope.
**STRATEGIC FRAME (pinned; refined 2026-07-14 post product-assessment):** **DIRECT competitive set = NetBird ·
Firezone · Netmaker · Defguard** (the self-hosted, WireGuard, ZTNA+SSO products that overlap Tunnex head-on).
**Tailscale = the ANCHOR / category-definer** (reference for DX + mesh magic, NOT a head-to-head target — we
do NOT compete on developer-DX breadth). Twingate/Headscale = adjacent references. NOT the Zscaler tier.
**Win condition:** match-or-beat the DIRECT set on ZTNA DEPTH while holding the differentiator — **fully
self-hosted, zero SaaS in the trust path, air-gappable** — the wedge that Tailscale/Twingate (SaaS control
plane) structurally can't hold and Headscale (community reimpl) doesn't productize. L7/app-aware proxying,
risk scoring, continuous re-auth = Tier-3 roadmap NAMES, explicitly NOT built. **NAMED WEAKNESS (honest):** no
relay/NAT-traversal fleet (batch-3 #3) = a real UX gap vs the Tailscale-likes; positions Tunnex as
"modern Pritunl/sovereign ZTNA," not "connects-anywhere mesh" — target buyers who value the wedge over the magic.

**PROPOSED EPIC 7.5 — "ZTNA Competitiveness" → RATIFIED 2026-07-14 (the `## EPIC 7.5` section above is CANONICAL,
incl. S7.5.5 MFA/TOTP + the locked order; THIS block is the HISTORICAL record — do not edit its story list):**
- **S7.5.1 Flow / access logs** — per-connection / per-grant access events, org-scoped, queryable + exportable;
  builds on the S7.2 per-rule `counter`s seam. **Starts FIRST under any beta outcome.** Decide-before-code:
  event granularity, retention/rotation (customer's disk), append-only / audit-class storage posture.
- **S7.5.2 IdP-group sync + SCIM** — Entra/Google groups as policy SUBJECTS (sync, not mirror); SCIM rides or
  splits at paper. Enterprise-gated. Decide-before-code: IdP-authoritative vs merge-conflict rules; a
  deprovisioned user gets the full S2.6/S7.2 sweep.
- **S7.5.3 Posture checks v1** — extends S7.3's gate: OS version · disk-encryption · EDR-present; block-or-warn
  per org. Decide-before-code: client-reported attestation limits named HONESTLY (spoofable by a compromised
  device — threat model stated, not oversold).
- **S7.5.4 Per-user + temporary grants** — USER as a subject kind in `policyspec.Compiled` (versioned-artifact
  bump per the S8 seam discipline) + grant EXPIRY (`expires_at` → recompile+push on lapse, org-wide push law).
  **Decide before the S7.4a UI hardens the group-only habit.**

**Tier 2 (carriers exist — confirm at session):** S8.4 internal DNS (stands) · EPIC 8 site-to-site under policy
(pre-wired, stands) · connection-events / session-lite (extension of S7.5.1) · SCIM (in S7.5.2).
**COLLISION flagged for planning (user decision, NOT pre-decided):** EPIC 7.5 vs the beta re-decide — beta at
EPIC-7-done while building 7.5 during beta, OR beta after Tier 1. Flow-logs-first is common to both paths.
**Consequences acknowledged:** EPIC 8/9/10 slide right ~one epic; the EPIC 9/10 ZT-coverage guarantees
(batch-1 items 6–8) UNCHANGED. Batch-1 items 1–4 are SUPERSEDED-BY-INCLUSION into S7.5.1–S7.5.4.

**S7.5.4 CONSTRAINT (recorded at S7.4c-close):** temporary grants are **WINDOW-EXTENSIBLE**, not expiry-only —
a grant carries a time window that can be EXTENDED before it lapses (renew/extend, not only set-and-expire).
Design `expires_at` + the recompile-on-lapse seam so an extend is a window bump, not a delete+recreate.

## PRE-LAUNCH LEDGER — BATCH 3 (user-directed 2026-07-14; recorded at S7.4c-close / EPIC 7 COMPLETE, PR#21 sha 8ad71cd; PAPER — DISPOSITION AT EPIC-7-CLOSE PLANNING) — COMPLETE (10/10)
1. **MFA / TOTP — STORY-REQUIRED** (own story, not a ride-along) → **S7.5.5**: second factor for local auth
   before any outside-circle distribution. Decide-before-code (TOTP enrollment, recovery codes, per-org enforce
   policy, SSO-vs-local interplay).
2. **SIEM export — folds into the S7.5.1 (flow/access logs) DoD:** the access-event stream must be EXPORTABLE in
   a SIEM-ingestable shape (syslog/CEF/JSON push or pull), not just viewable — bake into S7.5.1's DoD.
3. **NAT-traversal limitation NAMED** — no relay fleet; gateways need public reachability / port-forward,
   CGNAT clients may fail direct connect. Document-as-DEPLOYMENT-REQUIREMENT now; optional STUN/relay item,
   trigger = repeated prospect friction.
4. **Control-plane HA posture** — decide-item, rides **S10.1 / S11**: state the supported HA shape + the
   already-true guarantee (a CP outage NEVER kills running tunnels — agents reconcile) as a public operational
   claim.
5. **SECURITY.md + vulnerability disclosure** — trigger = repo-public / beta; seeded from the Armed Guards
   inventory. (In the beta bundle.)
6. **External security audit / pentest** — trigger = first enterprise deal OR GA; scope candidates: the
   privilege helper, the kill-switches, the policy engine.
7. **Security whitepaper / public trust page** — productize the box-proof / armed-guards story; pre-beta
   candidate (feeds the site's /security).
8. **Mobile clients → EPIC M** (new epic, iOS/Android WireGuard clients; CONFIRMED for insertion — see
   decisions below).
9. **Distribution workstream → the `tunnex-site` repo IS this workstream** (complete through S4.3, launch
   runbook approved; re-pointed from a platform story). Subsumes S6.5b's signing/notarization trigger on the
   platform side.
10. **GDPR → S12.6 scope addition** — the hosted issuance service holds EU billing data (EU data-subject
    obligations on the trial/issuance funnel).

## DECISIONS RESOLVED (user-directed 2026-07-14, PRE-SESSION FINAL — the planning collisions are closed)
**LOCKED build order (RESTRUCTURED 2026-07-15; EPIC 15 INSERTED 2026-08-03): EPIC 7 (done) → EPIC 7.5 →
EPIC 8 → EPIC 9 → EPIC 10 → EPIC 11 (FULL) → EPIC 14 (UI redesign — **TWO screens remain: Audit Log, Dashboard**) → EPIC 15 (Zero Trust
for AI agents) →
BETA BUNDLE → PUBLIC BETA (joint w/ site) → EPIC M (PARKED, founder trigger) → EPIC 12-remainder.**

⛔ **EPIC 15 — ZERO TRUST FOR AI AGENTS. REGISTERED 2026-08-03, sequenced AFTER EPIC 14 and BEFORE the beta
bundle.** Paper: `docs/EPIC-15-zero-trust-for-ai-agents.md`. **REGISTRATION ONLY — no design, no schema, no
commit-one.**
**The thesis:** MCP servers deploy either on localhost (safe, unreachable) or on the public internet behind a
bearer token and nothing else; there is no network boundary and no device identity between those two. An agent
is a non-human principal that runs unattended, at machine rate, and **can be prompt-injected into asking for
the wrong thing while remaining correctly authenticated** — so ZT bounds the BLAST RADIUS of a
correctly-authenticated principal, and does NOT detect injection.
**Measured inventory:** audit `actor_system`, `policy_rules.expires_at` and device identity are reusable
UNCHANGED; `k8s_service` as a named `dst_kind` is the shipped PRECEDENT for an `mcp_server` destination.
⛔ **And the closest existing thing has a defect: `machine_credentials.role` is FIXED at `operator`, which holds
`PermPolicyManage` — so today's non-human principal can write its own access rules.** An agent principal needs
its own role.
⛔ **Per-tool granularity (`read_file` vs `delete_repo`) is a SECOND ENFORCEMENT PLANE, not an extension:**
every mechanism we own is L3/L4 and cannot see inside an MCP call. It needs an L7 proxy — the differentiator
and the risk are the same item, so it is the LAST slice.
**Protocol-independent (durable):** principal, role, expiring grants, audit attribution, device identity,
default-deny. **Protocol-coupled (will rot):** per-tool enforcement, tool discovery, MCP-shaped posture.
⛔⛔ **THE CATEGORY IS NOT EMPTY — MEASURED, AND IT REPLACES THIS PAPER'S FIRST POSITIONING SECTION.**
**Versa Networks** already markets *"Industry's first Zero Trust MCP Server"* (~May 2026) · ⛔ **Teleport
shipped protocol-level MCP access control down to INDIVIDUAL TOOL INVOCATIONS in Dec 2025** (deny-new-tools by
default, JIT for high-risk tools) · **Octelium** is a FOSS architectural twin (WireGuard+QUIC, unified identity
for humans/workloads/agents, per-request ABAC, L7 policy, names MCP and A2A) · also Pomerium, AccuKnox,
TrueFoundry. **NO PRIMACY CLAIM — not "not yet", NOT AT ALL: it is checkable and false.** And Teleport is
already where per-tool granularity goes, so that is a CATCH-UP item, not a differentiator — the first draft
called it "the part nobody else is doing" without checking, which is the Tier-3 defect this epic exists to cut.
**THE ACTUAL REASON TO BUILD:** beta is more compelling with agent support than without it, and our model
already carries most of the shape. Neither reason needs us to be first.
⛔ **THE BOUNDARY GOES IN THE OPENING, NOT THE CAVEATS:** under prompt injection, authentication AND
authorization are both intact — only INTENT is corrupted. ZT bounds the blast radius of a correctly-
authenticated principal; **it does not detect injection, and any copy claiming detection is a RENDER-FLOOR
VIOLATION AT PRODUCT SCALE** — a promise the product cannot keep, made to people who cannot check it.
**POSTURE CUT (founder-ruled):** keep only what binds to a real credential — which human account launched it ·
which host · which enrollment. **Drop model self-reporting** or label it exactly as existing posture is
(*client-reported, not attestation*) and never let a rule depend on it.
**SLICE ORDER:** MCP-as-destination FIRST (small–medium; the `k8s_service` precedent already shipped) → agent
device type SECOND (medium) → **per-tool LAST (large, and a SECOND enforcement plane)**.
⛔ **THREE LIVE FINDINGS EXTRACTED AND REGISTERED AGAINST THE CURRENT PRODUCT — they do NOT wait for EPIC 15:**
`docs/REGISTER-nonhuman-principal-defects.md` (operator+`PermPolicyManage` · `CountOwners` · `managed_by_machine`).
EPIC 12 (licensing) trigger = **first paying-customer INTENT**.
- **BETA-SCOPE (AMENDED 2026-07-15):** beta ships 7.5 + EPICs 8/9/10/11 + the bundle. **EPIC M is PARKED — beta
  NO LONGER gates on it.** Mobile ships at beta via the official WireGuard apps (S3.3/S3.4 QR export;
  gateway-side ZT applies). "Beta at EPIC-7-done" REJECTED still stands (beta is full-platform, just not native
  mobile). EPIC M's stage-1-vs-native decide-item PARKS WITH IT, resolved at M's commit-one when it unparks.
- **OPS — domain DONE:** `tunnex.io` live on Cloudflare ($5 plan); enquiry + enterprise email tested working.
  Supersedes "domain pending (Pawan)". UNBLOCKS: production `APP_BASE_URL` · SSO redirect URIs · outbound email
  · `get.tunnex.io` serving · the B2 domain-capture walk leg. **The vanity Go-module-path trigger (domain
  purchase) has FIRED** → the `tunnexio/tunnex` → `tunnex.io/…` rename gets a story slot (in the beta bundle).
  **Entity formation = the ONLY remaining long ops clock** (gates Windows EV signing, S12 commercial).
- **SITE-LAUNCH — single complete launch:** the `tunnex-site` prelaunch cutover is HELD; the site goes live
  ONCE, content-complete, synchronized with the platform's PUBLIC BETA. **Consequence: S12.1 (runtime
  license-gate refactor, DECIDE-BEFORE-CODE, load-bearing) + S12.2 (Ed25519 offline issuance) JOIN THE BETA
  BUNDLE** — no prelaunch phase means the site's trial funnel delivers REAL keys at its only launch (payments
  **S12.5 stays PARKED**). The superseded-edition-model note (S1.1 runtime gate) FIRES here. Site-sync
  milestones the platform emits: **(a)** 7.5 close → site feature/pricing/compare refresh; **(b)** EPIC M close
  → mobile claims + downloads; **(c)** bundle done → joint cutover. Cross-repo corrections: batch-3 item 9
  re-pointed (the `tunnex-site` repo IS the distribution workstream, complete through S4.3, runbook approved);
  the site's `/security` "Windows kill-switch in progress" caution is STALE (S6.7 MERGED + pcap-proven) →
  relay to the site ledger.

## STRATEGIC POSTURE — DELIBERATE-BUILD MARKET ENTRY (user-directed 2026-07-14, DECIDED)
**Decided: build to full scope, enter the market ONCE, strong.** No launch urgency. Rationale (pinned): the
wedge buyer (regulated / sovereignty / air-gap) rewards COMPLETENESS + evidence of rigor over speed; a
half-product first impression is unrecoverable in enterprise evaluation. CONFIRMS the deliberate-build posture
(the LOCKED order itself was RESTRUCTURED 2026-07-15 — 7.5 → 8 → 9 → 10 → 11 → BUNDLE → BETA → M-parked; see
the Build Order section). The posture's failure mode is "no hurry → no clock"; four guards:

1. **Internal milestones (anti-drift, NOT protocol-compromising deadlines) — RE-ANCHORED 2026-07-15.** Proposed
   at **7.5 / 8 / 9 / 10 / 11 closes** (+ "first design-partner deployment", "bundle done"); slippage REPORTED,
   not hidden. Dates never justify skipping decision-first / box-proof / review. **DEFERRED PROOFS must NOT ride
   the now-distant bundle:** the **client-wire-smoke** + the **S6.6 clean-VPS acceptance** re-trigger to the
   "next available desktop/VPS session" (founder-schedulable NOW) — else several epics of code stack on unproven
  legs. The configured test-relay customer-path check rides the S6.6 acceptance.
2. **Design-partner track REFRAMED (supersedes earlier framing): private deployments ≠ launch.** Goal = 1–2
   friendly orgs in the wedge (regulated fintech · defense/govt integrators · OT/industrial · Pritunl
   migrations · India/DPDP angle) running the product PRIVATELY during the build → launch day carries "running
   in production at real orgs for N months." Founder-owned, parallel, NO code. Pre-authorized escape valve
   STANDS: a partner's concrete need may RE-ORDER stories within the locked sequence; never gate-skip.
3. **Trust-asset pipeline (the runway must produce more than features):** (a) **entity formation** — founder
   starts NOW, longest clock; (b) **scoped pentest** (privilege helper + kill-switches ONLY, founder-affordable)
   — trigger moved EARLIER to **post-entity + post-7.5, NOT gated on a deal** → launch carries "independently
   tested"; the FULL audit (batch-3 #6) keeps its existing trigger (first enterprise deal / GA); (c) **security
   whitepaper** (batch-3 #7) — drafted DURING the 7.5/8 build from the armed-guards / box-proof material, not
   after; founder-reviewed like the launch posts. *(The scoped pentest KEEPS its trigger — post-entity +
   post-7.5 — it does NOT slide to post-everything.)*
4. **OPEN DECIDE-ITEM (founder's word, NOT decided): early content-only site launch — HIGHER-VALUE under the
   longer runway (RESTRUCTURED 2026-07-15: beta is now several more epics out, so more domain-aging time to
   bank).** Option: BLOG + `/compare` pages ONLY go live early (no product pages / downloads / trial funnel) so
   the domain AGES and "Tailscale alternative / Pritunl migration / NetBird vs" queries rank by launch day —
   SEO time is the one asset that can't be bought later. Partially amends the single-launch decision (content early; product-launch still once
   + complete). Needs founder yes/no; if yes, a small `tunnex-site` content-only-mode story. Disposition =
   founder's word.

**FOUNDER PARALLEL TRACK (no code; homework):** (1) entity formation — start this week; (2) design-partner
conversations — identify the 3–5 wedge candidates; (3) the blog-early yes/no when sat with. Build side is fully
unblocked; the next Claude Code artifact is the S7.5.1 commit-one.

**LEDGERED (S7.2 story-end review #8/#9/#10, DEFERRED — CORRECTNESS-NEUTRAL perf pass): policy-fetch
throughput.** (#8) `CompiledForNode` recompiles the artifact on EVERY `DesiredState` fetch — cache by
policy version instead. (#9) no off-mode fast-path — off-mode orgs still walk the compile path to
produce a mesh artifact; short-circuit to the blanket-mesh artifact. (#10) redundant re-apply per
fetch — an identical `Compiled` re-renders + re-applies each cycle (the idempotence guard makes it a
kernel no-op, but it still burns an `nft` transaction); skip apply when the applied hash already
matches. None change behavior; all are throughput optimizations. **Trigger = policy-fetch load becomes
measurable.** Documented in docs/S7.2-decisions.md. **S7.5.5 adds two to this class (review #8/#9):** the
MFA-enrollment gate runs a `UserInEnforcingOrg` query on EVERY authenticated request (enterprise), and
`/auth/me` double-reads `user_totp` (IsEnrollmentGated + HasConfirmedTOTP both `GetTOTP`) — a principal-
attached enforce flag / a single TOTP fetch would remove both. Correctness-neutral; same trigger.

## EPIC 12 — Commercial / Licensing Infrastructure *(trigger: FIRST PAYING-CUSTOMER INTENT — build-on-intent, not calendar)*

**RESTRUCTURED 2026-07-14:** **S12.1 (runtime license-gate refactor) + S12.2 (Ed25519 offline issuance) are
PULLED FORWARD into the BETA BUNDLE** (the single-complete-launch consequence — the site's trial funnel
delivers real keys at its only launch). **S12.5 (payments) stays PARKED.** The remainder below (S12.3 upgrade
affordance, S12.4 issuance service, S12.5 payment, S12.6 compliance incl. **GDPR / batch-3 #10**) fires on
first paying-customer INTENT.

**Positioning guard:** licensing MUST NOT break the "self-hosted, no SaaS in the trust path" differentiator. License verification is **OFFLINE** — the customer's deployment verifies a signed key locally against a baked-in public key; it works air-gapped and **NEVER calls Tunnex infra to function.** Any phone-home (renewal reminders, telemetry) is optional, async, and degrades gracefully — a lapsed connection to Tunnex infra **NEVER hard-fails a running VPN.** This is the sovereignty/Tailscale-differentiator constraint; a call-home validation model is explicitly **REJECTED**.

- **S12.1 Edition Model refactor (build-tag → runtime license-gate)** — decide-before-code, **supersedes the S1.1 model**. Single binary; enterprise code compiled in; a `LicenseManager` gates enterprise features at runtime on a verified key. Replace the test-editions build-tag guard with a **runtime-gating guard** (open-by-default; features light up only with a valid enterprise key). **The load-bearing story — everything else depends on it.**
- **S12.2 License key format + offline verification** — **Ed25519-signed** key (private key in the issuance service; public key baked into the binary). Key encodes `{company_domain, tier, seats, issued_at, expires_at, license_id}`. Binary verifies signature + expiry **offline**. Expiry → grace period + UI warning → revert to open features; **never a hard VPN cutoff.** In-app "paste your license key" UI + a `POST /admin/license` endpoint (owner/admin-gated, audited).
- **S12.3 In-app upgrade + trial-request affordance** — "Upgrade to Enterprise" in the open build; "Start 30-day trial" flow that requests a key from the issuance service.
- **S12.4 License issuance service** *(Tunnex-hosted infra — the ONLY hosted piece; holds billing + entitlement data ONLY, never VPN traffic/configs/user data)* — signing service (guards the private key), issues keys on paid purchase or validated trial, emails the key (support-flow delivery). Trial-per-company-domain anti-abuse: a `domain → trial_issued_at` table refuses a second trial for the same domain. **DECIDE-BEFORE-CODE:** trial gating = **DNS-TXT domain-ownership proof** (STRONG — reuses the S2.5 domain-capture verifier) vs email-domain best-effort (weak, gameable). *[Leaning DNS-TXT — S2.5 already built it; confirm at story open.]*
- **S12.5 Landing + payment** — pricing/landing page; **Stripe (US) + Razorpay (India)** — both markets from launch; purchase → issuance.
- **S12.6 Compliance pass** *(needs a real lawyer per market — NOT hand-waved)* — India **DPDP Act 2023** + US state privacy; data-residency review. **Architectural compliance win to preserve:** the hosted infra holds only billing + license data; all VPN traffic, configs, and user data stay entirely on the customer's self-hosted deployment — minimizing hosted-infra data footprint is the single biggest compliance lever. ToS/privacy policy; export-control check on crypto distribution (US EAR) for the US+India launch.

**Build-order note (RESTRUCTURED 2026-07-14):** **S12.1 + S12.2 = BETA BUNDLE (NEAR-TERM, pulled 2026-07-14)** —
the single-complete-launch consequence; the site's trial funnel delivers real keys at its only launch. **S12.3–
S12.6 = first paying-customer INTENT.** (Supersedes the pre-restructure "EPIC 12 slots after the public beta /
not near-term" note — S12.1's runtime license-gate now leads the bundle, so build-tag permanence is NOT assumed.)

---

## Build Order — LOCKED (RESTRUCTURED 2026-07-15; supersedes the 2026-07-14 lock)
EPIC 0 → 1 → 2 → 3 → 4 → 5 → 6 → **7 ✅ → 7.5 (in flight) → 8 → 9 → 10 → 11 (FULL) → BETA BUNDLE → PUBLIC BETA
(joint with the site) → M (PARKED, founder trigger) → 12-remainder.**
- **EPIC M → PARKED** (native mobile clients; founder trigger = beta-bundle-planning revisit OR a design-
  partner/prospect requiring native mobile, whichever first). **Beta no longer gates on EPIC M.** Mobile
  connectivity STILL ships at beta via the S3.3/S3.4 QR/config export consumed by the OFFICIAL WireGuard
  iOS/Android apps (gateway-side ZT enforcement is transport-agnostic) — see the EPIC M section.
- **EPIC 11 now runs COMPLETE before the bundle** — S11.3 (rate limits + security headers) REJOINS EPIC 11;
  the bundle SHEDS it.
- **S12.1 + S12.2 stay in the BETA BUNDLE** (single-complete-launch — the site trial funnel delivers real keys
  at the one launch); the rest of EPIC 12 fires on **first paying-customer INTENT**. Bundle internal order
  stands: **S12.1 → S12.2 → S6.5b → rest.**
- ZT-coverage guarantees carry UNCHANGED: OVPN-through-compiler (S9.1) · DNS-under-enforcing (S8.4) ·
  egress-under-enforcing (S3.7-review).
- **NEXT ARTIFACT: S7.5.1 box-walk (build phase complete), then S7.5.2.**

### (historical) original recommended order
EPIC 0 → 1 → 2 → 3 (WG core loop) → 4 (dashboard) → 5 (CLI) → 6 (Electron) → 7 → 8 → 9 → 10 → 11.

## First Story to Execute: **S0.1 + S0.2 (Foundation + one-command boot)**
Deliverable: a `git`-ready monorepo where `docker compose up` brings up postgres, redis, a Go API `/healthz` (structured logging + request IDs), a node-agent stub (`NET_ADMIN`, WG UDP port), and a React dashboard shell reachable through nginx.

Critical files (S0.1/S0.2):
- `go.mod`, `apps/api/cmd/server/main.go`, `apps/api/internal/http/router.go` (chi + `/healthz`), `apps/api/internal/log` (slog + request-ID middleware)
- `apps/node/cmd/agent/main.go` (agent stub + registration handshake placeholder)
- `apps/web/` Vite + React + Tailwind app shell
- `docker-compose.yml`, `deploy/docker/{api,node,web,nginx}.Dockerfile`, `deploy/nginx/nginx.conf`
- `.env.example`, `Makefile`, `pnpm-workspace.yaml`, `turbo.json`, root `README.md`

## Verification (S0.1/S0.2)
1. `cp .env.example .env && docker compose up -d` → all services healthy (`docker compose ps`).
2. `curl localhost/healthz` → `200 {"status":"ok"}` through nginx; response carries a request ID that appears in structured logs.
3. Browser `http://localhost` → Tunnex dashboard shell loads; email flows use the configured SMTP relay.
4. `docker compose down -v` → clean teardown, no orphaned volumes.

## Resolved Decisions (recap)
- React + Vite SPA (reused by Electron) · single-domain multi-tenancy · control/data-plane split from day one.
- OpenAPI-first contract with codegen. CLI before Electron; cert procurement starts when EPIC 5 begins.
- Logging in EPIC 0; metrics in EPIC 11.
- **Open-core:** multi-tenant schema in core, org-creation limit in open build; enterprise boundary established at **S1.1**; SSO/policies/operator gated.
