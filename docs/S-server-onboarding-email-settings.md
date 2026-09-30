# Server onboarding and editable email delivery

## Accepted scope

Keep the approved installer flow and optional Linux same-host gateway consent. Use “Tunnex Server” in customer-facing copy, preserving configuration names and compatibility. Add a dashboard setup guide after sign-in, with Company VPN, site-to-site and private Kubernetes service paths. Existing gateway enrollment is reused. Purpose selection is navigation, not a persistent product mode; other capabilities stay available. Existing feature screens remain the owners of mutations and permission checks.

## Email settings ownership and lifecycle

- Email delivery is deployment-wide, available only to the existing verified server-administrator capability after initial password rotation. Organization ownership does not confer this authority.
- An absent database override uses installer/environment values. The first explicit save creates a singleton override, encrypted under the existing master key. Subsequent saves use a revision precondition. No restart or reinstall rewrites it.
- The override is read for each send, including invites, password resets and alerts; all replicas use the same authoritative value. A read/decryption failure refuses delivery rather than silently switching providers. An in-flight send keeps its captured configuration.
- Reads expose non-secret fields, origin, revision and whether a password is configured. Password actions are explicitly keep/replace/clear. Changing the destination or login with an existing password requires replacement or clearing, preventing accidental credential reuse at a different endpoint.
- Save validates and atomically audits the configuration; it does not send mail. Test sends a fixed message only to the authenticated server administrator, using the candidate configuration without saving it. Failed tests preserve the saved configuration. SMTP acceptance is not an inbox-delivery claim.
- Disabling delivery is explicit and persists; old environment configuration must not reactivate it. No SMTP secrets or provider errors are returned or audited. Existing mandatory STARTTLS behavior is retained.
- Database connection settings and public URL/TLS are outside this ordinary settings editor. No production infrastructure changes, real recipient tests, publication or deployment are part of local development.

## Proof

Cover secret non-disclosure, fallback/override precedence, stale saves, explicit disable, rollback on audit failure, cross-replica sends, failed reads, admin-only handlers and candidate tests. Check setup navigation, reuse of existing gateways, permission/loading/error states, and SMTP form prefill/keep/replace/test/save. Render desktop and narrow layouts using the existing design tokens and settings components. A local fixture proves presentation only; it never proves VPN or email delivery.

## Local validation (2026-09-29)

- Full web suite: 140 files, 1,689 passing tests and two pre-existing expected failures. Includes setup paths, authorization, failed loads, existing-gateway reuse and email form save/test behavior.
- Web typecheck and production build passed. Open and enterprise server builds and generated CLI build passed.
- SMTP/database integration used the isolated `tunnex-email-onboarding-0929` Compose project with tmpfs PostgreSQL and a database-name refusal guard. It passed encryption, first-save concurrency, replica reads, test failure/throttle, audit rollback, persisted disable and corrupt-ciphertext refusal. No real mail was sent.
- Installer fresh-host contract, ten first-organization tests and 27 local demo interaction checks passed. The gateway choice, consent, wordmark and animation remain intact.
- Browser reviewed actual Settings and Setup components through a localhost-only fixture: existing gateway, purpose choices, SMTP prefill, simulated failed test, save/reload, desktop and 390-pixel layouts. Both narrow pages fit without horizontal overflow. Fixture writes affect only its own memory.
- SMTP read failure omits the optional metadata field instead of inventing a disabled state or failing unrelated metadata. Delivery and settings endpoints still fail closed.

Real SMTP provider delivery and Linux VPN traffic are not proven by these local checks. No changes were committed, pushed or deployed during this work.

## Operational notes

Apply the new migration with the normal release migration path. Retain the existing master key with database backups; it decrypts the saved override. Changing installer environment variables does not overwrite an explicit server-settings save. Rolling this migration down removes the override and returns older binaries to environment-owned SMTP configuration. A configured badge confirms saved configuration, not mail delivery.

## Customer handoff follow-up

Keep installer questions unchanged. Link supported releases directly to the dashboard setup guide and preserve that local destination through initial password rotation. Older releases retain their existing dashboard entry. Use a dedicated client connection page for ordinary members and accepted invitations; configuration exports remain available in Devices. Read the server address from metadata, never infer it from a download service or invitation token.

The guide reuses gateway health and device inventory for its next action. Registered, reporting, awaiting approval, and handshake observed are separate facts. An observed handshake never proves private-resource access. Missing/failed telemetry is unknown, not empty or successful. Return links carry a validated setup purpose and step; saved product configuration remains authoritative, with no new progress database or permission changes.

Local demonstration uses a dedicated Compose project and PostgreSQL database, separate roots of trust and loopback listeners. It must not reuse or migrate the default development database. No real mail or VPN connection is claimed by this demonstration.

### Follow-up validation (2026-09-30)

- Complete web regression: 141 files passed, 1,702 tests passed and two existing expected failures. The mock shell bootstrap test initially timed out in the restricted environment; it passed with system-first PATH outside that sandbox, then the complete suite passed in that environment.
- Typecheck, production bundle, installer host contract and ten first-organization tests passed. Focused handoff tests cover failed metadata, clipboard failure, unsafe return destinations, password-save refusal, expired invitations and pending device approvals.
- Started the real API with an isolated `tunnex-customer-demo-0929` PostgreSQL/Redis project, verified container labels/network, separate secrets and localhost-only listeners. Browser exercised fresh bootstrap login, mandatory password rotation returning to setup, and Settings -> Continue setup. No default data was used.
- Browser checked Company VPN and client connection pages, including authoritative server address, download link, truthful empty gateway/device states and a 390-pixel layout without horizontal overflow. A navigation check caught a hash-only router link dropping the purpose query; the corrected native anchor preserves the task.
- Local server has no enrolled VPN gateway. Handshake, private-resource access and real email delivery remain untested. No database-switching UI, commit, push or deployment was added.

### Step-by-step setup (2026-09-30)

Each purpose now shows one stage at a time, with a four-step navigation bar and Back/Continue controls. Stage navigation does not mark configuration complete. Extra email help and connection telemetry stay in expandable sections. Existing configuration and permission checks remain authoritative, and gateway enrollment holds wizard navigation until its form closes.

The current step is in the URL, including return links from existing editors. Invalid steps fall back to the first stage. The client connection instructions are shorter inside the wizard; the standalone connection page keeps its full guidance.

- Focused setup, handoff, network editor and overview checks: 49 tests passed; TypeScript and production build passed.
- Browser verified one visible stage, Back/Continue, all three purposes, and Settings/site-to-site return links restoring the original stage. Desktop and 390-pixel layouts checked; no horizontal overflow. The existing-gateway fixture retains gateway health and reuse guidance.
- These checks cover navigation and presentation, not real VPN or email delivery.
