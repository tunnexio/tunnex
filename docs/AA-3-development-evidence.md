# AA-3 connector and origin checks

Status: locally accepted on 2026-10-03. The actual outbound gateway pool carried HTTP and HTTPS checks, including destination-policy and TLS refusals, followed by retained-identity reconnect and browser review. AA-4 browser proxy work is in progress. This local result is not CI, publication or release evidence.

## Implemented data authority

Migration 169 adds immutable revision destination policy and public CA certificate trust, a separate gateway capability store, server-issued assignment generations and bounded origin-check results. Existing immutable revision digests are retained. New revisions hash normalized policy; omitted policy fields in old-client PATCH requests preserve prior values, while explicit empty values clear them. HTTP revision views expose the CA digest rather than PEM.

The shared origin-policy module canonicalizes up to 32 CIDRs and up to eight public CA certificates within 32 KiB. Empty CIDRs permit safe public destinations only. Private destinations require an explicitly contained private range; loopback, metadata, reserved and current control-plane destinations remain refused. Private keys and non-CA PEM are rejected.

Connector authority uses the exact organization, application, gateway, revision, digest, generation and `origin_check` purpose. Database foreign keys bind assignments to the immutable revision's gateway/digest; triggers reject authority-tuple edits. Gateway calls independently reread the live organization, active gateway and current certificate serial/expiry. Exact capability version 1 must be fresh within 30 seconds. Drafts remain unpublished and confer no browser authority.

Requests use the saved application version. Each gateway has at most 64 current assignments, eight running checks and 32 queued checks, with a ten-second deadline including queue time. Pending checks for the same assignment are reused. Completion requires the exact running tuple and is accepted once; fixed enums replace raw errors or origin bodies. Short channel leases last at most five seconds measured from decision start, so database latency consumes validity; elapsed or canceled decisions are refused. They recheck current assignment authority. Feature loss returns withdrawn desired state and retires pending work. Repeated identical applied reports are idempotent.

Check history retains 64 finalized records per application. App-scoped finalization retires expired or withdrawn work before pruning, including after moving an application away from a gateway that no longer polls. Assignment cleanup retains 64 latest withdrawn generations plus generations referenced by retained check history and the current assignment: at most 129 per application. Machine completion/applied reports use the named `app-access-connector` audit actor within the state transaction.

## Completed verification

- `GOFLAGS=-mod=readonly go test ./db ./internal/appaccess` passed, including query-isolation checks and service compilation.
- `tests/app-access-local/verify-registry.sh` passed against fresh child PostgreSQL databases on the owned local network. The native control-plane database was not modified by these tests.
- Actual database coverage passed empty migration 168→169→168→169 and refused destructive rollback once connector/policy history existed. AA-1 registry and AA-2 grant regressions also passed with schema 169.
- Actual connector tests passed canonical CIDR persistence, omitted-field preservation, explicit clearing, immutable prior history, unknown and legacy capability refusal, desired check claiming, bounded channel leases with database decision latency consuming validity and canceled/elapsed admission refused, exact completion, replay refusal, stale-revision refusal, certificate rotation refusal, feature-loss withdrawal and foreign-tenant check refusal.
- Actual capacity tests accepted eight running plus 32 queued checks and rejected the next queued request. Direct assignment/check authority-tuple updates failed. Moving an application to another gateway retired old pending work without any further old-gateway poll.
- Injected completion-audit failure rolled the result back to `running`; successful reporting asserted the named system actor. A failed HTTP probe after completed connection stages remained failed rather than falsely successful.
- Policy digest tests passed normalization/deduplication, changed policy changing the digest, presence flags not changing the digest, broad CIDR rejection and private-key rejection.

## Independent review and remaining proof

The source review of `apps/web/src/pages/AppAccess.tsx` and the nested `apps/web/src/components/AppAccessConnection.tsx` found policy preservation/explicit clearing, saved-version check requests, read-only feature-loss views, bounded redacted result labels, dirty-form check refusal and route-keyed remounts that prevent responses from a prior application or organization populating the next editor. API/migrate Docker paths copy the shared module at the location required by the API module replacement; Makefile API/node test mounts preserve that layout. This is a source review, not a Docker build or browser acceptance result.

Review identified a node capability freshness issue: reporting capability only once would become stale after 30 seconds without recovery from a successful withdrawn response. The transport lane was asked to refresh capability periodically. It was also asked to enforce one execution per check on the gateway pool, preventing repeated origin probes over keepalive channels. Subsequent source review confirms capability refresh every ten seconds, a consumed-check-ID guard, strict body-free fixed-route/header checks, and shared exact-root URL refusal. Transport test and actual pool evidence are still required before treating those fixes as accepted. The API dispatcher source review found it schedules only exact running gateway checks, bounds workers globally and per gateway, uses the certificate serial returned by the admitted pool channel for result recording, and leaves absent-channel work to its durable deadline rather than inventing a gateway result. Stage mapping and the bounded 8 KiB diagnostic response agree with the service contract.

The reviews above were recorded during implementation. The following completed tests and runtime checks supersede their pending transport and pool gates. Browser serving, publication, app sessions and login authority remain later stories.

## Transport, HTTP and runtime proof

Shared transport and node tests use actual outbound mutually authenticated TLS channels. They passed exact binding, missing/foreign certificates, certificate replacement, assignment withdrawal, pool reconnect and TLS 1.2 downgrade refusal. The app channel requires TLS 1.3 while existing VPN control compatibility remains intact. Origin tests passed all-address DNS validation, no second lookup when dialing, control/metadata/reserved address refusal including mapped aliases, explicit private ranges, public CA trust, timeouts, cancellation and bounded fixed-route diagnostic responses. A consumed-check guard prevents duplicate probes on one diagnostic channel.

Review found a blocked renewal callback could delay the old lease timer. An independent expiry watchdog now closes the socket regardless of that callback. Race tests prove expiry while the callback remains blocked, rejection of late admission, and bounded pending admission and outstanding authority callbacks. Limits include pending and accepted connections; an ignored callback cannot free its slot before it returns.

Owned child PostgreSQL plus real HTTP/mTLS integration passed missing-certificate handshake refusal, same-CN unknown-serial refusal, capability-zero refusal, strict unknown body fields, wrong gateway/digest refusal, exact completion and replay refusal. Real certificate renewal refused the old serial and admitted the new serial; revocation refused subsequent control requests. Final affected HTTP/auth-census race tests passed in 6.077 seconds; shared race tests passed in 6.6 seconds and affected node race tests passed after the watchdog fix. Linux gateway cross-compilation passed.

The complete API suite passed. The complete node suite passed in the cached Linux Go 1.26.8 image, with optional networking-tool dependent tests retaining their existing skips; the actual owned gateway separately used the networking-equipped qualification image. Native macOS full-node compilation encounters existing Linux-specific egress methods, so Linux is the full-node acceptance environment. Web typecheck, all 148 test files (1827 passed, two expected failures) and production build passed. The final label-only change passed its 28 focused tests and another typecheck. Changed lease/watchdog files were covered by subsequent race runs; earlier full-suite runs are not claimed to include them.

The owned API upgraded through schema 169 cleanly, preserving its database, Redis and secrets volumes. A subsequent rebuild also embedded additive AA-4 schema 170; its clean readback was verified and both new authority tables were empty. The paid fixture refused its exact-169 guard, then was rebuilt to explicitly accept clean 169 or 170 and restored on the same loopback ports. No history was removed or rolled back. Final compatible HTTP test fixture SHA-256: `840b11cd81c160f661a2afbdd6ea2a15908358183fe68866977714cf5745897e`.

`verify-reconnect.sh` restarted only the owned gateway and asserted unchanged node ID, certificate serial and key fingerprint, then a newer heartbeat and healthy API/gateway. Node ID stayed `01a100fb-de0b-747a-bcc3-8666eb0742b4`; PostgreSQL and Redis identities stayed unchanged. Another HTTPS probe succeeded through the replenished outbound pool afterward.

## Actual browser review

The paid fixture supplies an ephemeral entitlement to real handlers on the owned database; native Community remains unchanged. No licence was installed into the native control plane. Actual test draft `Local connector proof` (`01a10174-6c30-7a3c-a769-6d45c645001f`) has no grants and remains unpublished.

Browser actions saved and checked four immutable revisions:

1. HTTP with empty destination policy failed with `target_refused`.
2. Saving exact owned origin address `172.20.0.7/32` admitted HTTP: DNS/connect passed, TLS skipped.
3. `https://origin-app-fixture:8444` with system roots passed DNS/connect and failed TLS verification with a redacted corrective message.
4. Saving the fixture public CA admitted HTTPS: DNS/connect/TLS passed. Its saved fingerprint appeared without exposing PEM in revision metadata.

Editing the origin disabled checking and marked the old result as not covering unsaved changes. Following the final fixture/API refresh and gateway restart, saved revision 4 succeeded again at 16:55:37 Asia/Kolkata. Desktop stages and messages were visually inspected. At 390 pixels the policy/trust controls remained readable and document width equaled viewport width. Screenshots: `/private/tmp/app-access-aa3-final-https.png` and `/private/tmp/app-access-aa3-trusted-https-mobile.png`.

The UI still states that checks do not publish browser traffic. Browser serving, publication, app sessions and login authority belong to AA-4 through AA-6. Production release qualification and live load/revocation acceptance remain later stories.
