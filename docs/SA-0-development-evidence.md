# SA-0 local development evidence

Date: 2026-10-05. Branch feature/browser-access, base 435b4d53900c768073a49dbcc72579567fcdc524. Status: **SA-0a/SA-0b technically accepted for the explicitly authorized local single-CP POC after the decision review and bounded recording qualification. Full epic and production acceptance remain open.** Later integrated development was explicitly authorized; this record covers SA-0 only.

## Native and isolated topology proof

After user-directed Docker cleanup, the coordinator verified zero containers/images/volumes. Fresh local project `tunnex-sa0-browser-1005` uses only the local Colima Unix socket. Five healthy services: actual repository API, PostgreSQL, Redis, actual repository Linux gateway and Linux OpenSSH target. A one-shot sixth broker container is a nonshipping transport spike. No AWS/remote mutation, commit/push/PR.

Actual API/node binaries are built from this base using cached Go 1.26.8 with GOPROXY=off and -mod=readonly. API SHA256 b210f502a621d5b312b3a3850e2429c9292d37eeabe1b9cd453ac382010e09a8; node SHA256 bc435469b0270ef7ce2d153316e5684ac141bfaee1bdb814748d49d83d5aaf8d. These are SA-0 baseline hashes; integrated development must rebuild and replace the provenance record.

Actual bootstrap/enrollment readback: clean schema 180; one active gateway named sa0-gateway, node 01a109d9-42ca-7d53-b4dd-3f166cd23192, org 01a109d9-382b-7bc1-82c9-2b0bf036139c; fresh heartbeat and valid certificate. Gateway NET_ADMIN affects only its container network namespace. Identity persists through the owned fixture mount update; no re-enrollment or new node was required. API/control/health ports bind loopback 18183/18546/19193; DB/Redis/SSH target have no host ports.

The unchanged frontend runs at http://127.0.0.1:15195 using existing dependency cache. In-app browser rendered the real login page with Email/Password/Sign in and no console errors. This is rendering proof, not an authenticated browser terminal. Screenshot: /private/tmp/tunnex-sa0-spike/cp-login.png. Bootstrap credential logs remain private; do not publish them.

| Probe | Result | Evidence boundary |
| --- | --- | --- |
| macOS native OpenSSH 10.2p1 | Certificate PTY login, wrong principal/key denied, new login expires, existing shell survives expiry | Disposable daemon/config/keys only; macOS audit warnings do not prove Linux audit. Generated private keys removed by probe. |
| Linux OpenSSH 10.2p1, Alpine 3.23.6 | Native gateway→target PTY 24x80 then 40x120, UTF-8 héllo, clean exit | Real SSH and PTY, no browser product yet. Initial headless stty probe was insufficient; explicit local PTY test supplies dimensions. |
| Linux boundary checks | 9 assertions pass: two actors share fixture account; wrong server principal/account/foreign CA/host key denied; expired new login denied; active shell survives expiry; valid cert reusable | Actor IDs are synthetic signed cert key IDs; not integrated Tunnex actor authorization or Observer events. No automatic product OS user creation; fixture account exists only in disposable image. |
| Outbound mTLS PTY spike | Enrolled gateway cert pinned, gateway initiates connection, PTY and resize roundtrip, watchdog closes in ~0.305s | Own broker TLS trust; pinned current gateway identity; authorization is fixture-only. No CP launch/grant enforcement or WebSocket frontend. |
| Linux recording/lease primitives | 7/7 pass on final review: native PTY resize/UTF-8, OFF no payload but event, admission snapshot, ordered durable output, injected and real ENOSPC close before forwarding, stalled-renewal socket watchdog | Small nonshipping prototypes; actual 64 KiB Linux tmpfs filled to ENOSPC on final review. No encrypted storage/replay or product lifecycle proof. |
| Existing apptransport race probes | 4/4 pass: actual mTLS expiry, capacity/EOF reclamation, lease expiry with blocked renewal, expired admission refusal | Existing HTTP channel reuse evidence; new SSH purpose/protocol not implemented by these tests. |

## Artifacts and reproducibility

Harness and sources: [tests/server-access-local](../tests/server-access-local/README.md). Private runtime env, keys, binaries and raw evidence are ignored under .runtime. Public CA/principals mount only into SSH target; gateway receives client keys, never user-CA signing keys; broker receives its own TLS key plus public enrolled gateway trust. Source-only mounts avoid leaking the harness runtime tree. Build context excludes .runtime.

Recorded native result: .runtime/linux-boundary-results.json; enrollment .runtime/enrollment-evidence.txt; outbound .runtime/outbound-evidence.txt. Focused existing tests were run with -race -count=1 on packages/apptransport and passed in 9.025 seconds. No unrelated suite was run for SA-0 prototype/docs work. See [authority contract](SA-0-authority-contract.md) for decisions and measured versus proposed bounds.

## Review amendment and technical acceptance — 2026-10-05

The first review correctly declined acceptance while choices were labelled pending. The human then explicitly required Community availability, confirmed per-server recording selection, and authorized proceeding with all recommendations plus bounded admin configuration. Seven-day configurable retention, encrypted PostgreSQL POC storage, fail-closed capture and active MFA-expiry closure are approved decisions. The concrete amended [authority contract](SA-0-authority-contract.md) supersedes the previously proposed spool/asciicast export and pending production-policy wording; it does not infer production capacity/restore acceptance.

| Exact SA-0 acceptance criterion | Final bounded result |
| --- | --- |
| SA-0a signed-off decision record | **Met for local POC contracts.** Explicit human decisions above plus the concrete per-org sealed signer/key recovery/rotation proposal, named roles, tenant registry/grant/session/recording schemas, Community gate and threat boundaries are recorded. |
| Intended account/server principal; wrong host/tenant/credential audience denied | **Pass.** Historical Linux nine-assertion native results cover wrong account/server principal, foreign CA and host pin, two synthetic actors, expiry/reuse. Enrolled transport identity is separate from signing trust. Later integrated authorization has separate evidence. |
| No product implementation in planning phase | **Met for the historical SA-0 phase.** Product development was subsequently explicitly authorized and is recorded separately. |
| PTY/resize and stalled lease closure | **Pass.** Native dimensions/Unicode and outbound enrolled-gateway watchdog evidence above; later actual CP/Redis-pause PTY teardown provides additional evidence, not retroactive planning implementation. |
| Enabled/disabled capture and full-disk behavior | **Pass for bounded feasibility.** Seven nonshipping primitive probes pass, including real ENOSPC from a dedicated full 64 KiB Linux tmpfs, close-before-forward, OFF/no payload and immutable snapshot. Reproduction: `sh tests/server-access-local/recording-review.sh`. |
| Recorder format/storage, backpressure and timeout contracts | **Frozen for POC.** Exact byte envelope, AES-GCM org/session/sequence AAD, wrapped per-session key, synchronous durable-before-forward PostgreSQL capture, zero queued output, finite quotas/events and one-second capture deadline are specified. Real opt-in PostgreSQL/Redis qualification passes durable replay, quota refusal, foreign tenant, missing/tampered chunk refusal, logout denial and retention of metadata after chunk/key removal. |
| Library licenses and supported matrix | **Recorded.** Pinned xterm 5.5.0 + fit 0.10.0 MIT; existing Go SSH v0.56.0 BSD-3-Clause; bounded Linux/macOS native matrix. Real in-app browser terminal/replay has separate evidence; no complete browser fleet support is claimed. |
| UI/state review and replay accessibility prototype plan | **Recorded.** Registration/grants/MFA and disconnect/expiry/recording/replay state contracts; actual pinned read-only/screen-reader xterm prototype, keyboard controls and explicit narrow/hostile-escape browser qualification plan. Existing App Access reference layout inspected, with its shared tabs/tables/forms/settings patterns reused. |

**SA-0 technical acceptance is complete for this scope.** The full epic remains open. Later slices require their own source-matched integrated verification; SA-0 does not certify production capacity, HA, complete command audit, background-job killing, key rotation/distribution, backup recovery or deployment.

The seven-probe review container has no network, read-only root, dedicated bounded writable /tmp and /capture, and mounts only public probe source. The initial read-only run lacked /tmp; the corrected run passes all seven probes. It removes only its newly created disposable container. The real DB test explicitly opts in, refuses databases other than the owned aa0 fixture and exact org, and creates/removes only its own random session/Redis parent.
