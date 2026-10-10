# Shared DNS owner-view candidate — source qualification

Base: `790be7fc`, isolated branch `gcp-s2s-dns-owner-view`.

Imported source-only patch SHA256: `8abfbb1eed2375b9b92fd1ba64d8e4a218a1d09ad416ef2157d14cd03811d833` from retained `/private/tmp/ipsec-dns-owner-view-sourceonly-20261010-1/candidate-v2.patch`. No AWS checkout file replacement, cloud commands, current lab or licence mutation.

The conflicting runtime status hunk was adapted manually: Classic preserves its actual active count and never consults the inactive second slot. Newer GCP reports, contract versions, cleanup/recovery and helper code remain in place.

The view stores immutable owner-selected inputs, not cached health. Each exchange still requires fresh native proof, exact full guard readback, exact source and route inventory, original and current accepted authority, and the same non-revoked epoch before returning a response. Withdrawal precedes relevant serial mutations. No deadline or timeout was extended.

## Verification

- Full local `go test ./internal/ipsec ./internal/fqdnrpc -count=1`: PASS (42.044s / 0.837s). Disposable localhost socket binds required sandbox escalation; the first restricted run could not bind sockets.
- Owner-view race regression suite: PASS (3.808s), including GCP contract3 HA and contract4 Classic snapshot validation, zero inactive Classic allocation, original deadline refusal and route/interface mutation epoch cancellation.
- Linux ARM64 `go test -c ./internal/ipsec`: PASS; `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`: PASS.
- Focused related runtime/DNS race: PASS (`DNS|RuntimeController|BGP|Recovery|Classic|GCP|RuntimeUnderlay|Guard`, 46.413s / 2.299s, 90s bound).
- Full package race: NOT PASS. The bounded 90s run timed out in unchanged `TestRuntimeJournalOversizedWriterPreservesPriorDuty`, executing restoration `reflect.DeepEqual` / journal payload validation. `fqdnrpc` race passed (1.511s). No deadline was widened to obtain a green result; focused DNS/controller/GCP runtime race checks are recorded separately.

## Remaining native component gap

The imported positive owner-view fixture models SA/source/route inventories (`c.prove`), although it uses the real guard parser. The new GCP profile tests use real material validation and immutable epochs, and do not establish native packet compatibility.

Existing `runtime_classic_linux_test.go` provides actual Classic single-link/zero-inactive kernel and full guard proof, while `daemon_gcp_linux_test.go` provides actual GCP SA/cardinality component proof. `runtime_controller_linux_test.go` combines controller/SA/guard under a synthetic component lease, but its current external harness is AWS two-slot. These compiled suites do not constitute a newly executed GCP owner-view proof. A coordinated owned disposable native fixture combining GCP HA3 route/SA/fullguard and Classic4 one-slot is still required before acceptance of this candidate. No actual CP entitlement, enrolled gateway, cloud status or live DNS success is inferred.

## Prepared actual native component fixture

`TestDNSOwnerViewGCPNative` in `runtime_dns_owner_gcp_linux_test.go` now runs the real daemon supervisor, native platform probe, HA native BGP preflight, normal runtime `Apply`, real SA cardinality/public Up and (HA) both BGP peers Established plus owned route checks. It substitutes only the explicitly synthetic component lease responder reused from the existing native controller fixture. Native proof, source, route, full guard and BGP observers remain production implementations.

The test holds the serial owner mutex during a fresh `proveResolverDNS`, then requires exact A responses from both actual UDP and TCP bound socket exchanges. The reused owned receiver must listen on `10.20.0.53:53` and answer `app.localemulated.gcp.lab.test.` with `10.20.0.53`, recording each transport's counters. Exact native cleanup must then make DNS proof fail. Classic's inactive second slot remains empty. Underlay must be private or benchmark `198.18.0.0/15`; an explicit disposable namespace marker and empty initial daemon ownership are required.

Preparation is opt-in and performs no networking:

```sh
TUNNEX_GCP_DNS_OWNER_PREPARE_DIR=/absolute/new/private/directory \
  go test ./internal/ipsec -run '^TestDNSOwnerViewGCPComponentPrepare$' -count=1
```

It writes each profile's complete synthetic `RuntimeMaterial` plus random disposable PSKs as a mode0600 JSON line inside a newly created mode0700 directory, never stdout. The gateway owns underlay `198.18.222.10` and LAN/source `10.10.0.1/24`; peers own `.20` (and HA `.21`) plus receiver LAN `10.20.0.53/24`. HA uses the generated exact `/30` tunnel inputs/private ASNs. The external peer must supply exact return routing and independent UDP/TCP53 allowances for source `10.10.0.1`, without granting the gateway anything.

The isolated test requires `TUNNEX_GCP_DNS_OWNER_COMPONENT=1` and `/run/gcp-dns-owner-component` containing exactly `owned disposable namespace` plus newline. Feed the selected private material JSON line on stdin, then `exchange` after the test emits `GCP_DNS_OWNER_NATIVE_PROOF`, then `cleanup` after `GCP_DNS_OWNER_NATIVE_EXCHANGE`. The test emits only key-free phase markers. Use the separately source-bound Linux test binary in an immutable pinned daemon/FRR image; never the enrolled production gateway or its journal.

Fixture compilation and private material preparation passed. Native execution is still held for root coordination after the genuine restoration boundary settles. Existing Classic standalone peer supports exact DNS service tuples; its HA peer currently refuses those tuples, so HA's bounded test-only receiver service setup needs independent runtime review before executing. No native owner-view acceptance is claimed yet.
