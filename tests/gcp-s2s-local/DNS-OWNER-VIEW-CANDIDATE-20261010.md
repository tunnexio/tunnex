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

The test holds the serial owner mutex during a fresh `proveResolverDNS`, then requires exact A responses from both actual UDP and TCP bound socket exchanges. The reused owned receiver must listen on `10.87.0.53:53` and answer `app.localemulated.gcp.lab.test.` with `10.87.0.53`, recording each transport's counters. Exact native cleanup must then make DNS proof fail. Classic's inactive second slot remains empty. Underlay must be private or benchmark `198.18.0.0/15`; an explicit disposable namespace marker and empty initial daemon ownership are required.

Preparation is opt-in and performs no networking:

```sh
TUNNEX_GCP_DNS_OWNER_PREPARE_DIR=/absolute/new/private/directory \
  go test ./internal/ipsec -run '^TestDNSOwnerViewGCPComponentPrepare$' -count=1
```

It writes each profile's complete synthetic `RuntimeMaterial` plus random disposable PSKs as a mode0600 JSON line inside a newly created mode0700 directory, never stdout. The gateway owns underlay `198.18.222.10` and LAN/source `10.86.0.1/24`; peers own `.20` (and HA `.21`) plus receiver LAN `10.87.0.53/24`. HA uses the generated exact `/30` tunnel inputs/private ASNs. The external peer must supply exact return routing and independent UDP/TCP53 allowances for source `10.86.0.1`, without granting the gateway anything.

The isolated test requires `TUNNEX_GCP_DNS_OWNER_COMPONENT=1` and `/run/gcp-dns-owner-component` containing exactly `owned disposable namespace` plus newline. Feed the selected private material JSON line on stdin, then `exchange` after the test emits `GCP_DNS_OWNER_NATIVE_PROOF`, then `cleanup` after `GCP_DNS_OWNER_NATIVE_EXCHANGE`. The test emits only key-free phase markers. Use the separately source-bound Linux test binary in an immutable pinned daemon/FRR image; never the enrolled production gateway or its journal.

Fixture compilation and private material preparation passed. Native execution is still held for root coordination after the genuine restoration boundary settles. Existing Classic standalone peer supports exact DNS service tuples; its HA peer currently refuses those tuples, so HA's bounded test-only receiver service setup needs independent runtime review before executing. No native owner-view acceptance is claimed yet.

## HA peer DNS component allowance

A subsequent test-only slice adds `DNSOwnerComponent: true` to the standalone GCP HA peer configuration. Only exactly two services are accepted: the same approved source host and `LocalTarget` destination, one UDP53 and one TCP53. Additional ports, sources, duplicate transports, reverse grants or missing opt-in refuse. AWS and Classic reject this HA-specific flag; their existing/default service behavior remains separate. Default HA still rejects additional services.

The external emulator reuses the existing static encrypted-reply service rules on the freshly selected owned return child and accepts exact requests on either independently healthy child. It adds no enrolled-gateway permission. Contract/rule regressions were added and the Linux ARM64 test binary compiles; their Linux execution is held until coordinated component execution, not reported as passed. Native peer/receiver counters remain required.

## Read-only licence request path

Current LicenceCard provides owner-only installation of an issued key through the normal `POST /api/v1/license` path, and does not contain a free-trial link. Existing CeilingUpgrade/CreateOrg links point to [the official trial page](https://tunnex.io/trial). Read on 2026-10-10, that page describes one trial per company domain, verified work email (consumer/disposable addresses refused), a 30-minute inbox verification link followed by explicit confirmation, and key issuance starting the 30-day period. It advertises two gateways, without card or sales call. The page does not explicitly establish FQDN entitlement; the issued key must pass the real feature gate. No email, trial request, confirmation, key signing or licence installation was performed in this read-only check.


Native harness preflight refused the original local10.10/24 and remote10.20/24 because existing colleague/AWS Docker networks own them. No containers were created and those networks were not touched. Preparation now defaults to isolated10.86/24 and10.87/24 and accepts explicit `TUNNEX_GCP_DNS_OWNER_LOCAL_PREFIX`, `TUNNEX_GCP_DNS_OWNER_REMOTE_PREFIX`, `TUNNEX_GCP_DNS_OWNER_SOURCE` and `TUNNEX_GCP_DNS_OWNER_RESOLVER`. Prefixes must be exact disjoint private IPv4 /24s; source and receiver must be actual host addresses inside their respective prefixes. The Go helper updates material, BGP router ID and policy and reseals with the existing runtime implementation; no manual digest reconstruction.


Preparation also accepts bounded `TUNNEX_GCP_DNS_OWNER_GATEWAY_OUTSIDE`, `TUNNEX_GCP_DNS_OWNER_PEER_OUTSIDE_1` and `TUNNEX_GCP_DNS_OWNER_PEER_OUTSIDE_2`. They must be distinct private/benchmark IPv4 hosts in one /24, outside both LANs. To preserve Classic fixtures while qualifying HA sequentially, the latter prepared material uses198.19.223/24 underlay and10.88/24→10.89/24 LANs after independent harness non-overlap preflight. No existing networks are adopted.

The first actual Classic component run refused controller construction before any SA. The fixture used plain `t.TempDir()` for `JournalDir`; the journal requires a canonical root-owned mode0700 directory. The fixture now reuses `journalDir(t)` and creates its temporary root under `/run` in the explicitly disposable namespace, so BGP's strict private-ancestor checks also hold. BGP qualification uses the same private journal parent. No production directory validation was relaxed. Newly created component containers were retained/stopped for diagnosis; the enrolled gateway and existing namespaces were untouched. This failed startup is not a native acceptance result.


## Actual Classic native component accepted

The replacement immutable `078ca04313708990b16857c78549bf2053b1d89d` test binary passed the isolated Classic component on the pinned image recorded in [the key-free receipt](DNS-OWNER-CLASSIC-NATIVE-20261010.json). Actual one-slot native proof while the serial owner mutex was held, exact UDP and TCP A socket exchange, then exact cleanup and DNS proof refusal all completed (native test4.94s). Receiver counters recorded one query/one A answer for each transport; no truncation or NXDOMAIN was exercised by this fixture. New owned components were stopped and preserved, with no observed OOM. The prior startup attempt remains a failed fixture-construction checkpoint, not a passed run.

This uses the explicitly synthetic component lease. It does not establish normal CP delivery/entitlement, automatic FQDN licence acceptance or Google Cloud interoperability. HA actual owner-view compatibility and native route-slot permutation are still pending.

A later immutable fixture slice closes an additional acceptance gap: after exact cleanup, it performs normal `DNSRuntimeTransport.ExchangeDNS` requests for both UDP and TCP using the captured exact source/query/binding. The original accepted authority must still have at least the unchanged minimum completion window, so lease expiry cannot explain the denial. Both transport requests must refuse with no response; the external harness must compare receiver counters before and after cleanup and prove no extra query arrived. The earlier `078ca043` Classic result established cleanup proof refusal only. Post-cleanup exchange/counter denial is not claimed until the new slice executes; the running HA artifact is not replaced mid-run.

The final Classic component run used source `bcc925db` and immutable binary SHA256 `1512178e4e78b14416f46638a695ee4f2b96cacc46ad8a73ea01bcb71e73dba4`. Actual production DNS transport exchanged the exact A answer over UDP and TCP, then exact owned cleanup completed. With the captured original authority still valid and the context live, both normal `ExchangeDNS` requests were refused; receiver counters remained one query and one answer per transport. The key-free receipt is [DNS-OWNER-CLASSIC-CLEANUP-EXCHANGE-NATIVE-20261010.json](DNS-OWNER-CLASSIC-CLEANUP-EXCHANGE-NATIVE-20261010.json). This is isolated synthetic-lease component evidence, not control-plane, licensed FQDN, or Google-cloud acceptance.

HA preflight has not passed. The original observer socket path was measured at 114 bytes, beyond the Linux AF_UNIX path bound; fixture-only `47453c90` shortened its private paths. The new run passed the socket startup boundary but refused child identity. That refusal remains under diagnosis without relaxing ownership checks or claiming native HA DNS acceptance.

Final source `f92fac12` passed sequential owned native ARM64 component runs for GCP HA and Classic using binary SHA256 `db7ae3c3053fa72dbed6024099a5af6410fa5cc6cd1b73df77b502527558aa8b`. HA waited for `STANDALONE_DNS_PEER_READY`, emitted only after independently observed SA health, owned BGP return route/link verification, atomic exact service guard replacement and complete typed native guard readback. Each profile made one UDP and one TCP query, received the exact A answer, then refused both normal transport requests after cleanup with original authority/context still live; receiver counters stayed one query and one answer for each transport. No query retries or added readiness sleeps were used. The earlier HA failures remain historical evidence: overlong observer socket path, incorrectly copied non-root supervisor ownership, and an exchange before service readiness were not treated as successful qualification. A first serve attempt with transport absent was preserved before the clean final run.

The final receipts are [HA](DNS-OWNER-HA-FINAL-NATIVE-20261010.json) and [Classic](DNS-OWNER-CLASSIC-FINAL-NATIVE-20261010.json). [Stopped state](DNS-OWNER-FINAL-STOPPED-20261010.json) records all six owned containers stopped, none OOM-killed; exit137 followed bounded stop. These runs use synthetic component lease authority and prove compatibility of production SA/kernel/full-guard/DNS exchange paths with both GCP profiles. They do not prove enrolled control-plane FQDN entitlement, Google Cloud traffic, or current cloud readiness. Final focused DNS race tests passed in 3.836 seconds; the prior unchanged full-package journal race timeout remains reported above.
