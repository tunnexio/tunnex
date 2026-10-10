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
