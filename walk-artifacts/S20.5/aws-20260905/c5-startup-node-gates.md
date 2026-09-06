# C5 runtime startup correction — local gate and review

2026-09-05. Decision-first C5 is recorded in
`docs/S20.5-aws-cni-compatibility-decision-proposal.md` before product changes.
This is a local substitute, not successful AWS enrollment or story acceptance.

## Exact tested product bytes

Base source was `84c8597be80dde2410d7886c6115fba9701bd952`, with only these
three node files changed. Their SHA-256 values remained unchanged through the
focused tests, full suites and independent review:

| File under `apps/node/cmd/agent/` | SHA-256 |
|---|---|
| `main.go` | `9ac0ecebe6ac7fb78bfcda9d2cb5dc1bfd581def2d6a5e5285ba6c428775f97b` |
| `k8s_cni_startup.go` | `2aa08b34552a47b59c59aaa5da96a0e756e6c4936b11093b2935dc7d33cd99e5` |
| `k8s_cni_startup_test.go` | `a1c8a09d6409710a09a736277fda5fb0ac2cd7c7c96c5c903b1f4ab8c8f8f33c` |

## Gate results

- Focused observer tests: PASS, 10.671 seconds, isolated Linux container with
  no network and read-only source/module mounts.
- Full node suite: `GOFLAGS=-mod=readonly go test -count=1 ./...`, PASS all
  14 packages; command package 100.316 seconds.
- Full race suite: `GOFLAGS=-mod=readonly go test -race -count=1 -p 1 ./...`,
  PASS all 14 packages; command package 101.931 seconds, no race reports.
- Complete node-source manifest hash before and after:
  `c70aebf3f9cd9975b5bd09016c45613a824a2717d85fdde2b2257a8603141620`.
- Go 1.25.13, Linux/arm64, nft 1.1.6, iptables-nft-save 1.8.13
  (`nf_tables`), OpenVPN 2.7.5. Full suites used a disposable container with
  NET_ADMIN only in its own namespace, source read-only, and the explicitly
  verified `tunnex-s205-aws-20260905a_default` task network. Default Compose
  and cloud resources were not changed by these tests.
- An attempted native Darwin command-package run did not compile the existing
  Linux-only egress surfaces. It is recorded as unsuccessful, not hidden or
  counted green; Linux suites above are the applicable node runtime tests.

Tests cover invalid/missing grants, both closed scopes, no premature admission,
immediate probe release, cancellation, real Store owner/epoch/scope reset,
and continued observation across an actual greater-than-ten-second startup
delay. No init proof or cached write authority is transferred into runtime.

## Bounded independent review

An independent reviewer checked these frozen bytes against actual Store
mutex/flock handling, main startup ordering, slow desired-state fetches,
operation-scoped expiry, cancellation and readiness. No concrete high/medium
defect was found. Root separately reviewed the implementation and tests.

Limits remain explicit: the sampler does not itself withdraw traffic or set
readiness after admission; existing guarded reconciliation owns those actions.
The tests are not the complete main/CP/withdraw wire composition. New immutable
AWS enrollment must prove that composition, and final exact-SHA gates, CI and
story-end multi-finder review remain outstanding.
