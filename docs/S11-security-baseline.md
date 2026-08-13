# S11 — security scanning baseline (first-ever run)

Recorded 2026-07-29 against `story/S11-hardening` (PR #41). CodeQL, Trivy and OpenSSF Scorecard had **never**
executed on this repository; govulncheck had never run in CI. This is the baseline event, kept as a record
because the *count* is the artifact: "CodeQL security-extended: 0 high, 0 medium, 0 low" is a materially
stronger claim than one that only mentions high — and an unenumerated tail is the first thing a reviewing
security team asks about.

## CodeQL — `security-extended`, Go + TypeScript

**ZERO alerts at every severity.** Verified from the code-scanning API rather than inferred from a green job:

| language | analysis | duration | `results_count` |
|---|---|---|---|
| go | `/language:go` | 3m26s | **0** |
| javascript-typescript | `/language:javascript-typescript` | 1m6s | **0** |

`GET /code-scanning/alerts` returns `[]`. Both analyses uploaded successfully, and the run times are
consistent with real analysis rather than a no-op.

**Classification:** no clusters (no error-handling, path-handling or crypto-usage pile-up — the usual shape
of a first scan on a large Go codebase), and no outliers. Nothing to disposition, nothing suppressed.
**There are no suppressions anywhere in this repository**, and adding one would need its own ruling — a first
scan papered over with `nosec`-equivalents is the exact debt EPIC 11 slice 1 repaid.

**Honest caveats, so the number is not over-read:**
- CodeQL's Go extraction runs via `autobuild`. Whether it built **all five** Go modules or a subset is
  **unverified** — if autobuild covered only part of the tree, the zero is a zero over what it analysed.
  *Follow-up (registered): assert per-module extraction coverage, or replace autobuild with an explicit
  build, so the denominator is known.*
- The threshold the CI gate BLOCKS on is high/critical (SARIF `level: error`). Medium/low would appear in the
  Security tab without failing the build; today there are none of either.
- A clean static-analysis baseline is not an audit. No independent third-party assessment has been performed
  (stated the same way in `SECURITY.md`).

## govulncheck — all five Go modules

The gate's first honest run **rejected**, and every finding was real and reachable. Two roots, one dependency,
one clean module:

| module | finding | root | disposition |
|---|---|---|---|
| apps/cli | `GO-2026-5856` `crypto/tls@go1.25.11` | **Cluster A** — toolchain | fixed (pin bumped) |
| apps/helper | `GO-2026-4971` `net@go1.25` | **Cluster A** — toolchain | fixed (pin bumped) |
| apps/api | `GO-2026-5970` `golang.org/x/text@v0.32.0` | **Cluster B** — dependency | fixed → v0.39.0 |
| apps/operator | `GO-2026-5970` `golang.org/x/text@v0.19.0` | **Cluster B** — dependency | fixed → v0.39.0 |
| apps/node | — | — | clean |

**Cluster A root — two toolchain pins that disagreed** (one-truth violation at the toolchain tier). The
Makefile/Dockerfiles had been bumped to `1.25.12`, but the `go` directives still read `1.25.0`/`1.25`, and
CI's `setup-go` resolves `go-version-file: <module>/go.mod` — so the docker gates built on a patched
toolchain while the security jobs scanned an unpatched one. **Fixed structurally, not just corrected:**
every pin site now reads `1.25.12`, and `scripts/check-toolchain-pin.sh` **fails the build** when the go
directives, `GO_IMAGE`, the Dockerfiles and the devcontainer disagree. The guard was proven to reject
(partial bump → exit 1; agreement → exit 0).

## Trivy + Scorecard — did not produce a baseline

**O-1: Trivy never ran** — `Unable to resolve action aquasecurity/trivy-action@0.28.0` (a pin that does not
exist), failing in 3 seconds. Because `continue-on-error` sat on the JOB, that 3-second no-op reported the
same green as a real scan: **an advisory job that fails to start is indistinguishable from one that passes.**
That is the S11-1 class in miniature, discovered inside the slice that repaid it.

**Fixed as a class, not an instance:** `continue-on-error` now sits on the **findings-producing step only**,
never on the job, and each advisory job **asserts it actually produced results** (`test -s *.sarif`). Advisory
means *its findings don't block* — never *the job needn't run*. Pin corrected to `0.36.0`. Scorecard is
`main`-push-gated and has not produced a baseline yet; both will on the first post-merge run.

## Registered follow-ups from this baseline

1. **CodeQL Go extraction coverage** — verify autobuild covers all five modules, or use an explicit build.
   *Trigger: the next security-workflow change, or any claim made publicly about the CodeQL result.*
2. **Trivy + Scorecard baselines** — capture and record on the first `main` run after merge.
