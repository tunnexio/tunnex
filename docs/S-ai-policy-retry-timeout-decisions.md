# Deterministic retry timeout regression

The retry test starts a 150ms deadline before database selection and timestamp persistence. If the deadline expires there, no native attempt occurs and the second-pass starvation assertion does not test its intended condition.

Locked: keep production scheduling unchanged. Trigger context cancellation synchronously at the existing engine fixture hook, after database preparation. Assert the hook was reached and the context reports Canceled. Both cancellation and deadline expiry abort the same transaction; rename the test to describe cancellation accurately. Preserve the second-target applied assertion. Validate against an isolated PostgreSQL fixture in both editions and mutation-check removal of the scheduling timestamp update.

## Validation

- Dedicated `tunnexretry0910` PostgreSQL container/network; ephemeral data, loopback port 15496. Existing stacks untouched.
- Original test with forced pre-query deadline expiry reproduced `timed-out target starved another pending assignment`.
- Corrected test: five actual database runs per edition passed.
- Mutation: removing the scheduling timestamp update caused the corrected starvation assertion to fail; production source restored byte-for-byte.
- Full `internal/aigateway` package passed in open (44.741s) and enterprise (41.889s) editions, GOFLAGS=-mod=readonly.
- Main composite CI and post-merge publication remain unverified.
