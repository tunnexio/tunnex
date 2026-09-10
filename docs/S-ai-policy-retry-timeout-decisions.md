# Deterministic retry timeout regression

The retry test starts a 150ms deadline before database selection and timestamp persistence. If the deadline expires there, no native attempt occurs and the second-pass starvation assertion does not test its intended condition.

Locked: keep production scheduling unchanged. Trigger deadline expiry synchronously at the existing engine fixture hook, after database preparation. Assert the hook was reached and the context reports DeadlineExceeded. Preserve the second-target applied assertion. Validate against an isolated PostgreSQL fixture in both editions and mutation-check removal of the scheduling timestamp update.
