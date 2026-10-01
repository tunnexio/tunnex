# Dashboard upgrade descriptor transfer — 2026-10-01

A user-triggered v0.1.34 to v0.1.35 upgrade completed signed-release verification, database backup, and preflight, then reported `pulling_failed`. The target API image downloaded successfully. Its release verifier rejected `/tmp/release.json` because it was a directory.

The installed runner has `PrivateTmp=yes`. Its downloaded manifest existed in the service mount namespace, while Docker resolved the `-v` source in the daemon namespace. The repair sends the descriptor through stdin into a temporary file inside the verified API container.

## Live proof

A temporary systemd unit with `PrivateTmp=true` executed the actual changed shell block from `deploy/upgrade.sh` against the published signed v0.1.35 descriptor (source `32411ac9758796bc0997a4f8ba05acca56268cbd`, sequence 303).

- The probe confirmed its mount namespace differed from the host.
- The descriptor verified and exported the signed native AI engine digest.
- Changing the descriptor version without resigning caused verification to fail.
- Existing engine encryption/admin credentials and egress configuration passed `ai_validate_existing` without printing their values.
- Installed environment, Compose, release metadata, and gateway container identity/start time were unchanged.
- The verifier container used the signed API digest, no host mounts, and `--network none`; it was removed after the probe.

The probe did not apply the application upgrade. The user retains the dashboard retry action and the failed attempt's verified database backup.

## Regression checks

`upgrade_contract_test.sh`, `upgrade_apply_contract_test.sh`, and `upgrade_runner_contract_test.sh` pass. The updated fixture requires nonempty byte-identical stdin, the approved image and verification arguments, no host binds, and unchanged deployment files with retained backups when verification fails. Independent review found no actionable issue.
