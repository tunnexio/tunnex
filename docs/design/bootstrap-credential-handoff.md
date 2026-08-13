# Installer bootstrap credential handoff

Status: design decision for local implementation; no production rollout is implied.

## Decision

The installer owns the first-run administrator password. It generates one only when
the target database has no users, invokes a one-shot bootstrap entrypoint with its
standard output attached to the installer's terminal, and prints the credential in
that terminal exactly once. The long-running API is started only after this step.

The installer and the one-shot bootstrap command are one trusted local operator
boundary: both run under the operator's Docker authority on the deployment host.
The bootstrap command receives the password only for the duration of that process,
uses the existing password hashing/authentication path, creates the account, and
exits. SMTP delivery is optional and is not part of credential display.

## Required invariants

- No Docker-log parsing. The attached bootstrap stdout is the sole installer display
  path; the API must not duplicate the credential into structured or container logs.
- Fresh install only. If the database already contains an administrator/user, the
  bootstrap command is a no-op: it must not generate, reset, print, or email a new
  credential.
- No persistent plaintext storage. The password may exist in installer/bootstrap
  process memory and the attached stdout stream only. Do not use a host temp file,
  Compose `.env` entry, Docker volume, or long-running container environment value.
- Cleanup is immediate: the installer releases the in-memory value after printing
  and the one-shot process exits before the normal API stack starts. Interrupts and
  failures must leave no credential artifact and must not claim success.
- SMTP-independent. SMTP configured and SMTP skipped must produce the same terminal
  credential behavior. SMTP failure must not suppress or duplicate the terminal
  output.
- Existing password hashing, forced-change, and OTP-reuse protections remain the
  only authentication implementation; the installer must not hash or verify a
  password itself.

## Test and evidence requirements

The implementation is not complete until tests demonstrate:

1. Fresh database + SMTP configured: one terminal password, account created, email
   optional, no credential in structured logs.
2. Fresh database + SMTP skipped: one terminal password, account created, no log
   fallback or Docker-log instruction.
3. Existing database/admin with either SMTP mode: no password generated, printed,
   reset, or emailed.
4. Bootstrap failure or interrupted installer: non-zero result and no success claim;
   subsequent rerun remains safe and idempotent.
5. Installer shell contract confirms the attached one-shot command is used and no
   `docker compose logs` credential extraction remains.

This document authorizes implementation only within the invariants above; it does
not authorize pushing, CI, merging, or production execution.
