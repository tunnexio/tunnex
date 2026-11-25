# SA-UX-3: Server Access setup failure reason and the fake pinned fingerprint

2026-11-25; local branch `story/sa-ux-3`, base `origin/main` 60c8f7c2. Not pushed.

Two Server Access bugs found on the live v0.1.47 demo. Product principles that bound every decision: no user
confusion, security never weakens, one-click upgrades keep working (old/new gateway against new/old control plane),
no feature-to-feature dependencies.

## Bug 1: the real setup failure reason is lost

### Problem

Automatic SSH setup against a host with a previous Tunnex setup failed. The target helper
(`packages/apptransport/bootstrap/helper.py`) raised `Existing setup found. Use add-account, or inspect and explicitly
remove it first.` and printed it to stderr. The gateway (`apps/node/internal/serveraccess/enrollment.go`) collected the
output in `boundedSetupOutput` but, on a non-zero exit, discarded it and reported only `setup_failed`. The control
plane then showed "Target setup failed. Check the target journal; …" — but the helper never wrote to the journal, so
the administrator had no way to learn the reason.

### Decisions

1. **One structured failure line, fixed codes.** On every refusal it can name, the helper prints exactly one line
   `TUNNEX SSH SETUP ERROR <code>` to stdout before exiting non-zero. `<code>` is from a fixed allow-list; the
   human message stays on stderr as before. Codes are flat snake_case with a `setup_` prefix (the shared reason map
   and its Go sync test use `[a-z_]+` keys, so `missing_prerequisite:<cmd>` is not representable, and the prefix keeps
   setup codes from colliding with `failed` and other session codes). The allow-list:

   | Code | Helper trigger |
   |---|---|
   | `setup_not_root` | helper not run as root |
   | `setup_unsupported_os` | not Linux |
   | `setup_unsupported_distro` | distribution outside the supported families |
   | `setup_no_systemd` | `/run/systemd/system` missing |
   | `setup_missing_systemctl`, `setup_missing_ssh_keygen`, `setup_missing_ip` | prerequisite command missing |
   | `setup_no_openssh` | `/usr/sbin/sshd` missing |
   | `setup_selinux_enforcing` | SELinux enforcing |
   | `setup_unsafe_path` | symlink or non-root-owned/writable path in the helper tree |
   | `setup_existing_setup` | a `tunnex-browser-sshd` unit exists but `/etc/tunnex-browser-ssh` does not (leftover or foreign) |
   | `setup_foreign_setup` | `/etc/tunnex-browser-ssh` exists but is not owned by this helper (no valid `managed.json` marker) |
   | `setup_identity_differs` | existing setup belongs to another organization, server record, port or CA |
   | `setup_ca_mismatch` | CA key/fingerprint differs from the verified Tunnex CA, or the installed CA changed |
   | `setup_principal_conflict` | an existing principals file differs |
   | `setup_ip_mismatch` | the machine does not own the registered private IP |
   | `setup_port_invalid` | dedicated port outside 1024–65535 |
   | `setup_port_in_use` | the dedicated port is already bound |
   | `setup_no_eligible_accounts` | no (or not all chosen) accounts are eligible non-system login users |
   | `setup_too_many_accounts` | more than 16 accounts |
   | `setup_service_failed` | `sshd -t` or the systemd unit failed to start/reload |
   | `setup_authorization_expired` | (launcher) the one-time authorization expired before the installer ran |
   | `setup_installer_mismatch` | (launcher) the installer digest did not match |

   Anything else (bundle missing, malformed identity, unexpected exceptions) emits no line and falls back to the
   generic `setup_failed`.

2. **The allow-list lives once, in Go.** `bootstrap.SetupErrorCodes` in `packages/apptransport/bootstrap` is used by
   the gateway (parse) and the control plane (re-check). A Go test extracts every code literal from `helper.py` and
   the launcher in `authorize.py` and asserts each is in the list, and the reverse.

3. **Gateway parses only the allow-listed code, never free text.** On a failed `session.Run`, the gateway scans the
   already-bounded output (64 KiB cap unchanged) for a line that is exactly the prefix plus a code in the set, with
   nothing trailing and at most 80 bytes. The last such line wins. Unknown codes, trailing text and oversize lines are
   dropped. The code travels in a typed error; the report carries `setup_error: <code>` with `result: setup_failed`.

4. **Control plane maps code → sentence + next step.** It re-checks the code against the same set (defense in depth),
   then sets the job `Message` from `setupErrorMessages`. An unknown or absent code yields the generic `setup_failed`
   message, never `bad()` (a refused report would leave the job stuck in "running" until expiry). A `setup_error` on
   any other report kind (public key, running, ok, other failures) is refused as malformed. The code (not text) goes
   into the `enrollment_status` audit metadata as `reason`.

5. **UI wiring: keep `Message` as the carrier, no OpenAPI change.** The setup panel renders `job.message`. Adding an
   API `reason` field would need an OpenAPI change and still need `Message` for stale bundles. Instead each code also
   has an entry in `apps/web/src/lib/serverAccessReasons.ts`, and a Go test asserts that the control plane's
   message for every setup code equals the web entry's `text + " " + next` exactly, so the two cannot drift.
   `TestEveryServerAccessCodeHasWebText` also iterates `bootstrap.SetupErrorCodes`.

6. **The journal claim becomes true.** The helper (and the launcher, for its own two refusals) writes
   `setup refused: <code>` (code only, plus the local human message) to syslog under the identifier
   `tunnex-browser-ssh` using Python's standard `syslog` module; journald stores it, so
   `journalctl -t tunnex-browser-ssh` shows it. Logging is best effort and can never change the exit path. The
   generic text now names that command instead of a vague "check the journal".

7. **Next steps match real triggers.** `setup_existing_setup` happens only when the unit exists without
   `/etc/tunnex-browser-ssh`; `tunnex-browser-ssh remove` refuses there (no `managed.json`), so the text tells the
   administrator to inspect and remove the leftover unit by hand instead. `setup_identity_differs` names the port as
   one possible difference and points to `sudo tunnex-browser-ssh remove` (which works there).

### Security analysis

- What can reach the UI: one of the fixed control-plane sentences, selected by a code that passed two exact-match
  allow-list checks (gateway and control plane). No target-originated bytes are ever displayed, stored or audited
  except the code itself, and a code is a compile-time constant on both sides.
- Why it cannot carry secrets: the gateway never forwards free text; the per-job key K, HMAC/attestation lines, the
  temporary private key and tokens are never part of a code. A hostile or compromised target can at most choose the
  wrong canned sentence, which it could already cause by failing in that way.
- The helper's human message (paths, account names) goes only to the target's own stderr and journal, as today; the
  helper holds no secrets (its bundle is public material).
- Output limits are unchanged (64 KiB total, 80-byte line cap for the code line).

### Version skew

The helper and launcher always match the control plane: the control plane embeds them (`bundleScript`,
`authorizationCommand`); the gateway only transports the script and never uses `bootstrap.Helper`. Skew is therefore
only gateway ↔ control plane:

- **New control plane, old gateway:** the new `setup_error_codes` job flag is ignored by the old gateway (lenient
  decode), which reports plain `setup_failed`; the administrator sees the generic text, which is now accurate because
  the new helper logged the code to the journal.
- **Old control plane, new gateway:** the old control plane decodes reports strictly. The new gateway sends
  `setup_error` only when the job carries `setup_error_codes` (the `host_key_attestation` pattern), so an old control
  plane never sees the field and keeps its old behaviour.
- **New + new:** the specific sentence is shown.

## Bug 2: Edit server shows a fake pinned fingerprint

### Problem

A Linux server registered for automatic setup has no accounts and no host trust. The API stores (and requires on
input) the placeholder `SHA256:` + 43 × `A` for it, and returned it to the dashboard. The Connection view masked it as
"Host trust pending SSH setup", but **Edit connection** pre-filled "Independently verified SHA256 host fingerprint"
with the placeholder as a real, required value, and made accounts required. Typing an account and saving pinned the
placeholder as a real fingerprint: the API accepted placeholder + accounts. Every later check or setup sync would then
fail or carry the wrong trust.

### Decisions

1. **The placeholder stays an internal storage value only.** It is still what the database holds for a pending
   server (no migration), but:
   - the API never returns it: `Workspace` and server save responses omit `host_fingerprint` when it is the
     placeholder;
   - on input, a pending Linux server (no accounts) accepts an empty `host_fingerprint` (normalized to the stored
     placeholder) and still accepts the placeholder itself, so an old cached bundle or script keeps working;
   - **the placeholder is refused as a pin** whenever the server has accounts (Linux or Windows) with
     `host_fingerprint_placeholder` / "This is Tunnex's placeholder for pending host trust, not a real fingerprint…".
     It is also refused as a management pin in setup input and as a target-reported setup result fingerprint.
   - One named constant in Go (`PendingHostFingerprint`) and one in the web replace the inline literals.
2. **Edit form, pending Linux server:** no fingerprint and no accounts field by default; the form says host trust is
   pending SSH setup. A disclosure "Advanced: enter accounts and verify the host key independently" holds empty,
   optional fields for accounts and the browser-terminal listener fingerprint (the dedicated `ssh_port` listener, not
   the management key). They are coupled: both empty keeps trust unchanged (sends an empty fingerprint and no
   accounts); filling one requires the other, and the fingerprint must look like `SHA256:` + 43 characters and not be
   the placeholder.
3. **Edit form, Linux server with real trust:** the current pin is shown read-only ("Pinned host fingerprint") and
   sent back unchanged. Replacing it is explicit: a disclosure "Advanced: replace the pinned host fingerprint" with an
   empty field; empty keeps the current pin. Editing any other field therefore never changes the pin.
4. **Windows:** the RDP certificate fingerprint stays an editable field (this form is the only place it is set);
   Windows servers always have accounts and a real pin, so the placeholder never applies to them.
5. **Dashboard round-trips:** `save()` (enable, toggles) sends the server's fingerprint or an empty string, never
   the placeholder; the Connection view derives "Host trust pending SSH setup" from a Linux server with no pin.
   `sshBootstrap.ts` refuses a manual import result carrying the placeholder.

### Leak scan

- API: `Workspace` (servers list, the only server read path) and `SaveServer` return value — redacted.
  Non-managers already never receive `host_fingerprint`. Session material to the gateway uses the fingerprint only
  for servers with accounts, which can no longer hold the placeholder through the API.
- Audit: server create/update metadata does not include the fingerprint. Exports: none for servers.
- CLI (`apps/cli`): uses only editor endpoints; no server fingerprint.
- Web: Connection view, edit form, `save()` round-trip, `RegisterServer` (bootstrap registration now sends an empty
  fingerprint). Test fixtures that used the placeholder as a "real" fingerprint are changed to a real-looking value.

## Deferred

- Recording a structured reason for failures before the helper/launcher runs (Python missing, sudo refused): they
  still show the generic text.
- Moving the placeholder out of the database (nullable column) — a migration, not needed for the fix.
