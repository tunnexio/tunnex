# UPG-1: one-click upgrade for installations with App Access

Status: decision paper plus implementation on the local branch
`story/app-access-one-click-upgrade`. Not pushed, not released and not run on a
live host. Single-host Compose only. Kubernetes and HA are out of scope (section 10).

## 1. Summary

An installation that has App Access composed cannot use the ordinary upgrade
command at all. The App Access helper accepts only same-schema image
replacement. Together, these two limits block every release that adds a
migration. The exclusion was a limit of what had been qualified, not an
invariant of the App Access authority contract (AA-0/AA-7). A forward migration
under the running installation authority does not mint, roll back or bypass
anything that contract protects. Only a restore does.

**Recommendation:** `deploy/upgrade.sh` should own the App Access composition
end to end (Option A), in a fixed and verified order:

1. Admission checks
2. Authority snapshot
3. Verified backup
4. Proxy stop
5. Migrate
6. Authority readback
7. Proxy start

A failure leaves the public App Access listener stopped and names the supported
rollback, `restore.py`. None of the open founder decisions (section 11) changes
the security contract, so the design is implemented on this branch.

## 2. Problem as measured (demo, 2026-11-24, v0.1.45)

- `deploy/upgrade.sh` calls `refuse_existing_app_access` before it creates any
  temporary state. The call refuses when the project has an `app-proxy`
  container, or an `api` container with the `/var/lib/tunnex/app-restore`
  mount. Its message points at a "separately reviewed opt-in install/upgrade
  workflow".
- That workflow, `deploy/app-access/upgrade.py`, admits only one case. Both API
  images must report the same clean schema, equal to their own ceiling, and the
  same completed authority (`validate_preflight`). It never migrates. The
  README forbids down migrations and calls schema-changing upgrades "a
  separately qualified offline procedure" that does not exist.
- Consequence: the next release adds migration 0243, and no supported path
  takes an App Access customer there.
- Bundled-database backups are validated with the host's `pg_restore --list`.
  Fresh Ubuntu hosts do not ship it, so the step fails even though the dump was
  taken inside the postgres container.

Further facts found while reading the code. Each one breaks a naive "just remove
the guard" fix:

| # | Fact | Effect if the guard were simply removed |
|---|------|------------------------------------------|
| F1 | `compose()` passes only `-f tunnex.yml`. The App Access overlay (`deploy/app-access/compose.yml`) is not part of the managed deployment and is not covered by `TUNNEX_COMPOSE_SHA256`. | `up -d` would recreate `api` **without** `TUNNEX_APP_ACCESS_RESTORE_MARKER` and without the marker mount. The API would then skip the restore barrier, and the old proxy would be orphaned. This is the real reason the guard exists. |
| F2 | `compose()` overwrites `COMPOSE_PROFILES` with `bundled-db`/`external-db` and persists that value to `.env`. | The `app-access` profile would be dropped silently. |
| F3 | The pin loop does not include `TUNNEX_APP_PROXY_IMAGE`, and verification never asks for `-require-app-proxy`. | The proxy would keep an old or unsigned pin, or the target release might not contain a proxy at all. |
| F4 | `backupctl app-preflight` takes a `flock` (`O_CREAT\|O_RDWR`) in the marker directory, which the serving API mounts read-only. | `compose exec api backupctl app-preflight` cannot work. A one-off helper with that single mount writable is needed. |
| F5 | `upgrade-runner.sh` runs the **installed** `upgrade.sh`, and self-update happens only after the guard. | Every installed App Access host refuses before it can fetch a fixed script. A one-time bootstrap is unavoidable (decision D3). |
| F6 | The failure text and `docs/upgrade.md` say to restore with raw `pg_restore`. | For App Access, that bypasses the restore barrier and the fresh-authority recovery that AA-7 requires. |
| F7 | The isolated test CP was already moved from schema 179 to 180 by a manual API-only upgrade, while App Access stayed live (AA-10). | Evidence that the limit was procedural. |

## 3. Why schema-changing upgrades were excluded, and what a migration really touches

| Mechanism | Where it lives | Effect of a forward migration |
|-----------|----------------|-------------------------------|
| Installation authority generation/version (AA-7) | PostgreSQL singleton | Preserved unchanged. Only offline recovery after a restore advances it. Upgrade must **verify** that it is unchanged, not rotate it. |
| User `app_auth_epoch`, revoke tombstones, publication pointers | PostgreSQL | Preserved. Migrations are forward-only. Schema 173 and 175 down migrations refuse to discard authority or settings. |
| External restore barrier | Named volume `<project>_app_restore`, outside DB/Redis backups | Unaffected, **provided** the upgrade keeps the same volume identity and refuses while a marker is pending. The API checks the barrier before it auto-migrates (`cmd/server/main.go`: `restorebarrier.Check` precedes `db.Up`). The proxy checks at startup. |
| Dedicated proxy credential and TLS | DB (hashed) plus private host directory | Unaffected, provided the same secrets directory stays mounted. |
| Schema-bound authority checks | `app-preflight` requires clean schema equal to the binary ceiling, and completed authority | A mixed window (old proxy, new API mid-migration) fails closed, because authority is unreachable and the 4-second lease expires. The design avoids the window entirely by stopping the proxy first. |
| Binary rollback | — | Impossible across a schema change because there are no down migrations. Rollback is a **restore**, and a restore needs the barrier plus fresh-authority recovery. This is the only place where schema changes and authority truly interact. |

`upgrade.py` was written as a narrowly qualified image swap that leaves
listeners stopped for human review. Its "same schema" rule follows from what it
qualified (no migration step, no backup step), not from any AA-7 rule.

## 4. Invariants that must not be weakened

1. No upgrade runs while a restore marker is pending, and the upgrade never
   creates, clears or relocates the marker. The marker volume identity is
   exactly `<project>_app_restore` for every participant, before and after.
2. Every API and proxy that serves after the upgrade has the marker env and the
   read-only marker mount, from the signed overlay.
3. Images come only from the signed release: API, web, nginx, node-agent,
   migrate, optional AI engine **and app-proxy** (`-require-app-proxy`). No
   mutable tags. A target without a signed proxy is refused before any
   mutation.
4. Installation authority generation and version are identical before and
   after the upgrade, and recovery remains completed. A change means something
   other than an upgrade happened, so the upgrade fails closed.
5. The public proxy never serves against an API whose schema or authority has
   not been re-verified. It is stopped before the API is replaced and started
   only after step 4 passes.
6. No down migration and no automatic restore. A restore is never treated as
   an ordinary restart (AA-7).
7. The proxy credential and TLS directory, the published port binding and the
   project identity are preserved exactly. A mismatch refuses the upgrade
   instead of "fixing" it.
8. Single API and single proxy only. More than one participant refuses (HA
   fencing is unqualified).
9. No secret is read from container environment, and no secret is printed.
   Inspection uses labels, mounts and port bindings only.
10. Server Access and App Access stay independent. Neither one's configuration
    is required, read or changed by the other's path.

## 5. Options

**A. `upgrade.sh` owns the App Access composition (recommended).**
- How it works:
  - It installs the signed-source overlay as `<install>/app-access.yml`, hashed
    like `tunnex.yml`.
  - It pins the proxy and adds `app-access` to the persisted profiles.
  - It runs the ordering in section 6, using `backupctl app-preflight` before
    and after as the authority gate.
- Pros:
  - One command, one runner and one UI flow for every installation.
  - It reuses the verified backup, signed-release, status-file and
    edge/AI/Server Access handling that already exists.
- Cons:
  - `upgrade.sh` gains App Access knowledge.
  - Existing hosts need a one-time bootstrap (F5).

**B. Extend `upgrade.py` with migration support.**
- It would need its own backup, signed-file replacement, `.env` pinning,
  edge/AI handling and status reporting, duplicating `upgrade.sh`.
- App Access customers would get a second, different upgrade command, and the
  dashboard upgrade could not drive it. That violates "one click" and "no
  confusion".
- **Rejected** as the primary path. `upgrade.py` stays as a manual
  image-replacement tool.

**C. Fold App Access into `tunnex.yml` and the installer, driven by `.env`.**
- This follows the Server Access model: canonical volumes and `.env` keys, no
  extra file.
- Cleanest long-term. However, the API override (marker env and mount) cannot
  be profile-conditional in a single file. Every base install would then carry
  App Access wiring, which changes non-App Access installs and the base API's
  startup contract.
- Worth doing together with installer-level enablement. **Deferred** (D5).

**D. Status quo plus a documented manual offline procedure.**
- Fails the founder principle. **Rejected.**

**E. `upgrade.sh` delegates to `upgrade.py` for the App Access participants.**
- Two tools with different freeze and plan-hash models, a human-reviewed plan
  hash in a one-click flow, and still no migration support. **Rejected.**

## 6. Recommended design (implemented)

Classification happens before any temporary state or mutation. It inspects only
labels, mounts and port bindings, never environment.

- **No App Access participant and no `app-access.yml`:** the behaviour is
  exactly what it was before.
- **App Access present** (proxy container, API with the marker mount, or a
  managed `app-access.yml`): all of the following must hold, or the upgrade
  exits 13 with a specific message and changes nothing.
  - **Single participants:** exactly one `api` and at most one `app-proxy` in
    the project.
  - **Project:** the containers' Compose project equals the project this
    installation addresses, `COMPOSE_PROJECT_NAME` or `tunnex`.
  - **Composition files:** `tunnex.yml` plus exactly one overlay, read from the
    `config_files` label. Either the overlay is the managed `app-access.yml`,
    or it is a single legacy overlay. A legacy overlay is **adopted** only if
    the identity checks below pass. The operator's file is left on disk
    untouched.
  - **Marker volume:** every participant mounts `<project>_app_restore` at the
    marker path. A proxy without the API marker refuses.
  - **Proxy secrets:** the proxy's mount at `/etc/tunnex/app-proxy` comes from
    `TUNNEX_APP_PROXY_SECRETS_DIR` in `.env`.
  - **Proxy port:** the proxy publishes exactly
    `8443/tcp = ${TUNNEX_APP_PROXY_BIND_IP:-127.0.0.1}:${TUNNEX_APP_PROXY_PUBLIC_PORT:-443}`.
  - **Base domain:** `TUNNEX_APP_ACCESS_BASE_DOMAIN` is set in `.env`.

Apply order:

1. Verify the signed release. If App Access is present, verify again with
   `-require-app-proxy`. If the installed verifier is too old, run the
   **target** API's verifier by digest, as the AI path already does. Take the
   `TUNNEX_APP_PROXY_IMAGE` pin, which must have the form
   `ghcr.io/tunnexio/tunnex-app-proxy@sha256:<64 hex>`. A target without a
   signed proxy is refused here, before any backup or mutation.
2. Fetch the signed-source overlay and `restore.py` at the release source SHA.
3. **Authority snapshot.** Run `compose run --rm --no-deps --pull never
   --entrypoint backupctl api app-preflight` on the **current** API image. The
   run adds a derived one-off override that makes only the marker mount
   writable, so the lock works; serving mounts stay read-only. This refuses
   when:
   - a restore is pending,
   - the schema is dirty or does not match the binary,
   - authority is incomplete, or
   - the binary is too old.

   It records the generation and version.
4. Run the existing verified backup. For bundled PostgreSQL, the archive is now
   checked **inside** the postgres container (section 9). Then the manifest is
   created and verified, and the API preflight runs.
5. Write the pins (including the proxy), install `app-access.yml` and
   `app-access-restore.py`, persist the profiles (`bundled-db,app-access` or
   `external-db,app-access`), and record the overlay hash. Pull.
6. Stop `app-proxy`. Bring up the stack with the overlay but without the
   `app-access` profile. The API checks the barrier, auto-migrates and becomes
   healthy.
7. **Authority readback** with the **target** API image. The schema must be
   clean and equal to the new ceiling, recovery must still be completed, and
   the generation and version must be identical to step 3. Otherwise the
   upgrade fails closed.
8. Start `app-proxy` with the new signed pin (`--wait`, so its readiness
   requires a fresh authority claim). Run the API health check. Status becomes
   healthy.

If anything fails after step 6 begins, the proxy is stopped again (best
effort), the status becomes failed, and the message gives the rollback.

Status reporting uses only the existing states. New reason codes are free
text: `app_access_admission_failed` and `app_access_authority_changed`.

## 7. Threat notes

- **Restore racing an upgrade.** `app-preflight` holds the shared marker lock
  for its snapshot. The API refuses to boot with a pending marker before it
  migrates, and the proxy refuses to start. If a restore begins mid-upgrade,
  the new API or proxy refuses to start, and step 7 fails because the marker
  check runs under the lock.
- **Silent composition drift.** Reusing a different restore volume, secrets
  directory, port or project would either create an empty barrier (losing a
  pending marker) or expose the proxy differently. Every one of these refuses
  the upgrade. None is auto-corrected.
- **Target without a signed proxy, or a mutable proxy tag.** Refused (invariant 3).
- **Mixed versions.** Avoided by the stop, migrate, verify, start order. Even
  without it, authority loss fails closed.
- **Migration that needs authority recovery** (a future migration in the style
  of schema 173). Step 7 detects that recovery is incomplete, or that the
  generation changed, and leaves the proxy stopped. This is the backstop.
- **Secret exposure.** The helper output is non-secret JSON (schema, UUID,
  version, bool). No container environment is inspected. The failure messages
  name only backup file names.
- **Adopting a hand-written overlay.** Operator customisations beyond `.env`
  variables would be replaced by the signed overlay, the same "never edit,
  configure in `.env`" rule that already applies to `tunnex.yml`. The identity
  checks ensure the security-relevant identity (barrier, secrets, port) is
  unchanged.

## 8. Rollback story

| Failure point | State | Operator action |
|---|---|---|
| Before step 5 (verification, admission, authority snapshot, backup) | Nothing changed; the old stack keeps serving | Fix the cause and re-run |
| Steps 5–6 before the API migrated | Files and pins updated, proxy stopped | Re-run the same upgrade (forward fix). It is idempotent. |
| After migration (step 6 onward, including the step 7 mismatch) | DB may be at the new schema; proxy stopped | Prefer a forward fix: re-run, or move to the next release. To go back, restore the named pre-upgrade dump and manifest with `<install>/app-access-restore.py` (dry run, then `--apply`). That runs fresh-authority recovery: users sign in again, proxy credentials are reprovisioned, and apps are re-checked and republished. Never use raw `pg_restore` or a down migration. |

The upgrade never restores automatically (AA-7: never treat a restore as a
restart). The raw `pg_restore` instructions in `docs/upgrade.md` now state that
they do not apply to App Access installations.

## 9. Host `pg_restore` dependency

Archive validation for bundled PostgreSQL now streams the dump into
`compose exec -T postgres pg_restore --list`, the same container and version
that produced it. The `postgres:16-alpine` image ships `pg_restore`. The host
needs only Docker. External databases continue to validate through
`api preflight --database-verify-archive`. The contract test no longer provides
a host `pg_restore` fake, so it proves the host binary is not used. The change
applies to every installation, not only App Access.

## 10. Independence and scope

- **Server Access** stays wholly `.env`/canonical-volume driven and is never
  read, required or changed by the App Access path. App Access admission
  requires no Server Access setting, and the reverse also holds. Tests cover
  App Access alone, App Access with Server Access, and Server Access alone.
- **Out of scope:** Kubernetes/Helm upgrades, HA (more than one API or proxy
  is refused), the `install.sh` reinstall path (still refuses App Access, see
  D4), and first-time App Access enablement.

## 11. Founder decisions still open (none changes the AA-7 security contract)

- **D1 — Automatic proxy start after a verified forward upgrade.**
  - `upgrade.py` and the README leave listeners stopped for human inspection.
  - **Recommendation:** start the proxy automatically, but only after the
    authority readback proves that the generation and version are unchanged,
    recovery is complete and the schema is clean. That machine check replaces
    the human inspection for the upgrade case only. Restore and recovery keep
    "no automatic restart".
  - This is implemented as recommended. Reverting it is a one-line change
    (skip step 8).
- **D2 — Rollback across a schema change means restore with full invalidation.**
  - It forces fresh logins, proxy reprovisioning and app republishing. There is
    no down migration.
  - **Recommendation:** accept this and document it, with forward fix as the
    default.
- **D3 — One-time bootstrap for installed App Access hosts at or below v0.1.45.**
  - Their installed `upgrade.sh` refuses before self-update (F5). For each such
    host, the operator replaces `upgrade.sh` once with the copy at the target
    release's signed source SHA, after verifying the release descriptor. From
    then on, the upgrade is one click.
  - **Recommendation:** accept this, and announce it in the release notes for
    the first release that contains this change.
  - **Follow-up:** run the target's `upgrade.sh` (fetched at the signed SHA)
    immediately after verification, so that future guards can never trap an
    installation again. That changes when new code runs relative to the
    backup, so it needs its own review.
- **D4 — `install.sh` reinstall over an App Access installation keeps refusing.**
  - **Recommendation:** keep the refusal. Reinstall is not upgrade.
- **D5 — First-class enablement.**
  - Installer or dashboard enablement of App Access, which would make Option C
    the long-term shape.
  - **Recommendation:** schedule it as a separate story.
- **D6 — Kubernetes/HA App Access upgrade.**
  - **Recommendation:** keep it excluded until HA fencing is qualified.

## 12. Verification

- **Runs locally:**
  - `deploy/upgrade_apply_contract_test.sh`, `deploy/upgrade_contract_test.sh`
    and `deploy/upgrade_runner_contract_test.sh` under `sh` and `dash`.
  - The App Access Python tests (`deploy/app-access/tests`).
  - `docker compose config` merge checks of the overlay and the one-off helper
    override. These use the Compose CLI only and start no containers.
- **Not verified here:**
  - A real migration of a populated App Access database through a real
    `compose up`.
  - `app-preflight` inside a real container with the derived writable marker
    mount.
  - `restore.py` against the managed `tunnex.yml` + `app-access.yml` layout.
  - `pg_restore --list` from stdin in `postgres:16-alpine`.
  - The systemd runner.

  All of these need a Linux host with the signed images, and should be
  exercised on an isolated test CP before release.
